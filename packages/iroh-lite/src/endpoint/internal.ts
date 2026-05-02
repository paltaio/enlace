import { concatBytes, copyBytes } from '../bytes'
import { endpointIdFromSecretKey, randomSecretKey } from '../crypto/ed25519'
import { validateX25519PrivateKey } from '../crypto/x25519'
import type { Datagrams } from '../relay/frames'
import type { RelayWebSocketClient, RelayWebSocketReceiveFrame } from '../relay/client'
import {
  connectRelayWebSocket,
  type ConnectRelayWebSocketOptions,
  type RelayWebSocketConstructor,
} from '../relay/client'
import { type RelayUrlInput, normalizeRelayUrl } from '../relay/url'
import {
  QuicClientHandshakeDriver,
  QuicServerHandshakeDriver,
  type QuicServerTransportParametersInput,
} from '../quic/handshake-driver'
import { QuicEndpointRole } from '../quic/transport-parameters'
import {
  QuicRelayClientDriver,
  QuicRelayServerDriver,
  type QuicRelayReceiveResult,
  type QuicRelayStreamSendResult,
  splitRelayDatagramPackets,
} from '../quic/relay-driver'
import { parseQuicLongHeader } from '../quic/packet'
import { encodeQuicTransportParameters } from '../quic/transport-parameters'
import type { QuicStreamReceiveOutput } from '../quic/streams'

const defaultFlowControlLimit = 65536n
const connectionIdLength = 8

type EndpointConnectionDriver = QuicRelayClientDriver | QuicRelayServerDriver

export interface EndpointCreateRelayOnlyOptions {
  readonly relayUrl: RelayUrlInput
  readonly secretKey?: Uint8Array
  readonly WebSocket?: RelayWebSocketConstructor
}

export interface EndpointConnectOptions {
  readonly endpointId: Uint8Array
  readonly relayUrl: RelayUrlInput
  readonly alpn: Uint8Array
  readonly x25519PrivateKey?: Uint8Array
}

export interface EndpointAcceptOptions {
  readonly alpn: Uint8Array
  readonly x25519PrivateKey?: Uint8Array
}

export interface BidiStreamWriteOptions {
  readonly fin?: boolean
}

type EndpointStream = BidiStream | UniStream

export class Endpoint {
  readonly relayUrl: URL
  readonly endpointId: Uint8Array
  readonly #secretKey: Uint8Array
  readonly #relayClient: RelayWebSocketClient
  readonly #relayRouter: RelayDatagramRouter

  private constructor(options: {
    readonly relayUrl: URL
    readonly endpointId: Uint8Array
    readonly secretKey: Uint8Array
    readonly relayClient: RelayWebSocketClient
  }) {
    this.relayUrl = new URL(options.relayUrl)
    this.endpointId = copyBytes(options.endpointId)
    this.#secretKey = copyBytes(options.secretKey)
    this.#relayClient = options.relayClient
    this.#relayRouter = new RelayDatagramRouter(options.relayClient)
  }

  static async createRelayOnly(options: EndpointCreateRelayOnlyOptions): Promise<Endpoint> {
    const secretKey =
      options.secretKey === undefined ? randomSecretKey() : copyBytes(options.secretKey)
    const connectOptions = relayConnectOptions(options.relayUrl, secretKey, options.WebSocket)
    const relayClient = await connectRelayWebSocket(connectOptions)
    const endpointId = await endpointIdFromSecretKey(secretKey)
    if (!equalBytes(relayClient.endpointId, endpointId)) {
      throw new Error('relay authenticated unexpected endpoint id')
    }
    return new Endpoint({
      relayUrl: normalizeRelayUrl(options.relayUrl),
      endpointId,
      secretKey,
      relayClient,
    })
  }

  async connect(options: EndpointConnectOptions): Promise<Connection> {
    this.requireRelayUrl(options.relayUrl)
    const sourceConnectionId = randomConnectionId()
    const initialDestinationConnectionId = randomConnectionId()
    const driver = new QuicRelayClientDriver({
      peerEndpointId: options.endpointId,
      handshake: new QuicClientHandshakeDriver({
        x25519PrivateKey: endpointX25519PrivateKey(options.x25519PrivateKey),
        endpointSecretKey: this.#secretKey,
        expectedServerEndpointId: options.endpointId,
        alpnProtocols: [options.alpn],
        expectedAlpn: options.alpn,
        transportParameters: clientTransportParameters(sourceConnectionId),
        sourceConnectionId,
        initialDestinationConnectionId,
      }),
    })
    const connection = new Connection(this.#relayRouter, driver)
    this.#relayRouter.registerConnectionId(sourceConnectionId, connection)
    try {
      this.#relayRouter.sendDatagrams(await driver.start())
      await connection.driveUntilConnected()
      return connection
    } catch (error) {
      this.#relayRouter.unregister(connection)
      throw error
    }
  }

  async accept(options: EndpointAcceptOptions): Promise<Connection> {
    const sourceConnectionId = randomConnectionId()
    const driver = new QuicRelayServerDriver({
      handshake: new QuicServerHandshakeDriver({
        x25519PrivateKey: endpointX25519PrivateKey(options.x25519PrivateKey),
        endpointSecretKey: this.#secretKey,
        selectedAlpn: options.alpn,
        transportParameters: (input) => serverTransportParameters(input, sourceConnectionId),
        sourceConnectionId,
      }),
    })
    const connection = new Connection(this.#relayRouter, driver)
    this.#relayRouter.registerConnectionId(sourceConnectionId, connection)
    this.#relayRouter.registerAccept(connection)
    try {
      await connection.driveUntilConnected()
      return connection
    } catch (error) {
      this.#relayRouter.unregister(connection)
      throw error
    }
  }

  close(code?: number, reason?: string): void {
    this.#relayClient.close(code, reason)
  }

  private requireRelayUrl(relayUrl: RelayUrlInput): void {
    if (normalizeRelayUrl(relayUrl).href !== this.relayUrl.href) {
      throw new RangeError('endpoint is not connected to requested relay URL')
    }
  }
}

interface RelayDatagramWaiter {
  resolve(datagrams: Datagrams): void
  reject(error: Error): void
}

interface RelayDatagramQueue {
  readonly datagrams: Datagrams[]
  readonly waiters: RelayDatagramWaiter[]
}

class RelayDatagramRouter {
  readonly #relayClient: RelayWebSocketClient
  readonly #connectionIdRoutes = new Map<string, Connection>()
  readonly #connectionQueues = new Map<Connection, RelayDatagramQueue>()
  readonly #acceptingConnections: Connection[] = []
  readonly #pendingAcceptDatagrams: Datagrams[] = []
  #readLoopStarted = false
  #terminalError: Error | null = null

  constructor(relayClient: RelayWebSocketClient) {
    this.#relayClient = relayClient
  }

  registerConnectionId(connectionId: Uint8Array, connection: Connection): void {
    this.#connectionIdRoutes.set(routeKey(connectionId), connection)
    this.ensureReadLoop()
  }

  registerAccept(connection: Connection): void {
    const datagrams = this.#pendingAcceptDatagrams.shift()
    if (datagrams !== undefined) {
      this.#connectionIdRoutes.set(routeKeyForDatagrams(datagrams), connection)
      this.enqueue(connection, datagrams)
      return
    }
    this.#acceptingConnections.push(connection)
    this.ensureReadLoop()
  }

  unregister(connection: Connection): void {
    this.removeAccept(connection)
    this.#connectionQueues.delete(connection)
    for (const [key, routedConnection] of this.#connectionIdRoutes) {
      if (routedConnection === connection) {
        this.#connectionIdRoutes.delete(key)
      }
    }
  }

  sendDatagrams(datagrams: Datagrams): void {
    this.#relayClient.sendDatagrams(datagrams)
  }

  async receiveDatagrams(connection: Connection): Promise<Datagrams> {
    const queue = this.connectionQueue(connection)
    const datagrams = queue.datagrams.shift()
    if (datagrams !== undefined) {
      return datagrams
    }
    if (this.#terminalError !== null) {
      throw this.#terminalError
    }
    this.ensureReadLoop()
    return await new Promise((resolve, reject) => {
      queue.waiters.push({ resolve, reject })
    })
  }

  private ensureReadLoop(): void {
    if (this.#readLoopStarted || this.#terminalError !== null) {
      return
    }
    this.#readLoopStarted = true
    void this.readLoop()
  }

  private async readLoop(): Promise<void> {
    try {
      while (true) {
        const frame = await this.#relayClient.receive()
        if (frame === null) {
          this.fail(new Error('relay websocket closed before QUIC datagram'))
          return
        }
        if (frame.type === 'datagrams') {
          this.route(frame.datagrams)
          continue
        }
        ignoreRelayControlFrame(frame)
      }
    } catch (error) {
      this.fail(error instanceof Error ? error : new Error(String(error)))
    }
  }

  private route(datagrams: Datagrams): void {
    const route = this.#connectionIdRoutes.get(routeKeyForDatagrams(datagrams))
    if (route !== undefined) {
      this.enqueue(route, datagrams)
      return
    }
    const acceptingConnection = this.#acceptingConnections.shift()
    if (acceptingConnection !== undefined) {
      this.#connectionIdRoutes.set(routeKeyForDatagrams(datagrams), acceptingConnection)
      this.enqueue(acceptingConnection, datagrams)
      return
    }
    this.#pendingAcceptDatagrams.push(datagrams)
  }

  private enqueue(connection: Connection, datagrams: Datagrams): void {
    const queue = this.connectionQueue(connection)
    const waiter = queue.waiters.shift()
    if (waiter !== undefined) {
      waiter.resolve(datagrams)
      return
    }
    queue.datagrams.push(datagrams)
  }

  private connectionQueue(connection: Connection): RelayDatagramQueue {
    const existing = this.#connectionQueues.get(connection)
    if (existing !== undefined) {
      return existing
    }
    const queue = { datagrams: [], waiters: [] }
    this.#connectionQueues.set(connection, queue)
    return queue
  }

  private removeAccept(connection: Connection): void {
    const index = this.#acceptingConnections.indexOf(connection)
    if (index !== -1) {
      this.#acceptingConnections.splice(index, 1)
    }
  }

  private fail(error: Error): void {
    if (this.#terminalError !== null) {
      return
    }
    this.#terminalError = error
    for (const queue of this.#connectionQueues.values()) {
      for (const waiter of queue.waiters.splice(0)) {
        waiter.reject(error)
      }
    }
  }
}

export class Connection {
  readonly #relayRouter: RelayDatagramRouter
  readonly #driver: EndpointConnectionDriver
  readonly #streams = new Map<number, EndpointStream>()
  readonly #acceptedBidiStreams: BidiStream[] = []
  readonly #acceptedUniStreams: UniStream[] = []
  #nextBidiStreamId: number | null = null
  #nextUniStreamId: number | null = null

  constructor(relayRouter: RelayDatagramRouter, driver: EndpointConnectionDriver) {
    this.#relayRouter = relayRouter
    this.#driver = driver
  }

  openBidiStream(): BidiStream {
    const streamId = this.nextOpenBidiStreamId()
    const stream = new BidiStream(this, streamId)
    this.#streams.set(streamId, stream)
    this.#nextBidiStreamId = streamId + 4
    return stream
  }

  openUniStream(): UniStream {
    const streamId = this.nextOpenUniStreamId()
    const stream = new UniStream(this, streamId)
    this.#streams.set(streamId, stream)
    this.#nextUniStreamId = streamId + 4
    return stream
  }

  async acceptBidiStream(): Promise<BidiStream> {
    while (true) {
      const stream = this.#acceptedBidiStreams.shift()
      if (stream !== undefined) {
        return stream
      }
      await this.receiveRelayDatagrams()
    }
  }

  async acceptUniStream(): Promise<UniStream> {
    while (true) {
      const stream = this.#acceptedUniStreams.shift()
      if (stream !== undefined) {
        return stream
      }
      await this.receiveRelayDatagrams()
    }
  }

  async driveUntilConnected(): Promise<void> {
    while (this.#driver.connection === null) {
      await this.receiveRelayDatagrams()
    }
    this.setInitialStreamId()
  }

  sendStream(streamId: number, data: Uint8Array, fin = false): QuicRelayStreamSendResult {
    const sent = this.#driver.sendStream(streamId, data, fin)
    this.#relayRouter.sendDatagrams(sent.datagrams)
    return sent
  }

  async readStreamOutput(streamId: number): Promise<QuicStreamReceiveOutput> {
    const stream = this.requireStream(streamId)
    while (true) {
      const output = stream.dequeueOutput()
      if (output !== null) {
        return output
      }
      await this.receiveRelayDatagrams()
    }
  }

  async receiveRelayDatagrams(): Promise<void> {
    const datagrams = await this.#relayRouter.receiveDatagrams(this)
    const result = await this.#driver.receive(datagrams)
    this.sendOutgoing(result)
    this.queueStreamOutputs(result.streamOutputs)
  }

  private sendOutgoing(result: QuicRelayReceiveResult): void {
    for (const datagrams of result.outgoing) {
      this.#relayRouter.sendDatagrams(datagrams)
    }
  }

  private queueStreamOutputs(outputs: readonly QuicStreamReceiveOutput[]): void {
    for (const output of outputs) {
      const existing = this.#streams.get(output.streamId)
      if (existing !== undefined) {
        existing.enqueueOutput(output)
        continue
      }
      if (isUnidirectionalStream(output.streamId)) {
        const uniStream = new UniStream(this, output.streamId)
        uniStream.enqueueOutput(output)
        this.#streams.set(output.streamId, uniStream)
        this.#acceptedUniStreams.push(uniStream)
        continue
      }
      const stream = new BidiStream(this, output.streamId)
      stream.enqueueOutput(output)
      this.#streams.set(output.streamId, stream)
      this.#acceptedBidiStreams.push(stream)
    }
  }

  private nextOpenBidiStreamId(): number {
    if (this.#nextBidiStreamId === null) {
      this.setInitialStreamId()
    }
    if (this.#nextBidiStreamId === null) {
      throw new RangeError('connection is not ready to open streams')
    }
    return this.#nextBidiStreamId
  }

  private nextOpenUniStreamId(): number {
    if (this.#nextUniStreamId === null) {
      this.setInitialStreamId()
    }
    if (this.#nextUniStreamId === null) {
      throw new RangeError('connection is not ready to open streams')
    }
    return this.#nextUniStreamId
  }

  private setInitialStreamId(): void {
    if (this.#nextBidiStreamId !== null && this.#nextUniStreamId !== null) {
      return
    }
    const role = this.#driver.connection?.role
    if (role === QuicEndpointRole.Client) {
      this.#nextBidiStreamId = 0
      this.#nextUniStreamId = 2
      return
    }
    if (role === QuicEndpointRole.Server) {
      this.#nextBidiStreamId = 1
      this.#nextUniStreamId = 3
      return
    }
  }

  private requireStream(streamId: number): EndpointStream {
    const stream = this.#streams.get(streamId)
    if (stream === undefined) {
      throw new RangeError('unknown stream')
    }
    return stream
  }
}

export class BidiStream {
  readonly #connection: Connection
  readonly #outputs: QuicStreamReceiveOutput[] = []
  readonly streamId: number

  constructor(connection: Connection, streamId: number) {
    this.#connection = connection
    this.streamId = streamId
  }

  write(data: Uint8Array, options: BidiStreamWriteOptions = {}): void {
    this.#connection.sendStream(this.streamId, data, options.fin ?? false)
  }

  async read(): Promise<QuicStreamReceiveOutput> {
    return await this.#connection.readStreamOutput(this.streamId)
  }

  async readToEnd(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = []
    while (true) {
      const output = await this.read()
      chunks.push(output.data)
      if (output.complete) {
        return concatBytes(chunks)
      }
    }
  }

  enqueueOutput(output: QuicStreamReceiveOutput): void {
    this.#outputs.push(output)
  }

  dequeueOutput(): QuicStreamReceiveOutput | null {
    return this.#outputs.shift() ?? null
  }
}

export class UniStream {
  readonly #connection: Connection
  readonly #outputs: QuicStreamReceiveOutput[] = []
  readonly streamId: number

  constructor(connection: Connection, streamId: number) {
    this.#connection = connection
    this.streamId = streamId
  }

  write(data: Uint8Array, options: BidiStreamWriteOptions = {}): void {
    this.#connection.sendStream(this.streamId, data, options.fin ?? false)
  }

  async read(): Promise<QuicStreamReceiveOutput> {
    return await this.#connection.readStreamOutput(this.streamId)
  }

  async readToEnd(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = []
    while (true) {
      const output = await this.read()
      chunks.push(output.data)
      if (output.complete) {
        return concatBytes(chunks)
      }
    }
  }

  enqueueOutput(output: QuicStreamReceiveOutput): void {
    this.#outputs.push(output)
  }

  dequeueOutput(): QuicStreamReceiveOutput | null {
    return this.#outputs.shift() ?? null
  }
}

function relayConnectOptions(
  relayUrl: RelayUrlInput,
  secretKey: Uint8Array,
  WebSocketCtor: RelayWebSocketConstructor | undefined,
): ConnectRelayWebSocketOptions {
  if (WebSocketCtor === undefined) {
    return { url: relayUrl, secretKey }
  }
  return { url: relayUrl, secretKey, WebSocket: WebSocketCtor }
}

function clientTransportParameters(sourceConnectionId: Uint8Array): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: defaultFlowControlLimit,
    initialMaxStreamDataBidiLocal: defaultFlowControlLimit,
    initialMaxStreamDataBidiRemote: defaultFlowControlLimit,
    initialMaxStreamDataUni: defaultFlowControlLimit,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    initialSourceConnectionId: sourceConnectionId,
  })
}

function serverTransportParameters(
  input: QuicServerTransportParametersInput,
  sourceConnectionId: Uint8Array,
): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: defaultFlowControlLimit,
    initialMaxStreamDataBidiLocal: defaultFlowControlLimit,
    initialMaxStreamDataBidiRemote: defaultFlowControlLimit,
    initialMaxStreamDataUni: defaultFlowControlLimit,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    originalDestinationConnectionId: input.originalDestinationConnectionId,
    initialSourceConnectionId: sourceConnectionId,
  })
}

function endpointX25519PrivateKey(privateKey: Uint8Array | undefined): Uint8Array {
  if (privateKey !== undefined) {
    return validateX25519PrivateKey(privateKey)
  }
  return crypto.getRandomValues(new Uint8Array(32))
}

function randomConnectionId(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(connectionIdLength))
}

function routeKeyForDatagrams(datagrams: Datagrams): string {
  const packet = splitRelayDatagramPackets(datagrams)[0]
  if (packet === undefined) {
    throw new RangeError('relay QUIC datagram is empty')
  }
  const firstByte = packet[0]
  if (firstByte === undefined) {
    throw new RangeError('relay QUIC datagram is empty')
  }
  if ((firstByte & 0x80) === 0) {
    return routeKey(packet.subarray(1, 1 + connectionIdLength))
  }
  return routeKey(parseQuicLongHeader(packet).destinationConnectionId)
}

function routeKey(bytes: Uint8Array): string {
  let key = ''
  for (const byte of bytes) {
    key += byte.toString(16).padStart(2, '0')
  }
  return key
}

function ignoreRelayControlFrame(
  frame: Exclude<RelayWebSocketReceiveFrame, { readonly type: 'datagrams' }>,
): void {
  if (frame.type === 'status' || frame.type === 'pong' || frame.type === 'restarting') {
    return
  }
  if (frame.type === 'endpoint-gone') {
    throw new Error('relay peer endpoint disconnected')
  }
  if (frame.type === 'health') {
    throw new Error(`relay reported health problem: ${frame.problem}`)
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  let diff = 0
  for (let index = 0; index < left.length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0)
  }
  return diff === 0
}

function isUnidirectionalStream(streamId: number): boolean {
  return (streamId & 0x02) === 0x02
}

import { concatBytes, copyBytes } from '../bytes'
import { endpointIdFromSecretKey, randomSecretKey } from '../crypto/ed25519'
import { validateX25519PrivateKey } from '../crypto/x25519'
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
} from '../quic/relay-driver'
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
    this.#relayClient.sendDatagrams(await driver.start())
    const connection = new Connection(this.#relayClient, driver)
    await connection.driveUntilConnected()
    return connection
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
    const connection = new Connection(this.#relayClient, driver)
    await connection.driveUntilConnected()
    return connection
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

export class Connection {
  readonly #relayClient: RelayWebSocketClient
  readonly #driver: EndpointConnectionDriver
  readonly #streams = new Map<number, EndpointStream>()
  readonly #acceptedBidiStreams: BidiStream[] = []
  readonly #acceptedUniStreams: UniStream[] = []
  #nextBidiStreamId: number | null = null
  #nextUniStreamId: number | null = null

  constructor(relayClient: RelayWebSocketClient, driver: EndpointConnectionDriver) {
    this.#relayClient = relayClient
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
    this.#relayClient.sendDatagrams(sent.datagrams)
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
    while (true) {
      const frame = await this.#relayClient.receive()
      if (frame === null) {
        throw new Error('relay websocket closed before QUIC datagram')
      }
      if (frame.type === 'datagrams') {
        const result = await this.#driver.receive(frame.datagrams)
        this.sendOutgoing(result)
        this.queueStreamOutputs(result.streamOutputs)
        return
      }
      ignoreRelayControlFrame(frame)
    }
  }

  private sendOutgoing(result: QuicRelayReceiveResult): void {
    for (const datagrams of result.outgoing) {
      this.#relayClient.sendDatagrams(datagrams)
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

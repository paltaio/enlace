import { copyBytes } from '../bytes'
import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { deriveQuicDirectionalKeys, deriveQuicInitialKeys } from './crypto'
import {
  encodeQuicCryptoFrame,
  parseQuicFrames,
  type QuicCryptoFrame,
  type QuicFrame,
} from './frame'
import {
  decryptQuicHandshakePacket,
  encryptQuicHandshakePacket,
  type QuicHandshakeKeys,
} from './handshake'
import { decryptQuicInitialPacket, encryptQuicInitialPacket } from './initial'
import { createQuicConnectionStateFromHandshake, type QuicConnectionState } from './connection'
import { parseQuicInitialPacketHeaderPrefix } from './packet'
import {
  buildTls13ClientEncryptedFlight,
  buildTls13ClientHello,
  buildTls13ServerEncryptedFlight,
  buildTls13ServerHello,
} from './tls-handshake-flight'
import {
  deriveTls13X25519HandshakeSecrets,
  type Tls13X25519HandshakeSecrets,
  TlsHandshakeRole,
} from './tls-handshake'
import {
  verifyTls13ClientHandshakeState,
  verifyTls13ServerHandshakeState,
} from './tls-handshake-state'
import {
  getTlsExtension,
  TlsExtensionType,
  TlsHandshakeKind,
  type TlsClientHelloHandshake,
  type TlsServerHelloHandshake,
} from './tls'
import { collectQuicTlsHandshakeMessages, type QuicTlsHandshakeMessage } from './tls-crypto-stream'
import {
  parseQuicTransportParameters,
  QuicEndpointRole,
  type QuicTransportParameters,
} from './transport-parameters'

const quicMinimumInitialPacketLength = 1200

export interface QuicClientHandshakeDriverOptions {
  readonly x25519PrivateKey: Uint8Array
  readonly endpointSecretKey: Uint8Array
  readonly expectedServerEndpointId: Uint8Array
  readonly alpnProtocols: readonly Uint8Array[]
  readonly expectedAlpn?: Uint8Array
  readonly transportParameters: Uint8Array
  readonly sourceConnectionId: Uint8Array
  readonly initialDestinationConnectionId: Uint8Array
  readonly initialPacketNumber?: number | bigint
  readonly handshakePacketNumber?: number | bigint
}

export interface QuicServerHandshakeDriverOptions {
  readonly x25519PrivateKey: Uint8Array
  readonly endpointSecretKey: Uint8Array
  readonly selectedAlpn: Uint8Array
  readonly transportParameters:
    | Uint8Array
    | ((input: QuicServerTransportParametersInput) => Uint8Array)
  readonly sourceConnectionId: Uint8Array
  readonly certificateRequest?: boolean
  readonly initialPacketNumber?: number | bigint
  readonly handshakePacketNumber?: number | bigint
}

export interface QuicServerTransportParametersInput {
  readonly originalDestinationConnectionId: Uint8Array
  readonly initialSourceConnectionId: Uint8Array
  readonly peerSourceConnectionId: Uint8Array
}

export interface QuicClientInitialFlight {
  readonly packet: Uint8Array
  readonly packetNumber: bigint
  readonly clientHello: QuicTlsHandshakeMessage
}

export interface QuicServerHandshakeFlight {
  readonly initialPacket: Uint8Array
  readonly handshakePacket: Uint8Array
  readonly initialPacketNumber: bigint
  readonly handshakePacketNumber: bigint
  readonly serverHello: QuicTlsHandshakeMessage
  readonly encryptedMessages: readonly QuicTlsHandshakeMessage[]
}

export interface QuicClientHandshakeFlight {
  readonly packet: Uint8Array
  readonly packetNumber: bigint
  readonly encryptedMessages: readonly QuicTlsHandshakeMessage[]
  readonly connection: QuicConnectionState
}

export interface QuicServerHandshakeComplete {
  readonly connection: QuicConnectionState
}

interface QuicServerInitialState {
  readonly initialDestinationConnectionId: Uint8Array
  readonly peerConnectionId: Uint8Array
  readonly handshakeKeys: QuicHandshakeKeys
  readonly messages: readonly QuicTlsHandshakeMessage[]
  readonly serverFlight: QuicServerHandshakeFlight
}

interface QuicClientStartedState {
  readonly initialKeys: ReturnType<typeof deriveQuicInitialKeys>
  readonly clientHello: QuicTlsHandshakeMessage
}

export class QuicClientHandshakeDriver {
  readonly #options: QuicClientHandshakeDriverOptions
  #started: QuicClientStartedState | null = null
  #messages: readonly QuicTlsHandshakeMessage[] | null = null
  #connection: QuicConnectionState | null = null

  constructor(options: QuicClientHandshakeDriverOptions) {
    this.#options = options
  }

  get connection(): QuicConnectionState | null {
    return this.#connection
  }

  async start(): Promise<QuicClientInitialFlight> {
    if (this.#started !== null) {
      throw new RangeError('QUIC client handshake already started')
    }
    const clientHello = await buildTls13ClientHello({
      x25519PrivateKey: this.#options.x25519PrivateKey,
      alpnProtocols: this.#options.alpnProtocols,
      transportParameters: this.#options.transportParameters,
    })
    const initialKeys = deriveQuicInitialKeys(this.#options.initialDestinationConnectionId)
    const packetNumber = this.#options.initialPacketNumber ?? 0
    const packet = encryptQuicInitialPacket(initialKeys.client, {
      destinationConnectionId: this.#options.initialDestinationConnectionId,
      sourceConnectionId: this.#options.sourceConnectionId,
      packetNumber,
      packetNumberLength: 1,
      payload: encodeQuicCryptoFrame(0, clientHello.message.message),
      minimumPacketLength: quicMinimumInitialPacketLength,
    })

    this.#started = {
      initialKeys,
      clientHello: clientHello.message,
    }

    return {
      packet,
      packetNumber: BigInt(packetNumber),
      clientHello: clientHello.message,
    }
  }

  async receiveServerFlights(
    initialPacket: Uint8Array,
    handshakePacket: Uint8Array,
  ): Promise<QuicClientHandshakeFlight> {
    const started = requireState(this.#started, 'QUIC client handshake not started')
    if (this.#connection !== null) {
      throw new RangeError('QUIC client handshake already complete')
    }

    const serverInitial = decryptQuicInitialPacket(initialPacket, started.initialKeys.server)
    const serverHello = requireServerHelloMessage(collectCryptoMessages(serverInitial.payload))
    const handshake = await deriveHandshake(started.clientHello, serverHello, {
      role: TlsHandshakeRole.Client,
      privateKey: this.#options.x25519PrivateKey,
    })
    const handshakeKeys = handshakeKeysFromSecrets(handshake)
    const serverHandshake = decryptQuicHandshakePacket(handshakePacket, handshakeKeys.server)
    const serverEncryptedMessages = collectCryptoMessages(serverHandshake.payload)
    const priorMessages = [started.clientHello, serverHello, ...serverEncryptedMessages]
    const clientFlight = await buildTls13ClientEncryptedFlight({
      priorMessages,
      clientHandshakeTrafficSecret: handshake.secrets.clientHandshakeTrafficSecret,
      endpointSecretKey: this.#options.endpointSecretKey,
    })
    const allMessages = [...priorMessages, ...clientFlight.messages]
    const clientState = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: this.#options.x25519PrivateKey,
      expectedServerEndpointId: this.#options.expectedServerEndpointId,
      messages: allMessages,
      ...(this.#options.expectedAlpn === undefined
        ? {}
        : { expectedAlpn: this.#options.expectedAlpn }),
    })
    validateClientTransportParameterConnectionIds(
      clientState.transportParameters.client,
      this.#options.sourceConnectionId,
    )
    validateServerTransportParameterConnectionIds(
      clientState.transportParameters.server,
      this.#options.initialDestinationConnectionId,
      serverInitial.header.sourceConnectionId,
    )
    const packetNumber = this.#options.handshakePacketNumber ?? 0
    const packet = encryptQuicHandshakePacket(handshakeKeys.client, {
      destinationConnectionId: serverInitial.header.sourceConnectionId,
      sourceConnectionId: this.#options.sourceConnectionId,
      packetNumber,
      packetNumberLength: 1,
      payload: encodeQuicCryptoFrame(0, clientFlight.cryptoStream),
    })
    const connection = createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Client,
      handshakeState: clientState,
      localConnectionId: this.#options.sourceConnectionId,
      peerConnectionId: serverInitial.header.sourceConnectionId,
    })

    this.#messages = allMessages
    this.#connection = connection

    return {
      packet,
      packetNumber: BigInt(packetNumber),
      encryptedMessages: clientFlight.messages,
      connection,
    }
  }

  messages(): readonly QuicTlsHandshakeMessage[] {
    return this.#messages ?? (this.#started === null ? [] : [this.#started.clientHello])
  }
}

export class QuicServerHandshakeDriver {
  readonly #options: QuicServerHandshakeDriverOptions
  #initial: QuicServerInitialState | null = null
  #connection: QuicConnectionState | null = null

  constructor(options: QuicServerHandshakeDriverOptions) {
    this.#options = options
  }

  get connection(): QuicConnectionState | null {
    return this.#connection
  }

  async receiveClientInitial(packet: Uint8Array): Promise<QuicServerHandshakeFlight> {
    if (this.#initial !== null) {
      return this.#initial.serverFlight
    }
    const prefix = parseQuicInitialPacketHeaderPrefix(packet)
    const initialKeys = deriveQuicInitialKeys(prefix.destinationConnectionId)
    const clientInitial = decryptQuicInitialPacket(packet, initialKeys.client)
    const clientHello = requireClientHelloMessage(collectCryptoMessages(clientInitial.payload))
    validateClientTransportParameterConnectionIds(
      clientTransportParameters(clientHello.handshake),
      clientInitial.header.sourceConnectionId,
    )
    const transportParameters = serverTransportParameters(this.#options.transportParameters, {
      originalDestinationConnectionId: prefix.destinationConnectionId,
      initialSourceConnectionId: this.#options.sourceConnectionId,
      peerSourceConnectionId: clientInitial.header.sourceConnectionId,
    })
    validateServerTransportParameterConnectionIds(
      parseQuicTransportParameters(transportParameters, QuicEndpointRole.Server),
      prefix.destinationConnectionId,
      this.#options.sourceConnectionId,
    )
    const serverHello = await buildTls13ServerHello({
      clientHello: clientHello.handshake,
      x25519PrivateKey: this.#options.x25519PrivateKey,
    })
    const handshake = await deriveHandshake(clientHello, serverHello.message, {
      role: TlsHandshakeRole.Server,
      privateKey: this.#options.x25519PrivateKey,
    })
    const handshakeKeys = handshakeKeysFromSecrets(handshake)
    const serverFlight = await buildTls13ServerEncryptedFlight({
      clientHelloMessage: clientHello.message,
      serverHelloMessage: serverHello.message.message,
      serverHandshakeTrafficSecret: handshake.secrets.serverHandshakeTrafficSecret,
      endpointSecretKey: this.#options.endpointSecretKey,
      selectedAlpn: this.#options.selectedAlpn,
      transportParameters,
      ...(this.#options.certificateRequest === undefined
        ? {}
        : { certificateRequest: this.#options.certificateRequest }),
    })
    const initialPacketNumber = this.#options.initialPacketNumber ?? 0
    const handshakePacketNumber = this.#options.handshakePacketNumber ?? 0
    const initialPacket = encryptQuicInitialPacket(initialKeys.server, {
      destinationConnectionId: clientInitial.header.sourceConnectionId,
      sourceConnectionId: this.#options.sourceConnectionId,
      packetNumber: initialPacketNumber,
      packetNumberLength: 1,
      payload: encodeQuicCryptoFrame(0, serverHello.message.message),
    })
    const handshakePacket = encryptQuicHandshakePacket(handshakeKeys.server, {
      destinationConnectionId: clientInitial.header.sourceConnectionId,
      sourceConnectionId: this.#options.sourceConnectionId,
      packetNumber: handshakePacketNumber,
      packetNumberLength: 1,
      payload: encodeQuicCryptoFrame(0, serverFlight.cryptoStream),
    })
    const messages = [clientHello, serverHello.message, ...serverFlight.messages]

    const serverFlightResult = {
      initialPacket,
      handshakePacket,
      initialPacketNumber: BigInt(initialPacketNumber),
      handshakePacketNumber: BigInt(handshakePacketNumber),
      serverHello: serverHello.message,
      encryptedMessages: serverFlight.messages,
    }

    this.#initial = {
      initialDestinationConnectionId: copyBytes(prefix.destinationConnectionId),
      peerConnectionId: copyBytes(clientInitial.header.sourceConnectionId),
      handshakeKeys,
      messages,
      serverFlight: serverFlightResult,
    }

    return serverFlightResult
  }

  async receiveClientHandshake(packet: Uint8Array): Promise<QuicServerHandshakeComplete> {
    const initial = requireState(this.#initial, 'QUIC server handshake not started')
    if (this.#connection !== null) {
      throw new RangeError('QUIC server handshake already complete')
    }

    const clientHandshake = decryptQuicHandshakePacket(packet, initial.handshakeKeys.client)
    const clientMessages = collectCryptoMessages(clientHandshake.payload)
    const messages = [...initial.messages, ...clientMessages]
    const serverEndpointId = await endpointIdFromSecretKey(this.#options.endpointSecretKey)
    const serverState = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: this.#options.x25519PrivateKey,
      localServerEndpointId: serverEndpointId,
      expectedAlpn: this.#options.selectedAlpn,
      messages,
    })
    validateClientTransportParameterConnectionIds(
      serverState.transportParameters.client,
      initial.peerConnectionId,
    )
    validateServerTransportParameterConnectionIds(
      serverState.transportParameters.server,
      initial.initialDestinationConnectionId,
      this.#options.sourceConnectionId,
    )
    const connection = createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Server,
      handshakeState: serverState,
      localConnectionId: this.#options.sourceConnectionId,
      peerConnectionId: initial.peerConnectionId,
    })

    this.#connection = connection
    this.#initial = {
      ...initial,
      messages,
    }

    return { connection }
  }

  messages(): readonly QuicTlsHandshakeMessage[] {
    return this.#initial?.messages ?? []
  }
}

function collectCryptoMessages(payload: Uint8Array): readonly QuicTlsHandshakeMessage[] {
  const frames = parseQuicFrames(payload).frames
  const cryptoFrames = frames.filter(isCryptoFrame)
  if (cryptoFrames.length === 0) {
    throw new RangeError('QUIC packet does not contain CRYPTO frames')
  }
  return collectQuicTlsHandshakeMessages(cryptoFrames).messages
}

function isCryptoFrame(frame: QuicFrame): frame is QuicCryptoFrame {
  return frame.type === 'crypto'
}

async function deriveHandshake(
  clientHello: QuicTlsHandshakeMessage,
  serverHello: QuicTlsHandshakeMessage,
  options: {
    readonly role: typeof TlsHandshakeRole.Client | typeof TlsHandshakeRole.Server
    readonly privateKey: Uint8Array
  },
): Promise<Tls13X25519HandshakeSecrets> {
  return deriveTls13X25519HandshakeSecrets({
    role: options.role,
    privateKey: options.privateKey,
    clientHello: requireClientHelloMessage([clientHello]).handshake,
    serverHello: requireServerHelloMessage([serverHello]).handshake,
    clientHelloMessage: clientHello.message,
    serverHelloMessage: serverHello.message,
  })
}

function handshakeKeysFromSecrets(secrets: Tls13X25519HandshakeSecrets): QuicHandshakeKeys {
  return {
    client: deriveQuicDirectionalKeys(secrets.secrets.clientHandshakeTrafficSecret),
    server: deriveQuicDirectionalKeys(secrets.secrets.serverHandshakeTrafficSecret),
  }
}

function clientTransportParameters(clientHello: TlsClientHelloHandshake): QuicTransportParameters {
  const extension = getTlsExtension(
    clientHello.body.extensions,
    TlsExtensionType.QuicTransportParameters,
  )
  if (extension === null) {
    throw new RangeError('TLS ClientHello must include QUIC transport parameters')
  }
  return parseQuicTransportParameters(extension.data, QuicEndpointRole.Client)
}

function serverTransportParameters(
  transportParameters: Uint8Array | ((input: QuicServerTransportParametersInput) => Uint8Array),
  input: QuicServerTransportParametersInput,
): Uint8Array {
  return typeof transportParameters === 'function'
    ? transportParameters(input)
    : transportParameters
}

function validateClientTransportParameterConnectionIds(
  transportParameters: QuicTransportParameters,
  initialSourceConnectionId: Uint8Array,
): void {
  requireConnectionIdMatch(
    transportParameters.initialSourceConnectionId,
    initialSourceConnectionId,
    'client QUIC initial_source_connection_id does not match Initial source connection id',
  )
}

function validateServerTransportParameterConnectionIds(
  transportParameters: QuicTransportParameters,
  originalDestinationConnectionId: Uint8Array,
  initialSourceConnectionId: Uint8Array,
): void {
  requireConnectionIdMatch(
    transportParameters.originalDestinationConnectionId,
    originalDestinationConnectionId,
    'server QUIC original_destination_connection_id does not match client Initial destination connection id',
  )
  requireConnectionIdMatch(
    transportParameters.initialSourceConnectionId,
    initialSourceConnectionId,
    'server QUIC initial_source_connection_id does not match Initial source connection id',
  )
}

function requireConnectionIdMatch(
  actual: Uint8Array | null,
  expected: Uint8Array,
  message: string,
): void {
  if (actual === null || !equalBytes(actual, expected)) {
    throw new RangeError(message)
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

function requireClientHelloMessage(messages: readonly QuicTlsHandshakeMessage[]): {
  readonly handshake: TlsClientHelloHandshake
  readonly message: Uint8Array
} {
  const message = messages[0]
  if (message === undefined || message.handshake.kind !== TlsHandshakeKind.ClientHello) {
    throw new RangeError('missing TLS ClientHello handshake message')
  }
  return {
    handshake: message.handshake,
    message: message.message,
  }
}

function requireServerHelloMessage(messages: readonly QuicTlsHandshakeMessage[]): {
  readonly handshake: TlsServerHelloHandshake
  readonly message: Uint8Array
} {
  const message = messages[0]
  if (message === undefined || message.handshake.kind !== TlsHandshakeKind.ServerHello) {
    throw new RangeError('missing TLS ServerHello handshake message')
  }
  return {
    handshake: message.handshake,
    message: message.message,
  }
}

function requireState<T>(value: T | null, message: string): T {
  if (value === null) {
    throw new RangeError(message)
  }
  return value
}

import { copyBytes, readU8 } from '../bytes'
import type { QuicTlsHandshakeMessage } from './tls-crypto-stream'
import {
  deriveTls13X25519HandshakeSecrets,
  TlsHandshakeRole,
  type Tls13X25519HandshakeSecrets,
} from './tls-handshake'
import {
  type Tls13ClientEncryptedHandshakeVerification,
  type Tls13ServerEncryptedHandshakeVerification,
  verifyTls13ClientEncryptedHandshakeMessages,
  verifyTls13ServerEncryptedHandshakeMessages,
} from './tls-handshake-verify'
import {
  getTlsExtension,
  parseTlsAlpnProtocols,
  TlsExtensionType,
  TlsHandshakeKind,
  type TlsClientHelloHandshake,
  type TlsExtension,
  type TlsServerHelloHandshake,
} from './tls'

export interface VerifyTls13ClientHandshakeStateOptions {
  readonly x25519PrivateKey: Uint8Array
  readonly expectedServerEndpointId: Uint8Array
  readonly expectedAlpn?: Uint8Array
  readonly messages: readonly QuicTlsHandshakeMessage[]
}

export interface VerifyTls13ServerHandshakeStateOptions {
  readonly x25519PrivateKey: Uint8Array
  readonly localServerEndpointId: Uint8Array
  readonly expectedAlpn?: Uint8Array
  readonly messages: readonly QuicTlsHandshakeMessage[]
}

export interface Tls13HandshakeTranscriptBoundaries {
  readonly serverHello: Uint8Array
  readonly serverCertificateVerify: Uint8Array
  readonly serverFinished: Uint8Array
  readonly clientCertificateVerify: Uint8Array | null
  readonly clientFinished: Uint8Array | null
}

export interface Tls13ClientHandshakeState {
  readonly negotiatedAlpn: Uint8Array
  readonly peerEndpointId: Uint8Array
  readonly handshake: Tls13X25519HandshakeSecrets
  readonly server: Tls13ServerEncryptedHandshakeVerification
  readonly client: Tls13ClientEncryptedHandshakeVerification | null
  readonly transcriptHashes: Tls13HandshakeTranscriptBoundaries
}

export interface Tls13ServerHandshakeState {
  readonly negotiatedAlpn: Uint8Array
  readonly peerEndpointId: Uint8Array | null
  readonly handshake: Tls13X25519HandshakeSecrets
  readonly server: Tls13ServerEncryptedHandshakeVerification
  readonly client: Tls13ClientEncryptedHandshakeVerification | null
  readonly transcriptHashes: Tls13HandshakeTranscriptBoundaries
}

export async function verifyTls13ClientHandshakeState(
  options: VerifyTls13ClientHandshakeStateOptions,
): Promise<Tls13ClientHandshakeState> {
  const hello = requireHelloMessages(options.messages)
  const handshake = await deriveTls13X25519HandshakeSecrets({
    role: TlsHandshakeRole.Client,
    privateKey: options.x25519PrivateKey,
    clientHello: hello.client.handshake,
    serverHello: hello.server.handshake,
    clientHelloMessage: hello.client.message,
    serverHelloMessage: hello.server.message,
  })
  const server = await verifyTls13ServerEncryptedHandshakeMessages({
    serverHandshakeTrafficSecret: handshake.secrets.serverHandshakeTrafficSecret,
    expectedEndpointId: options.expectedServerEndpointId,
    messages: options.messages,
  })
  const client =
    server.certificateRequest === null
      ? null
      : await verifyTls13ClientEncryptedHandshakeMessages({
          clientHandshakeTrafficSecret: handshake.secrets.clientHandshakeTrafficSecret,
          messages: options.messages,
        })
  const negotiatedAlpn = requireNegotiatedAlpn(
    hello.client.handshake,
    server.encryptedExtensions.extensions,
    options.expectedAlpn,
  )

  return {
    negotiatedAlpn,
    peerEndpointId: copyBytes(server.endpointId),
    handshake,
    server,
    client,
    transcriptHashes: transcriptBoundaries(handshake, server, client),
  }
}

export async function verifyTls13ServerHandshakeState(
  options: VerifyTls13ServerHandshakeStateOptions,
): Promise<Tls13ServerHandshakeState> {
  const hello = requireHelloMessages(options.messages)
  const handshake = await deriveTls13X25519HandshakeSecrets({
    role: TlsHandshakeRole.Server,
    privateKey: options.x25519PrivateKey,
    clientHello: hello.client.handshake,
    serverHello: hello.server.handshake,
    clientHelloMessage: hello.client.message,
    serverHelloMessage: hello.server.message,
  })
  const server = await verifyTls13ServerEncryptedHandshakeMessages({
    serverHandshakeTrafficSecret: handshake.secrets.serverHandshakeTrafficSecret,
    expectedEndpointId: options.localServerEndpointId,
    messages: options.messages,
  })
  const client =
    server.certificateRequest === null
      ? null
      : await verifyTls13ClientEncryptedHandshakeMessages({
          clientHandshakeTrafficSecret: handshake.secrets.clientHandshakeTrafficSecret,
          messages: options.messages,
        })
  const negotiatedAlpn = requireNegotiatedAlpn(
    hello.client.handshake,
    server.encryptedExtensions.extensions,
    options.expectedAlpn,
  )

  return {
    negotiatedAlpn,
    peerEndpointId: client === null ? null : copyBytes(client.endpointId),
    handshake,
    server,
    client,
    transcriptHashes: transcriptBoundaries(handshake, server, client),
  }
}

function requireHelloMessages(messages: readonly QuicTlsHandshakeMessage[]): {
  readonly client: ClientHelloMessage
  readonly server: ServerHelloMessage
} {
  const client = messages[0]
  if (client === undefined || client.handshake.kind !== TlsHandshakeKind.ClientHello) {
    throw new RangeError('missing TLS ClientHello handshake message')
  }
  const server = messages[1]
  if (server === undefined || server.handshake.kind !== TlsHandshakeKind.ServerHello) {
    throw new RangeError('missing TLS ServerHello handshake message')
  }
  return {
    client: {
      handshake: client.handshake,
      message: client.message,
    },
    server: {
      handshake: server.handshake,
      message: server.message,
    },
  }
}

function requireNegotiatedAlpn(
  clientHello: TlsClientHelloHandshake,
  encryptedExtensions: readonly TlsExtension[],
  expectedAlpn: Uint8Array | undefined,
): Uint8Array {
  const offered = parseTlsAlpnProtocols(
    requireExtensionData(
      clientHello.body.extensions,
      TlsExtensionType.ApplicationLayerProtocolNegotiation,
      'TLS ClientHello must offer ALPN',
    ),
  )
  const selected = parseTlsAlpnProtocols(
    requireExtensionData(
      encryptedExtensions,
      TlsExtensionType.ApplicationLayerProtocolNegotiation,
      'TLS EncryptedExtensions must select ALPN',
    ),
  )
  if (selected.length !== 1) {
    throw new RangeError('TLS EncryptedExtensions must select exactly one ALPN protocol')
  }
  const selectedAlpn = selected[0]
  if (selectedAlpn === undefined) {
    throw new RangeError('TLS EncryptedExtensions must select ALPN')
  }
  if (!includesBytes(offered, selectedAlpn)) {
    throw new RangeError('TLS selected ALPN must be offered by ClientHello')
  }
  if (expectedAlpn !== undefined && !equalBytes(selectedAlpn, expectedAlpn)) {
    throw new RangeError('TLS selected ALPN mismatch')
  }
  return copyBytes(selectedAlpn)
}

function requireExtensionData(
  extensions: readonly TlsExtension[],
  extensionType: number,
  message: string,
): Uint8Array {
  const extension = getTlsExtension(extensions, extensionType)
  if (extension === null) {
    throw new RangeError(message)
  }
  return extension.data
}

function includesBytes(values: readonly Uint8Array[], needle: Uint8Array): boolean {
  for (const value of values) {
    if (equalBytes(value, needle)) {
      return true
    }
  }
  return false
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  let diff = 0
  for (let index = 0; index < left.length; index += 1) {
    diff |= readU8(left, index) ^ readU8(right, index)
  }
  return diff === 0
}

function transcriptBoundaries(
  handshake: Tls13X25519HandshakeSecrets,
  server: Tls13ServerEncryptedHandshakeVerification,
  client: Tls13ClientEncryptedHandshakeVerification | null,
): Tls13HandshakeTranscriptBoundaries {
  return {
    serverHello: copyBytes(handshake.transcriptHash),
    serverCertificateVerify: copyBytes(server.certificateVerifyTranscriptHash),
    serverFinished: copyBytes(server.finishedTranscriptHash),
    clientCertificateVerify:
      client === null ? null : copyBytes(client.certificateVerifyTranscriptHash),
    clientFinished: client === null ? null : copyBytes(client.finishedTranscriptHash),
  }
}

interface ClientHelloMessage {
  readonly handshake: TlsClientHelloHandshake
  readonly message: Uint8Array
}

interface ServerHelloMessage {
  readonly handshake: TlsServerHelloHandshake
  readonly message: Uint8Array
}

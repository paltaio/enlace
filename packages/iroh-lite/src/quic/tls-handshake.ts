import { requireLength } from '../bytes'
import type { QuicTlsHandshakeMessages } from './tls-crypto-stream'
import {
  deriveTls13HandshakeSecrets,
  TLS13_SHA256_SECRET_LENGTH,
  tls13TranscriptHash,
  type Tls13HandshakeSecrets,
} from './tls-key-schedule'
import { deriveTlsX25519SharedSecret, findTlsClientX25519KeyShare } from './tls-key-share'
import {
  getTlsExtension,
  parseTlsClientKeyShares,
  parseTlsClientSupportedVersions,
  parseTlsServerKeyShare,
  parseTlsServerSupportedVersion,
  TLS_VERSION_1_3,
  TlsExtensionType,
  type TlsExtension,
  type TlsClientHelloHandshake,
  type TlsServerHelloHandshake,
} from './tls'

export const TLS_AES_128_GCM_SHA256 = 0x1301

export const TlsHandshakeRole = {
  Client: 'client',
  Server: 'server',
} as const

export type TlsHandshakeRoleValue = (typeof TlsHandshakeRole)[keyof typeof TlsHandshakeRole]

export interface DeriveTls13X25519HandshakeSecretsOptions {
  readonly role: TlsHandshakeRoleValue
  readonly privateKey: Uint8Array
  readonly clientHello: TlsClientHelloHandshake
  readonly serverHello: TlsServerHelloHandshake
  readonly clientHelloMessage: Uint8Array
  readonly serverHelloMessage: Uint8Array
}

export interface DeriveTls13X25519HandshakeSecretsFromQuicCryptoOptions {
  readonly role: TlsHandshakeRoleValue
  readonly privateKey: Uint8Array
  readonly clientMessages: QuicTlsHandshakeMessages
  readonly serverMessages: QuicTlsHandshakeMessages
}

export interface Tls13X25519HandshakeSecrets {
  readonly sharedSecret: Uint8Array
  readonly transcriptHash: Uint8Array
  readonly secrets: Tls13HandshakeSecrets
}

export async function deriveTls13X25519HandshakeSecrets(
  options: DeriveTls13X25519HandshakeSecretsOptions,
): Promise<Tls13X25519HandshakeSecrets> {
  validateTls13HelloNegotiation(options.clientHello, options.serverHello)
  const peerKeyShare =
    options.role === TlsHandshakeRole.Client
      ? parseTlsServerKeyShare(
          requireExtensionData(options.serverHello.body.extensions, TlsExtensionType.KeyShare),
        )
      : findTlsClientX25519KeyShare(
          parseTlsClientKeyShares(
            requireExtensionData(options.clientHello.body.extensions, TlsExtensionType.KeyShare),
          ),
        )
  const sharedSecret = await deriveTlsX25519SharedSecret(options.privateKey, peerKeyShare)
  const transcriptHash = tls13TranscriptHash([
    options.clientHelloMessage,
    options.serverHelloMessage,
  ])
  requireLength(transcriptHash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')

  return {
    sharedSecret,
    transcriptHash,
    secrets: deriveTls13HandshakeSecrets(sharedSecret, transcriptHash),
  }
}

export async function deriveTls13X25519HandshakeSecretsFromQuicCrypto(
  options: DeriveTls13X25519HandshakeSecretsFromQuicCryptoOptions,
): Promise<Tls13X25519HandshakeSecrets> {
  const clientHello = requireClientHelloMessage(options.clientMessages)
  const serverHello = requireServerHelloMessage(options.serverMessages)

  return deriveTls13X25519HandshakeSecrets({
    role: options.role,
    privateKey: options.privateKey,
    clientHello: clientHello.handshake,
    serverHello: serverHello.handshake,
    clientHelloMessage: clientHello.message,
    serverHelloMessage: serverHello.message,
  })
}

function validateTls13HelloNegotiation(
  clientHello: TlsClientHelloHandshake,
  serverHello: TlsServerHelloHandshake,
): void {
  const clientVersions = parseTlsClientSupportedVersions(
    requireExtensionData(clientHello.body.extensions, TlsExtensionType.SupportedVersions),
  )
  if (!clientVersions.includes(TLS_VERSION_1_3)) {
    throw new RangeError('TLS ClientHello must offer TLS 1.3')
  }
  const serverVersion = parseTlsServerSupportedVersion(
    requireExtensionData(serverHello.body.extensions, TlsExtensionType.SupportedVersions),
  )
  if (serverVersion !== TLS_VERSION_1_3) {
    throw new RangeError('TLS ServerHello must select TLS 1.3')
  }
  if (serverHello.body.cipherSuite !== TLS_AES_128_GCM_SHA256) {
    throw new RangeError('TLS ServerHello must select TLS_AES_128_GCM_SHA256')
  }
  if (!clientHello.body.cipherSuites.includes(serverHello.body.cipherSuite)) {
    throw new RangeError('TLS ServerHello cipher suite must be offered by ClientHello')
  }
}

function requireExtensionData(
  extensions: readonly TlsExtension[],
  extensionType: number,
): Uint8Array {
  const extension = getTlsExtension(extensions, extensionType)
  if (extension === null) {
    throw new RangeError(`missing TLS extension 0x${extensionType.toString(16)}`)
  }
  return extension.data
}

function requireClientHelloMessage(messages: QuicTlsHandshakeMessages): {
  readonly handshake: TlsClientHelloHandshake
  readonly message: Uint8Array
} {
  for (const message of messages.messages) {
    if (message.handshake.kind === 'client-hello') {
      return {
        handshake: message.handshake,
        message: message.message,
      }
    }
  }
  throw new RangeError('missing TLS ClientHello handshake message')
}

function requireServerHelloMessage(messages: QuicTlsHandshakeMessages): {
  readonly handshake: TlsServerHelloHandshake
  readonly message: Uint8Array
} {
  for (const message of messages.messages) {
    if (message.handshake.kind === 'server-hello') {
      return {
        handshake: message.handshake,
        message: message.message,
      }
    }
  }
  throw new RangeError('missing TLS ServerHello handshake message')
}

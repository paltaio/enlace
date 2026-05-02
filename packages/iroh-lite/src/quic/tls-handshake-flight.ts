import { concatBytes, copyBytes, writeU16BE } from '../bytes'
import { endpointIdFromSecretKey, sign } from '../crypto/ed25519'
import { deriveX25519PublicKey, validateX25519PrivateKey } from '../crypto/x25519'
import { ed25519SpkiFromEndpointId } from './tls-certificate'
import {
  buildTls13CertificateVerifyMessage,
  TlsCertificateVerifyRole,
  TlsSignatureScheme,
} from './tls-certificate-verify'
import { parseTlsCertificateRequest } from './tls-certificate-request'
import { computeTls13FinishedVerifyData, tls13TranscriptHash } from './tls-key-schedule'
import {
  parseTlsHandshakes,
  TlsCertificateType,
  TlsExtensionType,
  TlsHandshakeKind,
  TlsHandshakeType,
  TLS_VERSION_1_3,
  TlsNamedGroup,
  type TlsClientHelloHandshake,
} from './tls'
import type { QuicTlsHandshakeMessage } from './tls-crypto-stream'

export interface BuildTls13ClientHelloOptions {
  readonly x25519PrivateKey: Uint8Array
  readonly alpnProtocols: readonly Uint8Array[]
  readonly transportParameters: Uint8Array
  readonly random?: Uint8Array
  readonly legacySessionId?: Uint8Array
}

export interface BuildTls13ServerHelloOptions {
  readonly clientHello: TlsClientHelloHandshake
  readonly x25519PrivateKey: Uint8Array
  readonly random?: Uint8Array
}

export interface BuildTls13ServerEncryptedFlightOptions {
  readonly clientHelloMessage: Uint8Array
  readonly serverHelloMessage: Uint8Array
  readonly serverHandshakeTrafficSecret: Uint8Array
  readonly endpointSecretKey: Uint8Array
  readonly selectedAlpn: Uint8Array
  readonly transportParameters: Uint8Array
  readonly certificateRequest?: boolean
}

export interface BuildTls13ClientEncryptedFlightOptions {
  readonly priorMessages: readonly QuicTlsHandshakeMessage[]
  readonly clientHandshakeTrafficSecret: Uint8Array
  readonly endpointSecretKey: Uint8Array
}

export interface Tls13HelloFlight {
  readonly message: QuicTlsHandshakeMessage
  readonly x25519PublicKey: Uint8Array
}

export interface Tls13EncryptedFlight {
  readonly messages: readonly QuicTlsHandshakeMessage[]
  readonly cryptoStream: Uint8Array
  readonly endpointId: Uint8Array | null
  readonly certificateVerifyTranscriptHash: Uint8Array | null
  readonly finishedTranscriptHash: Uint8Array
  readonly finishedVerifyData: Uint8Array
}

const TLS_LEGACY_VERSION = 0x0303
const TLS_AES_128_GCM_SHA256 = 0x1301
const TLS_COMPRESSION_NULL = 0x00
const TLS_RANDOM_LENGTH = 32
const DEFAULT_SESSION_ID_LENGTH = 32

export async function buildTls13ClientHello(
  options: BuildTls13ClientHelloOptions,
): Promise<Tls13HelloFlight> {
  const x25519PublicKey = await deriveX25519PublicKey(
    validateX25519PrivateKey(options.x25519PrivateKey),
  )
  const body = concatBytes([
    writeU16BE(TLS_LEGACY_VERSION),
    randomOrCopy(options.random, TLS_RANDOM_LENGTH, 'TLS ClientHello random'),
    tlsU8Vector(options.legacySessionId ?? randomBytes(DEFAULT_SESSION_ID_LENGTH)),
    tlsU16Vector(writeU16BE(TLS_AES_128_GCM_SHA256)),
    tlsU8Vector(new Uint8Array([TLS_COMPRESSION_NULL])),
    tlsExtensions([
      {
        type: TlsExtensionType.SupportedVersions,
        data: tlsU8Vector(writeU16BE(TLS_VERSION_1_3)),
      },
      {
        type: TlsExtensionType.SupportedGroups,
        data: tlsU16Vector(writeU16BE(TlsNamedGroup.X25519)),
      },
      {
        type: TlsExtensionType.KeyShare,
        data: tlsU16Vector(tlsKeyShareEntry(TlsNamedGroup.X25519, x25519PublicKey)),
      },
      {
        type: TlsExtensionType.SignatureAlgorithms,
        data: tlsU16Vector(writeU16BE(TlsSignatureScheme.Ed25519)),
      },
      {
        type: TlsExtensionType.ClientCertificateType,
        data: tlsCertificateTypeList(TlsCertificateType.RawPublicKey),
      },
      {
        type: TlsExtensionType.ServerCertificateType,
        data: tlsCertificateTypeList(TlsCertificateType.RawPublicKey),
      },
      {
        type: TlsExtensionType.ApplicationLayerProtocolNegotiation,
        data: tlsAlpnExtensionData(options.alpnProtocols),
      },
      {
        type: TlsExtensionType.QuicTransportParameters,
        data: copyBytes(options.transportParameters),
      },
    ]),
  ])

  return {
    message: parseBuiltHandshake(tlsHandshakeMessage(TlsHandshakeType.ClientHello, body)),
    x25519PublicKey,
  }
}

export async function buildTls13ServerHello(
  options: BuildTls13ServerHelloOptions,
): Promise<Tls13HelloFlight> {
  const x25519PublicKey = await deriveX25519PublicKey(
    validateX25519PrivateKey(options.x25519PrivateKey),
  )
  const body = concatBytes([
    writeU16BE(TLS_LEGACY_VERSION),
    randomOrCopy(options.random, TLS_RANDOM_LENGTH, 'TLS ServerHello random'),
    tlsU8Vector(options.clientHello.body.legacySessionId),
    writeU16BE(TLS_AES_128_GCM_SHA256),
    new Uint8Array([TLS_COMPRESSION_NULL]),
    tlsExtensions([
      {
        type: TlsExtensionType.SupportedVersions,
        data: writeU16BE(TLS_VERSION_1_3),
      },
      {
        type: TlsExtensionType.KeyShare,
        data: tlsKeyShareEntry(TlsNamedGroup.X25519, x25519PublicKey),
      },
    ]),
  ])

  return {
    message: parseBuiltHandshake(tlsHandshakeMessage(TlsHandshakeType.ServerHello, body)),
    x25519PublicKey,
  }
}

export async function buildTls13ServerEncryptedFlight(
  options: BuildTls13ServerEncryptedFlightOptions,
): Promise<Tls13EncryptedFlight> {
  const endpointId = await endpointIdFromSecretKey(options.endpointSecretKey)
  const encryptedExtensions = tlsHandshakeMessage(
    TlsHandshakeType.EncryptedExtensions,
    tlsExtensions([
      {
        type: TlsExtensionType.ApplicationLayerProtocolNegotiation,
        data: tlsAlpnExtensionData([options.selectedAlpn]),
      },
      {
        type: TlsExtensionType.QuicTransportParameters,
        data: copyBytes(options.transportParameters),
      },
      {
        type: TlsExtensionType.ClientCertificateType,
        data: new Uint8Array([TlsCertificateType.RawPublicKey]),
      },
      {
        type: TlsExtensionType.ServerCertificateType,
        data: new Uint8Array([TlsCertificateType.RawPublicKey]),
      },
    ]),
  )
  const certificateRequest =
    options.certificateRequest === false
      ? null
      : tlsHandshakeMessage(TlsHandshakeType.CertificateRequest, certificateRequestBody())
  const certificate = tlsHandshakeMessage(
    TlsHandshakeType.Certificate,
    certificateBody(new Uint8Array(), [
      {
        data: ed25519SpkiFromEndpointId(endpointId),
        extensions: new Uint8Array(),
      },
    ]),
  )
  const beforeCertificateVerify =
    certificateRequest === null
      ? [options.clientHelloMessage, options.serverHelloMessage, encryptedExtensions, certificate]
      : [
          options.clientHelloMessage,
          options.serverHelloMessage,
          encryptedExtensions,
          certificateRequest,
          certificate,
        ]
  const certificateVerifyTranscriptHash = tls13TranscriptHash(beforeCertificateVerify)
  const signature = await sign(
    options.endpointSecretKey,
    buildTls13CertificateVerifyMessage(
      TlsCertificateVerifyRole.Server,
      certificateVerifyTranscriptHash,
    ),
  )
  const certificateVerify = tlsHandshakeMessage(
    TlsHandshakeType.CertificateVerify,
    certificateVerifyBody(signature),
  )
  const finishedTranscriptHash = tls13TranscriptHash([
    ...beforeCertificateVerify,
    certificateVerify,
  ])
  const finishedVerifyData = computeTls13FinishedVerifyData(
    options.serverHandshakeTrafficSecret,
    finishedTranscriptHash,
  )
  const finished = tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)
  const rawMessages =
    certificateRequest === null
      ? [encryptedExtensions, certificate, certificateVerify, finished]
      : [encryptedExtensions, certificateRequest, certificate, certificateVerify, finished]

  return encryptedFlightResult(
    rawMessages,
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
    finishedVerifyData,
  )
}

export async function buildTls13ClientEncryptedFlight(
  options: BuildTls13ClientEncryptedFlightOptions,
): Promise<Tls13EncryptedFlight> {
  const certificateRequest = findCertificateRequest(options.priorMessages)
  if (certificateRequest === null) {
    const finishedTranscriptHash = tls13TranscriptHash(
      options.priorMessages.map((message) => message.message),
    )
    const finishedVerifyData = computeTls13FinishedVerifyData(
      options.clientHandshakeTrafficSecret,
      finishedTranscriptHash,
    )
    return encryptedFlightResult(
      [tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)],
      null,
      null,
      finishedTranscriptHash,
      finishedVerifyData,
    )
  }

  const endpointId = await endpointIdFromSecretKey(options.endpointSecretKey)
  const parsedRequest = parseTlsCertificateRequest(certificateRequest.handshake)
  const certificate = tlsHandshakeMessage(
    TlsHandshakeType.Certificate,
    certificateBody(parsedRequest.requestContext, [
      {
        data: ed25519SpkiFromEndpointId(endpointId),
        extensions: new Uint8Array(),
      },
    ]),
  )
  const beforeCertificateVerify = [
    ...options.priorMessages.map((message) => message.message),
    certificate,
  ]
  const certificateVerifyTranscriptHash = tls13TranscriptHash(beforeCertificateVerify)
  const signature = await sign(
    options.endpointSecretKey,
    buildTls13CertificateVerifyMessage(
      TlsCertificateVerifyRole.Client,
      certificateVerifyTranscriptHash,
    ),
  )
  const certificateVerify = tlsHandshakeMessage(
    TlsHandshakeType.CertificateVerify,
    certificateVerifyBody(signature),
  )
  const finishedTranscriptHash = tls13TranscriptHash([
    ...beforeCertificateVerify,
    certificateVerify,
  ])
  const finishedVerifyData = computeTls13FinishedVerifyData(
    options.clientHandshakeTrafficSecret,
    finishedTranscriptHash,
  )
  const finished = tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)

  return encryptedFlightResult(
    [certificate, certificateVerify, finished],
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
    finishedVerifyData,
  )
}

export function tlsAlpnExtensionData(protocols: readonly Uint8Array[]): Uint8Array {
  if (protocols.length === 0) {
    throw new RangeError('TLS ALPN protocol list must not be empty')
  }
  return tlsU16Vector(concatBytes(protocols.map(tlsAlpnProtocolName)))
}

function encryptedFlightResult(
  rawMessages: readonly Uint8Array[],
  endpointId: Uint8Array | null,
  certificateVerifyTranscriptHash: Uint8Array | null,
  finishedTranscriptHash: Uint8Array,
  finishedVerifyData: Uint8Array,
): Tls13EncryptedFlight {
  const cryptoStream = concatBytes(rawMessages)
  return {
    messages: rawMessages.map(parseBuiltHandshake),
    cryptoStream,
    endpointId: endpointId === null ? null : copyBytes(endpointId),
    certificateVerifyTranscriptHash:
      certificateVerifyTranscriptHash === null ? null : copyBytes(certificateVerifyTranscriptHash),
    finishedTranscriptHash: copyBytes(finishedTranscriptHash),
    finishedVerifyData: copyBytes(finishedVerifyData),
  }
}

function findCertificateRequest(
  messages: readonly QuicTlsHandshakeMessage[],
): QuicTlsHandshakeMessage | null {
  for (const message of messages) {
    if (message.handshake.kind === TlsHandshakeKind.CertificateRequest) {
      return message
    }
  }
  return null
}

function parseBuiltHandshake(message: Uint8Array): QuicTlsHandshakeMessage {
  const parsed = parseTlsHandshakes(message)
  if (parsed.handshakes.length !== 1 || parsed.endOffset !== message.length) {
    throw new RangeError('TLS handshake builder produced invalid message')
  }
  const handshake = parsed.handshakes[0]
  if (handshake === undefined) {
    throw new RangeError('TLS handshake builder produced invalid message')
  }
  return {
    handshake,
    message: copyBytes(message),
  }
}

function tlsHandshakeMessage(handshakeType: number, body: Uint8Array): Uint8Array {
  if (!Number.isInteger(handshakeType) || handshakeType < 0 || handshakeType > 0xff) {
    throw new RangeError('TLS handshake type out of range')
  }
  return concatBytes([new Uint8Array([handshakeType]), tlsU24Length(body.length), body])
}

function tlsExtensions(extensions: readonly TlsExtensionInput[]): Uint8Array {
  return tlsU16Vector(concatBytes(extensions.map(tlsExtension)))
}

function tlsExtension(extension: TlsExtensionInput): Uint8Array {
  return concatBytes([
    writeU16BE(extension.type),
    writeU16BE(extension.data.length),
    extension.data,
  ])
}

function tlsKeyShareEntry(group: number, keyExchange: Uint8Array): Uint8Array {
  return concatBytes([writeU16BE(group), tlsU16Vector(keyExchange)])
}

function tlsCertificateTypeList(certificateType: number): Uint8Array {
  return tlsU8Vector(new Uint8Array([certificateType]))
}

function tlsAlpnProtocolName(protocol: Uint8Array): Uint8Array {
  if (protocol.length === 0) {
    throw new RangeError('TLS ALPN protocol must not be empty')
  }
  return tlsU8Vector(protocol)
}

function certificateRequestBody(): Uint8Array {
  return concatBytes([
    tlsU8Vector(new Uint8Array()),
    tlsExtensions([
      {
        type: TlsExtensionType.SignatureAlgorithms,
        data: tlsU16Vector(writeU16BE(TlsSignatureScheme.Ed25519)),
      },
    ]),
  ])
}

function certificateBody(
  requestContext: Uint8Array,
  entries: readonly TlsCertificateEntryInput[],
): Uint8Array {
  return concatBytes([
    tlsU8Vector(requestContext),
    tlsU24Vector(concatBytes(entries.map(certificateEntry))),
  ])
}

function certificateEntry(entry: TlsCertificateEntryInput): Uint8Array {
  return concatBytes([
    tlsU24Vector(entry.data),
    writeU16BE(entry.extensions.length),
    entry.extensions,
  ])
}

function certificateVerifyBody(signature: Uint8Array): Uint8Array {
  return concatBytes([
    writeU16BE(TlsSignatureScheme.Ed25519),
    writeU16BE(signature.length),
    signature,
  ])
}

function tlsU8Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xff) {
    throw new RangeError('TLS u8 vector too large')
  }
  return concatBytes([new Uint8Array([bytes.length]), bytes])
}

function tlsU16Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) {
    throw new RangeError('TLS u16 vector too large')
  }
  return concatBytes([writeU16BE(bytes.length), bytes])
}

function tlsU24Vector(bytes: Uint8Array): Uint8Array {
  return concatBytes([tlsU24Length(bytes.length), bytes])
}

function tlsU24Length(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > 0xffffff) {
    throw new RangeError('TLS u24 length out of range')
  }
  return new Uint8Array([(length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff])
}

function randomOrCopy(bytes: Uint8Array | undefined, length: number, name: string): Uint8Array {
  if (bytes === undefined) {
    return randomBytes(length)
  }
  if (bytes.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`)
  }
  return copyBytes(bytes)
}

function randomBytes(length: number): Uint8Array {
  const crypto = globalThis.crypto
  if (crypto === undefined) {
    throw new Error('WebCrypto is required for TLS handshake randomness')
  }
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

interface TlsExtensionInput {
  readonly type: number
  readonly data: Uint8Array
}

interface TlsCertificateEntryInput {
  readonly data: Uint8Array
  readonly extensions: Uint8Array
}

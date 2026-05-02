import { copyBytes, readU8, requireLength } from '../bytes'
import { validateEndpointId } from '../crypto/ed25519'
import type { QuicTlsHandshakeMessage } from './tls-crypto-stream'
import { parseTlsCertificateRequest, type TlsCertificateRequest } from './tls-certificate-request'
import {
  parseTlsCertificate,
  requireTlsEd25519RawPublicKeyCertificate,
  type TlsCertificate,
} from './tls-certificate'
import {
  parseTlsCertificateVerify,
  TlsCertificateVerifyRole,
  verifyTls13Ed25519CertificateVerifyHandshake,
  type TlsCertificateVerify,
} from './tls-certificate-verify'
import {
  parseTlsEncryptedExtensions,
  type TlsEncryptedExtensions,
} from './tls-encrypted-extensions'
import { requireTlsFinishedVerifyData, verifyTls13FinishedHandshake } from './tls-finished'
import { TLS13_SHA256_SECRET_LENGTH, tls13TranscriptHash } from './tls-key-schedule'
import { TlsHandshakeKind } from './tls'

export interface VerifyTls13ServerEncryptedHandshakeMessagesOptions {
  readonly serverHandshakeTrafficSecret: Uint8Array
  readonly expectedEndpointId: Uint8Array
  readonly messages: readonly QuicTlsHandshakeMessage[]
}

export interface VerifyTls13ClientEncryptedHandshakeMessagesOptions {
  readonly clientHandshakeTrafficSecret: Uint8Array
  readonly messages: readonly QuicTlsHandshakeMessage[]
}

export interface Tls13ServerEncryptedHandshakeVerification {
  readonly encryptedExtensions: TlsEncryptedExtensions
  readonly certificateRequest: TlsCertificateRequest | null
  readonly certificate: TlsCertificate
  readonly certificateVerify: TlsCertificateVerify
  readonly finishedVerifyData: Uint8Array
  readonly endpointId: Uint8Array
  readonly certificateVerifyTranscriptHash: Uint8Array
  readonly finishedTranscriptHash: Uint8Array
  readonly applicationTrafficTranscriptHash: Uint8Array
}

export interface Tls13ClientEncryptedHandshakeVerification {
  readonly certificate: TlsCertificate
  readonly certificateVerify: TlsCertificateVerify
  readonly finishedVerifyData: Uint8Array
  readonly endpointId: Uint8Array
  readonly certificateVerifyTranscriptHash: Uint8Array
  readonly finishedTranscriptHash: Uint8Array
}

interface IndexedHandshakeMessage {
  readonly index: number
  readonly value: QuicTlsHandshakeMessage
}

interface EncryptedHandshakeSequence {
  readonly encryptedExtensions: IndexedHandshakeMessage
  readonly certificateRequest: IndexedHandshakeMessage | null
  readonly certificate: IndexedHandshakeMessage
  readonly certificateVerify: IndexedHandshakeMessage
  readonly finished: IndexedHandshakeMessage
}

interface ClientEncryptedHandshakeSequence {
  readonly certificateRequest: IndexedHandshakeMessage
  readonly certificate: IndexedHandshakeMessage
  readonly certificateVerify: IndexedHandshakeMessage
  readonly finished: IndexedHandshakeMessage
}

export async function verifyTls13ServerEncryptedHandshakeMessages(
  options: VerifyTls13ServerEncryptedHandshakeMessagesOptions,
): Promise<Tls13ServerEncryptedHandshakeVerification> {
  requireLength(
    options.serverHandshakeTrafficSecret,
    TLS13_SHA256_SECRET_LENGTH,
    'TLS server handshake traffic secret',
  )

  const sequence = requireServerEncryptedHandshakeSequence(options.messages)
  const encryptedExtensions = parseTlsEncryptedExtensions(
    sequence.encryptedExtensions.value.handshake,
  )
  const certificateRequest =
    sequence.certificateRequest === null
      ? null
      : parseTlsCertificateRequest(sequence.certificateRequest.value.handshake)
  const certificate = parseTlsCertificate(sequence.certificate.value.handshake)
  if (certificateRequest !== null) {
    requireEmptyCertificateContext(
      certificateRequest.requestContext,
      'TLS CertificateRequest context',
    )
  }
  requireEmptyCertificateContext(certificate.requestContext, 'TLS Certificate request context')
  const certificateVerify = parseTlsCertificateVerify(sequence.certificateVerify.value.handshake)
  const endpointId = requireTlsEd25519RawPublicKeyCertificate(sequence.certificate.value.handshake)
  requireEndpointId(endpointId, options.expectedEndpointId)

  const certificateVerifyTranscriptHash = transcriptHashBefore(
    options.messages,
    sequence.certificateVerify.index,
  )
  const certificateVerifyOk = await verifyTls13Ed25519CertificateVerifyHandshake(
    TlsCertificateVerifyRole.Server,
    certificateVerifyTranscriptHash,
    endpointId,
    sequence.certificateVerify.value.handshake,
  )
  if (!certificateVerifyOk) {
    throw new RangeError('TLS CertificateVerify signature invalid')
  }

  const finishedTranscriptHash = transcriptHashBefore(options.messages, sequence.finished.index)
  if (
    !verifyTls13FinishedHandshake(
      options.serverHandshakeTrafficSecret,
      finishedTranscriptHash,
      sequence.finished.value.handshake,
    )
  ) {
    throw new RangeError('TLS Finished verify_data invalid')
  }

  return {
    encryptedExtensions,
    certificateRequest,
    certificate,
    certificateVerify,
    finishedVerifyData: requireTlsFinishedVerifyData(sequence.finished.value.handshake),
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
    applicationTrafficTranscriptHash: transcriptHashThrough(
      options.messages,
      sequence.finished.index,
    ),
  }
}

export async function verifyTls13ClientEncryptedHandshakeMessages(
  options: VerifyTls13ClientEncryptedHandshakeMessagesOptions,
): Promise<Tls13ClientEncryptedHandshakeVerification> {
  requireLength(
    options.clientHandshakeTrafficSecret,
    TLS13_SHA256_SECRET_LENGTH,
    'TLS client handshake traffic secret',
  )

  const sequence = requireClientEncryptedHandshakeSequence(options.messages)
  const certificateRequest = parseTlsCertificateRequest(sequence.certificateRequest.value.handshake)
  const certificate = parseTlsCertificate(sequence.certificate.value.handshake)
  requireEmptyCertificateContext(
    certificateRequest.requestContext,
    'TLS CertificateRequest context',
  )
  requireCertificateContext(
    certificate.requestContext,
    certificateRequest.requestContext,
    'TLS Certificate request context',
  )
  const certificateVerify = parseTlsCertificateVerify(sequence.certificateVerify.value.handshake)
  const endpointId = requireTlsEd25519RawPublicKeyCertificate(sequence.certificate.value.handshake)

  const certificateVerifyTranscriptHash = transcriptHashBefore(
    options.messages,
    sequence.certificateVerify.index,
  )
  const certificateVerifyOk = await verifyTls13Ed25519CertificateVerifyHandshake(
    TlsCertificateVerifyRole.Client,
    certificateVerifyTranscriptHash,
    endpointId,
    sequence.certificateVerify.value.handshake,
  )
  if (!certificateVerifyOk) {
    throw new RangeError('TLS CertificateVerify signature invalid')
  }

  const finishedTranscriptHash = transcriptHashBefore(options.messages, sequence.finished.index)
  if (
    !verifyTls13FinishedHandshake(
      options.clientHandshakeTrafficSecret,
      finishedTranscriptHash,
      sequence.finished.value.handshake,
    )
  ) {
    throw new RangeError('TLS Finished verify_data invalid')
  }

  return {
    certificate,
    certificateVerify,
    finishedVerifyData: requireTlsFinishedVerifyData(sequence.finished.value.handshake),
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
  }
}

function requireServerEncryptedHandshakeSequence(
  messages: readonly QuicTlsHandshakeMessage[],
): EncryptedHandshakeSequence {
  requireHandshakeAt(messages, 0, TlsHandshakeKind.ClientHello)
  requireHandshakeAt(messages, 1, TlsHandshakeKind.ServerHello)
  const encryptedExtensions = requireHandshakeAt(messages, 2, TlsHandshakeKind.EncryptedExtensions)
  let index = encryptedExtensions.index + 1

  let certificateRequest: IndexedHandshakeMessage | null = null
  const next = messages[index]
  if (next !== undefined && next.handshake.kind === TlsHandshakeKind.CertificateRequest) {
    certificateRequest = { index, value: next }
    index += 1
  }

  const certificate = requireHandshakeAt(messages, index, TlsHandshakeKind.Certificate)
  const certificateVerify = requireHandshakeAt(
    messages,
    certificate.index + 1,
    TlsHandshakeKind.CertificateVerify,
  )
  const finished = requireHandshakeAt(
    messages,
    certificateVerify.index + 1,
    TlsHandshakeKind.Finished,
  )

  return {
    encryptedExtensions,
    certificateRequest,
    certificate,
    certificateVerify,
    finished,
  }
}

function requireClientEncryptedHandshakeSequence(
  messages: readonly QuicTlsHandshakeMessage[],
): ClientEncryptedHandshakeSequence {
  const serverSequence = requireServerEncryptedHandshakeSequence(messages)
  if (serverSequence.certificateRequest === null) {
    throw new RangeError('missing TLS certificate-request handshake')
  }
  const certificate = requireHandshakeAt(
    messages,
    serverSequence.finished.index + 1,
    TlsHandshakeKind.Certificate,
  )
  const certificateVerify = requireHandshakeAt(
    messages,
    certificate.index + 1,
    TlsHandshakeKind.CertificateVerify,
  )
  const finished = requireHandshakeAt(
    messages,
    certificateVerify.index + 1,
    TlsHandshakeKind.Finished,
  )

  return {
    certificateRequest: serverSequence.certificateRequest,
    certificate,
    certificateVerify,
    finished,
  }
}

function requireHandshakeAt(
  messages: readonly QuicTlsHandshakeMessage[],
  index: number,
  kind: string,
): IndexedHandshakeMessage {
  const message = messages[index]
  if (message === undefined || message.handshake.kind !== kind) {
    throw new RangeError(`missing TLS ${kind} handshake`)
  }
  return { index, value: message }
}

function transcriptHashBefore(
  messages: readonly QuicTlsHandshakeMessage[],
  endIndex: number,
): Uint8Array {
  const hash = tls13TranscriptHash(messages.slice(0, endIndex).map((message) => message.message))
  requireLength(hash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')
  return copyBytes(hash)
}

function transcriptHashThrough(
  messages: readonly QuicTlsHandshakeMessage[],
  endIndex: number,
): Uint8Array {
  const hash = tls13TranscriptHash(
    messages.slice(0, endIndex + 1).map((message) => message.message),
  )
  requireLength(hash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')
  return copyBytes(hash)
}

function requireEndpointId(actual: Uint8Array, expected: Uint8Array): void {
  const checkedActual = validateEndpointId(actual)
  const checkedExpected = validateEndpointId(expected)
  let diff = 0
  for (let index = 0; index < checkedActual.length; index += 1) {
    diff |= readU8(checkedActual, index) ^ readU8(checkedExpected, index)
  }
  if (diff !== 0) {
    throw new RangeError('TLS raw public key does not match expected endpoint id')
  }
}

function requireEmptyCertificateContext(context: Uint8Array, name: string): void {
  requireCertificateContext(context, new Uint8Array(), name)
}

function requireCertificateContext(actual: Uint8Array, expected: Uint8Array, name: string): void {
  if (actual.length !== expected.length) {
    throw new RangeError(`${name} mismatch`)
  }
  let diff = 0
  for (let index = 0; index < actual.length; index += 1) {
    diff |= readU8(actual, index) ^ readU8(expected, index)
  }
  if (diff !== 0) {
    throw new RangeError(`${name} mismatch`)
  }
}

import { SIGNATURE_LENGTH, verify } from '../crypto/ed25519'
import { concatBytes, copyBytes, readU16BE, requireLength } from '../bytes'
import { TLS13_SHA256_SECRET_LENGTH } from './tls-key-schedule'
import { TlsHandshakeKind, type TlsHandshake } from './tls'
import { requireTlsEd25519RawPublicKeyCertificate } from './tls-certificate'

export const TlsCertificateVerifyRole = {
  Client: 'client',
  Server: 'server',
} as const

export type TlsCertificateVerifyRole =
  (typeof TlsCertificateVerifyRole)[keyof typeof TlsCertificateVerifyRole]

export const TlsSignatureScheme = {
  Ed25519: 0x0807,
} as const

export interface TlsCertificateVerify {
  readonly signatureScheme: number
  readonly signature: Uint8Array
}

const TLS13_CERTIFICATE_VERIFY_CONTEXT_PREFIX = new Uint8Array(64).fill(0x20)
const TLS13_CERTIFICATE_VERIFY_SEPARATOR = new Uint8Array([0])
const TLS13_CLIENT_CERTIFICATE_VERIFY_CONTEXT = new TextEncoder().encode(
  'TLS 1.3, client CertificateVerify',
)
const TLS13_SERVER_CERTIFICATE_VERIFY_CONTEXT = new TextEncoder().encode(
  'TLS 1.3, server CertificateVerify',
)

export function parseTlsCertificateVerify(handshake: TlsHandshake): TlsCertificateVerify {
  if (handshake.kind !== TlsHandshakeKind.CertificateVerify) {
    throw new RangeError('TLS handshake must be CertificateVerify')
  }
  if (handshake.body.length < 4) {
    throw new RangeError('not enough bytes for TLS CertificateVerify')
  }

  const signatureScheme = readU16BE(handshake.body, 0)
  const signatureLength = readU16BE(handshake.body, 2)
  const signatureOffset = 4
  const endOffset = signatureOffset + signatureLength
  if (handshake.body.length !== endOffset) {
    throw new RangeError('TLS CertificateVerify signature length mismatch')
  }

  return {
    signatureScheme,
    signature: copyBytes(handshake.body.subarray(signatureOffset, endOffset)),
  }
}

export function requireTlsEd25519CertificateVerifySignature(handshake: TlsHandshake): Uint8Array {
  const parsed = parseTlsCertificateVerify(handshake)
  if (parsed.signatureScheme !== TlsSignatureScheme.Ed25519) {
    throw new RangeError('TLS CertificateVerify signature scheme must be Ed25519')
  }
  requireLength(parsed.signature, SIGNATURE_LENGTH, 'TLS CertificateVerify signature')
  return parsed.signature
}

export function buildTls13CertificateVerifyMessage(
  role: TlsCertificateVerifyRole,
  transcriptHash: Uint8Array,
): Uint8Array {
  requireLength(transcriptHash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')

  return concatBytes([
    TLS13_CERTIFICATE_VERIFY_CONTEXT_PREFIX,
    certificateVerifyContext(role),
    TLS13_CERTIFICATE_VERIFY_SEPARATOR,
    transcriptHash,
  ])
}

export async function verifyTls13CertificateVerifySignature(
  role: TlsCertificateVerifyRole,
  transcriptHash: Uint8Array,
  endpointId: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  return verify(endpointId, buildTls13CertificateVerifyMessage(role, transcriptHash), signature)
}

export async function verifyTls13Ed25519CertificateVerifyHandshake(
  role: TlsCertificateVerifyRole,
  transcriptHash: Uint8Array,
  endpointId: Uint8Array,
  handshake: TlsHandshake,
): Promise<boolean> {
  return verifyTls13CertificateVerifySignature(
    role,
    transcriptHash,
    endpointId,
    requireTlsEd25519CertificateVerifySignature(handshake),
  )
}

export async function verifyTls13Ed25519CertificateVerifyWithCertificate(
  role: TlsCertificateVerifyRole,
  transcriptHash: Uint8Array,
  certificateHandshake: TlsHandshake,
  certificateVerifyHandshake: TlsHandshake,
): Promise<boolean> {
  return verifyTls13Ed25519CertificateVerifyHandshake(
    role,
    transcriptHash,
    requireTlsEd25519RawPublicKeyCertificate(certificateHandshake),
    certificateVerifyHandshake,
  )
}

function certificateVerifyContext(role: TlsCertificateVerifyRole): Uint8Array {
  if (role === TlsCertificateVerifyRole.Client) {
    return TLS13_CLIENT_CERTIFICATE_VERIFY_CONTEXT
  }
  if (role === TlsCertificateVerifyRole.Server) {
    return TLS13_SERVER_CERTIFICATE_VERIFY_CONTEXT
  }
  throw new RangeError('unknown TLS CertificateVerify role')
}

import { ENDPOINT_ID_LENGTH, validateEndpointId } from '../crypto/ed25519'
import { concatBytes, copyBytes, readU8, readU16BE } from '../bytes'
import { TlsHandshakeKind, type TlsHandshake } from './tls'

export interface TlsCertificateEntry {
  readonly data: Uint8Array
  readonly extensions: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export interface TlsCertificate {
  readonly requestContext: Uint8Array
  readonly entries: readonly TlsCertificateEntry[]
}

const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])
const ED25519_SPKI_LENGTH = ED25519_SPKI_PREFIX.length + ENDPOINT_ID_LENGTH

export function parseTlsCertificate(handshake: TlsHandshake): TlsCertificate {
  if (handshake.kind !== TlsHandshakeKind.Certificate) {
    throw new RangeError('TLS handshake must be Certificate')
  }

  let pos = 0
  const requestContext = readTlsU8Vector(handshake.body, pos, 'TLS Certificate request context')
  pos = requestContext.endOffset

  const certificateListLength = readU24BE(handshake.body, pos)
  pos += 3
  const certificateListEndOffset = pos + certificateListLength
  if (handshake.body.length !== certificateListEndOffset) {
    throw new RangeError('TLS Certificate list length mismatch')
  }

  const entries: TlsCertificateEntry[] = []
  while (pos < certificateListEndOffset) {
    const entry = readTlsCertificateEntry(handshake.body, pos, certificateListEndOffset)
    entries.push(entry)
    pos = entry.endOffset
  }

  return {
    requestContext: requestContext.value,
    entries,
  }
}

export function requireTlsEd25519RawPublicKeyCertificate(handshake: TlsHandshake): Uint8Array {
  const certificate = parseTlsCertificate(handshake)
  if (certificate.entries.length !== 1) {
    throw new RangeError('TLS Certificate must contain exactly one raw public key')
  }

  const entry = certificate.entries[0]
  if (entry === undefined) {
    throw new RangeError('TLS Certificate must contain exactly one raw public key')
  }
  return endpointIdFromEd25519Spki(entry.data)
}

export function endpointIdFromEd25519Spki(spki: Uint8Array): Uint8Array {
  if (spki.length !== ED25519_SPKI_LENGTH) {
    throw new RangeError('TLS raw public key must be an Ed25519 SubjectPublicKeyInfo')
  }
  for (let index = 0; index < ED25519_SPKI_PREFIX.length; index += 1) {
    if (readU8(spki, index) !== readU8(ED25519_SPKI_PREFIX, index)) {
      throw new RangeError('TLS raw public key must be an Ed25519 SubjectPublicKeyInfo')
    }
  }
  return validateEndpointId(spki.subarray(ED25519_SPKI_PREFIX.length))
}

export function ed25519SpkiFromEndpointId(endpointId: Uint8Array): Uint8Array {
  return concatBytes([ED25519_SPKI_PREFIX, validateEndpointId(endpointId)])
}

function readTlsCertificateEntry(
  bytes: Uint8Array,
  offset: number,
  listEndOffset: number,
): TlsCertificateEntry {
  let pos = offset
  const dataLength = readU24BE(bytes, pos)
  if (dataLength === 0) {
    throw new RangeError('TLS Certificate data must not be empty')
  }
  pos += 3
  const dataEndOffset = pos + dataLength
  if (dataEndOffset > listEndOffset) {
    throw new RangeError('not enough bytes for TLS Certificate data')
  }
  const data = copyBytes(bytes.subarray(pos, dataEndOffset))
  pos = dataEndOffset

  const extensionsLength = readU16BE(bytes, pos)
  pos += 2
  const extensionsEndOffset = pos + extensionsLength
  if (extensionsEndOffset > listEndOffset) {
    throw new RangeError('not enough bytes for TLS Certificate extensions')
  }

  return {
    data,
    extensions: copyBytes(bytes.subarray(pos, extensionsEndOffset)),
    offset,
    endOffset: extensionsEndOffset,
  }
}

function readTlsU8Vector(
  bytes: Uint8Array,
  offset: number,
  name: string,
): {
  readonly value: Uint8Array
  readonly endOffset: number
} {
  const length = readU8(bytes, offset)
  const valueOffset = offset + 1
  const endOffset = valueOffset + length
  if (endOffset > bytes.length) {
    throw new RangeError(`not enough bytes for ${name}`)
  }
  return {
    value: copyBytes(bytes.subarray(valueOffset, endOffset)),
    endOffset,
  }
}

function readU24BE(bytes: Uint8Array, offset: number): number {
  const b0 = readU8(bytes, offset)
  const b1 = readU8(bytes, offset + 1)
  const b2 = readU8(bytes, offset + 2)
  return b0 * 2 ** 16 + (b1 << 8) + b2
}

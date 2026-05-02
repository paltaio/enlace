import { copyBytes, readU8 } from '../bytes'
import { TlsHandshakeKind, type TlsExtension, type TlsHandshake } from './tls'
import { readTlsExtensions } from './tls-extension'

export interface TlsCertificateRequest {
  readonly requestContext: Uint8Array
  readonly extensions: readonly TlsExtension[]
}

export function parseTlsCertificateRequest(handshake: TlsHandshake): TlsCertificateRequest {
  if (handshake.kind !== TlsHandshakeKind.CertificateRequest) {
    throw new RangeError('TLS handshake must be CertificateRequest')
  }

  let pos = 0
  const requestContext = readTlsU8Vector(handshake.body, pos, 'TLS CertificateRequest context')
  pos = requestContext.endOffset

  const extensions = readTlsExtensions(
    handshake.body,
    pos,
    'TLS CertificateRequest extensions',
    'TLS CertificateRequest extension data',
  )
  if (extensions.value.length === 0) {
    throw new RangeError('TLS CertificateRequest extensions must not be empty')
  }
  if (extensions.endOffset !== handshake.body.length) {
    throw new RangeError('TLS CertificateRequest contains trailing bytes')
  }

  return {
    requestContext: requestContext.value,
    extensions: extensions.value,
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

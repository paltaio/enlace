import { TlsHandshakeKind, type TlsExtension, type TlsHandshake } from './tls'
import { readTlsExtensions } from './tls-extension'

export interface TlsEncryptedExtensions {
  readonly extensions: readonly TlsExtension[]
}

export function parseTlsEncryptedExtensions(handshake: TlsHandshake): TlsEncryptedExtensions {
  if (handshake.kind !== TlsHandshakeKind.EncryptedExtensions) {
    throw new RangeError('TLS handshake must be EncryptedExtensions')
  }

  const extensions = readTlsExtensions(
    handshake.body,
    0,
    'TLS EncryptedExtensions',
    'TLS EncryptedExtensions data',
  )
  if (extensions.endOffset !== handshake.body.length) {
    throw new RangeError('TLS EncryptedExtensions contains trailing bytes')
  }

  return {
    extensions: extensions.value,
  }
}

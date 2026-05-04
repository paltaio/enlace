import { copyBytes, requireLength } from '../bytes'
import { deriveX25519SharedSecret, X25519_PUBLIC_KEY_LENGTH } from '../crypto/x25519'
import { TlsNamedGroup, type TlsKeyShareEntry } from './tls'

export function findTlsClientX25519KeyShare(
  keyShares: readonly TlsKeyShareEntry[],
): TlsKeyShareEntry {
  for (const keyShare of keyShares) {
    if (keyShare.group === TlsNamedGroup.X25519) {
      return keyShare
    }
  }
  throw new RangeError('TLS ClientHello must include X25519 key share')
}

export function tlsX25519KeySharePublicKey(keyShare: TlsKeyShareEntry): Uint8Array {
  if (keyShare.group !== TlsNamedGroup.X25519) {
    throw new RangeError('TLS key share group must be X25519')
  }
  requireLength(keyShare.keyExchange, X25519_PUBLIC_KEY_LENGTH, 'TLS X25519 key share')
  return copyBytes(keyShare.keyExchange)
}

export async function deriveTlsX25519SharedSecret(
  privateKey: Uint8Array,
  peerKeyShare: TlsKeyShareEntry,
): Promise<Uint8Array> {
  return deriveX25519SharedSecret(privateKey, tlsX25519KeySharePublicKey(peerKeyShare))
}

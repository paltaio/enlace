import { concatBytes, copyBytes, requireLength } from '../bytes'

export const X25519_PRIVATE_KEY_LENGTH = 32
export const X25519_PUBLIC_KEY_LENGTH = 32
export const X25519_SHARED_SECRET_LENGTH = 32

const X25519_ALGORITHM = 'X25519'
const X25519_PKCS8_PRIVATE_KEY_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
])
const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

export async function deriveX25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await importX25519PrivateKey(privateKey, true)
  const jwk = await getSubtleCrypto().exportKey('jwk', cryptoKey)
  if (typeof jwk.x !== 'string') {
    throw new Error('X25519 private key export did not include public key')
  }
  return validateX25519PublicKey(decodeBase64Url(jwk.x))
}

export async function deriveX25519SharedSecret(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getSubtleCrypto()
  const peerPublicKeyBytes = validateX25519PublicKey(peerPublicKey)
  if (isAllZero(peerPublicKeyBytes)) {
    throw new RangeError('X25519 shared secret must not be all zero')
  }

  const ownPrivateKey = await importX25519PrivateKey(privateKey, false)
  const peerCryptoKey = await subtle.importKey(
    'raw',
    toArrayBuffer(peerPublicKeyBytes),
    X25519_ALGORITHM,
    false,
    [],
  )
  const sharedSecret = new Uint8Array(
    await subtle.deriveBits(
      {
        name: X25519_ALGORITHM,
        public: peerCryptoKey,
      },
      ownPrivateKey,
      X25519_SHARED_SECRET_LENGTH * 8,
    ),
  )
  if (isAllZero(sharedSecret)) {
    throw new RangeError('X25519 shared secret must not be all zero')
  }
  return sharedSecret
}

export function validateX25519PrivateKey(privateKey: Uint8Array): Uint8Array {
  requireLength(privateKey, X25519_PRIVATE_KEY_LENGTH, 'X25519 private key')
  return copyBytes(privateKey)
}

export function validateX25519PublicKey(publicKey: Uint8Array): Uint8Array {
  requireLength(publicKey, X25519_PUBLIC_KEY_LENGTH, 'X25519 public key')
  return copyBytes(publicKey)
}

async function importX25519PrivateKey(
  privateKey: Uint8Array,
  extractable: boolean,
): Promise<CryptoKey> {
  return getSubtleCrypto().importKey(
    'pkcs8',
    toArrayBuffer(
      concatBytes([X25519_PKCS8_PRIVATE_KEY_PREFIX, validateX25519PrivateKey(privateKey)]),
    ),
    X25519_ALGORITHM,
    extractable,
    ['deriveBits'],
  )
}

function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle
  if (subtle === undefined) {
    throw new Error('WebCrypto SubtleCrypto is required for X25519')
  }
  return subtle
}

function decodeBase64Url(value: string): Uint8Array {
  if (value.length % 4 === 1) {
    throw new RangeError('invalid base64url length')
  }

  let bits = 0
  let buffer = 0
  const out: number[] = []
  for (const char of value) {
    const index = BASE64URL_ALPHABET.indexOf(char)
    if (index === -1) {
      throw new RangeError('invalid base64url character')
    }
    buffer = (buffer << 6) | index
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((buffer >>> bits) & 0xff)
    }
  }

  return new Uint8Array(out)
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(out).set(bytes)
  return out
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) {
      return false
    }
  }
  return true
}

import { extract } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { copyBytes, requireLength } from '../bytes'
import { hkdfExpandTls13LabelSha256 } from '../crypto/hkdf'

export const TLS13_SHA256_SECRET_LENGTH = 32
export const TLS13_AES_128_GCM_KEY_LENGTH = 16
export const TLS13_AES_128_GCM_IV_LENGTH = 12
export const TLS13_X25519_SHARED_SECRET_LENGTH = 32

const TLS13_DERIVED_LABEL = 'derived'
const TLS13_CLIENT_HANDSHAKE_TRAFFIC_LABEL = 'c hs traffic'
const TLS13_SERVER_HANDSHAKE_TRAFFIC_LABEL = 's hs traffic'
const TLS13_TRAFFIC_KEY_LABEL = 'key'
const TLS13_TRAFFIC_IV_LABEL = 'iv'
const ZERO_SHA256_SECRET = new Uint8Array(TLS13_SHA256_SECRET_LENGTH)

export interface Tls13HandshakeSecrets {
  readonly earlySecret: Uint8Array
  readonly derivedSecret: Uint8Array
  readonly handshakeSecret: Uint8Array
  readonly clientHandshakeTrafficSecret: Uint8Array
  readonly serverHandshakeTrafficSecret: Uint8Array
}

export interface Tls13TrafficKeys {
  readonly key: Uint8Array
  readonly iv: Uint8Array
}

export class Tls13Transcript {
  readonly #messages: Uint8Array[] = []

  append(message: Uint8Array): void {
    this.#messages.push(copyBytes(message))
  }

  digest(): Uint8Array {
    return tls13TranscriptHash(this.#messages)
  }
}

export function tls13EmptyTranscriptHash(): Uint8Array {
  return sha256(new Uint8Array())
}

export function tls13TranscriptHash(messages: readonly Uint8Array[]): Uint8Array {
  const hash = sha256.create()
  for (const message of messages) {
    hash.update(message)
  }
  return hash.digest()
}

export function deriveTls13HandshakeSecrets(
  sharedSecret: Uint8Array,
  transcriptHash: Uint8Array,
): Tls13HandshakeSecrets {
  requireLength(sharedSecret, TLS13_X25519_SHARED_SECRET_LENGTH, 'TLS X25519 shared secret')
  if (isAllZero(sharedSecret)) {
    throw new RangeError('TLS X25519 shared secret must not be all zero')
  }
  requireLength(transcriptHash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')
  const earlySecret = extract(sha256, ZERO_SHA256_SECRET, ZERO_SHA256_SECRET)
  const derivedSecret = deriveTls13Secret(
    earlySecret,
    TLS13_DERIVED_LABEL,
    tls13EmptyTranscriptHash(),
  )
  const handshakeSecret = extract(sha256, sharedSecret, derivedSecret)

  return {
    earlySecret,
    derivedSecret,
    handshakeSecret,
    clientHandshakeTrafficSecret: deriveTls13Secret(
      handshakeSecret,
      TLS13_CLIENT_HANDSHAKE_TRAFFIC_LABEL,
      transcriptHash,
    ),
    serverHandshakeTrafficSecret: deriveTls13Secret(
      handshakeSecret,
      TLS13_SERVER_HANDSHAKE_TRAFFIC_LABEL,
      transcriptHash,
    ),
  }
}

export function deriveTls13Secret(
  secret: Uint8Array,
  label: string,
  transcriptHash: Uint8Array,
): Uint8Array {
  requireLength(transcriptHash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')
  return hkdfExpandTls13LabelSha256(secret, label, transcriptHash, TLS13_SHA256_SECRET_LENGTH)
}

export function deriveTls13Aes128GcmTrafficKeys(trafficSecret: Uint8Array): Tls13TrafficKeys {
  requireLength(trafficSecret, TLS13_SHA256_SECRET_LENGTH, 'TLS traffic secret')
  return {
    key: hkdfExpandTls13LabelSha256(
      trafficSecret,
      TLS13_TRAFFIC_KEY_LABEL,
      new Uint8Array(),
      TLS13_AES_128_GCM_KEY_LENGTH,
    ),
    iv: hkdfExpandTls13LabelSha256(
      trafficSecret,
      TLS13_TRAFFIC_IV_LABEL,
      new Uint8Array(),
      TLS13_AES_128_GCM_IV_LENGTH,
    ),
  }
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) {
      return false
    }
  }
  return true
}

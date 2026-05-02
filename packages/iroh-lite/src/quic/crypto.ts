import { ecb, gcm } from '@noble/ciphers/aes.js'
import { extract } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { copyBytes, readU8, requireLength } from '../bytes'
import { hkdfExpandTls13LabelSha256 } from '../crypto/hkdf'
import { quicPacketNumberToBigInt } from './packet'

const CLIENT_INITIAL_LABEL = 'client in'
const SERVER_INITIAL_LABEL = 'server in'
const QUIC_PACKET_KEY_LABEL = 'quic key'
const QUIC_PACKET_IV_LABEL = 'quic iv'
const QUIC_HEADER_PROTECTION_KEY_LABEL = 'quic hp'

export const QUIC_V1_INITIAL_SALT = new Uint8Array([
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
  0xcc, 0xbb, 0x7f, 0x0a,
])

export const QUIC_INITIAL_SECRET_LENGTH = 32
export const QUIC_AES_128_KEY_LENGTH = 16
export const QUIC_AES_128_IV_LENGTH = 12
export const QUIC_HEADER_PROTECTION_SAMPLE_LENGTH = 16
export const QUIC_HEADER_PROTECTION_MASK_LENGTH = 5

export interface QuicInitialSecrets {
  readonly initial: Uint8Array
  readonly client: Uint8Array
  readonly server: Uint8Array
}

export interface QuicDirectionalKeys {
  readonly secret: Uint8Array
  readonly packetKey: Uint8Array
  readonly packetIv: Uint8Array
  readonly headerProtectionKey: Uint8Array
}

export type QuicInitialDirectionalKeys = QuicDirectionalKeys

export interface QuicInitialKeys {
  readonly client: QuicInitialDirectionalKeys
  readonly server: QuicInitialDirectionalKeys
}

export interface QuicHeaderProtectionResult {
  readonly packet: Uint8Array
  readonly firstByte: number
  readonly packetNumberLength: number
}

export function deriveQuicInitialSecrets(destinationConnectionId: Uint8Array): QuicInitialSecrets {
  const initial = extract(sha256, destinationConnectionId, QUIC_V1_INITIAL_SALT)
  return {
    initial,
    client: hkdfExpandTls13LabelSha256(
      initial,
      CLIENT_INITIAL_LABEL,
      new Uint8Array(),
      QUIC_INITIAL_SECRET_LENGTH,
    ),
    server: hkdfExpandTls13LabelSha256(
      initial,
      SERVER_INITIAL_LABEL,
      new Uint8Array(),
      QUIC_INITIAL_SECRET_LENGTH,
    ),
  }
}

export function deriveQuicInitialKeys(destinationConnectionId: Uint8Array): QuicInitialKeys {
  const secrets = deriveQuicInitialSecrets(destinationConnectionId)
  return {
    client: deriveQuicDirectionalKeys(secrets.client),
    server: deriveQuicDirectionalKeys(secrets.server),
  }
}

export function deriveQuicDirectionalKeys(secret: Uint8Array): QuicDirectionalKeys {
  requireLength(secret, QUIC_INITIAL_SECRET_LENGTH, 'QUIC traffic secret')
  return {
    secret,
    packetKey: hkdfExpandTls13LabelSha256(
      secret,
      QUIC_PACKET_KEY_LABEL,
      new Uint8Array(),
      QUIC_AES_128_KEY_LENGTH,
    ),
    packetIv: hkdfExpandTls13LabelSha256(
      secret,
      QUIC_PACKET_IV_LABEL,
      new Uint8Array(),
      QUIC_AES_128_IV_LENGTH,
    ),
    headerProtectionKey: hkdfExpandTls13LabelSha256(
      secret,
      QUIC_HEADER_PROTECTION_KEY_LABEL,
      new Uint8Array(),
      QUIC_AES_128_KEY_LENGTH,
    ),
  }
}

export function quicPacketNonce(packetIv: Uint8Array, packetNumber: number | bigint): Uint8Array {
  requireLength(packetIv, QUIC_AES_128_IV_LENGTH, 'QUIC packet IV')
  const nonce = copyBytes(packetIv)
  let remaining = quicPacketNumberToBigInt(packetNumber)

  for (let index = nonce.length - 1; index >= 0 && remaining > 0n; index -= 1) {
    nonce[index] = readU8(nonce, index) ^ Number(remaining & 0xffn)
    remaining >>= 8n
  }

  return nonce
}

export function encryptQuicAes128GcmPacket(
  keys: QuicInitialDirectionalKeys,
  packetNumber: number | bigint,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const nonce = quicPacketNonce(keys.packetIv, packetNumber)
  return gcm(keys.packetKey, nonce, associatedData).encrypt(plaintext)
}

export function decryptQuicAes128GcmPacket(
  keys: QuicInitialDirectionalKeys,
  packetNumber: number | bigint,
  associatedData: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const nonce = quicPacketNonce(keys.packetIv, packetNumber)
  return gcm(keys.packetKey, nonce, associatedData).decrypt(ciphertext)
}

export function createQuicHeaderProtectionMask(
  headerProtectionKey: Uint8Array,
  sample: Uint8Array,
): Uint8Array {
  requireLength(headerProtectionKey, QUIC_AES_128_KEY_LENGTH, 'QUIC header protection key')
  requireLength(sample, QUIC_HEADER_PROTECTION_SAMPLE_LENGTH, 'QUIC header protection sample')
  const encrypted = ecb(headerProtectionKey, { disablePadding: true }).encrypt(sample)
  return copyBytes(encrypted.subarray(0, QUIC_HEADER_PROTECTION_MASK_LENGTH))
}

export function removeQuicHeaderProtection(
  packet: Uint8Array,
  packetNumberOffset: number,
  headerProtectionKey: Uint8Array,
): QuicHeaderProtectionResult {
  const sample = headerProtectionSample(packet, packetNumberOffset)
  const mask = createQuicHeaderProtectionMask(headerProtectionKey, sample)
  const unprotected = copyBytes(packet)
  const protectedFirstByte = readU8(unprotected, 0)
  const firstMask = isLongHeader(protectedFirstByte) ? 0x0f : 0x1f

  const firstByte = protectedFirstByte ^ (readU8(mask, 0) & firstMask)
  unprotected[0] = firstByte
  const packetNumberLength = (firstByte & 0x03) + 1
  ensurePacketNumberBytes(unprotected, packetNumberOffset, packetNumberLength)
  for (let index = 0; index < packetNumberLength; index += 1) {
    const packetNumberIndex = packetNumberOffset + index
    unprotected[packetNumberIndex] =
      readU8(unprotected, packetNumberIndex) ^ readU8(mask, index + 1)
  }

  return {
    packet: unprotected,
    firstByte,
    packetNumberLength,
  }
}

export function headerProtectionSample(packet: Uint8Array, packetNumberOffset: number): Uint8Array {
  validateOffset(packetNumberOffset, 'QUIC packet number offset')
  const sampleOffset = packetNumberOffset + 4
  if (packet.length - sampleOffset < QUIC_HEADER_PROTECTION_SAMPLE_LENGTH) {
    throw new RangeError('not enough bytes for QUIC header protection sample')
  }
  return copyBytes(
    packet.subarray(sampleOffset, sampleOffset + QUIC_HEADER_PROTECTION_SAMPLE_LENGTH),
  )
}

function isLongHeader(firstByte: number): boolean {
  return (firstByte & 0x80) !== 0
}

function ensurePacketNumberBytes(
  packet: Uint8Array,
  packetNumberOffset: number,
  packetNumberLength: number,
): void {
  if (packet.length - packetNumberOffset < packetNumberLength) {
    throw new RangeError('not enough bytes for QUIC packet number')
  }
}

function validateOffset(offset: number, name: string): void {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new RangeError(`${name} out of range`)
  }
}

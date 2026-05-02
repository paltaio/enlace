import { describe, expect, test } from 'bun:test'

import { concatBytes, readU8 } from '../bytes'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ServerHandshakeTrafficSecret,
} from '../testing/rfc8448-tls'
import { bytesToHex } from '../testing/hex'
import { encodeVarInt } from '../varint'
import {
  createQuicHeaderProtectionMask,
  deriveQuicDirectionalKeys,
  encryptQuicAes128GcmPacket,
  headerProtectionSample,
  type QuicDirectionalKeys,
} from './crypto'
import { decryptQuicHandshakePacket } from './handshake'

describe('QUIC Handshake key derivation', () => {
  test('derives QUIC keys from TLS handshake traffic secrets', () => {
    const clientKeys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)
    const serverKeys = deriveQuicDirectionalKeys(rfc8448ServerHandshakeTrafficSecret)

    expect(bytesToHex(clientKeys.packetKey)).toBe('b574ba1b323a2c6ad03e410836b5605c')
    expect(bytesToHex(clientKeys.packetIv)).toBe('200c933d2209b9a1aa879197')
    expect(bytesToHex(clientKeys.headerProtectionKey)).toBe('bb1db87365312baa38818fa20be44fde')
    expect(bytesToHex(serverKeys.packetKey)).toBe('03f01e7bf4e9bc37901b9ae3a022dfe7')
    expect(bytesToHex(serverKeys.packetIv)).toBe('53df176c0bdf845443fca523')
    expect(bytesToHex(serverKeys.headerProtectionKey)).toBe('5b6160d63552d737da036abf737ce2bf')
  })
})

describe('QUIC Handshake packet decryption', () => {
  test('unprotects and decrypts a protected Handshake packet', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)
    const packet = createProtectedHandshakePacket(keys, 1, new Uint8Array([0x00]))
    const result = decryptQuicHandshakePacket(packet, keys)

    expect(result.header.firstByte).toBe(0xe2)
    expect(result.header.length).toBe(20)
    expect(result.header.packetNumberLength).toBe(3)
    expect(result.header.packetNumber).toBe(1)
    expect(result.header.packetNumberOffset).toBe(17)
    expect(result.header.payloadOffset).toBe(20)
    expect(result.payload).toEqual(new Uint8Array([0x00]))
    expect(result.endOffset).toBe(packet.length)
  })

  test('rejects truncated protected Handshake packets', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)
    const packet = createProtectedHandshakePacket(keys, 1, new Uint8Array([0x00]))

    expect(() => decryptQuicHandshakePacket(packet.subarray(0, 22), keys)).toThrow(
      'not enough bytes for QUIC Handshake packet',
    )
  })
})

function createProtectedHandshakePacket(
  keys: QuicDirectionalKeys,
  packetNumber: number,
  plaintext: Uint8Array,
): Uint8Array {
  const packetNumberBytes = new Uint8Array([
    (packetNumber >>> 16) & 0xff,
    (packetNumber >>> 8) & 0xff,
    packetNumber & 0xff,
  ])
  const header = concatBytes([
    new Uint8Array([0xe2]),
    new Uint8Array([0x00, 0x00, 0x00, 0x01]),
    new Uint8Array([0x04, 0x01, 0x02, 0x03, 0x04]),
    new Uint8Array([0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]),
    encodeVarInt(packetNumberBytes.length + plaintext.length + 16),
    packetNumberBytes,
  ])
  const ciphertext = encryptQuicAes128GcmPacket(keys, packetNumber, header, plaintext)
  const packetNumberOffset = header.length - packetNumberBytes.length
  return applyLongHeaderProtection(concatBytes([header, ciphertext]), packetNumberOffset, keys)
}

function applyLongHeaderProtection(
  packet: Uint8Array,
  packetNumberOffset: number,
  keys: QuicDirectionalKeys,
): Uint8Array {
  const protectedPacket = new Uint8Array(packet)
  const sample = headerProtectionSample(packet, packetNumberOffset)
  const mask = createQuicHeaderProtectionMask(keys.headerProtectionKey, sample)
  protectedPacket[0] = readU8(protectedPacket, 0) ^ (readU8(mask, 0) & 0x0f)

  const packetNumberLength = (readU8(packet, 0) & 0x03) + 1
  for (let index = 0; index < packetNumberLength; index += 1) {
    const packetNumberIndex = packetNumberOffset + index
    protectedPacket[packetNumberIndex] =
      readU8(protectedPacket, packetNumberIndex) ^ readU8(mask, index + 1)
  }

  return protectedPacket
}

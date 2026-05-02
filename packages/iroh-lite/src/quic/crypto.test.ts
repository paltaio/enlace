import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc9001ClientInitialFrames,
  rfc9001ClientInitialSample,
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialHeader,
  rfc9001UnprotectedClientInitialHeader,
} from '../testing/rfc9001-quic'
import {
  createQuicHeaderProtectionMask,
  decryptQuicAes128GcmPacket,
  deriveQuicInitialKeys,
  deriveQuicInitialSecrets,
  encryptQuicAes128GcmPacket,
  headerProtectionSample,
  quicPacketNonce,
  removeQuicHeaderProtection,
} from './crypto'

describe('QUIC Initial key derivation', () => {
  test('matches RFC 9001 Initial secret vectors', () => {
    const secrets = deriveQuicInitialSecrets(rfc9001DestinationConnectionId)

    expect(bytesToHex(secrets.initial)).toBe(
      '7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44',
    )
    expect(bytesToHex(secrets.client)).toBe(
      'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea',
    )
    expect(bytesToHex(secrets.server)).toBe(
      '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b',
    )
  })

  test('matches RFC 9001 Initial packet protection key vectors', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)

    expect(bytesToHex(keys.client.packetKey)).toBe('1f369613dd76d5467730efcbe3b1a22d')
    expect(bytesToHex(keys.client.packetIv)).toBe('fa044b2f42a3fd3b46fb255c')
    expect(bytesToHex(keys.client.headerProtectionKey)).toBe('9f50449e04a0e810283a1e9933adedd2')
    expect(bytesToHex(keys.server.packetKey)).toBe('cf3a5331653c364c88f0f379b6067e37')
    expect(bytesToHex(keys.server.packetIv)).toBe('0ac1493ca1905853b0bba03e')
    expect(bytesToHex(keys.server.headerProtectionKey)).toBe('c206b8d9b9f0f37644430b490eeaa314')
  })
})

describe('QUIC AES-128-GCM Initial packet protection', () => {
  test('derives packet nonce by XORing packet number into IV', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)

    expect(bytesToHex(quicPacketNonce(keys.client.packetIv, 2))).toBe('fa044b2f42a3fd3b46fb255e')
  })

  test('encrypts and decrypts client Initial payload', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const plaintext = new Uint8Array(1162)
    plaintext.set(rfc9001ClientInitialFrames)

    const ciphertext = encryptQuicAes128GcmPacket(
      keys.client,
      2,
      rfc9001UnprotectedClientInitialHeader,
      plaintext,
    )

    expect(ciphertext).toHaveLength(1178)
    expect(bytesToHex(ciphertext.subarray(0, 16))).toBe(bytesToHex(rfc9001ClientInitialSample))
    expect(
      decryptQuicAes128GcmPacket(keys.client, 2, rfc9001UnprotectedClientInitialHeader, ciphertext),
    ).toEqual(plaintext)
  })
})

describe('QUIC header protection', () => {
  test('creates AES header protection mask', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)

    expect(
      bytesToHex(
        createQuicHeaderProtectionMask(keys.client.headerProtectionKey, rfc9001ClientInitialSample),
      ),
    ).toBe('437b9aec36')
  })

  test('removes long header protection', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const packetPrefix = concatBytes([
      rfc9001ProtectedClientInitialHeader,
      rfc9001ClientInitialSample,
    ])
    const result = removeQuicHeaderProtection(packetPrefix, 18, keys.client.headerProtectionKey)

    expect(result.firstByte).toBe(0xc3)
    expect(result.packetNumberLength).toBe(4)
    expect(
      bytesToHex(result.packet.subarray(0, rfc9001UnprotectedClientInitialHeader.length)),
    ).toBe(bytesToHex(rfc9001UnprotectedClientInitialHeader))
  })

  test('samples ciphertext from four bytes after packet number offset', () => {
    const packetPrefix = concatBytes([
      rfc9001ProtectedClientInitialHeader,
      rfc9001ClientInitialSample,
    ])

    expect(bytesToHex(headerProtectionSample(packetPrefix, 18))).toBe(
      bytesToHex(rfc9001ClientInitialSample),
    )
  })

  test('rejects missing header protection sample', () => {
    expect(() =>
      headerProtectionSample(hexToBytes('c000000001088394c8f03e5157080000449e7b9aec34'), 18),
    ).toThrow('not enough bytes for QUIC header protection sample')
  })

  test('rejects invalid packet number offset', () => {
    expect(() => headerProtectionSample(rfc9001ProtectedClientInitialHeader, -1)).toThrow(
      'QUIC packet number offset out of range',
    )
  })
})

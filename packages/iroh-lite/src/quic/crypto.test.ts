import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
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

const destinationConnectionId = hexToBytes('8394c8f03e515708')
const unprotectedClientInitialHeader = hexToBytes('c300000001088394c8f03e5157080000449e00000002')
const protectedClientInitialHeader = hexToBytes('c000000001088394c8f03e5157080000449e7b9aec34')
const clientInitialSample = hexToBytes('d1b1c98dd7689fb8ec11d242b123dc9b')
const clientInitialFrames = hexToBytes(`
  060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
  04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
  616d706c652e636f6dff01000100000a00080006001d00170018001000070005
  04616c706e000500050100000000003300260024001d00209370b2c9caa47fba
  baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400
  0d0010000e0403050306030203080408050806002d00020101001c0002400100
  3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000
  75300901100f088394c8f03e51570806048000ffff
`)

describe('QUIC Initial key derivation', () => {
  test('matches RFC 9001 Initial secret vectors', () => {
    const secrets = deriveQuicInitialSecrets(destinationConnectionId)

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
    const keys = deriveQuicInitialKeys(destinationConnectionId)

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
    const keys = deriveQuicInitialKeys(destinationConnectionId)

    expect(bytesToHex(quicPacketNonce(keys.client.packetIv, 2))).toBe('fa044b2f42a3fd3b46fb255e')
  })

  test('encrypts and decrypts client Initial payload', () => {
    const keys = deriveQuicInitialKeys(destinationConnectionId)
    const plaintext = new Uint8Array(1162)
    plaintext.set(clientInitialFrames)

    const ciphertext = encryptQuicAes128GcmPacket(
      keys.client,
      2,
      unprotectedClientInitialHeader,
      plaintext,
    )

    expect(ciphertext).toHaveLength(1178)
    expect(bytesToHex(ciphertext.subarray(0, 16))).toBe(bytesToHex(clientInitialSample))
    expect(
      decryptQuicAes128GcmPacket(keys.client, 2, unprotectedClientInitialHeader, ciphertext),
    ).toEqual(plaintext)
  })
})

describe('QUIC header protection', () => {
  test('creates AES header protection mask', () => {
    const keys = deriveQuicInitialKeys(destinationConnectionId)

    expect(
      bytesToHex(
        createQuicHeaderProtectionMask(keys.client.headerProtectionKey, clientInitialSample),
      ),
    ).toBe('437b9aec36')
  })

  test('removes long header protection', () => {
    const keys = deriveQuicInitialKeys(destinationConnectionId)
    const packetPrefix = concatBytes([protectedClientInitialHeader, clientInitialSample])
    const result = removeQuicHeaderProtection(packetPrefix, 18, keys.client.headerProtectionKey)

    expect(result.firstByte).toBe(0xc3)
    expect(result.packetNumberLength).toBe(4)
    expect(bytesToHex(result.packet.subarray(0, unprotectedClientInitialHeader.length))).toBe(
      bytesToHex(unprotectedClientInitialHeader),
    )
  })

  test('samples ciphertext from four bytes after packet number offset', () => {
    const packetPrefix = concatBytes([protectedClientInitialHeader, clientInitialSample])

    expect(bytesToHex(headerProtectionSample(packetPrefix, 18))).toBe(
      bytesToHex(clientInitialSample),
    )
  })

  test('rejects missing header protection sample', () => {
    expect(() =>
      headerProtectionSample(hexToBytes('c000000001088394c8f03e5157080000449e7b9aec34'), 18),
    ).toThrow('not enough bytes for QUIC header protection sample')
  })

  test('rejects invalid packet number offset', () => {
    expect(() => headerProtectionSample(protectedClientInitialHeader, -1)).toThrow(
      'QUIC packet number offset out of range',
    )
  })
})

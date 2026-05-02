import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex } from '../testing/hex'
import {
  rfc9001ClientInitialFrames,
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
  rfc9001ProtectedServerInitialPacket,
  rfc9001ServerInitialFrames,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import { decryptQuicInitialPacket, encryptQuicInitialPacket } from './initial'

describe('QUIC Initial packet decryption', () => {
  test('protects client Initial vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const packet = encryptQuicInitialPacket(keys.client, {
      destinationConnectionId: rfc9001DestinationConnectionId,
      sourceConnectionId: new Uint8Array(),
      packetNumber: 2,
      packetNumberLength: 4,
      payload: concatBytes([
        rfc9001ClientInitialFrames,
        new Uint8Array(1162 - rfc9001ClientInitialFrames.length),
      ]),
    })

    expect(bytesToHex(packet)).toBe(bytesToHex(rfc9001ProtectedClientInitialPacket))
  })

  test('protects server Initial vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const packet = encryptQuicInitialPacket(keys.server, {
      destinationConnectionId: new Uint8Array(),
      sourceConnectionId: new Uint8Array([0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5]),
      packetNumber: 1,
      packetNumberLength: 2,
      payload: rfc9001ServerInitialFrames,
    })

    expect(bytesToHex(packet)).toBe(bytesToHex(rfc9001ProtectedServerInitialPacket))
  })

  test('recovers wrapped Initial packet numbers for nonce construction', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const payload = new Uint8Array(16)
    const packet = encryptQuicInitialPacket(keys.client, {
      destinationConnectionId: rfc9001DestinationConnectionId,
      sourceConnectionId: new Uint8Array(),
      packetNumber: 256,
      packetNumberLength: 1,
      payload,
    })
    const result = decryptQuicInitialPacket(packet, keys.client, 0, 256)

    expect(result.header.packetNumber).toBe(0)
    expect(result.packetNumber).toBe(256n)
    expect(result.payload).toEqual(payload)
  })

  test('unprotects and decrypts protected client Initial vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const result = decryptQuicInitialPacket(rfc9001ProtectedClientInitialPacket, keys.client)

    expect(result.header.firstByte).toBe(0xc3)
    expect(result.header.length).toBe(1182)
    expect(result.header.packetNumberLength).toBe(4)
    expect(result.header.packetNumber).toBe(2)
    expect(result.packetNumber).toBe(2n)
    expect(result.header.packetNumberOffset).toBe(18)
    expect(result.header.payloadOffset).toBe(22)
    expect(result.payload).toHaveLength(1162)
    expect(bytesToHex(result.payload.subarray(0, rfc9001ClientInitialFrames.length))).toBe(
      bytesToHex(rfc9001ClientInitialFrames),
    )
    expect(result.endOffset).toBe(rfc9001ProtectedClientInitialPacket.length)
    expect(bytesToHex(result.unprotectedPacket.subarray(0, 22))).toBe(
      'c300000001088394c8f03e5157080000449e00000002',
    )
  })

  test('unprotects and decrypts protected server Initial vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const result = decryptQuicInitialPacket(rfc9001ProtectedServerInitialPacket, keys.server)

    expect(result.header.firstByte).toBe(0xc1)
    expect(result.header.length).toBe(117)
    expect(result.header.packetNumberLength).toBe(2)
    expect(result.header.packetNumber).toBe(1)
    expect(result.packetNumber).toBe(1n)
    expect(result.header.packetNumberOffset).toBe(18)
    expect(result.header.payloadOffset).toBe(20)
    expect(result.payload).toEqual(rfc9001ServerInitialFrames)
    expect(result.endOffset).toBe(rfc9001ProtectedServerInitialPacket.length)
    expect(bytesToHex(result.unprotectedPacket.subarray(0, 20))).toBe(
      'c1000000010008f067a5502a4262b50040750001',
    )
  })

  test('rejects truncated protected Initial packets', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const truncated = rfc9001ProtectedClientInitialPacket.subarray(0, 20)

    expect(() => decryptQuicInitialPacket(truncated, keys.client)).toThrow(
      'not enough bytes for QUIC Initial packet',
    )
  })

  test('rejects oversized Initial connection ids', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)

    expect(() =>
      encryptQuicInitialPacket(keys.client, {
        destinationConnectionId: new Uint8Array(21),
        sourceConnectionId: new Uint8Array(),
        packetNumber: 0,
        packetNumberLength: 1,
        payload: new Uint8Array(16),
      }),
    ).toThrow('QUIC destination connection id length out of range')
  })
})

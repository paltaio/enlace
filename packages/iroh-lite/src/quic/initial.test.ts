import { describe, expect, test } from 'bun:test'

import { bytesToHex } from '../testing/hex'
import {
  rfc9001ClientInitialFrames,
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
  rfc9001ProtectedServerInitialPacket,
  rfc9001ServerInitialFrames,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import { decryptQuicInitialPacket } from './initial'

describe('QUIC Initial packet decryption', () => {
  test('unprotects and decrypts protected client Initial vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const result = decryptQuicInitialPacket(rfc9001ProtectedClientInitialPacket, keys.client)

    expect(result.header.firstByte).toBe(0xc3)
    expect(result.header.length).toBe(1182)
    expect(result.header.packetNumberLength).toBe(4)
    expect(result.header.packetNumber).toBe(2)
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
})

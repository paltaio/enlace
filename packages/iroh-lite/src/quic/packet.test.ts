import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  QUIC_VERSION_1,
  QuicLongHeaderPacketType,
  parseQuicInitialPacketHeader,
  parseQuicLongHeader,
} from './packet'

const initialPacket = hexToBytes('c300000001088394c8f03e515708080001020304050607000700000002aabbcc')

describe('QUIC long header parsing', () => {
  test('decodes invariant long header fields', () => {
    const header = parseQuicLongHeader(initialPacket)

    expect(header.firstByte).toBe(0xc3)
    expect(header.version).toBe(QUIC_VERSION_1)
    expect(header.packetType).toBe(QuicLongHeaderPacketType.Initial)
    expect(bytesToHex(header.destinationConnectionId)).toBe('8394c8f03e515708')
    expect(bytesToHex(header.sourceConnectionId)).toBe('0001020304050607')
    expect(header.offset).toBe(23)
  })

  test('rejects short header packets', () => {
    expect(() => parseQuicLongHeader(hexToBytes('4000000001'))).toThrow(
      'QUIC packet is not long header',
    )
  })

  test('rejects packets without fixed bit', () => {
    expect(() => parseQuicLongHeader(hexToBytes('8000000001'))).toThrow('QUIC fixed bit is not set')
  })
})

describe('QUIC Initial header parsing', () => {
  test('decodes Initial token, length, packet number, and payload offset', () => {
    const header = parseQuicInitialPacketHeader(initialPacket)

    expect(header.packetType).toBe(QuicLongHeaderPacketType.Initial)
    expect(header.token).toEqual(new Uint8Array())
    expect(header.length).toBe(7)
    expect(header.packetNumberLength).toBe(4)
    expect(header.packetNumber).toBe(2)
    expect(header.payloadOffset).toBe(29)
    expect(bytesToHex(initialPacket.subarray(header.payloadOffset))).toBe('aabbcc')
  })

  test('rejects truncated Initial payload', () => {
    expect(() =>
      parseQuicInitialPacketHeader(
        hexToBytes('c300000001088394c8f03e515708080001020304050607000700000002aabb'),
      ),
    ).toThrow('not enough bytes for QUIC Initial payload')
  })

  test('rejects Initial length smaller than packet number length', () => {
    expect(() =>
      parseQuicInitialPacketHeader(
        hexToBytes('c300000001088394c8f03e515708080001020304050607000300000002'),
      ),
    ).toThrow('QUIC Initial length smaller than packet number')
  })
})

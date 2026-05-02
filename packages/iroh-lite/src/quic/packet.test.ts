import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  QUIC_VERSION_1,
  QuicLongHeaderPacketType,
  nextExpectedQuicPacketNumber,
  parseQuicHandshakePacketHeader,
  parseQuicInitialPacketHeader,
  parseQuicLongHeader,
  recoverQuicPacketNumber,
  updateLargestReceivedQuicPacketNumber,
} from './packet'

const initialPacket = hexToBytes('c300000001088394c8f03e515708080001020304050607000700000002aabbcc')
const handshakePacket = hexToBytes('e200000001040102030405060708090a05aabbccddee')

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

describe('QUIC Handshake header parsing', () => {
  test('decodes Handshake length, packet number, and payload offset', () => {
    const header = parseQuicHandshakePacketHeader(handshakePacket)

    expect(header.packetType).toBe(QuicLongHeaderPacketType.Handshake)
    expect(header.length).toBe(5)
    expect(header.packetNumberLength).toBe(3)
    expect(header.packetNumber).toBe(0xaabbcc)
    expect(header.packetNumberOffset).toBe(17)
    expect(header.payloadOffset).toBe(20)
    expect(bytesToHex(handshakePacket.subarray(header.payloadOffset))).toBe('ddee')
  })

  test('rejects non-Handshake packets', () => {
    expect(() => parseQuicHandshakePacketHeader(initialPacket)).toThrow(
      'QUIC packet is not Handshake',
    )
  })

  test('rejects truncated Handshake payload', () => {
    expect(() =>
      parseQuicHandshakePacketHeader(hexToBytes('e200000001040102030405060708090a05aabbccdd')),
    ).toThrow('not enough bytes for QUIC Handshake payload')
  })

  test('rejects Handshake length smaller than packet number length', () => {
    expect(() =>
      parseQuicHandshakePacketHeader(hexToBytes('e200000001040102030405060708090a02aabbcc')),
    ).toThrow('QUIC Handshake length smaller than packet number')
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

describe('QUIC packet number recovery', () => {
  test('recovers the full packet number from the truncated packet number', () => {
    expect(recoverQuicPacketNumber(0x9b32, 2, 0xa82f30eb)).toBe(0xa82f9b32n)
  })

  test('selects the lower candidate near the half-window boundary', () => {
    expect(recoverQuicPacketNumber(0xff, 1, 0x10000)).toBe(0xffffn)
  })

  test('selects the higher candidate near the half-window boundary', () => {
    expect(recoverQuicPacketNumber(0x00, 1, 0xffff)).toBe(0x10000n)
  })

  test('allows recovery up to the QUIC maximum packet number', () => {
    expect(recoverQuicPacketNumber(0xff, 1, 0x3fffffffffffff80n)).toBe(0x3fffffffffffffffn)
  })

  test('rejects invalid recovery inputs', () => {
    expect(() => recoverQuicPacketNumber(0, 0, 0)).toThrow('QUIC packet number length out of range')
    expect(() => recoverQuicPacketNumber(0x100, 1, 0)).toThrow(
      'QUIC truncated packet number out of range',
    )
    expect(() => recoverQuicPacketNumber(0, 1, -1)).toThrow('QUIC packet number out of range')
  })

  test('derives the expected next packet number from the largest received packet number', () => {
    expect(nextExpectedQuicPacketNumber(null)).toBe(0n)
    expect(nextExpectedQuicPacketNumber(0x100n)).toBe(0x101n)
    expect(() => nextExpectedQuicPacketNumber(0x3fffffffffffffffn)).toThrow(
      'QUIC expected packet number out of range',
    )
  })

  test('updates largest received without ACK scheduling state', () => {
    let largestReceived: bigint | null = null
    largestReceived = updateLargestReceivedQuicPacketNumber(largestReceived, 0x100n)
    largestReceived = updateLargestReceivedQuicPacketNumber(largestReceived, 0xffn)
    largestReceived = updateLargestReceivedQuicPacketNumber(largestReceived, 0x101n)

    expect(largestReceived).toBe(0x101n)
    expect(nextExpectedQuicPacketNumber(largestReceived)).toBe(0x102n)
  })
})

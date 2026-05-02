import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  QUIC_VERSION_1,
  QuicLongHeaderPacketType,
  parseQuicHandshakePacketHeader,
  parseQuicInitialPacketHeader,
  parseQuicLongHeader,
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

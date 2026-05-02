import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc9001ClientInitialFrames,
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
  rfc9001ProtectedServerInitialPacket,
  rfc9001ServerInitialFrames,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import { parseQuicFrames } from './frame'
import { decryptQuicInitialPacket } from './initial'

describe('QUIC frame parsing', () => {
  test('parses CRYPTO and PADDING from client Initial payload vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const packet = decryptQuicInitialPacket(rfc9001ProtectedClientInitialPacket, keys.client)
    const result = parseQuicFrames(packet.payload)

    expect(result.endOffset).toBe(packet.payload.length)
    expect(result.frames).toHaveLength(2)
    const crypto = result.frames[0]
    const padding = result.frames[1]

    expect(crypto?.type).toBe('crypto')
    if (crypto?.type !== 'crypto') {
      throw new Error('expected CRYPTO frame')
    }
    expect(crypto.cryptoOffset).toBe(0)
    expect(crypto.offset).toBe(0)
    expect(crypto.endOffset).toBe(rfc9001ClientInitialFrames.length)
    expect(bytesToHex(crypto.data)).toBe(bytesToHex(rfc9001ClientInitialFrames.subarray(4)))

    expect(padding?.type).toBe('padding')
    if (padding?.type !== 'padding') {
      throw new Error('expected PADDING frame')
    }
    expect(padding.offset).toBe(rfc9001ClientInitialFrames.length)
    expect(padding.length).toBe(packet.payload.length - rfc9001ClientInitialFrames.length)
    expect(padding.endOffset).toBe(packet.payload.length)
  })

  test('parses ACK and CRYPTO from server Initial payload vector', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const packet = decryptQuicInitialPacket(rfc9001ProtectedServerInitialPacket, keys.server)
    const result = parseQuicFrames(packet.payload)

    expect(result.endOffset).toBe(packet.payload.length)
    expect(result.frames).toHaveLength(2)
    const ack = result.frames[0]
    const crypto = result.frames[1]

    expect(ack?.type).toBe('ack')
    if (ack?.type !== 'ack') {
      throw new Error('expected ACK frame')
    }
    expect(ack.largestAcknowledged).toBe(0)
    expect(ack.ackDelay).toBe(0)
    expect(ack.firstAckRange).toBe(0)
    expect(ack.ranges).toEqual([])
    expect(ack.offset).toBe(0)
    expect(ack.endOffset).toBe(5)

    expect(crypto?.type).toBe('crypto')
    if (crypto?.type !== 'crypto') {
      throw new Error('expected CRYPTO frame')
    }
    expect(crypto.cryptoOffset).toBe(0)
    expect(crypto.offset).toBe(5)
    expect(crypto.endOffset).toBe(rfc9001ServerInitialFrames.length)
    expect(bytesToHex(crypto.data)).toBe(bytesToHex(rfc9001ServerInitialFrames.subarray(9)))
  })

  test('parses ACK ranges and ECN counts', () => {
    const result = parseQuicFrames(hexToBytes('03140101050307000405'))

    expect(result.frames).toEqual([
      {
        type: 'ack-ecn',
        largestAcknowledged: 20,
        ackDelay: 1,
        firstAckRange: 5,
        ranges: [{ gap: 3, length: 7 }],
        ecnCounts: { ect0: 0, ect1: 4, ce: 5 },
        offset: 0,
        endOffset: 10,
      },
    ])
  })

  test('rejects unsupported frame type', () => {
    expect(() => parseQuicFrames(hexToBytes('01'))).toThrow('unsupported QUIC frame type 0x1')
  })

  test('rejects unsupported multi-byte frame type', () => {
    expect(() => parseQuicFrames(hexToBytes('4040'))).toThrow('unsupported QUIC frame type 0x40')
  })

  test('rejects non-shortest frame type encoding', () => {
    expect(() => parseQuicFrames(hexToBytes('4006'))).toThrow(
      'QUIC frame type must use shortest encoding',
    )
  })

  test('rejects truncated CRYPTO frame data', () => {
    expect(() => parseQuicFrames(hexToBytes('060005aabbcc'))).toThrow(
      'not enough bytes for QUIC CRYPTO frame data',
    )
  })

  test('rejects ACK first range underflow', () => {
    expect(() => parseQuicFrames(hexToBytes('0200000001'))).toThrow(
      'QUIC ACK first range exceeds largest acknowledged',
    )
  })

  test('rejects ACK gap underflow', () => {
    expect(() => parseQuicFrames(hexToBytes('020a0001050400'))).toThrow(
      'QUIC ACK range gap underflows packet number',
    )
  })

  test('rejects ACK range length underflow', () => {
    expect(() => parseQuicFrames(hexToBytes('020a0001050301'))).toThrow(
      'QUIC ACK range length underflows packet number',
    )
  })
})

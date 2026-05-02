import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc9001ClientInitialFrames,
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
  rfc9001ProtectedServerInitialPacket,
  rfc9001ServerInitialFrames,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import {
  encodeQuicAckFrame,
  encodeQuicApplicationConnectionCloseFrame,
  encodeQuicCryptoFrame,
  encodeQuicMaxDataFrame,
  encodeQuicMaxStreamDataFrame,
  encodeQuicPaddingFrame,
  encodeQuicPingFrame,
  encodeQuicStreamFrame,
  encodeQuicTransportConnectionCloseFrame,
  parseQuicFrames,
} from './frame'
import { decryptQuicInitialPacket } from './initial'
import { QUIC_MAX_PACKET_NUMBER } from './packet'

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
    expect(ack.largestAcknowledged).toBe(0n)
    expect(ack.ackDelay).toBe(0)
    expect(ack.firstAckRange).toBe(0n)
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
        largestAcknowledged: 20n,
        ackDelay: 1,
        firstAckRange: 5n,
        ranges: [{ gap: 3n, length: 7n }],
        ecnCounts: { ect0: 0, ect1: 4, ce: 5 },
        offset: 0,
        endOffset: 10,
      },
    ])
  })

  test('parses 1-RTT PING and STREAM frame envelopes', () => {
    const data = hexToBytes('6869')
    const result = parseQuicFrames(
      concatBytes([encodeQuicPingFrame(), encodeQuicStreamFrame(4, 0x400, data, true)]),
    )

    expect(result.frames).toHaveLength(2)
    expect(result.frames[0]).toEqual({ type: 'ping', offset: 0, endOffset: 1 })
    expect(result.frames[1]).toEqual({
      type: 'stream',
      streamId: 4,
      streamOffset: 0x400,
      data,
      fin: true,
      offset: 1,
      endOffset: result.endOffset,
    })
  })

  test('parses STREAM frames without length as the remaining payload', () => {
    const result = parseQuicFrames(hexToBytes('08046869'))

    expect(result.frames).toEqual([
      {
        type: 'stream',
        streamId: 4,
        streamOffset: 0,
        data: hexToBytes('6869'),
        fin: false,
        offset: 0,
        endOffset: 4,
      },
    ])
  })

  test('parses flow-control frame envelopes', () => {
    const result = parseQuicFrames(
      concatBytes([encodeQuicMaxDataFrame(0x4000), encodeQuicMaxStreamDataFrame(7, 0x8000)]),
    )

    expect(result.frames).toEqual([
      { type: 'max-data', maximumData: 0x4000, offset: 0, endOffset: 5 },
      {
        type: 'max-stream-data',
        streamId: 7,
        maximumStreamData: 0x8000,
        offset: 5,
        endOffset: 11,
      },
    ])
  })

  test('parses transport and application CONNECTION_CLOSE frames', () => {
    const transport = encodeQuicTransportConnectionCloseFrame(0x10, 0x06, hexToBytes('626164'))
    const application = encodeQuicApplicationConnectionCloseFrame(0x100, hexToBytes('6f6b'))

    expect(parseQuicFrames(transport).frames).toEqual([
      {
        type: 'connection-close',
        errorSpace: 'transport',
        errorCode: 0x10,
        frameType: 0x06,
        reasonPhrase: hexToBytes('626164'),
        offset: 0,
        endOffset: transport.length,
      },
    ])
    expect(parseQuicFrames(application).frames).toEqual([
      {
        type: 'connection-close',
        errorSpace: 'application',
        errorCode: 0x100,
        frameType: null,
        reasonPhrase: hexToBytes('6f6b'),
        offset: 0,
        endOffset: application.length,
      },
    ])
  })

  test('encodes 1-RTT frame envelopes to exact bytes', () => {
    expect(bytesToHex(encodeQuicPingFrame())).toBe('01')
    expect(bytesToHex(encodeQuicCryptoFrame(0x40, hexToBytes('aabbcc')))).toBe('06404003aabbcc')
    expect(bytesToHex(encodeQuicStreamFrame(4, 0x400, hexToBytes('6869'), true))).toBe(
      '0f044400026869',
    )
    expect(bytesToHex(encodeQuicMaxDataFrame(0x4000))).toBe('1080004000')
    expect(bytesToHex(encodeQuicMaxStreamDataFrame(7, 0x8000))).toBe('110780008000')
    expect(
      bytesToHex(encodeQuicTransportConnectionCloseFrame(0x10, 0x06, hexToBytes('626164'))),
    ).toBe('1c100603626164')
    expect(bytesToHex(encodeQuicApplicationConnectionCloseFrame(0x100, hexToBytes('6f6b')))).toBe(
      '1d4100026f6b',
    )
  })

  test('encodes ACK for a single received packet', () => {
    const encoded = encodeQuicAckFrame([7])

    expect(bytesToHex(encoded)).toBe('0207000000')
    expect(parseQuicFrames(encoded).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 7n,
        ackDelay: 0,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: encoded.length,
      },
    ])
  })

  test('encodes contiguous ACK packets as one range', () => {
    const encoded = encodeQuicAckFrame([5, 6, 7])

    expect(bytesToHex(encoded)).toBe('0207000002')
    expect(parseQuicFrames(encoded).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 7n,
        ackDelay: 0,
        firstAckRange: 2n,
        ranges: [],
        offset: 0,
        endOffset: encoded.length,
      },
    ])
  })

  test('encodes sparse ACK packets with gaps and extra ranges', () => {
    const encoded = encodeQuicAckFrame([1, 2, 5, 8, 9, 10])

    expect(bytesToHex(encoded)).toBe('020a00020201000101')
    expect(parseQuicFrames(encoded).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 10n,
        ackDelay: 0,
        firstAckRange: 2n,
        ranges: [
          { gap: 1n, length: 0n },
          { gap: 1n, length: 1n },
        ],
        offset: 0,
        endOffset: encoded.length,
      },
    ])
  })

  test('sorts and deduplicates ACK packet numbers before encoding', () => {
    const encoded = encodeQuicAckFrame([10n, 7, 8, 10, 9, 7])

    expect(parseQuicFrames(encoded).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 10n,
        ackDelay: 0,
        firstAckRange: 3n,
        ranges: [],
        offset: 0,
        endOffset: encoded.length,
      },
    ])
  })

  test('encodes ACK packet numbers up to the QUIC maximum', () => {
    const encoded = encodeQuicAckFrame([QUIC_MAX_PACKET_NUMBER])

    expect(parseQuicFrames(encoded).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: QUIC_MAX_PACKET_NUMBER,
        ackDelay: 0,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: encoded.length,
      },
    ])
  })

  test('rejects unsupported frame type', () => {
    expect(() => parseQuicFrames(hexToBytes('04'))).toThrow('unsupported QUIC frame type 0x4')
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

  test('rejects truncated STREAM frame data', () => {
    expect(() => parseQuicFrames(hexToBytes('0a0105aabbcc'))).toThrow(
      'not enough bytes for QUIC STREAM frame data',
    )
  })

  test('rejects truncated CONNECTION_CLOSE reason', () => {
    expect(() => parseQuicFrames(hexToBytes('1c1006036261'))).toThrow(
      'not enough bytes for QUIC CONNECTION_CLOSE reason',
    )
  })

  test('encodes PADDING frames with validated length', () => {
    expect(encodeQuicPaddingFrame(3)).toEqual(hexToBytes('000000'))
    expect(() => encodeQuicPaddingFrame(-1)).toThrow('QUIC PADDING length out of range')
  })

  test('rejects invalid ACK packet numbers', () => {
    expect(() => encodeQuicAckFrame([])).toThrow('QUIC ACK requires at least one packet number')
    expect(() => encodeQuicAckFrame([-1])).toThrow('QUIC packet number out of range')
    expect(() => encodeQuicAckFrame([QUIC_MAX_PACKET_NUMBER + 1n])).toThrow(
      'QUIC packet number out of range',
    )
    expect(() => encodeQuicAckFrame([1], -1)).toThrow('QUIC ACK delay out of range')
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

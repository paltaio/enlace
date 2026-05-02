import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex } from '../testing/hex'
import {
  QuicAckReceiveTracker,
  receiveQuicOneRttFrames,
  receiveQuicOneRttPlaintextFrames,
} from './ack'
import {
  encodeQuicAckFrame,
  encodeQuicApplicationConnectionCloseFrame,
  encodeQuicPaddingFrame,
  encodeQuicPingFrame,
  encodeQuicStreamFrame,
  parseQuicFrames,
} from './frame'
import { QUIC_MAX_PACKET_NUMBER } from './packet'

describe('QUIC ACK receive tracking', () => {
  test('records one packet and emits a parser-compatible ACK', () => {
    const tracker = new QuicAckReceiveTracker()
    tracker.record(7)
    const ackFrame = tracker.ackFrame()

    expect(tracker.snapshot()).toEqual({
      receivedPacketNumbers: [7n],
      largestReceivedPacketNumber: 7n,
    })
    expect(parseQuicFrames(ackFrame).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 7n,
        ackDelay: 0,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: ackFrame.length,
      },
    ])
  })

  test('records contiguous packets as one ACK range', () => {
    const tracker = new QuicAckReceiveTracker()
    tracker.record(5)
    tracker.record(7)
    tracker.record(6)
    const ackFrame = tracker.ackFrame()

    expect(tracker.snapshot()).toEqual({
      receivedPacketNumbers: [7n, 6n, 5n],
      largestReceivedPacketNumber: 7n,
    })
    expect(parseQuicFrames(ackFrame).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 7n,
        ackDelay: 0,
        firstAckRange: 2n,
        ranges: [],
        offset: 0,
        endOffset: ackFrame.length,
      },
    ])
  })

  test('records sparse packets as ACK gap and range entries', () => {
    const tracker = new QuicAckReceiveTracker()
    for (const packetNumber of [1, 2, 5, 8, 9, 10]) {
      tracker.record(packetNumber)
    }
    const ackFrame = tracker.ackFrame()

    expect(tracker.snapshot()).toEqual({
      receivedPacketNumbers: [10n, 9n, 8n, 5n, 2n, 1n],
      largestReceivedPacketNumber: 10n,
    })
    expect(parseQuicFrames(ackFrame).frames).toEqual([
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
        endOffset: ackFrame.length,
      },
    ])
  })

  test('duplicate receives do not change ACK output', () => {
    const tracker = new QuicAckReceiveTracker()
    tracker.record(10)
    tracker.record(8)
    tracker.record(9)
    const firstAckFrame = tracker.ackFrame()

    tracker.record(10)
    tracker.record(8)

    expect(bytesToHex(tracker.ackFrame())).toBe(bytesToHex(firstAckFrame))
    expect(tracker.snapshot()).toEqual({
      receivedPacketNumbers: [10n, 9n, 8n],
      largestReceivedPacketNumber: 10n,
    })
  })

  test('rejects invalid packet numbers', () => {
    const tracker = new QuicAckReceiveTracker()

    expect(() => tracker.record(-1)).toThrow('QUIC packet number out of range')
    expect(() => tracker.record(QUIC_MAX_PACKET_NUMBER + 1n)).toThrow(
      'QUIC packet number out of range',
    )
  })

  test('rejects ACK emission before any packet is recorded', () => {
    const tracker = new QuicAckReceiveTracker()

    expect(tracker.snapshot()).toEqual({
      receivedPacketNumbers: [],
      largestReceivedPacketNumber: null,
    })
    expect(() => tracker.ackFrame()).toThrow('QUIC ACK requires at least one packet number')
  })
})

describe('QUIC 1-RTT plaintext ACK handling', () => {
  test('records PING packets and emits a parser-compatible ACK', () => {
    const tracker = new QuicAckReceiveTracker()
    const result = receiveQuicOneRttPlaintextFrames(12, encodeQuicPingFrame(), tracker)
    const ackFrame = result.ackFrame
    if (ackFrame === null) {
      throw new Error('expected ACK frame')
    }

    expect(result.ackEliciting).toBe(true)
    expect(result.ackSnapshot).toEqual({
      receivedPacketNumbers: [12n],
      largestReceivedPacketNumber: 12n,
    })
    expect(result.frames).toEqual([{ type: 'ping', offset: 0, endOffset: 1 }])
    expect(parseQuicFrames(ackFrame).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 12n,
        ackDelay: 0,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: 5,
      },
    ])
  })

  test('does not record ACK-only packets', () => {
    const tracker = new QuicAckReceiveTracker()
    const ackOnly = encodeQuicAckFrame([3])
    const result = receiveQuicOneRttPlaintextFrames(13, ackOnly, tracker)

    expect(result.ackEliciting).toBe(false)
    expect(result.ackFrame).toBeNull()
    expect(result.ackSnapshot).toEqual({
      receivedPacketNumbers: [],
      largestReceivedPacketNumber: null,
    })
    expect(result.frames[0]?.type).toBe('ack')
  })

  test('does not record PADDING-only packets', () => {
    const tracker = new QuicAckReceiveTracker()
    const result = receiveQuicOneRttPlaintextFrames(14, encodeQuicPaddingFrame(3), tracker)

    expect(result.ackEliciting).toBe(false)
    expect(result.ackFrame).toBeNull()
    expect(result.ackSnapshot).toEqual({
      receivedPacketNumbers: [],
      largestReceivedPacketNumber: null,
    })
    expect(result.frames).toEqual([{ type: 'padding', length: 3, offset: 0, endOffset: 3 }])
  })

  test('classifies STREAM frames as ack-eliciting without stream semantics', () => {
    const tracker = new QuicAckReceiveTracker()
    const payload = encodeQuicStreamFrame(4, 0, new Uint8Array([0x68, 0x69]), false)
    const result = receiveQuicOneRttPlaintextFrames(15, payload, tracker)

    expect(result.ackEliciting).toBe(true)
    expect(result.ackSnapshot.largestReceivedPacketNumber).toBe(15n)
    expect(result.ackFrame).not.toBeNull()
    expect(result.frames[0]?.type).toBe('stream')
  })

  test('handles already parsed frame envelopes', () => {
    const tracker = new QuicAckReceiveTracker()
    const frames = parseQuicFrames(
      concatBytes([encodeQuicPaddingFrame(1), encodeQuicPingFrame()]),
    ).frames
    const result = receiveQuicOneRttFrames(18, frames, tracker, 3)
    const ackFrame = result.ackFrame
    if (ackFrame === null) {
      throw new Error('expected ACK frame')
    }

    expect(result.frames).toBe(frames)
    expect(result.ackEliciting).toBe(true)
    expect(result.ackSnapshot.largestReceivedPacketNumber).toBe(18n)
    expect(parseQuicFrames(ackFrame).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 18n,
        ackDelay: 3,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: 5,
      },
    ])
  })

  test('treats CONNECTION_CLOSE as non-ack-eliciting', () => {
    const tracker = new QuicAckReceiveTracker()
    const payload = concatBytes([
      encodeQuicPaddingFrame(1),
      encodeQuicApplicationConnectionCloseFrame(0, new Uint8Array()),
    ])
    const result = receiveQuicOneRttPlaintextFrames(16, payload, tracker)

    expect(result.ackEliciting).toBe(false)
    expect(result.ackFrame).toBeNull()
    expect(result.ackSnapshot.receivedPacketNumbers).toEqual([])
    expect(result.frames.map((frame) => frame.type)).toEqual(['padding', 'connection-close'])
  })

  test('rejects malformed frame bytes through the parser', () => {
    const tracker = new QuicAckReceiveTracker()

    expect(() =>
      receiveQuicOneRttPlaintextFrames(17, new Uint8Array([0x0a, 0x01, 0x05, 0xaa]), tracker),
    ).toThrow('not enough bytes for QUIC STREAM frame data')
    expect(tracker.snapshot().receivedPacketNumbers).toEqual([])
  })
})

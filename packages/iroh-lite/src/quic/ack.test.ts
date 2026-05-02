import { describe, expect, test } from 'bun:test'

import { bytesToHex } from '../testing/hex'
import { QuicAckReceiveTracker } from './ack'
import { parseQuicFrames } from './frame'
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

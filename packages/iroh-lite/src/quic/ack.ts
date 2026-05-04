import { encodeQuicAckFrame, parseQuicFrames, type QuicFrame } from './frame'
import { quicPacketNumberToBigInt } from './packet'

export interface QuicAckReceiveSnapshot {
  readonly receivedPacketNumbers: readonly bigint[]
  readonly largestReceivedPacketNumber: bigint | null
}

export interface QuicOneRttFrameReceiveResult {
  readonly frames: readonly QuicFrame[]
  readonly ackEliciting: boolean
  readonly ackSnapshot: QuicAckReceiveSnapshot
  readonly ackFrame: Uint8Array | null
}

export class QuicAckReceiveTracker {
  readonly #receivedPacketNumbers = new Set<bigint>()

  record(packetNumber: number | bigint): void {
    this.#receivedPacketNumbers.add(quicPacketNumberToBigInt(packetNumber))
  }

  snapshot(): QuicAckReceiveSnapshot {
    const receivedPacketNumbers = this.receivedPacketNumbers()
    return {
      receivedPacketNumbers,
      largestReceivedPacketNumber: receivedPacketNumbers[0] ?? null,
    }
  }

  ackFrame(ackDelay: number = 0): Uint8Array {
    return encodeQuicAckFrame(this.receivedPacketNumbers(), ackDelay)
  }

  private receivedPacketNumbers(): readonly bigint[] {
    return Array.from(this.#receivedPacketNumbers).sort((left, right) => {
      if (left > right) {
        return -1
      }
      if (left < right) {
        return 1
      }
      return 0
    })
  }
}

function isQuicAckElicitingFrame(frame: QuicFrame): boolean {
  switch (frame.type) {
    case 'padding':
    case 'ack':
    case 'ack-ecn':
    case 'connection-close':
      return false
    case 'ping':
    case 'crypto':
    case 'stream':
    case 'max-data':
    case 'max-stream-data':
    case 'new-connection-id':
    case 'handshake-done':
      return true
  }
}

export function receiveQuicOneRttPlaintextFrames(
  packetNumber: number | bigint,
  frameBytes: Uint8Array,
  tracker: QuicAckReceiveTracker,
  ackDelay: number = 0,
): QuicOneRttFrameReceiveResult {
  return receiveQuicOneRttFrames(
    packetNumber,
    parseQuicFrames(frameBytes).frames,
    tracker,
    ackDelay,
  )
}

export function receiveQuicOneRttFrames(
  packetNumber: number | bigint,
  frames: readonly QuicFrame[],
  tracker: QuicAckReceiveTracker,
  ackDelay: number = 0,
): QuicOneRttFrameReceiveResult {
  const ackEliciting = frames.some(isQuicAckElicitingFrame)

  if (!ackEliciting) {
    return {
      frames,
      ackEliciting,
      ackSnapshot: tracker.snapshot(),
      ackFrame: null,
    }
  }

  tracker.record(packetNumber)
  return {
    frames,
    ackEliciting,
    ackSnapshot: tracker.snapshot(),
    ackFrame: tracker.ackFrame(ackDelay),
  }
}

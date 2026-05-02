import { encodeQuicAckFrame } from './frame'
import { quicPacketNumberToBigInt } from './packet'

export interface QuicAckReceiveSnapshot {
  readonly receivedPacketNumbers: readonly bigint[]
  readonly largestReceivedPacketNumber: bigint | null
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

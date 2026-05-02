import { copyBytes, readU8 } from '../bytes'
import { decodeVarIntNumber } from '../varint'

export const QuicFrameType = {
  Padding: 0x00,
  Ack: 0x02,
  AckEcn: 0x03,
  Crypto: 0x06,
} as const

export type QuicFrame = QuicPaddingFrame | QuicAckFrame | QuicAckEcnFrame | QuicCryptoFrame

export interface QuicPaddingFrame {
  readonly type: 'padding'
  readonly length: number
  readonly offset: number
  readonly endOffset: number
}

export interface QuicAckRange {
  readonly gap: number
  readonly length: number
}

export interface QuicAckEcnCounts {
  readonly ect0: number
  readonly ect1: number
  readonly ce: number
}

export interface QuicAckFrame {
  readonly type: 'ack'
  readonly largestAcknowledged: number
  readonly ackDelay: number
  readonly firstAckRange: number
  readonly ranges: readonly QuicAckRange[]
  readonly offset: number
  readonly endOffset: number
}

export interface QuicAckEcnFrame extends Omit<QuicAckFrame, 'type'> {
  readonly type: 'ack-ecn'
  readonly ecnCounts: QuicAckEcnCounts
}

export interface QuicCryptoFrame {
  readonly type: 'crypto'
  readonly cryptoOffset: number
  readonly data: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export interface QuicFramesParseResult {
  readonly frames: readonly QuicFrame[]
  readonly endOffset: number
}

export function parseQuicFrames(bytes: Uint8Array, offset = 0): QuicFramesParseResult {
  validateOffset(bytes, offset)
  const frames: QuicFrame[] = []
  let pos = offset

  while (pos < bytes.length) {
    const frameType = readQuicFrameType(bytes, pos)
    if (frameType === QuicFrameType.Padding) {
      const frame = parsePaddingFrame(bytes, pos)
      frames.push(frame)
      pos = frame.endOffset
      continue
    }
    if (frameType === QuicFrameType.Crypto) {
      const frame = parseCryptoFrame(bytes, pos)
      frames.push(frame)
      pos = frame.endOffset
      continue
    }
    if (frameType === QuicFrameType.Ack || frameType === QuicFrameType.AckEcn) {
      const frame = parseAckFrame(bytes, pos, frameType)
      frames.push(frame)
      pos = frame.endOffset
      continue
    }
    throw new RangeError(`unsupported QUIC frame type 0x${frameType.toString(16)}`)
  }

  return { frames, endOffset: pos }
}

function parsePaddingFrame(bytes: Uint8Array, offset: number): QuicPaddingFrame {
  let pos = offset
  while (pos < bytes.length && readU8(bytes, pos) === QuicFrameType.Padding) {
    pos += 1
  }

  return {
    type: 'padding',
    length: pos - offset,
    offset,
    endOffset: pos,
  }
}

function parseCryptoFrame(bytes: Uint8Array, offset: number): QuicCryptoFrame {
  let pos = offset + 1
  const cryptoOffset = decodeVarIntNumber(bytes, pos)
  pos += cryptoOffset.bytesRead
  const length = decodeVarIntNumber(bytes, pos)
  pos += length.bytesRead
  if (bytes.length - pos < length.value) {
    throw new RangeError('not enough bytes for QUIC CRYPTO frame data')
  }
  const endOffset = pos + length.value

  return {
    type: 'crypto',
    cryptoOffset: cryptoOffset.value,
    data: copyBytes(bytes.subarray(pos, endOffset)),
    offset,
    endOffset,
  }
}

function parseAckFrame(
  bytes: Uint8Array,
  offset: number,
  frameType: typeof QuicFrameType.Ack | typeof QuicFrameType.AckEcn,
): QuicAckFrame | QuicAckEcnFrame {
  let pos = offset + 1
  const largestAcknowledged = decodeVarIntNumber(bytes, pos)
  pos += largestAcknowledged.bytesRead
  const ackDelay = decodeVarIntNumber(bytes, pos)
  pos += ackDelay.bytesRead
  const ackRangeCount = decodeVarIntNumber(bytes, pos)
  pos += ackRangeCount.bytesRead
  const firstAckRange = decodeVarIntNumber(bytes, pos)
  pos += firstAckRange.bytesRead
  const ranges: QuicAckRange[] = []
  validateFirstAckRange(largestAcknowledged.value, firstAckRange.value)
  let smallestAcknowledged = largestAcknowledged.value - firstAckRange.value

  for (let index = 0; index < ackRangeCount.value; index += 1) {
    const gap = decodeVarIntNumber(bytes, pos)
    pos += gap.bytesRead
    const length = decodeVarIntNumber(bytes, pos)
    pos += length.bytesRead
    smallestAcknowledged = validateAckRange(smallestAcknowledged, gap.value, length.value)
    ranges.push({ gap: gap.value, length: length.value })
  }

  const base = {
    largestAcknowledged: largestAcknowledged.value,
    ackDelay: ackDelay.value,
    firstAckRange: firstAckRange.value,
    ranges,
    offset,
  }

  if (frameType === QuicFrameType.Ack) {
    return {
      type: 'ack',
      ...base,
      endOffset: pos,
    }
  }

  const ecnCounts = parseAckEcnCounts(bytes, pos)
  return {
    type: 'ack-ecn',
    ...base,
    ecnCounts: ecnCounts.value,
    endOffset: ecnCounts.endOffset,
  }
}

function validateFirstAckRange(largestAcknowledged: number, firstAckRange: number): void {
  if (firstAckRange > largestAcknowledged) {
    throw new RangeError('QUIC ACK first range exceeds largest acknowledged')
  }
}

function validateAckRange(
  previousSmallestAcknowledged: number,
  gap: number,
  length: number,
): number {
  if (previousSmallestAcknowledged < gap + 2) {
    throw new RangeError('QUIC ACK range gap underflows packet number')
  }
  const largestAcknowledged = previousSmallestAcknowledged - gap - 2
  if (length > largestAcknowledged) {
    throw new RangeError('QUIC ACK range length underflows packet number')
  }
  return largestAcknowledged - length
}

function parseAckEcnCounts(
  bytes: Uint8Array,
  offset: number,
): {
  readonly value: QuicAckEcnCounts
  readonly endOffset: number
} {
  let pos = offset
  const ect0 = decodeVarIntNumber(bytes, pos)
  pos += ect0.bytesRead
  const ect1 = decodeVarIntNumber(bytes, pos)
  pos += ect1.bytesRead
  const ce = decodeVarIntNumber(bytes, pos)
  pos += ce.bytesRead

  return {
    value: {
      ect0: ect0.value,
      ect1: ect1.value,
      ce: ce.value,
    },
    endOffset: pos,
  }
}

function readQuicFrameType(bytes: Uint8Array, offset: number): number {
  const first = readU8(bytes, offset)
  if ((first & 0xc0) === 0) {
    return first
  }

  const decoded = decodeVarIntNumber(bytes, offset)
  if (decoded.value <= 0x3f) {
    throw new RangeError('QUIC frame type must use shortest encoding')
  }
  return decoded.value
}

function validateOffset(bytes: Uint8Array, offset: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > bytes.length) {
    throw new RangeError('QUIC frame offset out of range')
  }
}

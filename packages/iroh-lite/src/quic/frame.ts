import { concatBytes, copyBytes, readU8 } from '../bytes'
import { decodeVarInt, decodeVarIntNumber, encodeVarInt } from '../varint'
import { quicPacketNumberToBigInt } from './packet'

export const QuicFrameType = {
  Padding: 0x00,
  Ping: 0x01,
  Ack: 0x02,
  AckEcn: 0x03,
  Crypto: 0x06,
  StreamBase: 0x08,
  MaxData: 0x10,
  MaxStreamData: 0x11,
  ConnectionCloseTransport: 0x1c,
  ConnectionCloseApplication: 0x1d,
} as const

export type QuicFrame =
  | QuicPaddingFrame
  | QuicPingFrame
  | QuicAckFrame
  | QuicAckEcnFrame
  | QuicCryptoFrame
  | QuicStreamFrame
  | QuicMaxDataFrame
  | QuicMaxStreamDataFrame
  | QuicConnectionCloseFrame

export interface QuicPaddingFrame {
  readonly type: 'padding'
  readonly length: number
  readonly offset: number
  readonly endOffset: number
}

export interface QuicPingFrame {
  readonly type: 'ping'
  readonly offset: number
  readonly endOffset: number
}

export interface QuicAckRange {
  readonly gap: bigint
  readonly length: bigint
}

export interface QuicAckEcnCounts {
  readonly ect0: number
  readonly ect1: number
  readonly ce: number
}

export interface QuicAckFrame {
  readonly type: 'ack'
  readonly largestAcknowledged: bigint
  readonly ackDelay: number
  readonly firstAckRange: bigint
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

export interface QuicStreamFrame {
  readonly type: 'stream'
  readonly streamId: number
  readonly streamOffset: number
  readonly data: Uint8Array
  readonly fin: boolean
  readonly offset: number
  readonly endOffset: number
}

export interface QuicMaxDataFrame {
  readonly type: 'max-data'
  readonly maximumData: number
  readonly offset: number
  readonly endOffset: number
}

export interface QuicMaxStreamDataFrame {
  readonly type: 'max-stream-data'
  readonly streamId: number
  readonly maximumStreamData: number
  readonly offset: number
  readonly endOffset: number
}

export type QuicConnectionCloseFrame =
  | QuicTransportConnectionCloseFrame
  | QuicApplicationConnectionCloseFrame

export interface QuicTransportConnectionCloseFrame {
  readonly type: 'connection-close'
  readonly errorSpace: 'transport'
  readonly errorCode: number
  readonly frameType: number
  readonly reasonPhrase: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export interface QuicApplicationConnectionCloseFrame {
  readonly type: 'connection-close'
  readonly errorSpace: 'application'
  readonly errorCode: number
  readonly frameType: null
  readonly reasonPhrase: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export interface QuicFramesParseResult {
  readonly frames: readonly QuicFrame[]
  readonly endOffset: number
}

interface QuicAckPacketRange {
  readonly smallest: bigint
  readonly largest: bigint
}

export function encodeQuicPaddingFrame(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError('QUIC PADDING length out of range')
  }
  return new Uint8Array(length)
}

export function encodeQuicPingFrame(): Uint8Array {
  return new Uint8Array([QuicFrameType.Ping])
}

export function encodeQuicAckFrame(
  receivedPacketNumbers: readonly (number | bigint)[],
  ackDelay = 0,
): Uint8Array {
  const ranges = buildAckPacketRanges(receivedPacketNumbers)
  if (ranges.length === 0) {
    throw new RangeError('QUIC ACK requires at least one packet number')
  }
  if (!Number.isSafeInteger(ackDelay) || ackDelay < 0) {
    throw new RangeError('QUIC ACK delay out of range')
  }

  const firstRange = ranges[0]
  if (firstRange === undefined) {
    throw new RangeError('QUIC ACK requires at least one packet number')
  }

  const fields = [
    new Uint8Array([QuicFrameType.Ack]),
    encodeVarInt(firstRange.largest),
    encodeVarInt(ackDelay),
    encodeVarInt(ranges.length - 1),
    encodeVarInt(firstRange.largest - firstRange.smallest),
  ]

  let previousSmallest = firstRange.smallest
  for (const range of ranges.slice(1)) {
    fields.push(encodeVarInt(previousSmallest - range.largest - 2n))
    fields.push(encodeVarInt(range.largest - range.smallest))
    previousSmallest = range.smallest
  }

  return concatBytes(fields)
}

export function encodeQuicCryptoFrame(cryptoOffset: number, data: Uint8Array): Uint8Array {
  return concatBytes([
    new Uint8Array([QuicFrameType.Crypto]),
    encodeVarInt(cryptoOffset),
    encodeVarInt(data.length),
    data,
  ])
}

export function encodeQuicStreamFrame(
  streamId: number,
  streamOffset: number,
  data: Uint8Array,
  fin: boolean,
): Uint8Array {
  const hasOffset = streamOffset !== 0
  const frameType = QuicFrameType.StreamBase | (hasOffset ? 0x04 : 0) | 0x02 | (fin ? 0x01 : 0)
  return concatBytes([
    new Uint8Array([frameType]),
    encodeVarInt(streamId),
    ...(hasOffset ? [encodeVarInt(streamOffset)] : []),
    encodeVarInt(data.length),
    data,
  ])
}

export function encodeQuicMaxDataFrame(maximumData: number): Uint8Array {
  return concatBytes([new Uint8Array([QuicFrameType.MaxData]), encodeVarInt(maximumData)])
}

export function encodeQuicMaxStreamDataFrame(
  streamId: number,
  maximumStreamData: number,
): Uint8Array {
  return concatBytes([
    new Uint8Array([QuicFrameType.MaxStreamData]),
    encodeVarInt(streamId),
    encodeVarInt(maximumStreamData),
  ])
}

export function encodeQuicTransportConnectionCloseFrame(
  errorCode: number,
  frameType: number,
  reasonPhrase: Uint8Array,
): Uint8Array {
  return concatBytes([
    new Uint8Array([QuicFrameType.ConnectionCloseTransport]),
    encodeVarInt(errorCode),
    encodeVarInt(frameType),
    encodeVarInt(reasonPhrase.length),
    reasonPhrase,
  ])
}

export function encodeQuicApplicationConnectionCloseFrame(
  errorCode: number,
  reasonPhrase: Uint8Array,
): Uint8Array {
  return concatBytes([
    new Uint8Array([QuicFrameType.ConnectionCloseApplication]),
    encodeVarInt(errorCode),
    encodeVarInt(reasonPhrase.length),
    reasonPhrase,
  ])
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
    if (frameType === QuicFrameType.Ping) {
      const frame = parsePingFrame(pos)
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
    if (isStreamFrameType(frameType)) {
      const frame = parseStreamFrame(bytes, pos, frameType)
      frames.push(frame)
      pos = frame.endOffset
      continue
    }
    if (frameType === QuicFrameType.MaxData) {
      const frame = parseMaxDataFrame(bytes, pos)
      frames.push(frame)
      pos = frame.endOffset
      continue
    }
    if (frameType === QuicFrameType.MaxStreamData) {
      const frame = parseMaxStreamDataFrame(bytes, pos)
      frames.push(frame)
      pos = frame.endOffset
      continue
    }
    if (
      frameType === QuicFrameType.ConnectionCloseTransport ||
      frameType === QuicFrameType.ConnectionCloseApplication
    ) {
      const frame = parseConnectionCloseFrame(bytes, pos, frameType)
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

function parsePingFrame(offset: number): QuicPingFrame {
  return {
    type: 'ping',
    offset,
    endOffset: offset + 1,
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
  const largestAcknowledged = decodeVarInt(bytes, pos)
  pos += largestAcknowledged.bytesRead
  const ackDelay = decodeVarIntNumber(bytes, pos)
  pos += ackDelay.bytesRead
  const ackRangeCount = decodeVarIntNumber(bytes, pos)
  pos += ackRangeCount.bytesRead
  const firstAckRange = decodeVarInt(bytes, pos)
  pos += firstAckRange.bytesRead
  const ranges: QuicAckRange[] = []
  validateFirstAckRange(largestAcknowledged.value, firstAckRange.value)
  let smallestAcknowledged = largestAcknowledged.value - firstAckRange.value

  for (let index = 0; index < ackRangeCount.value; index += 1) {
    const gap = decodeVarInt(bytes, pos)
    pos += gap.bytesRead
    const length = decodeVarInt(bytes, pos)
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

function parseStreamFrame(bytes: Uint8Array, offset: number, frameType: number): QuicStreamFrame {
  let pos = offset + 1
  const streamId = decodeVarIntNumber(bytes, pos)
  pos += streamId.bytesRead
  let streamOffset = 0
  if ((frameType & 0x04) !== 0) {
    const decodedOffset = decodeVarIntNumber(bytes, pos)
    pos += decodedOffset.bytesRead
    streamOffset = decodedOffset.value
  }

  let dataLength = bytes.length - pos
  if ((frameType & 0x02) !== 0) {
    const decodedLength = decodeVarIntNumber(bytes, pos)
    pos += decodedLength.bytesRead
    dataLength = decodedLength.value
  }
  if (bytes.length - pos < dataLength) {
    throw new RangeError('not enough bytes for QUIC STREAM frame data')
  }
  const endOffset = pos + dataLength

  return {
    type: 'stream',
    streamId: streamId.value,
    streamOffset,
    data: copyBytes(bytes.subarray(pos, endOffset)),
    fin: (frameType & 0x01) !== 0,
    offset,
    endOffset,
  }
}

function parseMaxDataFrame(bytes: Uint8Array, offset: number): QuicMaxDataFrame {
  const maximumData = decodeVarIntNumber(bytes, offset + 1)
  return {
    type: 'max-data',
    maximumData: maximumData.value,
    offset,
    endOffset: offset + 1 + maximumData.bytesRead,
  }
}

function parseMaxStreamDataFrame(bytes: Uint8Array, offset: number): QuicMaxStreamDataFrame {
  let pos = offset + 1
  const streamId = decodeVarIntNumber(bytes, pos)
  pos += streamId.bytesRead
  const maximumStreamData = decodeVarIntNumber(bytes, pos)
  pos += maximumStreamData.bytesRead

  return {
    type: 'max-stream-data',
    streamId: streamId.value,
    maximumStreamData: maximumStreamData.value,
    offset,
    endOffset: pos,
  }
}

function parseConnectionCloseFrame(
  bytes: Uint8Array,
  offset: number,
  frameType:
    | typeof QuicFrameType.ConnectionCloseTransport
    | typeof QuicFrameType.ConnectionCloseApplication,
): QuicConnectionCloseFrame {
  let pos = offset + 1
  const errorCode = decodeVarIntNumber(bytes, pos)
  pos += errorCode.bytesRead
  let closedFrameType: number | null = null
  if (frameType === QuicFrameType.ConnectionCloseTransport) {
    const decodedFrameType = decodeVarIntNumber(bytes, pos)
    pos += decodedFrameType.bytesRead
    closedFrameType = decodedFrameType.value
  }
  const reasonLength = decodeVarIntNumber(bytes, pos)
  pos += reasonLength.bytesRead
  if (bytes.length - pos < reasonLength.value) {
    throw new RangeError('not enough bytes for QUIC CONNECTION_CLOSE reason')
  }
  const endOffset = pos + reasonLength.value
  const base = {
    type: 'connection-close',
    errorCode: errorCode.value,
    reasonPhrase: copyBytes(bytes.subarray(pos, endOffset)),
    offset,
    endOffset,
  } as const

  if (closedFrameType === null) {
    return {
      ...base,
      errorSpace: 'application',
      frameType: null,
    }
  }

  return {
    ...base,
    errorSpace: 'transport',
    frameType: closedFrameType,
  }
}

function validateFirstAckRange(largestAcknowledged: bigint, firstAckRange: bigint): void {
  if (firstAckRange > largestAcknowledged) {
    throw new RangeError('QUIC ACK first range exceeds largest acknowledged')
  }
}

function validateAckRange(
  previousSmallestAcknowledged: bigint,
  gap: bigint,
  length: bigint,
): bigint {
  if (previousSmallestAcknowledged < gap + 2n) {
    throw new RangeError('QUIC ACK range gap underflows packet number')
  }
  const largestAcknowledged = previousSmallestAcknowledged - gap - 2n
  if (length > largestAcknowledged) {
    throw new RangeError('QUIC ACK range length underflows packet number')
  }
  return largestAcknowledged - length
}

function buildAckPacketRanges(
  receivedPacketNumbers: readonly (number | bigint)[],
): readonly QuicAckPacketRange[] {
  const sorted = Array.from(
    new Set(receivedPacketNumbers.map((packetNumber) => quicPacketNumberToBigInt(packetNumber))),
  ).sort((left, right) => {
    if (left > right) {
      return -1
    }
    if (left < right) {
      return 1
    }
    return 0
  })
  const ranges: QuicAckPacketRange[] = []

  for (const packetNumber of sorted) {
    const current = ranges.at(-1)
    if (current !== undefined && packetNumber + 1n === current.smallest) {
      ranges[ranges.length - 1] = { ...current, smallest: packetNumber }
      continue
    }
    ranges.push({ smallest: packetNumber, largest: packetNumber })
  }

  return ranges
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

function isStreamFrameType(frameType: number): boolean {
  return (frameType & 0xf8) === QuicFrameType.StreamBase
}

function validateOffset(bytes: Uint8Array, offset: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > bytes.length) {
    throw new RangeError('QUIC frame offset out of range')
  }
}

import { copyBytes, readU8, readU32BE } from '../bytes'
import { decodeVarIntNumber } from '../varint'

export const QUIC_VERSION_1 = 0x00000001

export const QuicLongHeaderPacketType = {
  Initial: 'initial',
  ZeroRtt: '0-rtt',
  Handshake: 'handshake',
  Retry: 'retry',
} as const

export type QuicLongHeaderPacketTypeValue =
  (typeof QuicLongHeaderPacketType)[keyof typeof QuicLongHeaderPacketType]

export interface QuicLongHeader {
  readonly firstByte: number
  readonly version: number
  readonly packetType: QuicLongHeaderPacketTypeValue
  readonly destinationConnectionId: Uint8Array
  readonly sourceConnectionId: Uint8Array
  readonly offset: number
}

export interface QuicInitialPacketHeader extends QuicLongHeader {
  readonly packetType: typeof QuicLongHeaderPacketType.Initial
  readonly token: Uint8Array
  readonly length: number
  readonly packetNumberOffset: number
  readonly packetNumberLength: number
  readonly packetNumber: number
  readonly payloadOffset: number
}

export interface QuicInitialPacketHeaderPrefix extends QuicLongHeader {
  readonly packetType: typeof QuicLongHeaderPacketType.Initial
  readonly token: Uint8Array
  readonly length: number
  readonly packetNumberOffset: number
}

export interface QuicHandshakePacketHeader extends QuicLongHeader {
  readonly packetType: typeof QuicLongHeaderPacketType.Handshake
  readonly length: number
  readonly packetNumberOffset: number
  readonly packetNumberLength: number
  readonly packetNumber: number
  readonly payloadOffset: number
}

export interface QuicHandshakePacketHeaderPrefix extends QuicLongHeader {
  readonly packetType: typeof QuicLongHeaderPacketType.Handshake
  readonly length: number
  readonly packetNumberOffset: number
}

export function parseQuicLongHeader(bytes: Uint8Array, offset = 0): QuicLongHeader {
  const firstByte = readU8(bytes, offset)
  if ((firstByte & 0x80) === 0) {
    throw new RangeError('QUIC packet is not long header')
  }
  if ((firstByte & 0x40) === 0) {
    throw new RangeError('QUIC fixed bit is not set')
  }

  const version = readU32BE(bytes, offset + 1)
  let pos = offset + 5
  const destinationConnectionIdLength = readU8(bytes, pos)
  pos += 1
  const destinationConnectionId = readBytes(
    bytes,
    pos,
    destinationConnectionIdLength,
    'destination connection id',
  )
  pos += destinationConnectionIdLength

  const sourceConnectionIdLength = readU8(bytes, pos)
  pos += 1
  const sourceConnectionId = readBytes(bytes, pos, sourceConnectionIdLength, 'source connection id')
  pos += sourceConnectionIdLength

  return {
    firstByte,
    version,
    packetType: longHeaderPacketType(firstByte),
    destinationConnectionId,
    sourceConnectionId,
    offset: pos,
  }
}

export function parseQuicInitialPacketHeader(
  bytes: Uint8Array,
  offset = 0,
): QuicInitialPacketHeader {
  const header = parseQuicInitialPacketHeaderPrefix(bytes, offset)
  let pos = header.packetNumberOffset

  const packetNumberLength = (header.firstByte & 0x03) + 1
  const packetNumber = readQuicPacketNumber(bytes, pos, packetNumberLength)
  pos += packetNumberLength

  if (header.length < packetNumberLength) {
    throw new RangeError('QUIC Initial length smaller than packet number')
  }
  if (bytes.length - pos < header.length - packetNumberLength) {
    throw new RangeError('not enough bytes for QUIC Initial payload')
  }

  return {
    ...header,
    packetType: QuicLongHeaderPacketType.Initial,
    token: header.token,
    length: header.length,
    packetNumberOffset: header.packetNumberOffset,
    packetNumberLength,
    packetNumber,
    payloadOffset: pos,
  }
}

export function parseQuicInitialPacketHeaderPrefix(
  bytes: Uint8Array,
  offset = 0,
): QuicInitialPacketHeaderPrefix {
  const header = parseQuicLongHeader(bytes, offset)
  if (header.packetType !== QuicLongHeaderPacketType.Initial) {
    throw new RangeError('QUIC packet is not Initial')
  }

  let pos = header.offset
  const tokenLength = decodeVarIntNumber(bytes, pos)
  pos += tokenLength.bytesRead
  const token = readBytes(bytes, pos, tokenLength.value, 'initial token')
  pos += tokenLength.value

  const encodedLength = decodeVarIntNumber(bytes, pos)
  pos += encodedLength.bytesRead

  return {
    ...header,
    packetType: QuicLongHeaderPacketType.Initial,
    token,
    length: encodedLength.value,
    packetNumberOffset: pos,
  }
}

export function parseQuicHandshakePacketHeader(
  bytes: Uint8Array,
  offset = 0,
): QuicHandshakePacketHeader {
  const header = parseQuicHandshakePacketHeaderPrefix(bytes, offset)
  let pos = header.packetNumberOffset

  const packetNumberLength = (header.firstByte & 0x03) + 1
  const packetNumber = readQuicPacketNumber(bytes, pos, packetNumberLength)
  pos += packetNumberLength

  if (header.length < packetNumberLength) {
    throw new RangeError('QUIC Handshake length smaller than packet number')
  }
  if (bytes.length - pos < header.length - packetNumberLength) {
    throw new RangeError('not enough bytes for QUIC Handshake payload')
  }

  return {
    ...header,
    packetType: QuicLongHeaderPacketType.Handshake,
    length: header.length,
    packetNumberOffset: header.packetNumberOffset,
    packetNumberLength,
    packetNumber,
    payloadOffset: pos,
  }
}

export function parseQuicHandshakePacketHeaderPrefix(
  bytes: Uint8Array,
  offset = 0,
): QuicHandshakePacketHeaderPrefix {
  const header = parseQuicLongHeader(bytes, offset)
  if (header.packetType !== QuicLongHeaderPacketType.Handshake) {
    throw new RangeError('QUIC packet is not Handshake')
  }

  let pos = header.offset
  const encodedLength = decodeVarIntNumber(bytes, pos)
  pos += encodedLength.bytesRead

  return {
    ...header,
    packetType: QuicLongHeaderPacketType.Handshake,
    length: encodedLength.value,
    packetNumberOffset: pos,
  }
}

export function readQuicPacketNumber(bytes: Uint8Array, offset: number, length: number): number {
  if (length < 1 || length > 4) {
    throw new RangeError('QUIC packet number length out of range')
  }
  if (bytes.length - offset < length) {
    throw new RangeError('not enough bytes for QUIC packet number')
  }

  let packetNumber = 0
  for (let index = 0; index < length; index += 1) {
    packetNumber = packetNumber * 0x100 + readU8(bytes, offset + index)
  }
  return packetNumber
}

function longHeaderPacketType(firstByte: number): QuicLongHeaderPacketTypeValue {
  const packetType = (firstByte & 0x30) >> 4
  switch (packetType) {
    case 0:
      return QuicLongHeaderPacketType.Initial
    case 1:
      return QuicLongHeaderPacketType.ZeroRtt
    case 2:
      return QuicLongHeaderPacketType.Handshake
    case 3:
      return QuicLongHeaderPacketType.Retry
    default:
      throw new RangeError('QUIC long header packet type out of range')
  }
}

function readBytes(bytes: Uint8Array, offset: number, length: number, name: string): Uint8Array {
  if (bytes.length - offset < length) {
    throw new RangeError(`not enough bytes for ${name}`)
  }
  return copyBytes(bytes.subarray(offset, offset + length))
}

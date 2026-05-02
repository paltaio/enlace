import { concatBytes, copyBytes, readU8 } from '../bytes'
import {
  createQuicHeaderProtectionMask,
  decryptQuicAes128GcmPacket,
  encryptQuicAes128GcmPacket,
  headerProtectionSample,
  removeQuicHeaderProtection,
  type QuicDirectionalKeys,
} from './crypto'
import { readQuicPacketNumber } from './packet'

export interface QuicOneRttPacketHeaderPrefix {
  readonly firstByte: number
  readonly destinationConnectionId: Uint8Array
  readonly packetNumberOffset: number
}

export interface QuicOneRttPacketHeader extends QuicOneRttPacketHeaderPrefix {
  readonly packetNumberLength: number
  readonly packetNumber: number
  readonly payloadOffset: number
}

export interface QuicOneRttPacketDecryptionResult {
  readonly header: QuicOneRttPacketHeader
  readonly payload: Uint8Array
  readonly unprotectedPacket: Uint8Array
  readonly endOffset: number
}

export interface QuicOneRttPacketProtectionOptions {
  readonly destinationConnectionId: Uint8Array
  readonly packetNumber: number
  readonly packetNumberLength: number
  readonly payload: Uint8Array
}

export function encryptQuicOneRttPacket(
  keys: QuicDirectionalKeys,
  options: QuicOneRttPacketProtectionOptions,
): Uint8Array {
  validatePacketNumberLength(options.packetNumberLength)
  const packetNumberBytes = encodeTruncatedPacketNumber(
    options.packetNumber,
    options.packetNumberLength,
  )
  const firstByte = 0x40 | (options.packetNumberLength - 1)
  const header = concatBytes([
    new Uint8Array([firstByte]),
    options.destinationConnectionId,
    packetNumberBytes,
  ])
  const ciphertext = encryptQuicAes128GcmPacket(keys, options.packetNumber, header, options.payload)
  const packetNumberOffset = 1 + options.destinationConnectionId.length
  return applyShortHeaderProtection(concatBytes([header, ciphertext]), packetNumberOffset, keys)
}

export function parseQuicOneRttPacketHeaderPrefix(
  bytes: Uint8Array,
  destinationConnectionIdLength: number,
  offset = 0,
): QuicOneRttPacketHeaderPrefix {
  validateConnectionIdLength(destinationConnectionIdLength)
  const firstByte = readU8(bytes, offset)
  validateShortHeaderFirstByte(firstByte)
  const destinationConnectionIdOffset = offset + 1
  const packetNumberOffset = destinationConnectionIdOffset + destinationConnectionIdLength
  if (bytes.length < packetNumberOffset) {
    throw new RangeError('not enough bytes for QUIC 1-RTT destination connection id')
  }

  return {
    firstByte,
    destinationConnectionId: copyBytes(
      bytes.subarray(destinationConnectionIdOffset, packetNumberOffset),
    ),
    packetNumberOffset,
  }
}

export function parseQuicOneRttPacketHeader(
  bytes: Uint8Array,
  destinationConnectionIdLength: number,
  offset = 0,
): QuicOneRttPacketHeader {
  const header = parseQuicOneRttPacketHeaderPrefix(bytes, destinationConnectionIdLength, offset)
  const packetNumberLength = (header.firstByte & 0x03) + 1
  const packetNumber = readQuicPacketNumber(bytes, header.packetNumberOffset, packetNumberLength)
  const payloadOffset = header.packetNumberOffset + packetNumberLength

  return {
    ...header,
    packetNumberLength,
    packetNumber,
    payloadOffset,
  }
}

export function decryptQuicOneRttPacket(
  packet: Uint8Array,
  keys: QuicDirectionalKeys,
  destinationConnectionIdLength: number,
  offset = 0,
): QuicOneRttPacketDecryptionResult {
  const prefix = parseQuicOneRttPacketHeaderPrefix(packet, destinationConnectionIdLength, offset)
  const protectedPacket = copyBytes(packet.subarray(offset))
  const packetNumberOffset = prefix.packetNumberOffset - offset
  const protection = removeQuicHeaderProtection(
    protectedPacket,
    packetNumberOffset,
    keys.headerProtectionKey,
  )
  const header = parseQuicOneRttPacketHeader(protection.packet, destinationConnectionIdLength)
  const ciphertext = protection.packet.subarray(header.payloadOffset)
  const associatedData = protection.packet.subarray(0, header.payloadOffset)
  const payload = decryptQuicAes128GcmPacket(keys, header.packetNumber, associatedData, ciphertext)

  return {
    header,
    payload,
    unprotectedPacket: protection.packet,
    endOffset: packet.length,
  }
}

function validateConnectionIdLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError('QUIC destination connection id length out of range')
  }
}

function validatePacketNumberLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 1 || length > 4) {
    throw new RangeError('QUIC packet number length out of range')
  }
}

function encodeTruncatedPacketNumber(packetNumber: number, length: number): Uint8Array {
  if (!Number.isSafeInteger(packetNumber) || packetNumber < 0) {
    throw new RangeError('QUIC packet number out of range')
  }
  const maxPacketNumber = 2 ** (8 * length) - 1
  if (packetNumber > maxPacketNumber) {
    throw new RangeError('QUIC packet number does not fit truncated length')
  }

  const bytes = new Uint8Array(length)
  for (let index = 0; index < length; index += 1) {
    const shift = 8 * (length - index - 1)
    bytes[index] = Math.floor(packetNumber / 2 ** shift) & 0xff
  }
  return bytes
}

function applyShortHeaderProtection(
  packet: Uint8Array,
  packetNumberOffset: number,
  keys: QuicDirectionalKeys,
): Uint8Array {
  const protectedPacket = new Uint8Array(packet)
  const sample = headerProtectionSample(packet, packetNumberOffset)
  const mask = createQuicHeaderProtectionMask(keys.headerProtectionKey, sample)
  protectedPacket[0] = readU8(protectedPacket, 0) ^ (readU8(mask, 0) & 0x1f)

  const packetNumberLength = (readU8(packet, 0) & 0x03) + 1
  for (let index = 0; index < packetNumberLength; index += 1) {
    const packetNumberIndex = packetNumberOffset + index
    protectedPacket[packetNumberIndex] =
      readU8(protectedPacket, packetNumberIndex) ^ readU8(mask, index + 1)
  }

  return protectedPacket
}

function validateShortHeaderFirstByte(firstByte: number): void {
  if ((firstByte & 0x80) !== 0) {
    throw new RangeError('QUIC packet is not short header')
  }
  if ((firstByte & 0x40) === 0) {
    throw new RangeError('QUIC fixed bit is not set')
  }
}

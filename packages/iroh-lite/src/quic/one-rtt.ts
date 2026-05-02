import { concatBytes, copyBytes, readU8 } from '../bytes'
import {
  QuicAckReceiveTracker,
  receiveQuicOneRttPlaintextFrames,
  type QuicAckReceiveSnapshot,
} from './ack'
import {
  createQuicHeaderProtectionMask,
  decryptQuicAes128GcmPacket,
  encryptQuicAes128GcmPacket,
  headerProtectionSample,
  removeQuicHeaderProtection,
  type QuicDirectionalKeys,
} from './crypto'
import type { QuicFrame } from './frame'
import {
  QUIC_MAX_PACKET_NUMBER,
  nextExpectedQuicPacketNumber,
  quicPacketNumberToBigInt,
  readQuicPacketNumber,
  recoverQuicPacketNumber,
  updateLargestReceivedQuicPacketNumber,
} from './packet'
import {
  QuicStreamState,
  type QuicStreamReceiveOutput,
  type QuicStreamReceiveSnapshot,
  type QuicStreamSendResult,
} from './streams'

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
  readonly packetNumber: bigint
  readonly payload: Uint8Array
  readonly unprotectedPacket: Uint8Array
  readonly endOffset: number
}

export interface QuicOneRttPacketReceiveResult extends QuicOneRttPacketDecryptionResult {
  readonly largestReceivedPacketNumber: bigint
}

export interface QuicOneRttPacketFrameReceiveResult extends QuicOneRttPacketReceiveResult {
  readonly frames: readonly QuicFrame[]
  readonly ackEliciting: boolean
  readonly ackSnapshot: QuicAckReceiveSnapshot
  readonly ackFrame: Uint8Array | null
}

export interface QuicOneRttPacketStreamReceiveResult extends QuicOneRttPacketFrameReceiveResult {
  readonly streamOutputs: readonly QuicStreamReceiveOutput[]
}

export interface QuicOneRttPacketProtectionOptions {
  readonly destinationConnectionId: Uint8Array
  readonly packetNumber: number | bigint
  readonly packetNumberLength: number
  readonly payload: Uint8Array
}

export interface QuicOneRttPacketSendResult {
  readonly packet: Uint8Array
  readonly packetNumber: bigint
  readonly nextPacketNumber: bigint
}

export interface QuicOneRttStreamPacketSendResult extends QuicOneRttPacketSendResult {
  readonly stream: QuicStreamSendResult
}

export class QuicOneRttSendState {
  #nextPacketNumber: bigint

  constructor(nextPacketNumber: number | bigint = 0) {
    this.#nextPacketNumber = quicPacketNumberToBigInt(nextPacketNumber)
  }

  get nextPacketNumber(): bigint {
    return this.#nextPacketNumber
  }

  send(
    keys: QuicDirectionalKeys,
    destinationConnectionId: Uint8Array,
    payload: Uint8Array,
  ): QuicOneRttPacketSendResult {
    const packetNumber = quicPacketNumberToBigInt(this.#nextPacketNumber)
    if (packetNumber === QUIC_MAX_PACKET_NUMBER) {
      throw new RangeError('QUIC next packet number out of range')
    }
    const packet = encryptQuicOneRttPacket(keys, {
      destinationConnectionId,
      packetNumber,
      packetNumberLength: selectQuicOneRttPacketNumberLength(packetNumber),
      payload,
    })
    const nextPacketNumber = packetNumber + 1n
    this.#nextPacketNumber = nextPacketNumber

    return {
      packet,
      packetNumber,
      nextPacketNumber,
    }
  }
}

export class QuicOneRttState {
  readonly #sendState: QuicOneRttSendState
  readonly #receiveState: QuicOneRttReceiveState
  readonly #streamState = new QuicStreamState()

  constructor(
    nextPacketNumber: number | bigint = 0,
    largestReceivedPacketNumber: number | bigint | null = null,
  ) {
    this.#sendState = new QuicOneRttSendState(nextPacketNumber)
    this.#receiveState = new QuicOneRttReceiveState(largestReceivedPacketNumber)
  }

  get nextPacketNumber(): bigint {
    return this.#sendState.nextPacketNumber
  }

  get largestReceivedPacketNumber(): bigint | null {
    return this.#receiveState.largestReceivedPacketNumber
  }

  ackSnapshot(): QuicAckReceiveSnapshot {
    return this.#receiveState.ackSnapshot()
  }

  streamSnapshot(streamId: number): QuicStreamReceiveSnapshot {
    return this.#streamState.receiveSnapshot(streamId)
  }

  streamSendOffset(streamId: number): number {
    return this.#streamState.sendOffset(streamId)
  }

  applyStreamFlowControl(frames: readonly QuicFrame[]): void {
    this.#streamState.applyFlowControlFrames(frames)
  }

  send(
    keys: QuicDirectionalKeys,
    destinationConnectionId: Uint8Array,
    payload: Uint8Array,
  ): QuicOneRttPacketSendResult {
    return this.#sendState.send(keys, destinationConnectionId, payload)
  }

  sendStream(
    keys: QuicDirectionalKeys,
    destinationConnectionId: Uint8Array,
    streamId: number,
    data: Uint8Array,
    fin = false,
  ): QuicOneRttStreamPacketSendResult {
    if (this.#sendState.nextPacketNumber === QUIC_MAX_PACKET_NUMBER) {
      throw new RangeError('QUIC next packet number out of range')
    }
    const stream = this.#streamState.send(streamId, data, fin)
    const sent = this.send(keys, destinationConnectionId, stream.frameBytes)

    return {
      ...sent,
      stream,
    }
  }

  receive(
    packet: Uint8Array,
    keys: QuicDirectionalKeys,
    destinationConnectionIdLength: number,
    offset = 0,
    ackDelay = 0,
  ): QuicOneRttPacketStreamReceiveResult {
    const result = this.#receiveState.receive(
      packet,
      keys,
      destinationConnectionIdLength,
      offset,
      ackDelay,
    )
    return {
      ...result,
      streamOutputs: this.#streamState.receiveFrames(result.frames),
    }
  }
}

export class QuicOneRttReceiveState {
  readonly #ackTracker = new QuicAckReceiveTracker()
  #largestReceivedPacketNumber: bigint | null

  constructor(largestReceivedPacketNumber: number | bigint | null = null) {
    this.#largestReceivedPacketNumber =
      largestReceivedPacketNumber === null
        ? null
        : quicPacketNumberToBigInt(largestReceivedPacketNumber)
  }

  get largestReceivedPacketNumber(): bigint | null {
    return this.#largestReceivedPacketNumber
  }

  ackSnapshot(): QuicAckReceiveSnapshot {
    return this.#ackTracker.snapshot()
  }

  receive(
    packet: Uint8Array,
    keys: QuicDirectionalKeys,
    destinationConnectionIdLength: number,
    offset = 0,
    ackDelay = 0,
  ): QuicOneRttPacketFrameReceiveResult {
    const result = receiveQuicOneRttPacketFrames(
      packet,
      keys,
      destinationConnectionIdLength,
      this.#largestReceivedPacketNumber,
      this.#ackTracker,
      offset,
      ackDelay,
    )

    this.#largestReceivedPacketNumber = result.largestReceivedPacketNumber
    return result
  }
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
  expectedPacketNumber: number | bigint | null = null,
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
  const packetNumber =
    expectedPacketNumber === null
      ? BigInt(header.packetNumber)
      : recoverQuicPacketNumber(
          header.packetNumber,
          header.packetNumberLength,
          expectedPacketNumber,
        )
  const payload = decryptQuicAes128GcmPacket(keys, packetNumber, associatedData, ciphertext)

  return {
    header,
    packetNumber,
    payload,
    unprotectedPacket: protection.packet,
    endOffset: packet.length,
  }
}

export function receiveQuicOneRttPacket(
  packet: Uint8Array,
  keys: QuicDirectionalKeys,
  destinationConnectionIdLength: number,
  largestReceivedPacketNumber: number | bigint | null,
  offset = 0,
): QuicOneRttPacketReceiveResult {
  const expectedPacketNumber = nextExpectedQuicPacketNumber(largestReceivedPacketNumber)
  const result = decryptQuicOneRttPacket(
    packet,
    keys,
    destinationConnectionIdLength,
    offset,
    expectedPacketNumber,
  )

  return {
    ...result,
    largestReceivedPacketNumber: updateLargestReceivedQuicPacketNumber(
      largestReceivedPacketNumber,
      result.packetNumber,
    ),
  }
}

export function receiveQuicOneRttPacketFrames(
  packet: Uint8Array,
  keys: QuicDirectionalKeys,
  destinationConnectionIdLength: number,
  largestReceivedPacketNumber: number | bigint | null,
  ackTracker: QuicAckReceiveTracker,
  offset = 0,
  ackDelay = 0,
): QuicOneRttPacketFrameReceiveResult {
  const receivedPacket = receiveQuicOneRttPacket(
    packet,
    keys,
    destinationConnectionIdLength,
    largestReceivedPacketNumber,
    offset,
  )
  const receivedFrames = receiveQuicOneRttPlaintextFrames(
    receivedPacket.packetNumber,
    receivedPacket.payload,
    ackTracker,
    ackDelay,
  )

  return {
    ...receivedPacket,
    frames: receivedFrames.frames,
    ackEliciting: receivedFrames.ackEliciting,
    ackSnapshot: receivedFrames.ackSnapshot,
    ackFrame: receivedFrames.ackFrame,
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

function selectQuicOneRttPacketNumberLength(packetNumber: number | bigint): number {
  const value = quicPacketNumberToBigInt(packetNumber)
  if (value <= 0xffn) {
    return 1
  }
  if (value <= 0xffffn) {
    return 2
  }
  if (value <= 0xffffffn) {
    return 3
  }
  return 4
}

function encodeTruncatedPacketNumber(packetNumber: number | bigint, length: number): Uint8Array {
  let remaining = quicPacketNumberToBigInt(packetNumber)
  const bytes = new Uint8Array(length)
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn)
    remaining >>= 8n
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

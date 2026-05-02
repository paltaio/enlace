import { concatBytes, copyBytes, writeU32BE } from '../bytes'
import { encodeVarInt } from '../varint'
import {
  QUIC_AES_128_GCM_TAG_LENGTH,
  applyQuicHeaderProtection,
  decryptQuicAes128GcmPacket,
  encryptQuicAes128GcmPacket,
  removeQuicHeaderProtection,
  type QuicInitialDirectionalKeys,
} from './crypto'
import {
  QUIC_VERSION_1,
  encodeQuicTruncatedPacketNumber,
  parseQuicInitialPacketHeader,
  parseQuicInitialPacketHeaderPrefix,
  recoverQuicPacketNumber,
  type QuicInitialPacketHeader,
  validateQuicConnectionIdLength,
} from './packet'

export interface QuicInitialPacketProtectionOptions {
  readonly destinationConnectionId: Uint8Array
  readonly sourceConnectionId: Uint8Array
  readonly token?: Uint8Array
  readonly packetNumber: number | bigint
  readonly packetNumberLength: number
  readonly payload: Uint8Array
}

export interface QuicInitialPacketDecryptionResult {
  readonly header: QuicInitialPacketHeader
  readonly packetNumber: bigint
  readonly payload: Uint8Array
  readonly unprotectedPacket: Uint8Array
  readonly endOffset: number
}

export function encryptQuicInitialPacket(
  keys: QuicInitialDirectionalKeys,
  options: QuicInitialPacketProtectionOptions,
): Uint8Array {
  validateQuicConnectionIdLength(options.destinationConnectionId, 'destination connection id')
  validateQuicConnectionIdLength(options.sourceConnectionId, 'source connection id')
  const token = options.token ?? new Uint8Array()
  const packetNumber = encodeQuicTruncatedPacketNumber(
    options.packetNumber,
    options.packetNumberLength,
  )
  const firstByte = 0xc0 | (options.packetNumberLength - 1)
  const header = concatBytes([
    new Uint8Array([firstByte]),
    writeU32BE(QUIC_VERSION_1),
    new Uint8Array([options.destinationConnectionId.length]),
    options.destinationConnectionId,
    new Uint8Array([options.sourceConnectionId.length]),
    options.sourceConnectionId,
    encodeVarInt(token.length),
    token,
    encodeVarInt(packetNumber.length + options.payload.length + QUIC_AES_128_GCM_TAG_LENGTH),
    packetNumber,
  ])
  const packetNumberOffset = header.length - packetNumber.length
  const ciphertext = encryptQuicAes128GcmPacket(keys, options.packetNumber, header, options.payload)

  return applyQuicHeaderProtection(
    concatBytes([header, ciphertext]),
    packetNumberOffset,
    keys.headerProtectionKey,
    0x0f,
  )
}

export function decryptQuicInitialPacket(
  packet: Uint8Array,
  keys: QuicInitialDirectionalKeys,
  offset = 0,
  expectedPacketNumber: number | bigint | null = null,
): QuicInitialPacketDecryptionResult {
  const prefix = parseQuicInitialPacketHeaderPrefix(packet, offset)
  const endOffset = prefix.packetNumberOffset + prefix.length
  if (packet.length < endOffset) {
    throw new RangeError('not enough bytes for QUIC Initial packet')
  }

  const protectedPacket = copyBytes(packet.subarray(offset, endOffset))
  const packetNumberOffset = prefix.packetNumberOffset - offset
  const protection = removeQuicHeaderProtection(
    protectedPacket,
    packetNumberOffset,
    keys.headerProtectionKey,
  )
  const header = parseQuicInitialPacketHeader(protection.packet)
  const ciphertextLength = header.length - header.packetNumberLength
  const ciphertextEnd = header.payloadOffset + ciphertextLength
  const associatedData = protection.packet.subarray(0, header.payloadOffset)
  const ciphertext = protection.packet.subarray(header.payloadOffset, ciphertextEnd)
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
    endOffset,
  }
}

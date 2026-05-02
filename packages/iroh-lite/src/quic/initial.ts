import { copyBytes } from '../bytes'
import {
  decryptQuicAes128GcmPacket,
  removeQuicHeaderProtection,
  type QuicInitialDirectionalKeys,
} from './crypto'
import {
  parseQuicInitialPacketHeader,
  parseQuicInitialPacketHeaderPrefix,
  type QuicInitialPacketHeader,
} from './packet'

export interface QuicInitialPacketDecryptionResult {
  readonly header: QuicInitialPacketHeader
  readonly payload: Uint8Array
  readonly unprotectedPacket: Uint8Array
  readonly endOffset: number
}

export function decryptQuicInitialPacket(
  packet: Uint8Array,
  keys: QuicInitialDirectionalKeys,
  offset = 0,
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
  const payload = decryptQuicAes128GcmPacket(keys, header.packetNumber, associatedData, ciphertext)

  return {
    header,
    payload,
    unprotectedPacket: protection.packet,
    endOffset,
  }
}

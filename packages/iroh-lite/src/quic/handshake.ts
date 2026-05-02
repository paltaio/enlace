import { concatBytes, copyBytes, writeU32BE } from '../bytes'
import { encodeVarInt } from '../varint'
import {
  QUIC_AES_128_GCM_TAG_LENGTH,
  applyQuicHeaderProtection,
  deriveQuicDirectionalKeys,
  decryptQuicAes128GcmPacket,
  encryptQuicAes128GcmPacket,
  removeQuicHeaderProtection,
  type QuicDirectionalKeys,
} from './crypto'
import {
  QUIC_VERSION_1,
  encodeQuicTruncatedPacketNumber,
  parseQuicHandshakePacketHeader,
  parseQuicHandshakePacketHeaderPrefix,
  recoverQuicPacketNumber,
  type QuicHandshakePacketHeader,
  validateQuicConnectionIdLength,
} from './packet'
import {
  deriveTls13X25519HandshakeSecretsFromQuicCrypto,
  type DeriveTls13X25519HandshakeSecretsFromQuicCryptoOptions,
} from './tls-handshake'

export interface QuicHandshakePacketDecryptionResult {
  readonly header: QuicHandshakePacketHeader
  readonly packetNumber: bigint
  readonly payload: Uint8Array
  readonly unprotectedPacket: Uint8Array
  readonly endOffset: number
}

export interface QuicHandshakePacketProtectionOptions {
  readonly destinationConnectionId: Uint8Array
  readonly sourceConnectionId: Uint8Array
  readonly packetNumber: number | bigint
  readonly packetNumberLength: number
  readonly payload: Uint8Array
}

export interface QuicHandshakeKeys {
  readonly client: QuicDirectionalKeys
  readonly server: QuicDirectionalKeys
}

export async function deriveQuicHandshakeKeysFromTlsCrypto(
  options: DeriveTls13X25519HandshakeSecretsFromQuicCryptoOptions,
): Promise<QuicHandshakeKeys> {
  const handshakeSecrets = await deriveTls13X25519HandshakeSecretsFromQuicCrypto(options)
  return {
    client: deriveQuicDirectionalKeys(handshakeSecrets.secrets.clientHandshakeTrafficSecret),
    server: deriveQuicDirectionalKeys(handshakeSecrets.secrets.serverHandshakeTrafficSecret),
  }
}

export function encryptQuicHandshakePacket(
  keys: QuicDirectionalKeys,
  options: QuicHandshakePacketProtectionOptions,
): Uint8Array {
  validateQuicConnectionIdLength(options.destinationConnectionId, 'destination connection id')
  validateQuicConnectionIdLength(options.sourceConnectionId, 'source connection id')
  const packetNumber = encodeQuicTruncatedPacketNumber(
    options.packetNumber,
    options.packetNumberLength,
  )
  const firstByte = 0xe0 | (options.packetNumberLength - 1)
  const header = concatBytes([
    new Uint8Array([firstByte]),
    writeU32BE(QUIC_VERSION_1),
    new Uint8Array([options.destinationConnectionId.length]),
    options.destinationConnectionId,
    new Uint8Array([options.sourceConnectionId.length]),
    options.sourceConnectionId,
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

export function decryptQuicHandshakePacket(
  packet: Uint8Array,
  keys: QuicDirectionalKeys,
  offset = 0,
  expectedPacketNumber: number | bigint | null = null,
): QuicHandshakePacketDecryptionResult {
  const prefix = parseQuicHandshakePacketHeaderPrefix(packet, offset)
  const endOffset = prefix.packetNumberOffset + prefix.length
  if (packet.length < endOffset) {
    throw new RangeError('not enough bytes for QUIC Handshake packet')
  }

  const protectedPacket = copyBytes(packet.subarray(offset, endOffset))
  const packetNumberOffset = prefix.packetNumberOffset - offset
  const protection = removeQuicHeaderProtection(
    protectedPacket,
    packetNumberOffset,
    keys.headerProtectionKey,
  )
  const header = parseQuicHandshakePacketHeader(protection.packet)
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

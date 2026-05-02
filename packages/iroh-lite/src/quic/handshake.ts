import { copyBytes } from '../bytes'
import {
  deriveQuicDirectionalKeys,
  decryptQuicAes128GcmPacket,
  removeQuicHeaderProtection,
  type QuicDirectionalKeys,
} from './crypto'
import {
  parseQuicHandshakePacketHeader,
  parseQuicHandshakePacketHeaderPrefix,
  type QuicHandshakePacketHeader,
} from './packet'
import {
  deriveTls13X25519HandshakeSecretsFromQuicCrypto,
  type DeriveTls13X25519HandshakeSecretsFromQuicCryptoOptions,
} from './tls-handshake'

export interface QuicHandshakePacketDecryptionResult {
  readonly header: QuicHandshakePacketHeader
  readonly payload: Uint8Array
  readonly unprotectedPacket: Uint8Array
  readonly endOffset: number
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

export function decryptQuicHandshakePacket(
  packet: Uint8Array,
  keys: QuicDirectionalKeys,
  offset = 0,
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
  const payload = decryptQuicAes128GcmPacket(keys, header.packetNumber, associatedData, ciphertext)

  return {
    header,
    payload,
    unprotectedPacket: protection.packet,
    endOffset,
  }
}

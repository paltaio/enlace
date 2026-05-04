import { describe, expect, test } from 'bun:test'

import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientHello,
  rfc8448ClientPrivateKey,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerHello,
} from '../testing/rfc8448-tls'
import { bytesToHex } from '../testing/hex'
import { deriveQuicDirectionalKeys, type QuicDirectionalKeys } from './crypto'
import type { QuicCryptoFrame } from './frame'
import {
  decryptQuicHandshakePacket,
  deriveQuicHandshakeKeysFromTlsCrypto,
  encryptQuicHandshakePacket,
} from './handshake'
import { TlsHandshakeRole } from './tls-handshake'
import { collectQuicTlsHandshakeMessages } from './tls-crypto-stream'

describe('QUIC Handshake key derivation', () => {
  test('derives QUIC keys from TLS handshake traffic secrets', () => {
    const clientKeys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)
    const serverKeys = deriveQuicDirectionalKeys(rfc8448ServerHandshakeTrafficSecret)

    expect(bytesToHex(clientKeys.packetKey)).toBe('b574ba1b323a2c6ad03e410836b5605c')
    expect(bytesToHex(clientKeys.packetIv)).toBe('200c933d2209b9a1aa879197')
    expect(bytesToHex(clientKeys.headerProtectionKey)).toBe('bb1db87365312baa38818fa20be44fde')
    expect(bytesToHex(serverKeys.packetKey)).toBe('03f01e7bf4e9bc37901b9ae3a022dfe7')
    expect(bytesToHex(serverKeys.packetIv)).toBe('53df176c0bdf845443fca523')
    expect(bytesToHex(serverKeys.headerProtectionKey)).toBe('5b6160d63552d737da036abf737ce2bf')
  })

  test('derives QUIC keys from collected TLS hellos', async () => {
    const keys = await deriveQuicHandshakeKeysFromTlsCrypto({
      role: TlsHandshakeRole.Client,
      privateKey: rfc8448ClientPrivateKey,
      clientMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]),
      serverMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)]),
    })

    expect(bytesToHex(keys.client.packetKey)).toBe('b574ba1b323a2c6ad03e410836b5605c')
    expect(bytesToHex(keys.client.packetIv)).toBe('200c933d2209b9a1aa879197')
    expect(bytesToHex(keys.client.headerProtectionKey)).toBe('bb1db87365312baa38818fa20be44fde')
    expect(bytesToHex(keys.server.packetKey)).toBe('03f01e7bf4e9bc37901b9ae3a022dfe7')
    expect(bytesToHex(keys.server.packetIv)).toBe('53df176c0bdf845443fca523')
    expect(bytesToHex(keys.server.headerProtectionKey)).toBe('5b6160d63552d737da036abf737ce2bf')
  })
})

describe('QUIC Handshake packet decryption', () => {
  test('protects and decrypts a Handshake packet', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ServerHandshakeTrafficSecret)
    const packet = encryptQuicHandshakePacket(keys, {
      destinationConnectionId: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
      sourceConnectionId: new Uint8Array([0x06, 0x07, 0x08, 0x09, 0x0a]),
      packetNumber: 7,
      packetNumberLength: 2,
      payload: rfc8448ServerHello,
    })
    const result = decryptQuicHandshakePacket(packet, keys)

    expect(result.header.firstByte).toBe(0xe1)
    expect(result.header.length).toBe(2 + rfc8448ServerHello.length + 16)
    expect(result.header.packetNumberLength).toBe(2)
    expect(result.header.packetNumber).toBe(7)
    expect(result.packetNumber).toBe(7n)
    expect(result.payload).toEqual(rfc8448ServerHello)
    expect(result.endOffset).toBe(packet.length)
  })

  test('recovers wrapped Handshake packet numbers for nonce construction', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ServerHandshakeTrafficSecret)
    const payload = new Uint8Array(16)
    const packet = encryptQuicHandshakePacket(keys, {
      destinationConnectionId: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
      sourceConnectionId: new Uint8Array([0x06, 0x07, 0x08, 0x09, 0x0a]),
      packetNumber: 256,
      packetNumberLength: 1,
      payload,
    })
    const result = decryptQuicHandshakePacket(packet, keys, 0, 256)

    expect(result.header.packetNumber).toBe(0)
    expect(result.packetNumber).toBe(256n)
    expect(result.payload).toEqual(payload)
  })

  test('unprotects and decrypts a protected Handshake packet', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)
    const packet = createProtectedHandshakePacket(keys, 1, new Uint8Array([0x00]))
    const result = decryptQuicHandshakePacket(packet, keys)

    expect(result.header.firstByte).toBe(0xe2)
    expect(result.header.length).toBe(20)
    expect(result.header.packetNumberLength).toBe(3)
    expect(result.header.packetNumber).toBe(1)
    expect(result.packetNumber).toBe(1n)
    expect(result.header.packetNumberOffset).toBe(17)
    expect(result.header.payloadOffset).toBe(20)
    expect(result.payload).toEqual(new Uint8Array([0x00]))
    expect(result.endOffset).toBe(packet.length)
  })

  test('rejects oversized Handshake connection ids', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)

    expect(() =>
      encryptQuicHandshakePacket(keys, {
        destinationConnectionId: new Uint8Array(21),
        sourceConnectionId: new Uint8Array(),
        packetNumber: 0,
        packetNumberLength: 1,
        payload: new Uint8Array(16),
      }),
    ).toThrow('QUIC destination connection id length out of range')
  })

  test('rejects truncated protected Handshake packets', () => {
    const keys = deriveQuicDirectionalKeys(rfc8448ClientHandshakeTrafficSecret)
    const packet = createProtectedHandshakePacket(keys, 1, new Uint8Array([0x00]))

    expect(() => decryptQuicHandshakePacket(packet.subarray(0, 22), keys)).toThrow(
      'not enough bytes for QUIC Handshake packet',
    )
  })
})

function createProtectedHandshakePacket(
  keys: QuicDirectionalKeys,
  packetNumber: number,
  plaintext: Uint8Array,
): Uint8Array {
  return encryptQuicHandshakePacket(keys, {
    destinationConnectionId: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
    sourceConnectionId: new Uint8Array([0x06, 0x07, 0x08, 0x09, 0x0a]),
    packetNumber,
    packetNumberLength: 3,
    payload: plaintext,
  })
}

function cryptoFrame(cryptoOffset: number, data: Uint8Array): QuicCryptoFrame {
  return {
    type: 'crypto',
    cryptoOffset,
    data,
    offset: 0,
    endOffset: data.length,
  }
}

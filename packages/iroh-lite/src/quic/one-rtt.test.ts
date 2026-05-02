import { describe, expect, test } from 'bun:test'

import { concatBytes, readU8 } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey } from '../testing/rfc8448-tls'
import { tlsHandshakeStateFixture } from '../testing/tls-handshake-fixtures'
import type { QuicDirectionalKeys } from './crypto'
import { encodeQuicPaddingFrame, encodeQuicPingFrame, parseQuicFrames } from './frame'
import {
  decryptQuicOneRttPacket,
  encryptQuicOneRttPacket,
  parseQuicOneRttPacketHeader,
  receiveQuicOneRttPacket,
} from './one-rtt'
import { deriveTls13ApplicationTrafficFromHandshakeState } from './tls-application-traffic'
import { verifyTls13ClientHandshakeState } from './tls-handshake-state'

describe('QUIC 1-RTT short-header packet foundation', () => {
  test('unprotects and decrypts a protected short-header packet', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const payload = concatBytes([encodeQuicPaddingFrame(1), encodeQuicPingFrame()])
    const packet = encryptQuicOneRttPacket(keys.server, {
      destinationConnectionId,
      packetNumber: 0x123456,
      packetNumberLength: 3,
      payload,
    })
    const result = decryptQuicOneRttPacket(packet, keys.server, destinationConnectionId.length)

    expect(result.header.firstByte).toBe(0x42)
    expect(bytesToHex(result.header.destinationConnectionId)).toBe(
      bytesToHex(destinationConnectionId),
    )
    expect(result.header.packetNumberLength).toBe(3)
    expect(result.header.packetNumber).toBe(0x123456)
    expect(result.packetNumber).toBe(0x123456n)
    expect(result.header.packetNumberOffset).toBe(5)
    expect(result.header.payloadOffset).toBe(8)
    expect(bytesToHex(result.payload)).toBe(bytesToHex(payload))
    expect(parseQuicFrames(result.payload).frames).toEqual([
      { type: 'padding', length: 1, offset: 0, endOffset: 1 },
      { type: 'ping', offset: 1, endOffset: 2 },
    ])
    expect(result.endOffset).toBe(packet.length)
  })

  test('rejects packets without the fixed bit', async () => {
    const keys = await applicationTrafficKeys()
    const packet = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId: hexToBytes('01020304'),
      packetNumber: 1,
      packetNumberLength: 3,
      payload: hexToBytes('00'),
    })
    const invalidPacket = new Uint8Array(packet)
    invalidPacket[0] = readU8(invalidPacket, 0) & ~0x40

    expect(() => decryptQuicOneRttPacket(invalidPacket, keys.client, 4)).toThrow(
      'QUIC fixed bit is not set',
    )
  })

  test('rejects long-header packets', () => {
    expect(() => parseQuicOneRttPacketHeader(hexToBytes('c000000001'), 4)).toThrow(
      'QUIC packet is not short header',
    )
  })

  test('rejects truncated destination connection ids', () => {
    expect(() => parseQuicOneRttPacketHeader(hexToBytes('400102'), 4)).toThrow(
      'not enough bytes for QUIC 1-RTT destination connection id',
    )
  })

  test('rejects truncated packet numbers', () => {
    expect(() => parseQuicOneRttPacketHeader(hexToBytes('42010203041234'), 4)).toThrow(
      'not enough bytes for QUIC packet number',
    )
  })

  test('rejects missing header protection samples', async () => {
    const keys = await applicationTrafficKeys()
    const packet = encryptQuicOneRttPacket(keys.server, {
      destinationConnectionId: hexToBytes('01020304'),
      packetNumber: 1,
      packetNumberLength: 3,
      payload: hexToBytes('00'),
    })

    expect(() => decryptQuicOneRttPacket(packet.subarray(0, 15), keys.server, 4)).toThrow(
      'not enough bytes for QUIC header protection sample',
    )
  })

  test('rejects truncated ciphertext', async () => {
    const keys = await applicationTrafficKeys()
    const packet = encryptQuicOneRttPacket(keys.server, {
      destinationConnectionId: hexToBytes('01020304'),
      packetNumber: 1,
      packetNumberLength: 3,
      payload: hexToBytes('000102030405060708090a0b0c0d0e0f'),
    })
    const truncated = packet.subarray(0, packet.length - 1)

    expect(() => decryptQuicOneRttPacket(truncated, keys.server, 4)).toThrow(
      'aes/gcm: invalid ghash tag',
    )
  })

  test('recovers the full packet number when the truncated packet number wraps', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const payload = concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()])
    const packet = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId,
      packetNumber: 0x100n,
      packetNumberLength: 1,
      payload,
    })
    const result = decryptQuicOneRttPacket(
      packet,
      keys.client,
      destinationConnectionId.length,
      0,
      0x100n,
    )

    expect(result.header.packetNumberLength).toBe(1)
    expect(result.header.packetNumber).toBe(0)
    expect(result.packetNumber).toBe(0x100n)
    expect(bytesToHex(result.payload)).toBe(bytesToHex(payload))
  })

  test('receives packets with recovered packet numbers and updated largest received state', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const payload = concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()])
    const wrappedPacket = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId,
      packetNumber: 0x100n,
      packetNumberLength: 1,
      payload,
    })
    const previousPacket = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId,
      packetNumber: 0xffn,
      packetNumberLength: 1,
      payload,
    })

    const first = receiveQuicOneRttPacket(
      wrappedPacket,
      keys.client,
      destinationConnectionId.length,
      0xffn,
    )
    const second = receiveQuicOneRttPacket(
      previousPacket,
      keys.client,
      destinationConnectionId.length,
      first.largestReceivedPacketNumber,
    )

    expect(first.packetNumber).toBe(0x100n)
    expect(first.largestReceivedPacketNumber).toBe(0x100n)
    expect(second.packetNumber).toBe(0xffn)
    expect(second.largestReceivedPacketNumber).toBe(0x100n)
  })

  test('rejects packet numbers outside the QUIC packet number range', async () => {
    const keys = await applicationTrafficKeys()
    expect(() =>
      encryptQuicOneRttPacket(keys.client, {
        destinationConnectionId: hexToBytes('01020304'),
        packetNumber: 0x4000000000000000n,
        packetNumberLength: 1,
        payload: hexToBytes('00'),
      }),
    ).toThrow('QUIC packet number out of range')
  })
})

async function applicationTrafficKeys(): Promise<{
  readonly client: QuicDirectionalKeys
  readonly server: QuicDirectionalKeys
}> {
  const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
  const state = await verifyTls13ClientHandshakeState({
    x25519PrivateKey: rfc8448ClientPrivateKey,
    expectedServerEndpointId: fixture.server.endpointId,
    messages: fixture.messages,
  })
  return deriveTls13ApplicationTrafficFromHandshakeState(state).keys
}

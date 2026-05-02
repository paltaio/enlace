import { describe, expect, test } from 'bun:test'

import { concatBytes, readU8 } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey } from '../testing/rfc8448-tls'
import { tlsHandshakeStateFixture } from '../testing/tls-handshake-fixtures'
import { QuicAckReceiveTracker } from './ack'
import type { QuicDirectionalKeys } from './crypto'
import {
  encodeQuicAckFrame,
  encodeQuicApplicationConnectionCloseFrame,
  encodeQuicPaddingFrame,
  encodeQuicPingFrame,
  encodeQuicStreamFrame,
  parseQuicFrames,
} from './frame'
import {
  decryptQuicOneRttPacket,
  encryptQuicOneRttPacket,
  parseQuicOneRttPacketHeader,
  QuicOneRttReceiveState,
  receiveQuicOneRttPacket,
  receiveQuicOneRttPacketFrames,
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

describe('QUIC 1-RTT packet frame receiving', () => {
  test('parses PING packets and emits a parser-compatible ACK', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const tracker = new QuicAckReceiveTracker()
    const packet = encryptQuicOneRttPacket(keys.server, {
      destinationConnectionId,
      packetNumber: 8,
      packetNumberLength: 2,
      payload: concatBytes([encodeQuicPaddingFrame(1), encodeQuicPingFrame()]),
    })
    const result = receiveQuicOneRttPacketFrames(
      packet,
      keys.server,
      destinationConnectionId.length,
      null,
      tracker,
      0,
      2,
    )
    const ackFrame = result.ackFrame
    if (ackFrame === null) {
      throw new Error('expected ACK frame')
    }

    expect(result.packetNumber).toBe(8n)
    expect(result.largestReceivedPacketNumber).toBe(8n)
    expect(result.ackEliciting).toBe(true)
    expect(result.ackSnapshot).toEqual({
      receivedPacketNumbers: [8n],
      largestReceivedPacketNumber: 8n,
    })
    expect(result.frames.map((frame) => frame.type)).toEqual(['padding', 'ping'])
    expect(parseQuicFrames(ackFrame).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 8n,
        ackDelay: 2,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: ackFrame.length,
      },
    ])
  })

  test('does not emit ACK for ACK-only, PADDING-only, or CONNECTION_CLOSE-only packets', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const tracker = new QuicAckReceiveTracker()
    const payloads = [
      encodeQuicAckFrame([1]),
      encodeQuicPaddingFrame(3),
      encodeQuicApplicationConnectionCloseFrame(0, new Uint8Array()),
    ]
    let largestReceivedPacketNumber: bigint | null = null

    for (const [index, payload] of payloads.entries()) {
      const packet = encryptQuicOneRttPacket(keys.client, {
        destinationConnectionId,
        packetNumber: index + 1,
        packetNumberLength: 1,
        payload,
      })
      const result = receiveQuicOneRttPacketFrames(
        packet,
        keys.client,
        destinationConnectionId.length,
        largestReceivedPacketNumber,
        tracker,
      )
      largestReceivedPacketNumber = result.largestReceivedPacketNumber

      expect(result.ackEliciting).toBe(false)
      expect(result.ackFrame).toBeNull()
    }

    expect(largestReceivedPacketNumber).toBe(3n)
    expect(tracker.snapshot()).toEqual({
      receivedPacketNumbers: [],
      largestReceivedPacketNumber: null,
    })
  })

  test('parses STREAM packets as ack-eliciting without stream state', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const tracker = new QuicAckReceiveTracker()
    const payload = encodeQuicStreamFrame(0, 0, new Uint8Array([0x68, 0x69]), false)
    const packet = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId,
      packetNumber: 11,
      packetNumberLength: 2,
      payload,
    })
    const result = receiveQuicOneRttPacketFrames(
      packet,
      keys.client,
      destinationConnectionId.length,
      null,
      tracker,
    )

    expect(result.frames[0]?.type).toBe('stream')
    expect(result.ackEliciting).toBe(true)
    expect(result.ackFrame).not.toBeNull()
    expect(result.ackSnapshot.largestReceivedPacketNumber).toBe(11n)
  })

  test('duplicate ack-eliciting packet numbers keep ACK output idempotent', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const tracker = new QuicAckReceiveTracker()
    const packet = encryptQuicOneRttPacket(keys.server, {
      destinationConnectionId,
      packetNumber: 21,
      packetNumberLength: 2,
      payload: concatBytes([encodeQuicPaddingFrame(1), encodeQuicPingFrame()]),
    })
    const first = receiveQuicOneRttPacketFrames(
      packet,
      keys.server,
      destinationConnectionId.length,
      null,
      tracker,
    )
    const second = receiveQuicOneRttPacketFrames(
      packet,
      keys.server,
      destinationConnectionId.length,
      first.largestReceivedPacketNumber,
      tracker,
    )

    expect(second.packetNumber).toBe(21n)
    expect(second.largestReceivedPacketNumber).toBe(21n)
    expect(second.ackSnapshot).toEqual(first.ackSnapshot)
    if (first.ackFrame === null || second.ackFrame === null) {
      throw new Error('expected ACK frames')
    }
    expect(bytesToHex(second.ackFrame)).toBe(bytesToHex(first.ackFrame))
  })

  test('rejects malformed frames after packet decryption', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const tracker = new QuicAckReceiveTracker()
    const packet = encryptQuicOneRttPacket(keys.server, {
      destinationConnectionId,
      packetNumber: 9,
      packetNumberLength: 2,
      payload: new Uint8Array([0x0a, 0x01, 0x05, 0xaa]),
    })

    expect(() =>
      receiveQuicOneRttPacketFrames(
        packet,
        keys.server,
        destinationConnectionId.length,
        null,
        tracker,
      ),
    ).toThrow('not enough bytes for QUIC STREAM frame data')
    expect(tracker.snapshot().receivedPacketNumbers).toEqual([])
  })
})

describe('QUIC 1-RTT receive state', () => {
  test('updates largest received and emits ACK for ack-eliciting packets', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const state = new QuicOneRttReceiveState()
    const packet = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      6,
      concatBytes([encodeQuicPaddingFrame(1), encodeQuicPingFrame()]),
    )
    const result = state.receive(packet, keys.server, destinationConnectionId.length, 0, 4)
    const ackFrame = result.ackFrame
    if (ackFrame === null) {
      throw new Error('expected ACK frame')
    }

    expect(result.packetNumber).toBe(6n)
    expect(state.largestReceivedPacketNumber).toBe(6n)
    expect(result.frames.map((frame) => frame.type)).toEqual(['padding', 'ping'])
    expect(state.ackSnapshot()).toEqual({
      receivedPacketNumbers: [6n],
      largestReceivedPacketNumber: 6n,
    })
    expect(parseQuicFrames(ackFrame).frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 6n,
        ackDelay: 4,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: ackFrame.length,
      },
    ])
  })

  test('updates largest received without ACK tracker mutation for non-ack-eliciting packets', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const state = new QuicOneRttReceiveState()

    for (const [index, payload] of [
      encodeQuicAckFrame([1]),
      encodeQuicPaddingFrame(3),
      encodeQuicApplicationConnectionCloseFrame(0, new Uint8Array()),
    ].entries()) {
      const packet = encryptTestOneRttPacket(
        keys.client,
        destinationConnectionId,
        index + 1,
        payload,
      )
      const result = state.receive(packet, keys.client, destinationConnectionId.length)

      expect(result.ackEliciting).toBe(false)
      expect(result.ackFrame).toBeNull()
    }

    expect(state.largestReceivedPacketNumber).toBe(3n)
    expect(state.ackSnapshot()).toEqual({
      receivedPacketNumbers: [],
      largestReceivedPacketNumber: null,
    })
  })

  test('keeps duplicate and out-of-order packets idempotent in ACK state', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const state = new QuicOneRttReceiveState()
    const packet3 = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      3,
      concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()]),
    )
    const packet1 = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      1,
      encodeQuicStreamFrame(0, 0, new Uint8Array([0x68, 0x69]), false),
    )

    state.receive(packet3, keys.server, destinationConnectionId.length)
    state.receive(packet1, keys.server, destinationConnectionId.length)
    const beforeDuplicate = state.ackSnapshot()
    const duplicate = state.receive(packet3, keys.server, destinationConnectionId.length)

    expect(state.largestReceivedPacketNumber).toBe(3n)
    expect(duplicate.packetNumber).toBe(3n)
    expect(state.ackSnapshot()).toEqual(beforeDuplicate)
    expect(state.ackSnapshot()).toEqual({
      receivedPacketNumbers: [3n, 1n],
      largestReceivedPacketNumber: 3n,
    })
  })

  test('uses initial largest received packet number for packet number recovery', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const state = new QuicOneRttReceiveState(0xffn)
    const packet = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId,
      packetNumber: 0x100n,
      packetNumberLength: 1,
      payload: concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()]),
    })
    const result = state.receive(packet, keys.client, destinationConnectionId.length)

    expect(result.header.packetNumber).toBe(0)
    expect(result.packetNumber).toBe(0x100n)
    expect(state.largestReceivedPacketNumber).toBe(0x100n)
    expect(state.ackSnapshot().largestReceivedPacketNumber).toBe(0x100n)
  })

  test('rejects undecryptable packets without state mutation', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const state = new QuicOneRttReceiveState()
    const validPacket = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      4,
      concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()]),
    )
    state.receive(validPacket, keys.server, destinationConnectionId.length)
    const largestReceivedPacketNumber = state.largestReceivedPacketNumber
    const ackSnapshot = state.ackSnapshot()
    const undecryptablePacket = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      5,
      concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()]),
    )
    const lastByteOffset = undecryptablePacket.length - 1
    undecryptablePacket[lastByteOffset] = readU8(undecryptablePacket, lastByteOffset) ^ 0xff

    expect(() =>
      state.receive(undecryptablePacket, keys.server, destinationConnectionId.length),
    ).toThrow('aes/gcm: invalid ghash tag')
    expect(state.largestReceivedPacketNumber).toBe(largestReceivedPacketNumber)
    expect(state.ackSnapshot()).toEqual(ackSnapshot)
  })

  test('rejects malformed frame bytes without state mutation', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const state = new QuicOneRttReceiveState()
    const validPacket = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      4,
      concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()]),
    )
    state.receive(validPacket, keys.server, destinationConnectionId.length)
    const largestReceivedPacketNumber = state.largestReceivedPacketNumber
    const ackSnapshot = state.ackSnapshot()
    const malformedPacket = encryptTestOneRttPacket(
      keys.server,
      destinationConnectionId,
      5,
      new Uint8Array([0x0a, 0x01, 0x05, 0xaa]),
    )

    expect(() =>
      state.receive(malformedPacket, keys.server, destinationConnectionId.length),
    ).toThrow('not enough bytes for QUIC STREAM frame data')
    expect(state.largestReceivedPacketNumber).toBe(largestReceivedPacketNumber)
    expect(state.ackSnapshot()).toEqual(ackSnapshot)
  })
})

function encryptTestOneRttPacket(
  keys: QuicDirectionalKeys,
  destinationConnectionId: Uint8Array,
  packetNumber: number | bigint,
  payload: Uint8Array,
): Uint8Array {
  return encryptQuicOneRttPacket(keys, {
    destinationConnectionId,
    packetNumber,
    packetNumberLength: 2,
    payload,
  })
}

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

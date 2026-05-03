import { describe, expect, test } from 'bun:test'
import { blake3 } from '@noble/hashes/blake3.js'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  decodeGossipStreamFrame,
  decodeGossipStreamHeader,
  decodeGossipTopicMessage,
  encodeGossipBroadcastMessage,
  encodeGossipStreamFrame,
  encodeGossipStreamHeader,
  encodeGossipSwarmJoinMessage,
  GossipFrameReader,
  gossipAlpn,
} from './wire'

const vector = {
  alpnHex: '2f69726f682d676f737369702f31',
  topicIdHex: '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
  streamHeaderFrameHex: '00000020101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
  joinMessageFrameHex: '0000000400000100',
  broadcastMessageFrameHex:
    '000000310100aab5d0114139f72a5670610ad1d21388f38fb6c8eac1aedab6d9f9e42006cf4f0c68656c6c6f20676f737369700000',
  broadcastPayloadHex: '68656c6c6f20676f73736970',
}

describe('gossip wire frames', () => {
  test('matches native iroh-gossip ALPN', () => {
    expect(bytesToHex(gossipAlpn)).toBe(vector.alpnHex)
  })

  test('decodes native stream header frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.streamHeaderFrameHex))
    const header = decodeGossipStreamHeader(frame.payload)

    expect(frame.bytesRead).toBe(hexToBytes(vector.streamHeaderFrameHex).length)
    expect(bytesToHex(header.topicId)).toBe(vector.topicIdHex)
  })

  test('encodes native stream header frame', () => {
    expect(bytesToHex(encodeGossipStreamHeader({ topicId: hexToBytes(vector.topicIdHex) }))).toBe(
      vector.streamHeaderFrameHex,
    )
  })

  test('decodes native join message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.joinMessageFrameHex))
    const message = decodeGossipTopicMessage(frame.payload)

    expect(message).toEqual({
      layer: 'swarm',
      type: 'join',
      peerData: new Uint8Array(),
    })
  })

  test('encodes native join message frame', () => {
    expect(bytesToHex(encodeGossipSwarmJoinMessage())).toBe(vector.joinMessageFrameHex)
  })

  test('decodes native broadcast message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.broadcastMessageFrameHex))
    const message = decodeGossipTopicMessage(frame.payload)
    const payload = hexToBytes(vector.broadcastPayloadHex)

    expect(message.layer).toBe('gossip')
    expect(message.type).toBe('gossip')
    if (message.layer !== 'gossip') {
      throw new Error('expected gossip message')
    }
    expect(message.content).toEqual(payload)
    expect(message.scope).toEqual({ type: 'swarm', round: 0 })
    expect(message.id).toEqual(blake3(payload))
  })

  test('encodes native broadcast message frame', () => {
    expect(
      bytesToHex(encodeGossipBroadcastMessage({ content: hexToBytes(vector.broadcastPayloadHex) })),
    ).toBe(vector.broadcastMessageFrameHex)
  })

  test('reads frames from arbitrary stream chunks', async () => {
    const frames = concatFrames([
      encodeGossipStreamFrame(new Uint8Array([1, 2, 3])),
      encodeGossipStreamFrame(new Uint8Array([4])),
    ])
    const reader = new GossipFrameReader(
      chunkedStream([
        frames.subarray(0, 2),
        frames.subarray(2, 7),
        frames.subarray(7),
        new Uint8Array(),
      ]),
    )

    expect(await reader.readFrame()).toEqual(new Uint8Array([1, 2, 3]))
    expect(await reader.readFrame()).toEqual(new Uint8Array([4]))
    expect(await reader.readFrame()).toBeNull()
  })

  test('rejects oversized frames', async () => {
    const reader = new GossipFrameReader(
      chunkedStream([encodeGossipStreamFrame(new Uint8Array(2))]),
      {
        maxFrameSize: 1,
      },
    )

    await expect(reader.readFrame()).rejects.toThrow('gossip stream frame exceeds max size')
  })

  test('rejects incomplete final frames', async () => {
    const reader = new GossipFrameReader(chunkedStream([hexToBytes('00000002ff')]))

    await expect(reader.readFrame()).rejects.toThrow('incomplete gossip stream frame')
  })
})

function concatFrames(frames: readonly Uint8Array[]): Uint8Array {
  const length = frames.reduce((sum, frame) => sum + frame.length, 0)
  const out = new Uint8Array(length)
  let offset = 0
  for (const frame of frames) {
    out.set(frame, offset)
    offset += frame.length
  }
  return out
}

function chunkedStream(chunks: readonly Uint8Array[]): {
  read(): Promise<{ readonly data: Uint8Array; readonly complete: boolean }>
} {
  const queue = [...chunks]
  return {
    async read(): Promise<{ readonly data: Uint8Array; readonly complete: boolean }> {
      const data = queue.shift() ?? new Uint8Array()
      return {
        data,
        complete: queue.length === 0,
      }
    },
  }
}

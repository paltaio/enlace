import { describe, expect, test } from 'bun:test'
import { blake3 } from '@noble/hashes/blake3.js'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  decodeGossipStreamFrame,
  decodeGossipStreamHeader,
  decodeGossipTopicMessage,
  encodeGossipBroadcastMessage,
  encodeGossipGraftMessage,
  encodeGossipIHaveMessage,
  encodeGossipPruneMessage,
  encodeGossipSwarmDisconnectMessage,
  encodeGossipSwarmForwardJoinMessage,
  encodeGossipStreamFrame,
  encodeGossipStreamHeader,
  encodeGossipSwarmJoinMessage,
  encodeGossipSwarmNeighborMessage,
  encodeGossipSwarmShuffleMessage,
  encodeGossipSwarmShuffleReplyMessage,
  GossipFrameReader,
  GossipTopicStreamWriter,
  gossipAlpn,
} from './wire'

const vector = {
  alpnHex: '2f69726f682d676f737369702f31',
  topicIdHex: '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
  streamHeaderFrameHex: '00000020101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
  joinMessageFrameHex: '0000000400000100',
  relayJoinMessageFrameHex:
    '000000210000011d011a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f00',
  neighborMessageFrameHex: '000000050004000100',
  forwardJoinMessageFrameHex:
    '000000250001ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1010006',
  shuffleMessageFrameHex:
    '0000004600028a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c010006',
  shuffleReplyMessageFrameHex:
    '000000250003018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0100',
  disconnectMessageFrameHex: '0000000400050000',
  broadcastMessageFrameHex:
    '000000310100aab5d0114139f72a5670610ad1d21388f38fb6c8eac1aedab6d9f9e42006cf4f0c68656c6c6f20676f737369700000',
  pruneMessageFrameHex: '000000020101',
  ihaveMessageFrameHex:
    '00000024010301283d8b10fc0413e78cb9eb40037257fc8a8cbac07b6ed30d6e77d134ee79176f00',
  graftMessageFrameHex:
    '00000024010201283d8b10fc0413e78cb9eb40037257fc8a8cbac07b6ed30d6e77d134ee79176f00',
  broadcastPayloadHex: '68656c6c6f20676f73736970',
  repairPayloadHex: '72657061697220676f73736970',
  relayPeerDataHex: '011a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f00',
  peerAHex: '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
  peerCHex: 'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1',
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

  test('encodes native join message frame with relay peer data', () => {
    expect(bytesToHex(encodeGossipSwarmJoinMessage(hexToBytes(vector.relayPeerDataHex)))).toBe(
      vector.relayJoinMessageFrameHex,
    )
  })

  test('decodes native join message frame with relay peer data', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.relayJoinMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'swarm',
      type: 'join',
      peerData: hexToBytes(vector.relayPeerDataHex),
    })
  })

  test('decodes native neighbor message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.neighborMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'swarm',
      type: 'neighbor',
      priority: 'high',
      peerData: new Uint8Array(),
    })
  })

  test('encodes native neighbor message frame', () => {
    expect(
      bytesToHex(
        encodeGossipSwarmNeighborMessage({ priority: 'high', peerData: new Uint8Array() }),
      ),
    ).toBe(vector.neighborMessageFrameHex)
  })

  test('decodes native forward join message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.forwardJoinMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'swarm',
      type: 'forward-join',
      peer: { id: hexToBytes(vector.peerCHex), peerData: new Uint8Array() },
      ttl: 6,
    })
  })

  test('encodes native forward join message frame', () => {
    expect(
      bytesToHex(
        encodeGossipSwarmForwardJoinMessage({
          peer: { id: hexToBytes(vector.peerCHex), peerData: new Uint8Array() },
          ttl: 6,
        }),
      ),
    ).toBe(vector.forwardJoinMessageFrameHex)
  })

  test('decodes native shuffle message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.shuffleMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'swarm',
      type: 'shuffle',
      origin: hexToBytes(vector.peerAHex),
      nodes: [{ id: hexToBytes(vector.peerAHex), peerData: new Uint8Array() }],
      ttl: 6,
    })
  })

  test('encodes native shuffle message frame', () => {
    expect(
      bytesToHex(
        encodeGossipSwarmShuffleMessage({
          origin: hexToBytes(vector.peerAHex),
          nodes: [{ id: hexToBytes(vector.peerAHex), peerData: new Uint8Array() }],
          ttl: 6,
        }),
      ),
    ).toBe(vector.shuffleMessageFrameHex)
  })

  test('decodes native shuffle reply message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.shuffleReplyMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'swarm',
      type: 'shuffle-reply',
      nodes: [{ id: hexToBytes(vector.peerAHex), peerData: new Uint8Array() }],
    })
  })

  test('encodes native shuffle reply message frame', () => {
    expect(
      bytesToHex(
        encodeGossipSwarmShuffleReplyMessage({
          nodes: [{ id: hexToBytes(vector.peerAHex), peerData: new Uint8Array() }],
        }),
      ),
    ).toBe(vector.shuffleReplyMessageFrameHex)
  })

  test('decodes native disconnect message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.disconnectMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'swarm',
      type: 'disconnect',
      alive: false,
      respond: false,
    })
  })

  test('encodes native disconnect message frame', () => {
    expect(bytesToHex(encodeGossipSwarmDisconnectMessage({ alive: false }))).toBe(
      vector.disconnectMessageFrameHex,
    )
  })

  test('decodes native broadcast message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.broadcastMessageFrameHex))
    const message = decodeGossipTopicMessage(frame.payload)
    const payload = hexToBytes(vector.broadcastPayloadHex)

    expect(message.layer).toBe('gossip')
    expect(message.type).toBe('gossip')
    if (message.type !== 'gossip') {
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

  test('decodes native prune message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.pruneMessageFrameHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'gossip',
      type: 'prune',
    })
  })

  test('encodes native prune message frame', () => {
    expect(bytesToHex(encodeGossipPruneMessage())).toBe(vector.pruneMessageFrameHex)
  })

  test('decodes native ihave message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.ihaveMessageFrameHex))
    const id = blake3(hexToBytes(vector.repairPayloadHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'gossip',
      type: 'ihave',
      messages: [{ id, round: 0 }],
    })
  })

  test('encodes native ihave message frame', () => {
    const id = blake3(hexToBytes(vector.repairPayloadHex))

    expect(bytesToHex(encodeGossipIHaveMessage({ messages: [{ id, round: 0 }] }))).toBe(
      vector.ihaveMessageFrameHex,
    )
  })

  test('decodes native graft message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.graftMessageFrameHex))
    const id = blake3(hexToBytes(vector.repairPayloadHex))

    expect(decodeGossipTopicMessage(frame.payload)).toEqual({
      layer: 'gossip',
      type: 'graft',
      id,
      round: 0,
    })
  })

  test('encodes native graft message frame', () => {
    const id = blake3(hexToBytes(vector.repairPayloadHex))

    expect(bytesToHex(encodeGossipGraftMessage({ id, round: 0 }))).toBe(vector.graftMessageFrameHex)
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

  test('writes topic header once before message frames', () => {
    const writes: Array<{ readonly data: Uint8Array; readonly fin: boolean }> = []
    const writer = new GossipTopicStreamWriter(
      {
        write(data, options = {}) {
          writes.push({ data, fin: options.fin ?? false })
        },
      },
      hexToBytes(vector.topicIdHex),
    )

    writer.writeFrame(encodeGossipSwarmJoinMessage())
    writer.writeFrame(
      encodeGossipBroadcastMessage({ content: hexToBytes(vector.broadcastPayloadHex) }),
    )
    writer.finish()

    expect(writes).toEqual([
      {
        data: encodeGossipStreamHeader({ topicId: hexToBytes(vector.topicIdHex) }),
        fin: false,
      },
      { data: encodeGossipSwarmJoinMessage(), fin: false },
      {
        data: encodeGossipBroadcastMessage({ content: hexToBytes(vector.broadcastPayloadHex) }),
        fin: false,
      },
      { data: new Uint8Array(), fin: true },
    ])
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

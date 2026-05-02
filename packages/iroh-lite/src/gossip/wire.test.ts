import { describe, expect, test } from 'bun:test'
import { blake3 } from '@noble/hashes/blake3.js'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  decodeGossipStreamFrame,
  decodeGossipStreamHeader,
  decodeGossipTopicMessage,
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

  test('decodes native join message frame', () => {
    const frame = decodeGossipStreamFrame(hexToBytes(vector.joinMessageFrameHex))
    const message = decodeGossipTopicMessage(frame.payload)

    expect(message).toEqual({
      layer: 'swarm',
      type: 'join',
      peerData: new Uint8Array(),
    })
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
})

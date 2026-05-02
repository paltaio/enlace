import { copyBytes, decodePostcardLen, readU32BE } from '../bytes'

export const gossipAlpn = new TextEncoder().encode('/iroh-gossip/1')

export interface GossipStreamFrame {
  readonly payload: Uint8Array
  readonly bytesRead: number
}

export interface GossipStreamHeader {
  readonly topicId: Uint8Array
}

export type GossipTopicMessage = GossipSwarmJoinMessage | GossipBroadcastMessage

export interface GossipSwarmJoinMessage {
  readonly layer: 'swarm'
  readonly type: 'join'
  readonly peerData: Uint8Array | null
}

export interface GossipBroadcastMessage {
  readonly layer: 'gossip'
  readonly type: 'gossip'
  readonly id: Uint8Array
  readonly content: Uint8Array
  readonly scope: GossipDeliveryScope
}

export type GossipDeliveryScope = GossipSwarmDeliveryScope | GossipNeighborDeliveryScope

export interface GossipSwarmDeliveryScope {
  readonly type: 'swarm'
  readonly round: number
}

export interface GossipNeighborDeliveryScope {
  readonly type: 'neighbors'
}

export function decodeGossipStreamFrame(bytes: Uint8Array, offset = 0): GossipStreamFrame {
  const length = readU32BE(bytes, offset)
  const payloadOffset = offset + 4
  const endOffset = payloadOffset + length
  if (endOffset > bytes.length) {
    throw new RangeError('not enough bytes for gossip stream frame')
  }
  return {
    payload: copyBytes(bytes.subarray(payloadOffset, endOffset)),
    bytesRead: endOffset - offset,
  }
}

export function decodeGossipStreamHeader(payload: Uint8Array): GossipStreamHeader {
  if (payload.length !== 32) {
    throw new RangeError('gossip stream header must be 32 bytes')
  }
  return { topicId: copyBytes(payload) }
}

export function decodeGossipTopicMessage(payload: Uint8Array): GossipTopicMessage {
  const reader = new PostcardReader(payload)
  const layer = reader.variant()
  if (layer === 0) {
    return decodeSwarmMessage(reader)
  }
  if (layer === 1) {
    return decodeGossipMessage(reader)
  }
  throw new RangeError(`unsupported gossip topic message layer ${layer}`)
}

function decodeSwarmMessage(reader: PostcardReader): GossipSwarmJoinMessage {
  const variant = reader.variant()
  if (variant !== 0) {
    throw new RangeError(`unsupported gossip swarm message variant ${variant}`)
  }
  const option = reader.variant()
  if (option === 0) {
    reader.requireDone()
    return { layer: 'swarm', type: 'join', peerData: null }
  }
  if (option === 1) {
    const peerData = reader.bytes()
    reader.requireDone()
    return { layer: 'swarm', type: 'join', peerData }
  }
  throw new RangeError(`unsupported gossip join peer data option ${option}`)
}

function decodeGossipMessage(reader: PostcardReader): GossipBroadcastMessage {
  const variant = reader.variant()
  if (variant !== 0) {
    throw new RangeError(`unsupported gossip broadcast message variant ${variant}`)
  }
  const id = reader.fixedBytes(32)
  const content = reader.bytes()
  const scope = decodeDeliveryScope(reader)
  reader.requireDone()
  return {
    layer: 'gossip',
    type: 'gossip',
    id,
    content,
    scope,
  }
}

function decodeDeliveryScope(reader: PostcardReader): GossipDeliveryScope {
  const variant = reader.variant()
  if (variant === 0) {
    return { type: 'swarm', round: reader.uint() }
  }
  if (variant === 1) {
    return { type: 'neighbors' }
  }
  throw new RangeError(`unsupported gossip delivery scope ${variant}`)
}

class PostcardReader {
  readonly #bytes: Uint8Array
  #offset = 0

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes
  }

  variant(): number {
    return this.uint()
  }

  uint(): number {
    const decoded = decodePostcardLen(this.#bytes, this.#offset)
    this.#offset += decoded.bytesRead
    return decoded.value
  }

  bytes(): Uint8Array {
    const length = this.uint()
    return this.fixedBytes(length)
  }

  fixedBytes(length: number): Uint8Array {
    const endOffset = this.#offset + length
    if (endOffset > this.#bytes.length) {
      throw new RangeError('not enough bytes for postcard bytes')
    }
    const out = copyBytes(this.#bytes.subarray(this.#offset, endOffset))
    this.#offset = endOffset
    return out
  }

  requireDone(): void {
    if (this.#offset !== this.#bytes.length) {
      throw new RangeError('trailing bytes in postcard message')
    }
  }
}

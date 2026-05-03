import { blake3 } from '@noble/hashes/blake3.js'

import {
  concatBytes,
  copyBytes,
  decodePostcardLen,
  encodePostcardLen,
  readU32BE,
  requireLength,
  writeU32BE,
} from '../bytes'

export const gossipAlpn = new TextEncoder().encode('/iroh-gossip/1')

export interface GossipStreamFrame {
  readonly payload: Uint8Array
  readonly bytesRead: number
}

export interface GossipStreamHeader {
  readonly topicId: Uint8Array
}

export interface GossipStreamRead {
  readonly data: Uint8Array
  readonly complete: boolean
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

export interface GossipBroadcastMessageInput {
  readonly content: Uint8Array
  readonly scope?: GossipDeliveryScope
}

export function encodeGossipStreamFrame(payload: Uint8Array): Uint8Array {
  return concatBytes([writeU32BE(payload.length), payload])
}

export function encodeGossipStreamHeader(header: GossipStreamHeader): Uint8Array {
  return encodeGossipStreamFrame(validateGossipTopicId(header.topicId))
}

export function encodeGossipSwarmJoinMessage(peerData = new Uint8Array()): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(0),
      encodePostcardLen(0),
      encodePostcardLen(1),
      encodePostcardLen(peerData.length),
      peerData,
    ]),
  )
}

export function encodeGossipBroadcastMessage(message: GossipBroadcastMessageInput): Uint8Array {
  const content = copyBytes(message.content)
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(1),
      encodePostcardLen(0),
      blake3(content),
      encodePostcardLen(content.length),
      content,
      encodeDeliveryScope(message.scope ?? { type: 'swarm', round: 0 }),
    ]),
  )
}

export function validateGossipTopicId(topicId: Uint8Array): Uint8Array {
  requireLength(topicId, 32, 'gossip topic id')
  return copyBytes(topicId)
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

export class GossipFrameReader {
  readonly #stream: { read(): Promise<GossipStreamRead> }
  readonly #maxFrameSize: number
  #buffer: Uint8Array<ArrayBufferLike> = new Uint8Array()
  #complete = false

  constructor(
    stream: { read(): Promise<GossipStreamRead> },
    options: { readonly maxFrameSize?: number } = {},
  ) {
    this.#stream = stream
    this.#maxFrameSize = options.maxFrameSize ?? 65536
  }

  async readFrame(): Promise<Uint8Array | null> {
    while (true) {
      const payload = this.tryReadBufferedFrame()
      if (payload !== null) {
        return payload
      }
      if (this.#complete) {
        if (this.#buffer.length !== 0) {
          throw new RangeError('incomplete gossip stream frame')
        }
        return null
      }
      const chunk = await this.#stream.read()
      if (chunk.data.length !== 0) {
        this.#buffer = concatBytes([this.#buffer, chunk.data])
      }
      this.#complete = chunk.complete
    }
  }

  private tryReadBufferedFrame(): Uint8Array | null {
    if (this.#buffer.length < 4) {
      return null
    }
    const length = readU32BE(this.#buffer, 0)
    if (length > this.#maxFrameSize) {
      throw new RangeError('gossip stream frame exceeds max size')
    }
    const endOffset = 4 + length
    if (this.#buffer.length < endOffset) {
      return null
    }
    const payload = copyBytes(this.#buffer.subarray(4, endOffset))
    this.#buffer = copyBytes(this.#buffer.subarray(endOffset))
    return payload
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

function encodeDeliveryScope(scope: GossipDeliveryScope): Uint8Array {
  if (scope.type === 'swarm') {
    return concatBytes([encodePostcardLen(0), encodePostcardLen(scope.round)])
  }
  return encodePostcardLen(1)
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

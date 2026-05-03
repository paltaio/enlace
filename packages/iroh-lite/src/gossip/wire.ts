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

export interface GossipStreamWrite {
  write(data: Uint8Array, options?: { readonly fin?: boolean }): void
}

export type GossipTopicMessage =
  | GossipSwarmJoinMessage
  | GossipSwarmForwardJoinMessage
  | GossipSwarmShuffleMessage
  | GossipSwarmShuffleReplyMessage
  | GossipSwarmNeighborMessage
  | GossipSwarmDisconnectMessage
  | GossipBroadcastMessage
  | GossipPruneMessage
  | GossipGraftMessage
  | GossipIHaveMessage

export interface GossipSwarmJoinMessage {
  readonly layer: 'swarm'
  readonly type: 'join'
  readonly peerData: Uint8Array | null
}

export interface GossipPeerInfo {
  readonly id: Uint8Array
  readonly peerData: Uint8Array | null
}

export interface GossipSwarmForwardJoinMessage {
  readonly layer: 'swarm'
  readonly type: 'forward-join'
  readonly peer: GossipPeerInfo
  readonly ttl: number
}

export interface GossipSwarmShuffleMessage {
  readonly layer: 'swarm'
  readonly type: 'shuffle'
  readonly origin: Uint8Array
  readonly nodes: readonly GossipPeerInfo[]
  readonly ttl: number
}

export interface GossipSwarmShuffleReplyMessage {
  readonly layer: 'swarm'
  readonly type: 'shuffle-reply'
  readonly nodes: readonly GossipPeerInfo[]
}

export interface GossipSwarmNeighborMessage {
  readonly layer: 'swarm'
  readonly type: 'neighbor'
  readonly priority: GossipSwarmNeighborPriority
  readonly peerData: Uint8Array | null
}

export type GossipSwarmNeighborPriority = 'high' | 'low'

export interface GossipSwarmDisconnectMessage {
  readonly layer: 'swarm'
  readonly type: 'disconnect'
  readonly alive: boolean
  readonly respond: boolean
}

export interface GossipBroadcastMessage {
  readonly layer: 'gossip'
  readonly type: 'gossip'
  readonly id: Uint8Array
  readonly content: Uint8Array
  readonly scope: GossipDeliveryScope
}

export interface GossipPruneMessage {
  readonly layer: 'gossip'
  readonly type: 'prune'
}

export interface GossipGraftMessage {
  readonly layer: 'gossip'
  readonly type: 'graft'
  readonly id: Uint8Array | null
  readonly round: number
}

export interface GossipIHaveMessage {
  readonly layer: 'gossip'
  readonly type: 'ihave'
  readonly messages: readonly GossipIHaveEntry[]
}

export interface GossipIHaveEntry {
  readonly id: Uint8Array
  readonly round: number
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
    concatBytes([encodePostcardLen(0), encodePostcardLen(0), encodeOptionalPeerData(peerData)]),
  )
}

export function encodeGossipSwarmForwardJoinMessage(message: {
  readonly peer: GossipPeerInfo
  readonly ttl: number
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(0),
      encodePostcardLen(1),
      encodePeerInfo(message.peer),
      encodePostcardLen(message.ttl),
    ]),
  )
}

export function encodeGossipSwarmShuffleMessage(message: {
  readonly origin: Uint8Array
  readonly nodes: readonly GossipPeerInfo[]
  readonly ttl: number
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(0),
      encodePostcardLen(2),
      validatePeerId(message.origin),
      encodePostcardLen(message.nodes.length),
      ...message.nodes.map(encodePeerInfo),
      encodePostcardLen(message.ttl),
    ]),
  )
}

export function encodeGossipSwarmShuffleReplyMessage(message: {
  readonly nodes: readonly GossipPeerInfo[]
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(0),
      encodePostcardLen(3),
      encodePostcardLen(message.nodes.length),
      ...message.nodes.map(encodePeerInfo),
    ]),
  )
}

export function encodeGossipSwarmNeighborMessage(message: {
  readonly priority: GossipSwarmNeighborPriority
  readonly peerData: Uint8Array | null
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(0),
      encodePostcardLen(4),
      encodeNeighborPriority(message.priority),
      encodeOptionalPeerData(message.peerData),
    ]),
  )
}

export function encodeGossipSwarmDisconnectMessage(message: {
  readonly alive: boolean
  readonly respond?: boolean
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(0),
      encodePostcardLen(5),
      encodeBool(message.alive),
      encodeBool(message.respond ?? false),
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

export function encodeGossipPruneMessage(): Uint8Array {
  return encodeGossipStreamFrame(concatBytes([encodePostcardLen(1), encodePostcardLen(1)]))
}

export function encodeGossipGraftMessage(message: {
  readonly id: Uint8Array | null
  readonly round: number
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(1),
      encodePostcardLen(2),
      encodeOptionalMessageId(message.id),
      encodePostcardLen(message.round),
    ]),
  )
}

export function encodeGossipIHaveMessage(message: {
  readonly messages: readonly GossipIHaveEntry[]
}): Uint8Array {
  return encodeGossipStreamFrame(
    concatBytes([
      encodePostcardLen(1),
      encodePostcardLen(3),
      encodePostcardLen(message.messages.length),
      ...message.messages.map(encodeIHaveEntry),
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

export class GossipTopicStreamWriter {
  readonly #stream: GossipStreamWrite
  #closed = false

  constructor(stream: GossipStreamWrite, topicId: Uint8Array) {
    this.#stream = stream
    this.#stream.write(encodeGossipStreamHeader({ topicId }))
  }

  writeFrame(frame: Uint8Array): void {
    this.requireOpen()
    this.#stream.write(frame)
  }

  finish(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    this.#stream.write(new Uint8Array(), { fin: true })
  }

  private requireOpen(): void {
    if (this.#closed) {
      throw new Error('gossip topic stream writer is closed')
    }
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

function decodeSwarmMessage(
  reader: PostcardReader,
):
  | GossipSwarmJoinMessage
  | GossipSwarmForwardJoinMessage
  | GossipSwarmShuffleMessage
  | GossipSwarmShuffleReplyMessage
  | GossipSwarmNeighborMessage
  | GossipSwarmDisconnectMessage {
  const variant = reader.variant()
  if (variant === 0) {
    return decodeSwarmJoinMessage(reader)
  }
  if (variant === 1) {
    return decodeSwarmForwardJoinMessage(reader)
  }
  if (variant === 2) {
    return decodeSwarmShuffleMessage(reader)
  }
  if (variant === 3) {
    return decodeSwarmShuffleReplyMessage(reader)
  }
  if (variant === 4) {
    return decodeSwarmNeighborMessage(reader)
  }
  if (variant === 5) {
    return decodeSwarmDisconnectMessage(reader)
  }
  throw new RangeError(`unsupported gossip swarm message variant ${variant}`)
}

function decodeSwarmJoinMessage(reader: PostcardReader): GossipSwarmJoinMessage {
  const peerData = decodeOptionalPeerData(reader)
  reader.requireDone()
  return { layer: 'swarm', type: 'join', peerData }
}

function decodeSwarmForwardJoinMessage(reader: PostcardReader): GossipSwarmForwardJoinMessage {
  const peer = decodePeerInfo(reader)
  const ttl = reader.uint()
  reader.requireDone()
  return { layer: 'swarm', type: 'forward-join', peer, ttl }
}

function decodeSwarmShuffleMessage(reader: PostcardReader): GossipSwarmShuffleMessage {
  const origin = reader.fixedBytes(32)
  const nodes = decodePeerInfoVec(reader)
  const ttl = reader.uint()
  reader.requireDone()
  return { layer: 'swarm', type: 'shuffle', origin, nodes, ttl }
}

function decodeSwarmShuffleReplyMessage(reader: PostcardReader): GossipSwarmShuffleReplyMessage {
  const nodes = decodePeerInfoVec(reader)
  reader.requireDone()
  return { layer: 'swarm', type: 'shuffle-reply', nodes }
}

function decodeSwarmNeighborMessage(reader: PostcardReader): GossipSwarmNeighborMessage {
  const priority = decodeNeighborPriority(reader)
  const peerData = decodeOptionalPeerData(reader)
  reader.requireDone()
  return { layer: 'swarm', type: 'neighbor', priority, peerData }
}

function decodeSwarmDisconnectMessage(reader: PostcardReader): GossipSwarmDisconnectMessage {
  const alive = reader.bool()
  const respond = reader.bool()
  reader.requireDone()
  return { layer: 'swarm', type: 'disconnect', alive, respond }
}

function decodeGossipMessage(
  reader: PostcardReader,
): GossipBroadcastMessage | GossipPruneMessage | GossipGraftMessage | GossipIHaveMessage {
  const variant = reader.variant()
  if (variant === 0) {
    return decodeGossipBroadcastMessage(reader)
  }
  if (variant === 1) {
    reader.requireDone()
    return { layer: 'gossip', type: 'prune' }
  }
  if (variant === 2) {
    return decodeGossipGraftMessage(reader)
  }
  if (variant === 3) {
    return decodeGossipIHaveMessage(reader)
  }
  throw new RangeError(`unsupported gossip broadcast message variant ${variant}`)
}

function decodeGossipBroadcastMessage(reader: PostcardReader): GossipBroadcastMessage {
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

function decodeGossipGraftMessage(reader: PostcardReader): GossipGraftMessage {
  const id = decodeOptionalMessageId(reader)
  const round = reader.uint()
  reader.requireDone()
  return { layer: 'gossip', type: 'graft', id, round }
}

function decodeGossipIHaveMessage(reader: PostcardReader): GossipIHaveMessage {
  const length = reader.uint()
  const messages: GossipIHaveEntry[] = []
  for (let index = 0; index < length; index += 1) {
    messages.push({
      id: reader.fixedBytes(32),
      round: reader.uint(),
    })
  }
  reader.requireDone()
  return { layer: 'gossip', type: 'ihave', messages }
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

function encodeOptionalMessageId(id: Uint8Array | null): Uint8Array {
  if (id === null) {
    return encodePostcardLen(0)
  }
  return concatBytes([encodePostcardLen(1), validateMessageId(id)])
}

function encodeOptionalPeerData(peerData: Uint8Array | null): Uint8Array {
  if (peerData === null) {
    return encodePostcardLen(0)
  }
  return concatBytes([encodePostcardLen(1), encodePostcardLen(peerData.length), peerData])
}

function decodeOptionalPeerData(reader: PostcardReader): Uint8Array | null {
  const option = reader.variant()
  if (option === 0) {
    return null
  }
  if (option === 1) {
    return reader.bytes()
  }
  throw new RangeError(`unsupported gossip peer data option ${option}`)
}

function encodePeerInfo(peer: GossipPeerInfo): Uint8Array {
  return concatBytes([validatePeerId(peer.id), encodeOptionalPeerData(peer.peerData)])
}

function decodePeerInfo(reader: PostcardReader): GossipPeerInfo {
  return {
    id: reader.fixedBytes(32),
    peerData: decodeOptionalPeerData(reader),
  }
}

function decodePeerInfoVec(reader: PostcardReader): readonly GossipPeerInfo[] {
  const length = reader.uint()
  const peers: GossipPeerInfo[] = []
  for (let index = 0; index < length; index += 1) {
    peers.push(decodePeerInfo(reader))
  }
  return peers
}

function encodeNeighborPriority(priority: GossipSwarmNeighborPriority): Uint8Array {
  if (priority === 'high') {
    return encodePostcardLen(0)
  }
  return encodePostcardLen(1)
}

function decodeNeighborPriority(reader: PostcardReader): GossipSwarmNeighborPriority {
  const variant = reader.variant()
  if (variant === 0) {
    return 'high'
  }
  if (variant === 1) {
    return 'low'
  }
  throw new RangeError(`unsupported gossip neighbor priority ${variant}`)
}

function encodeBool(value: boolean): Uint8Array {
  return new Uint8Array([value ? 1 : 0])
}

function decodeOptionalMessageId(reader: PostcardReader): Uint8Array | null {
  const option = reader.variant()
  if (option === 0) {
    return null
  }
  if (option === 1) {
    return reader.fixedBytes(32)
  }
  throw new RangeError(`unsupported gossip message id option ${option}`)
}

function encodeIHaveEntry(message: GossipIHaveEntry): Uint8Array {
  return concatBytes([validateMessageId(message.id), encodePostcardLen(message.round)])
}

function validateMessageId(id: Uint8Array): Uint8Array {
  requireLength(id, 32, 'gossip message id')
  return copyBytes(id)
}

function validatePeerId(id: Uint8Array): Uint8Array {
  requireLength(id, 32, 'gossip peer id')
  return copyBytes(id)
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

  bool(): boolean {
    const value = this.fixedByte()
    if (value === 0) {
      return false
    }
    if (value === 1) {
      return true
    }
    throw new RangeError(`unsupported postcard bool ${value}`)
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

  private fixedByte(): number {
    const value = this.#bytes[this.#offset]
    if (value === undefined) {
      throw new RangeError('not enough bytes for postcard byte')
    }
    this.#offset += 1
    return value
  }

  requireDone(): void {
    if (this.#offset !== this.#bytes.length) {
      throw new RangeError('trailing bytes in postcard message')
    }
  }
}

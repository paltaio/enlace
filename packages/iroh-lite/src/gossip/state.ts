import { blake3 } from '@noble/hashes/blake3.js'

import { copyBytes, requireLength } from '../bytes'
import {
  validateGossipTopicId,
  type GossipBroadcastMessage,
  type GossipDeliveryScope,
  type GossipIHaveEntry,
  type GossipPeerInfo,
  type GossipTopicMessage,
} from './wire'

const lazyDispatchDelayMs = 5
const graftTimeoutMs = 80
const retryGraftTimeoutMs = 40
const messageCacheRetentionMs = 30_000
const messageIdRetentionMs = 90_000
const activeViewCapacity = 5
const passiveViewCapacity = 30
const activeRandomWalkLength = 6
const passiveRandomWalkLength = 3
const pendingNeighborTimeoutMs = 500
const defaultMaxMessageSize = 4096
const minMaxMessageSize = 512
const ihaveEntryMaxEncodedSize = 35

export interface GossipProtocolStateOptions {
  readonly me: Uint8Array
  readonly peerData?: Uint8Array | null
  readonly maxMessageSize?: number
  readonly activeViewCapacity?: number
  readonly passiveViewCapacity?: number
}

export type GossipProtocolInEvent =
  | GossipProtocolRecvMessage
  | GossipProtocolCommandEvent
  | GossipProtocolTimerExpired
  | GossipProtocolPeerDisconnected
  | GossipProtocolUpdatePeerData

export interface GossipProtocolRecvMessage {
  readonly type: 'recv-message'
  readonly peer: Uint8Array
  readonly topicId: Uint8Array
  readonly message: GossipTopicMessage
}

export interface GossipProtocolCommandEvent {
  readonly type: 'command'
  readonly topicId: Uint8Array
  readonly command: GossipProtocolCommand
}

export type GossipProtocolCommand =
  | { readonly type: 'join'; readonly peers: readonly Uint8Array[] }
  | {
      readonly type: 'broadcast'
      readonly payload: Uint8Array
      readonly scope?: GossipBroadcastScope
    }
  | { readonly type: 'quit' }

export type GossipBroadcastScope = 'swarm' | 'neighbors'

export interface GossipProtocolTimerExpired {
  readonly type: 'timer-expired'
  readonly timer: GossipProtocolTimer
}

export interface GossipProtocolTimer {
  readonly topicId: Uint8Array
  readonly value: unknown
}

export interface GossipProtocolPeerDisconnected {
  readonly type: 'peer-disconnected'
  readonly peer: Uint8Array
}

export interface GossipProtocolUpdatePeerData {
  readonly type: 'update-peer-data'
  readonly peerData: Uint8Array | null
}

export type GossipProtocolOutEvent =
  | GossipProtocolSendMessage
  | GossipProtocolEmitEvent
  | GossipProtocolScheduleTimer
  | GossipProtocolDisconnectPeer
  | GossipProtocolPeerData

export interface GossipProtocolSendMessage {
  readonly type: 'send-message'
  readonly peer: Uint8Array
  readonly topicId: Uint8Array
  readonly message: GossipTopicMessage
}

export interface GossipProtocolEmitEvent {
  readonly type: 'emit-event'
  readonly topicId: Uint8Array
  readonly event: GossipProtocolTopicEvent
}

export type GossipProtocolTopicEvent =
  | { readonly type: 'neighbor-up'; readonly peer: Uint8Array }
  | { readonly type: 'neighbor-down'; readonly peer: Uint8Array }
  | {
      readonly type: 'received'
      readonly deliveredFrom: Uint8Array
      readonly id: Uint8Array
      readonly payload: Uint8Array
      readonly scope: GossipDeliveryScope
    }

export interface GossipProtocolScheduleTimer {
  readonly type: 'schedule-timer'
  readonly delayMs: number
  readonly timer: GossipProtocolTimer
}

export interface GossipProtocolDisconnectPeer {
  readonly type: 'disconnect-peer'
  readonly peer: Uint8Array
}

export interface GossipProtocolPeerData {
  readonly type: 'peer-data'
  readonly peer: Uint8Array
  readonly peerData: Uint8Array
}

type TopicOutEvent =
  | Omit<GossipProtocolSendMessage, 'topicId'>
  | Omit<GossipProtocolEmitEvent, 'topicId'>
  | (Omit<GossipProtocolScheduleTimer, 'timer'> & { readonly timer: unknown })
  | GossipProtocolDisconnectPeer
  | GossipProtocolPeerData

export class GossipProtocolState {
  readonly #me: Uint8Array
  readonly #maxMessageSize: number
  readonly #activeViewCapacity: number
  readonly #passiveViewCapacity: number
  #peerData: Uint8Array | null
  readonly #topics = new Map<string, GossipTopicProtocolState>()
  readonly #peerTopics = new Map<string, PeerTopicMembership>()

  constructor(options: GossipProtocolStateOptions) {
    this.#me = validatePeerId(options.me)
    this.#maxMessageSize = validateMaxMessageSize(options.maxMessageSize ?? defaultMaxMessageSize)
    this.#activeViewCapacity = validateViewCapacity(
      options.activeViewCapacity ?? activeViewCapacity,
      'active',
    )
    this.#passiveViewCapacity = validateViewCapacity(
      options.passiveViewCapacity ?? passiveViewCapacity,
      'passive',
    )
    this.#peerData = copyOptionalBytes(options.peerData ?? new Uint8Array())
  }

  me(): Uint8Array {
    return copyBytes(this.#me)
  }

  topics(): readonly Uint8Array[] {
    return Array.from(this.#topics.values(), (topic) => topic.topicId())
  }

  hasActivePeers(topicId: Uint8Array): boolean {
    return this.#topics.get(topicKey(topicId))?.hasActivePeers() ?? false
  }

  handle(
    event: GossipProtocolInEvent,
    nowMs = monotonicNowMs(),
  ): readonly GossipProtocolOutEvent[] {
    if (event.type === 'peer-disconnected') {
      const out = this.handleAllTopics(event, nowMs)
      this.#peerTopics.delete(peerKey(event.peer))
      return out
    }
    if (event.type === 'update-peer-data') {
      this.#peerData = copyOptionalBytes(event.peerData)
      return this.handleAllTopics(event, nowMs)
    }
    if (event.type === 'timer-expired') {
      const topicId = validateGossipTopicId(event.timer.topicId)
      return this.handleTopicEvent(
        topicId,
        {
          type: 'timer-expired',
          timer: event.timer.value,
        },
        nowMs,
      )
    }

    const topicId = validateGossipTopicId(event.topicId)
    if (event.type === 'command' && event.command.type === 'join') {
      this.requireTopic(topicId)
    }
    if (event.type === 'command' && event.command.type === 'quit') {
      const out = this.handleTopicEvent(topicId, event, nowMs)
      this.#topics.delete(bytesKey(topicId))
      return [...out, ...this.removeTopicMemberships(topicId)]
    }
    if (event.type === 'recv-message') {
      const topic = this.#topics.get(bytesKey(topicId))
      if (topic === undefined) {
        return []
      }
      this.trackPeerTopic(event.peer, topicId)
      return this.mapTopicOut(topicId, topic.handle(event, nowMs))
    }
    return this.handleTopicEvent(topicId, event, nowMs)
  }

  private handleAllTopics(
    event: GossipProtocolPeerDisconnected | GossipProtocolUpdatePeerData,
    nowMs: number,
  ): readonly GossipProtocolOutEvent[] {
    const out: GossipProtocolOutEvent[] = []
    for (const topic of this.#topics.values()) {
      out.push(...this.mapTopicOut(topic.topicId(), topic.handle(event, nowMs)))
    }
    return out
  }

  private handleTopicEvent(
    topicId: Uint8Array,
    event: GossipProtocolCommandEvent | { readonly type: 'timer-expired'; readonly timer: unknown },
    nowMs: number,
  ): readonly GossipProtocolOutEvent[] {
    const topic = this.#topics.get(bytesKey(topicId))
    if (topic === undefined) {
      return []
    }
    return this.mapTopicOut(topicId, topic.handle(event, nowMs))
  }

  private requireTopic(topicId: Uint8Array): GossipTopicProtocolState {
    const key = bytesKey(topicId)
    const topic = this.#topics.get(key)
    if (topic !== undefined) {
      return topic
    }
    const nextTopic = new GossipTopicProtocolState({
      activeViewCapacity: this.#activeViewCapacity,
      maxMessageSize: this.#maxMessageSize,
      me: this.#me,
      passiveViewCapacity: this.#passiveViewCapacity,
      peerData: this.#peerData,
      topicId,
    })
    this.#topics.set(key, nextTopic)
    return nextTopic
  }

  private mapTopicOut(
    topicId: Uint8Array,
    events: readonly TopicOutEvent[],
  ): readonly GossipProtocolOutEvent[] {
    const out: GossipProtocolOutEvent[] = []
    for (const event of events) {
      if (event.type === 'send-message') {
        this.trackPeerTopic(event.peer, topicId)
        out.push({
          type: 'send-message',
          peer: copyBytes(event.peer),
          topicId: copyBytes(topicId),
          message: copyTopicMessage(event.message),
        })
      } else if (event.type === 'emit-event') {
        out.push({
          type: 'emit-event',
          topicId: copyBytes(topicId),
          event: copyTopicEvent(event.event),
        })
      } else if (event.type === 'schedule-timer') {
        out.push({
          type: 'schedule-timer',
          delayMs: event.delayMs,
          timer: { topicId: copyBytes(topicId), value: event.timer },
        })
      } else if (event.type === 'disconnect-peer') {
        if (this.untrackPeerTopic(event.peer, topicId)) {
          out.push({ type: 'disconnect-peer', peer: copyBytes(event.peer) })
        }
      } else {
        out.push({
          type: 'peer-data',
          peer: copyBytes(event.peer),
          peerData: copyBytes(event.peerData),
        })
      }
    }
    return out
  }

  private trackPeerTopic(peer: Uint8Array, topicId: Uint8Array): void {
    const peerMapKey = peerKey(peer)
    let membership = this.#peerTopics.get(peerMapKey)
    if (membership === undefined) {
      membership = { peer: validatePeerId(peer), topics: new Set() }
      this.#peerTopics.set(peerMapKey, membership)
    }
    membership.topics.add(bytesKey(topicId))
  }

  private untrackPeerTopic(peer: Uint8Array, topicId: Uint8Array): boolean {
    const key = peerKey(peer)
    const membership = this.#peerTopics.get(key)
    if (membership === undefined) {
      return false
    }
    membership.topics.delete(bytesKey(topicId))
    if (membership.topics.size !== 0) {
      return false
    }
    this.#peerTopics.delete(key)
    return true
  }

  private removeTopicMemberships(topicId: Uint8Array): readonly GossipProtocolDisconnectPeer[] {
    const topicMapKey = bytesKey(topicId)
    const out: GossipProtocolDisconnectPeer[] = []
    for (const [key, membership] of this.#peerTopics) {
      membership.topics.delete(topicMapKey)
      if (membership.topics.size !== 0) {
        continue
      }
      this.#peerTopics.delete(key)
      out.push({ type: 'disconnect-peer', peer: copyBytes(membership.peer) })
    }
    return out
  }
}

interface PeerTopicMembership {
  readonly peer: Uint8Array
  readonly topics: Set<string>
}

type TopicTimer =
  | { readonly type: 'dispatch-lazy-push' }
  | { readonly type: 'pending-neighbor'; readonly peer: Uint8Array }
  | { readonly type: 'send-graft'; readonly id: Uint8Array }

interface LazyPushPeerQueue {
  readonly peer: Uint8Array
  readonly messages: GossipIHaveEntry[]
}

type MissingMessageQueue = MissingMessageSource[]

interface MissingMessageSource {
  readonly peer: Uint8Array
  readonly round: number
}

interface CachedGossipMessage {
  readonly message: GossipBroadcastMessage
  readonly expiresAtMs: number
}

class GossipTopicProtocolState {
  readonly #me: Uint8Array
  readonly #activeViewCapacity: number
  readonly #maxMessageSize: number
  readonly #passiveViewCapacity: number
  readonly #topicId: Uint8Array
  #peerData: Uint8Array | null
  readonly #neighbors = new Map<string, Uint8Array>()
  readonly #passivePeers = new Map<string, Uint8Array>()
  readonly #pendingNeighborRequests = new Set<string>()
  readonly #aliveDisconnectPeers = new Set<string>()
  readonly #eagerPeers = new Map<string, Uint8Array>()
  readonly #lazyPeers = new Map<string, Uint8Array>()
  readonly #lazyPushQueue = new Map<string, LazyPushPeerQueue>()
  readonly #missingMessages = new Map<string, MissingMessageQueue>()
  readonly #graftTimerScheduled = new Set<string>()
  readonly #cache = new Map<string, CachedGossipMessage>()
  readonly #peerDataByPeer = new Map<string, Uint8Array>()
  readonly #seenMessages = new Map<string, number>()
  #dispatchTimerScheduled = false

  constructor(options: {
    readonly activeViewCapacity: number
    readonly maxMessageSize: number
    readonly me: Uint8Array
    readonly passiveViewCapacity: number
    readonly peerData: Uint8Array | null
    readonly topicId: Uint8Array
  }) {
    this.#activeViewCapacity = validateViewCapacity(options.activeViewCapacity, 'active')
    this.#maxMessageSize = validateMaxMessageSize(options.maxMessageSize)
    this.#me = validatePeerId(options.me)
    this.#passiveViewCapacity = validateViewCapacity(options.passiveViewCapacity, 'passive')
    this.#peerData = copyOptionalBytes(options.peerData)
    this.#topicId = validateGossipTopicId(options.topicId)
  }

  topicId(): Uint8Array {
    return copyBytes(this.#topicId)
  }

  hasActivePeers(): boolean {
    return this.#neighbors.size !== 0
  }

  handle(
    event:
      | GossipProtocolRecvMessage
      | GossipProtocolCommandEvent
      | GossipProtocolPeerDisconnected
      | GossipProtocolUpdatePeerData
      | { readonly type: 'timer-expired'; readonly timer: unknown },
    nowMs: number,
  ): readonly TopicOutEvent[] {
    this.expireCaches(nowMs)
    if (event.type === 'command') {
      return this.handleCommand(event.command, nowMs)
    }
    if (event.type === 'recv-message') {
      return this.handleMessage(validatePeerId(event.peer), event.message, nowMs)
    }
    if (event.type === 'peer-disconnected') {
      return this.removeNeighbor(event.peer)
    }
    if (event.type === 'update-peer-data') {
      this.#peerData = copyOptionalBytes(event.peerData)
      return []
    }
    if (isTopicTimer(event.timer)) {
      return this.handleTimer(event.timer, nowMs)
    }
    return []
  }

  private handleCommand(command: GossipProtocolCommand, nowMs: number): readonly TopicOutEvent[] {
    if (command.type === 'join') {
      return command.peers.map((peer) => ({
        type: 'send-message',
        peer: validatePeerId(peer),
        message: { layer: 'swarm', type: 'join', peerData: copyOptionalBytes(this.#peerData) },
      }))
    }
    if (command.type === 'broadcast') {
      const content = copyBytes(command.payload)
      const message: GossipBroadcastMessage = {
        layer: 'gossip',
        type: 'gossip',
        id: blake3(content),
        content,
        scope: broadcastScope(command.scope),
      }
      const out: TopicOutEvent[] = []
      if (message.scope.type === 'swarm') {
        this.storeGossip(message, nowMs)
        out.push(...this.lazyPush(message, this.#me))
      }
      out.push(...this.eagerPush(message, this.#me))
      return out
    }
    const out: TopicOutEvent[] = []
    for (const peer of this.#neighbors.values()) {
      out.push({
        type: 'send-message',
        peer: copyBytes(peer),
        message: { layer: 'swarm', type: 'disconnect', alive: false, respond: false },
      })
      out.push({ type: 'disconnect-peer', peer: copyBytes(peer) })
    }
    this.#neighbors.clear()
    this.#passivePeers.clear()
    this.#pendingNeighborRequests.clear()
    this.#aliveDisconnectPeers.clear()
    this.#eagerPeers.clear()
    this.#lazyPeers.clear()
    this.#lazyPushQueue.clear()
    this.#missingMessages.clear()
    return out
  }

  private handleMessage(
    peer: Uint8Array,
    message: GossipTopicMessage,
    nowMs: number,
  ): readonly TopicOutEvent[] {
    if (message.layer === 'swarm') {
      return this.handleSwarmMessage(peer, message)
    }
    return this.handleGossipMessage(peer, message, nowMs)
  }

  private handleSwarmMessage(
    peer: Uint8Array,
    message: Exclude<GossipTopicMessage, { readonly layer: 'gossip' }>,
  ): readonly TopicOutEvent[] {
    if (message.type === 'join') {
      return [
        ...this.addActive(peer, message.peerData, 'high', true),
        ...this.forwardJoin(peer, message.peerData),
      ]
    }
    if (message.type === 'neighbor') {
      const key = peerKey(peer)
      const isReply = this.#pendingNeighborRequests.delete(key)
      return this.addActive(peer, message.peerData, message.priority, !isReply)
    }
    if (message.type === 'disconnect') {
      return this.handleDisconnectMessage(peer, message.alive)
    }
    if (message.type === 'forward-join') {
      return this.handleForwardJoin(peer, message)
    }
    if (message.type === 'shuffle') {
      return this.handleShuffle(peer, message)
    }
    if (message.type === 'shuffle-reply') {
      return [
        ...message.nodes.flatMap((node) => this.addPassive(node.id, node.peerData)),
        ...this.refillActiveFromPassive(),
      ]
    }
    return []
  }

  private handleGossipMessage(
    peer: Uint8Array,
    message: Exclude<GossipTopicMessage, { readonly layer: 'swarm' }>,
    nowMs: number,
  ): readonly TopicOutEvent[] {
    if (message.type === 'prune') {
      this.addLazy(peer)
      return []
    }
    if (message.type === 'graft') {
      this.addEager(peer)
      if (message.id === null) {
        return []
      }
      const cached = this.#cache.get(bytesKey(message.id))?.message
      if (cached === undefined) {
        return []
      }
      return [{ type: 'send-message', peer: copyBytes(peer), message: copyTopicMessage(cached) }]
    }
    if (message.type === 'ihave') {
      return this.handleIHave(peer, message.messages, nowMs)
    }
    if (!equalBytes(message.id, blake3(message.content))) {
      return []
    }
    const key = bytesKey(message.id)
    if (this.hasSeenMessage(key, nowMs)) {
      this.addLazy(peer)
      return [
        {
          type: 'send-message',
          peer: copyBytes(peer),
          message: { layer: 'gossip', type: 'prune' },
        },
      ]
    }
    const out: TopicOutEvent[] = []
    let deliveredMessage = message
    if (message.scope.type === 'swarm') {
      deliveredMessage = { ...message, scope: { type: 'swarm', round: message.scope.round + 1 } }
      this.storeGossip(deliveredMessage, nowMs)
      this.#graftTimerScheduled.delete(key)
      this.#missingMessages.delete(key)
    }
    out.push({
      type: 'emit-event',
      event: {
        type: 'received',
        deliveredFrom: copyBytes(peer),
        id: copyBytes(deliveredMessage.id),
        payload: copyBytes(deliveredMessage.content),
        scope: copyDeliveryScope(deliveredMessage.scope),
      },
    })
    if (message.scope.type === 'swarm') {
      out.push(...this.eagerPush(deliveredMessage, peer), ...this.lazyPush(deliveredMessage, peer))
    }
    return out
  }

  private addActive(
    peer: Uint8Array,
    data: Uint8Array | null,
    priority: 'high' | 'low',
    reply: boolean,
  ): readonly TopicOutEvent[] {
    if (equalBytes(peer, this.#me)) {
      return []
    }
    const key = peerKey(peer)
    const out: TopicOutEvent[] = [...this.addPeerData({ id: peer, peerData: data })]
    if (this.#neighbors.has(key)) {
      if (!reply) {
        return out
      }
      return [...out, ...this.sendNeighbor(peer, priority)]
    }
    if (priority === 'low' && this.#neighbors.size >= this.#activeViewCapacity) {
      return [
        ...out,
        {
          type: 'send-message',
          peer: copyBytes(peer),
          message: { layer: 'swarm', type: 'disconnect', alive: true, respond: false },
        },
        { type: 'disconnect-peer', peer: copyBytes(peer) },
      ]
    }
    if (this.#neighbors.size >= this.#activeViewCapacity) {
      const evicted = firstMapValue(this.#neighbors)
      if (evicted !== undefined) {
        out.push(...this.removeActive(evicted, { keepPassive: true, sendDisconnect: true }))
      }
    }
    this.#passivePeers.delete(key)
    this.#pendingNeighborRequests.delete(key)
    this.#aliveDisconnectPeers.delete(key)
    this.#neighbors.set(key, copyBytes(peer))
    this.addEager(peer)
    out.push({
      type: 'emit-event',
      event: { type: 'neighbor-up', peer: copyBytes(peer) },
    })
    if (reply) {
      out.push(...this.sendNeighbor(peer, priority))
    }
    return out
  }

  private removeNeighbor(peer: Uint8Array): readonly TopicOutEvent[] {
    const active = this.removeActive(peer, { keepPassive: false, sendDisconnect: false })
    if (active.length !== 0) {
      return [...active, ...this.refillActiveFromPassive()]
    }
    const key = peerKey(peer)
    if (this.#aliveDisconnectPeers.delete(key)) {
      return []
    }
    this.#passivePeers.delete(key)
    this.#pendingNeighborRequests.delete(key)
    this.#aliveDisconnectPeers.delete(key)
    this.#peerDataByPeer.delete(key)
    return []
  }

  private removeActive(
    peer: Uint8Array,
    options: { readonly keepPassive: boolean; readonly sendDisconnect: boolean },
  ): readonly TopicOutEvent[] {
    const key = peerKey(peer)
    const knownPeer = this.#neighbors.get(key)
    if (knownPeer === undefined) {
      return []
    }
    this.#neighbors.delete(key)
    this.#pendingNeighborRequests.delete(key)
    this.#eagerPeers.delete(key)
    this.#lazyPeers.delete(key)
    this.#lazyPushQueue.delete(key)
    this.removeMissingFromPeer(key)
    const out: TopicOutEvent[] = [
      {
        type: 'emit-event',
        event: { type: 'neighbor-down', peer: copyBytes(knownPeer) },
      },
    ]
    if (options.sendDisconnect) {
      out.push({
        type: 'send-message',
        peer: copyBytes(knownPeer),
        message: { layer: 'swarm', type: 'disconnect', alive: true, respond: false },
      })
    }
    out.push({ type: 'disconnect-peer', peer: copyBytes(knownPeer) })
    if (options.keepPassive) {
      this.addPassive(knownPeer, this.#peerDataByPeer.get(key) ?? null)
      this.#aliveDisconnectPeers.add(key)
    }
    return out
  }

  private handleDisconnectMessage(peer: Uint8Array, alive: boolean): readonly TopicOutEvent[] {
    const active = this.removeActive(peer, { keepPassive: alive, sendDisconnect: false })
    if (active.length !== 0) {
      return [...active, ...this.refillActiveFromPassive()]
    }
    if (!alive) {
      const key = peerKey(peer)
      this.#passivePeers.delete(key)
      this.#aliveDisconnectPeers.delete(key)
      this.#peerDataByPeer.delete(key)
    }
    return [{ type: 'disconnect-peer', peer: copyBytes(peer) }]
  }

  private sendNeighbor(peer: Uint8Array, priority: 'high' | 'low'): readonly TopicOutEvent[] {
    const key = peerKey(peer)
    if (this.#pendingNeighborRequests.has(key)) {
      return []
    }
    this.#pendingNeighborRequests.add(key)
    return [
      {
        type: 'send-message',
        peer: copyBytes(peer),
        message: {
          layer: 'swarm',
          type: 'neighbor',
          priority,
          peerData: copyOptionalBytes(this.#peerData),
        },
      },
    ]
  }

  private addPassive(peer: Uint8Array, data: Uint8Array | null): readonly TopicOutEvent[] {
    const out = this.addPeerData({ id: peer, peerData: data })
    if (equalBytes(peer, this.#me)) {
      return out
    }
    const key = peerKey(peer)
    if (this.#neighbors.has(key) || this.#passivePeers.has(key)) {
      return out
    }
    if (this.#passivePeers.size >= this.#passiveViewCapacity) {
      const evictedKey = this.#passivePeers.keys().next().value
      if (typeof evictedKey === 'string') {
        this.#passivePeers.delete(evictedKey)
      }
    }
    this.#passivePeers.set(key, copyBytes(peer))
    return out
  }

  private refillActiveFromPassive(): readonly TopicOutEvent[] {
    if (this.#neighbors.size + this.#pendingNeighborRequests.size >= this.#activeViewCapacity) {
      return []
    }
    const peer = this.firstPassiveWithoutPending()
    if (peer === undefined) {
      return []
    }
    const priority = this.#neighbors.size === 0 ? 'high' : 'low'
    return [
      ...this.sendNeighbor(peer, priority),
      {
        type: 'schedule-timer',
        delayMs: pendingNeighborTimeoutMs,
        timer: { type: 'pending-neighbor', peer: copyBytes(peer) },
      },
    ]
  }

  private handlePendingNeighbor(peer: Uint8Array): readonly TopicOutEvent[] {
    const key = peerKey(peer)
    if (!this.#pendingNeighborRequests.delete(key)) {
      return []
    }
    this.#passivePeers.delete(key)
    this.#aliveDisconnectPeers.delete(key)
    this.#peerDataByPeer.delete(key)
    return [{ type: 'disconnect-peer', peer: copyBytes(peer) }, ...this.refillActiveFromPassive()]
  }

  private handleForwardJoin(
    sender: Uint8Array,
    message: Extract<GossipTopicMessage, { readonly type: 'forward-join' }>,
  ): readonly TopicOutEvent[] {
    const out: TopicOutEvent[] = []
    const peer = message.peer.id
    const key = peerKey(peer)
    if (this.#neighbors.has(key) || message.ttl <= 0 || this.#neighbors.size <= 1) {
      out.push(...this.addPeerData(message.peer), ...this.sendNeighbor(peer, 'high'))
      return out
    }
    if (message.ttl === passiveRandomWalkLength) {
      out.push(...this.addPassive(peer, message.peer.peerData))
    }
    if (this.#pendingNeighborRequests.has(key)) {
      return out
    }
    const next = this.pickActiveExcept([sender])
    if (next === undefined) {
      return out
    }
    out.push({
      type: 'send-message',
      peer: next,
      message: {
        layer: 'swarm',
        type: 'forward-join',
        peer: copyPeerInfo(message.peer),
        ttl: Math.max(0, message.ttl - 1),
      },
    })
    return out
  }

  private handleShuffle(
    peer: Uint8Array,
    message: Extract<GossipTopicMessage, { readonly type: 'shuffle' }>,
  ): readonly TopicOutEvent[] {
    if (message.ttl <= 0 || this.#neighbors.size <= 1) {
      return [
        ...message.nodes.flatMap((node) => this.addPassive(node.id, node.peerData)),
        {
          type: 'send-message',
          peer: copyBytes(message.origin),
          message: {
            layer: 'swarm',
            type: 'shuffle-reply',
            nodes: this.peerSample(message.nodes.length),
          },
        },
      ]
    }
    const next = this.pickActiveExcept([message.origin, peer])
    if (next === undefined) {
      return []
    }
    return [
      {
        type: 'send-message',
        peer: next,
        message: {
          layer: 'swarm',
          type: 'shuffle',
          origin: copyBytes(message.origin),
          nodes: message.nodes.map(copyPeerInfo),
          ttl: Math.max(0, message.ttl - 1),
        },
      },
    ]
  }

  private pickActiveExcept(peers: readonly Uint8Array[]): Uint8Array | undefined {
    const excluded = new Set(peers.map(peerKey))
    for (const [key, peer] of this.#neighbors) {
      if (!excluded.has(key)) {
        return copyBytes(peer)
      }
    }
    return undefined
  }

  private firstPassiveWithoutPending(): Uint8Array | undefined {
    for (const [key, peer] of this.#passivePeers) {
      if (!this.#pendingNeighborRequests.has(key)) {
        return copyBytes(peer)
      }
    }
    return undefined
  }

  private peerSample(count: number): readonly GossipPeerInfo[] {
    const out: GossipPeerInfo[] = []
    for (const peer of this.#passivePeers.values()) {
      out.push({
        id: copyBytes(peer),
        peerData: copyOptionalBytes(this.#peerDataByPeer.get(peerKey(peer)) ?? null),
      })
      if (out.length >= count) {
        return out
      }
    }
    for (const peer of this.#neighbors.values()) {
      out.push({
        id: copyBytes(peer),
        peerData: copyOptionalBytes(this.#peerDataByPeer.get(peerKey(peer)) ?? null),
      })
      if (out.length >= count) {
        return out
      }
    }
    return out
  }

  private addPeerData(peer: GossipPeerInfo): readonly TopicOutEvent[] {
    if (peer.peerData === null || peer.peerData.length === 0) {
      return []
    }
    const key = peerKey(peer.id)
    const oldData = this.#peerDataByPeer.get(key)
    if (oldData !== undefined && equalBytes(oldData, peer.peerData)) {
      return []
    }
    const peerData = copyBytes(peer.peerData)
    this.#peerDataByPeer.set(key, peerData)
    return [{ type: 'peer-data', peer: validatePeerId(peer.id), peerData }]
  }

  private eagerPush(message: GossipBroadcastMessage, sender: Uint8Array): readonly TopicOutEvent[] {
    const senderKey = peerKey(sender)
    const out: TopicOutEvent[] = []
    for (const [key, peer] of this.#eagerPeers) {
      if (key === senderKey) {
        continue
      }
      out.push({ type: 'send-message', peer: copyBytes(peer), message: copyTopicMessage(message) })
    }
    return out
  }

  private lazyPush(message: GossipBroadcastMessage, sender: Uint8Array): readonly TopicOutEvent[] {
    if (message.scope.type !== 'swarm') {
      return []
    }
    const senderKey = peerKey(sender)
    for (const [key, peer] of this.#lazyPeers) {
      if (key === senderKey) {
        continue
      }
      let queue = this.#lazyPushQueue.get(key)
      if (queue === undefined) {
        queue = { peer: copyBytes(peer), messages: [] }
        this.#lazyPushQueue.set(key, queue)
      }
      queue.messages.push({ id: copyBytes(message.id), round: message.scope.round })
    }
    if (this.#lazyPushQueue.size === 0 || this.#dispatchTimerScheduled) {
      return []
    }
    this.#dispatchTimerScheduled = true
    return [
      {
        type: 'schedule-timer',
        delayMs: lazyDispatchDelayMs,
        timer: { type: 'dispatch-lazy-push' },
      },
    ]
  }

  private handleIHave(
    peer: Uint8Array,
    messages: readonly GossipIHaveEntry[],
    nowMs: number,
  ): readonly TopicOutEvent[] {
    const out: TopicOutEvent[] = []
    for (const message of messages) {
      const key = bytesKey(message.id)
      if (this.hasSeenMessage(key, nowMs)) {
        continue
      }
      let queue = this.#missingMessages.get(key)
      if (queue === undefined) {
        queue = []
        this.#missingMessages.set(key, queue)
      }
      queue.push({ peer: copyBytes(peer), round: message.round })
      if (this.#graftTimerScheduled.has(key)) {
        continue
      }
      this.#graftTimerScheduled.add(key)
      out.push({
        type: 'schedule-timer',
        delayMs: graftTimeoutMs,
        timer: { type: 'send-graft', id: copyBytes(message.id) },
      })
    }
    return out
  }

  private handleTimer(timer: TopicTimer, nowMs: number): readonly TopicOutEvent[] {
    if (timer.type === 'dispatch-lazy-push') {
      this.#dispatchTimerScheduled = false
      const out: TopicOutEvent[] = []
      for (const queue of this.#lazyPushQueue.values()) {
        if (queue.messages.length === 0) {
          continue
        }
        for (const chunk of this.chunkIHaveMessages(queue.messages)) {
          out.push({
            type: 'send-message',
            peer: copyBytes(queue.peer),
            message: {
              layer: 'gossip',
              type: 'ihave',
              messages: chunk,
            },
          })
        }
      }
      this.#lazyPushQueue.clear()
      return out
    }
    if (timer.type === 'pending-neighbor') {
      return this.handlePendingNeighbor(timer.peer)
    }

    const id = validateMessageId(timer.id)
    const key = bytesKey(id)
    this.#graftTimerScheduled.delete(key)
    if (this.hasSeenMessage(key, nowMs)) {
      return []
    }
    const queue = this.#missingMessages.get(key)
    const next = queue?.shift()
    if (queue !== undefined && queue.length === 0) {
      this.#missingMessages.delete(key)
    }
    if (next === undefined) {
      return []
    }
    this.addEager(next.peer)
    return [
      {
        type: 'send-message',
        peer: copyBytes(next.peer),
        message: { layer: 'gossip', type: 'graft', id, round: next.round },
      },
      {
        type: 'schedule-timer',
        delayMs: retryGraftTimeoutMs,
        timer: { type: 'send-graft', id },
      },
    ]
  }

  private storeGossip(message: GossipBroadcastMessage, nowMs: number): void {
    const key = bytesKey(message.id)
    this.#seenMessages.set(key, nowMs + messageIdRetentionMs)
    this.#cache.set(key, {
      message: copyGossipBroadcastMessage(message),
      expiresAtMs: nowMs + messageCacheRetentionMs,
    })
  }

  private hasSeenMessage(key: string, nowMs: number): boolean {
    const expiresAtMs = this.#seenMessages.get(key)
    if (expiresAtMs === undefined) {
      return false
    }
    if (expiresAtMs <= nowMs) {
      this.#seenMessages.delete(key)
      return false
    }
    return true
  }

  private expireCaches(nowMs: number): void {
    for (const [key, expiresAtMs] of this.#seenMessages) {
      if (expiresAtMs <= nowMs) {
        this.#seenMessages.delete(key)
      }
    }
    for (const [key, cached] of this.#cache) {
      if (cached.expiresAtMs <= nowMs) {
        this.#cache.delete(key)
      }
    }
  }

  private addEager(peer: Uint8Array): void {
    const key = peerKey(peer)
    this.#lazyPeers.delete(key)
    this.#lazyPushQueue.delete(key)
    this.#eagerPeers.set(key, copyBytes(peer))
  }

  private addLazy(peer: Uint8Array): void {
    const key = peerKey(peer)
    this.#eagerPeers.delete(key)
    this.#lazyPeers.set(key, copyBytes(peer))
  }

  private removeMissingFromPeer(peerMapKey: string): void {
    for (const [id, queue] of this.#missingMessages) {
      const nextQueue = queue.filter((entry) => peerKey(entry.peer) !== peerMapKey)
      if (nextQueue.length === 0) {
        this.#missingMessages.delete(id)
      } else {
        this.#missingMessages.set(id, nextQueue)
      }
    }
  }

  private chunkIHaveMessages(
    messages: readonly GossipIHaveEntry[],
  ): readonly (readonly GossipIHaveEntry[])[] {
    const chunkLength = Math.max(
      1,
      Math.floor((this.#maxMessageSize - 3) / ihaveEntryMaxEncodedSize),
    )
    const chunks: GossipIHaveEntry[][] = []
    for (let offset = 0; offset < messages.length; offset += chunkLength) {
      chunks.push(messages.slice(offset, offset + chunkLength).map(copyIHaveEntry))
    }
    return chunks
  }

  private forwardJoin(peer: Uint8Array, peerData: Uint8Array | null): readonly TopicOutEvent[] {
    const peerInfo = { id: peer, peerData: copyOptionalBytes(peerData) }
    const out: TopicOutEvent[] = []
    for (const [key, neighbor] of this.#neighbors) {
      if (key === peerKey(peer)) {
        continue
      }
      out.push({
        type: 'send-message',
        peer: copyBytes(neighbor),
        message: {
          layer: 'swarm',
          type: 'forward-join',
          peer: peerInfo,
          ttl: activeRandomWalkLength,
        },
      })
    }
    return out
  }
}

function broadcastScope(scope: GossipBroadcastScope | undefined): GossipDeliveryScope {
  if (scope === 'neighbors') {
    return { type: 'neighbors' }
  }
  return { type: 'swarm', round: 0 }
}

function validatePeerId(peer: Uint8Array): Uint8Array {
  requireLength(peer, 32, 'gossip peer id')
  return copyBytes(peer)
}

function validateMessageId(id: Uint8Array): Uint8Array {
  requireLength(id, 32, 'gossip message id')
  return copyBytes(id)
}

function validateMaxMessageSize(size: number): number {
  if (!Number.isInteger(size) || size < minMaxMessageSize) {
    throw new RangeError(`gossip max message size must be at least ${minMaxMessageSize}`)
  }
  return size
}

function validateViewCapacity(size: number, name: string): number {
  if (!Number.isInteger(size) || size < 1) {
    throw new RangeError(`gossip ${name} view capacity must be at least 1`)
  }
  return size
}

function isTopicTimer(timer: unknown): timer is TopicTimer {
  if (typeof timer !== 'object' || timer === null || !('type' in timer)) {
    return false
  }
  const type = timer.type
  if (type === 'dispatch-lazy-push') {
    return true
  }
  if (type === 'pending-neighbor') {
    return 'peer' in timer && timer.peer instanceof Uint8Array
  }
  return type === 'send-graft' && 'id' in timer && timer.id instanceof Uint8Array
}

function copyOptionalBytes(bytes: Uint8Array | null): Uint8Array | null {
  return bytes === null ? null : copyBytes(bytes)
}

function copyTopicMessage(message: GossipTopicMessage): GossipTopicMessage {
  if (message.layer === 'swarm') {
    if (message.type === 'join') {
      return { ...message, peerData: copyOptionalBytes(message.peerData) }
    }
    if (message.type === 'forward-join') {
      return { ...message, peer: copyPeerInfo(message.peer) }
    }
    if (message.type === 'shuffle') {
      return {
        ...message,
        origin: copyBytes(message.origin),
        nodes: message.nodes.map(copyPeerInfo),
      }
    }
    if (message.type === 'shuffle-reply') {
      return { ...message, nodes: message.nodes.map(copyPeerInfo) }
    }
    if (message.type === 'neighbor') {
      return { ...message, peerData: copyOptionalBytes(message.peerData) }
    }
    return { ...message }
  }
  if (message.type === 'gossip') {
    return {
      ...message,
      id: copyBytes(message.id),
      content: copyBytes(message.content),
      scope: copyDeliveryScope(message.scope),
    }
  }
  if (message.type === 'graft') {
    return { ...message, id: copyOptionalBytes(message.id) }
  }
  if (message.type === 'ihave') {
    return { ...message, messages: message.messages.map(copyIHaveEntry) }
  }
  return { ...message }
}

function copyGossipBroadcastMessage(message: GossipBroadcastMessage): GossipBroadcastMessage {
  return {
    ...message,
    id: copyBytes(message.id),
    content: copyBytes(message.content),
    scope: copyDeliveryScope(message.scope),
  }
}

function copyPeerInfo(peer: GossipPeerInfo): GossipPeerInfo {
  return {
    id: copyBytes(peer.id),
    peerData: copyOptionalBytes(peer.peerData),
  }
}

function copyIHaveEntry(message: GossipIHaveEntry): GossipIHaveEntry {
  return {
    id: copyBytes(message.id),
    round: message.round,
  }
}

function copyTopicEvent(event: GossipProtocolTopicEvent): GossipProtocolTopicEvent {
  if (event.type === 'received') {
    return {
      type: 'received',
      deliveredFrom: copyBytes(event.deliveredFrom),
      id: copyBytes(event.id),
      payload: copyBytes(event.payload),
      scope: copyDeliveryScope(event.scope),
    }
  }
  return { type: event.type, peer: copyBytes(event.peer) }
}

function copyDeliveryScope(scope: GossipDeliveryScope): GossipDeliveryScope {
  if (scope.type === 'swarm') {
    return { type: 'swarm', round: scope.round }
  }
  return { type: 'neighbors' }
}

function peerKey(peer: Uint8Array): string {
  return bytesKey(validatePeerId(peer))
}

function bytesKey(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0')
  }
  return out
}

function topicKey(topicId: Uint8Array): string {
  return bytesKey(validateGossipTopicId(topicId))
}

function firstMapValue<T>(map: ReadonlyMap<string, T>): T | undefined {
  for (const value of map.values()) {
    return value
  }
  return undefined
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  let diff = 0
  for (let index = 0; index < left.length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0)
  }
  return diff === 0
}

function monotonicNowMs(): number {
  return performance.now()
}

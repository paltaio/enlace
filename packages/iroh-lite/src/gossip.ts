import { copyBytes } from './bytes'
import type { IrohConnection, IrohEndpoint, IrohEndpointAddress } from './endpoint'
import { decodeGossipPeerDataAddrInfo, encodeGossipPeerDataAddrInfo } from './gossip/peer-data'
import {
  GossipProtocolState,
  GossipTimerScheduler,
  type GossipBroadcastScope,
  type GossipProtocolCommand,
  type GossipProtocolEmitEvent,
  type GossipProtocolOutEvent,
  type GossipProtocolStateOptions,
  type GossipProtocolSendMessage,
} from './gossip/state'
import {
  decodeGossipStreamHeader,
  decodeGossipTopicMessage,
  encodeGossipBroadcastMessage,
  encodeGossipGraftMessage,
  encodeGossipIHaveMessage,
  encodeGossipPruneMessage,
  encodeGossipSwarmDisconnectMessage,
  encodeGossipSwarmForwardJoinMessage,
  encodeGossipSwarmJoinMessage,
  encodeGossipSwarmNeighborMessage,
  encodeGossipSwarmShuffleMessage,
  encodeGossipSwarmShuffleReplyMessage,
  gossipAlpn,
  GossipFrameReader,
  GossipTopicStreamWriter,
  validateGossipTopicId,
  type GossipDeliveryScope,
  type GossipTopicMessage,
} from './gossip/wire'

export interface IrohGossipOptions {
  readonly activeViewCapacity?: number
  readonly maxMessageSize?: number
  readonly passiveViewCapacity?: number
}

export interface IrohGossipSubscribeOptions {
  readonly topicId: Uint8Array
  readonly bootstrap?: readonly IrohEndpointAddress[]
}

export interface IrohGossipJoinPeerOptions {
  readonly peer: IrohEndpointAddress
}

export interface IrohGossipBroadcastOptions {
  readonly payload: Uint8Array
  readonly scope?: GossipDeliveryScope
}

export type IrohGossipEvent =
  | IrohGossipJoinEvent
  | IrohGossipNeighborUpEvent
  | IrohGossipNeighborDownEvent
  | IrohGossipMessageEvent

export interface IrohGossipJoinEvent {
  readonly type: 'join'
  readonly topicId: Uint8Array
  readonly peerData: Uint8Array | null
}

export interface IrohGossipNeighborUpEvent {
  readonly type: 'neighbor-up'
  readonly topicId: Uint8Array
  readonly peer: Uint8Array
}

export interface IrohGossipNeighborDownEvent {
  readonly type: 'neighbor-down'
  readonly topicId: Uint8Array
  readonly peer: Uint8Array
}

export interface IrohGossipMessageEvent {
  readonly type: 'message'
  readonly topicId: Uint8Array
  readonly deliveredFrom: Uint8Array
  readonly id: Uint8Array
  readonly payload: Uint8Array
  readonly scope: GossipDeliveryScope
}

export function createGossip(endpoint: IrohEndpoint, options: IrohGossipOptions = {}): IrohGossip {
  return new IrohGossip(endpoint, options)
}

export class IrohGossip {
  readonly #actor: GossipActor

  constructor(endpoint: IrohEndpoint, options: IrohGossipOptions = {}) {
    this.#actor = new GossipActor(endpoint, options)
  }

  subscribe(options: IrohGossipSubscribeOptions): IrohGossipSubscription {
    return this.#actor.subscribe(options)
  }

  close(): void {
    this.#actor.close()
  }
}

export class IrohGossipSubscription {
  readonly #actor: GossipActor
  readonly #topicId: Uint8Array
  readonly #events = new AsyncQueue<IrohGossipEvent>()
  readonly #neighbors = new Map<string, Uint8Array>()
  readonly #joinedResolvers: (() => void)[] = []
  readonly #peerJoined = new Map<string, PendingPeerJoin>()
  #closed = false

  constructor(actor: GossipActor, topicId: Uint8Array) {
    this.#actor = actor
    this.#topicId = validateGossipTopicId(topicId)
  }

  get topicId(): Uint8Array {
    return copyBytes(this.#topicId)
  }

  joined(): Promise<void> {
    if (this.isJoined()) {
      return Promise.resolve()
    }
    return new Promise((resolve) => {
      this.#joinedResolvers.push(resolve)
    })
  }

  isJoined(): boolean {
    return this.#neighbors.size !== 0
  }

  neighbors(): readonly Uint8Array[] {
    return Array.from(this.#neighbors.values(), copyBytes)
  }

  events(): AsyncIterable<IrohGossipEvent> {
    return this.#events
  }

  joinPeer(options: IrohGossipJoinPeerOptions): Promise<void> {
    try {
      this.requireOpen()
    } catch (error) {
      return Promise.reject(error)
    }
    const joined = this.peerJoined(options.peer.endpointId)
    void this.#actor.joinPeer(this.#topicId, options.peer).catch((error: unknown) => {
      this.fail(error)
    })
    return joined
  }

  async joinPeers(peers: readonly IrohEndpointAddress[]): Promise<void> {
    this.requireOpen()
    await this.#actor.joinPeers(this.#topicId, peers)
    await Promise.all(peers.map((peer) => this.peerJoined(peer.endpointId)))
  }

  broadcast(options: IrohGossipBroadcastOptions): void {
    this.requireOpen()
    this.#actor.broadcast(this.#topicId, options.payload, protocolScope(options.scope))
  }

  broadcastNeighbors(options: { readonly payload: Uint8Array }): void {
    this.requireOpen()
    this.#actor.broadcast(this.#topicId, options.payload, 'neighbors')
  }

  close(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    this.#actor.unsubscribe(this.#topicId, this)
    this.#events.close()
    this.#joinedResolvers.splice(0).forEach((resolve) => resolve())
    this.resolvePeerJoined()
  }

  push(event: IrohGossipEvent): void {
    if (this.#closed) {
      return
    }
    if (event.type === 'neighbor-up') {
      const peerKey = bytesKey(event.peer)
      this.#neighbors.set(peerKey, copyBytes(event.peer))
      this.#joinedResolvers.splice(0).forEach((resolve) => resolve())
      this.resolvePeerJoined(peerKey)
    } else if (event.type === 'neighbor-down') {
      this.#neighbors.delete(bytesKey(event.peer))
    }
    this.#events.push(event)
  }

  fail(error: unknown): void {
    this.#events.fail(error)
    this.#joinedResolvers.splice(0).forEach((resolve) => resolve())
    this.resolvePeerJoined()
  }

  private requireOpen(): void {
    if (this.#closed) {
      throw new Error('gossip subscription is closed')
    }
  }

  private peerJoined(peer: Uint8Array): Promise<void> {
    const key = bytesKey(peer)
    if (this.#neighbors.has(key)) {
      return Promise.resolve()
    }
    const pending = this.#peerJoined.get(key)
    if (pending !== undefined) {
      return pending.promise
    }
    let resolvePromise: () => void = noop
    const promise = new Promise<void>((resolve) => {
      resolvePromise = resolve
    })
    this.#peerJoined.set(key, { promise, resolve: resolvePromise })
    return promise
  }

  private resolvePeerJoined(peerKey?: string): void {
    if (peerKey === undefined) {
      for (const pending of this.#peerJoined.values()) {
        pending.resolve()
      }
      this.#peerJoined.clear()
      return
    }
    const pending = this.#peerJoined.get(peerKey)
    if (pending === undefined) {
      return
    }
    this.#peerJoined.delete(peerKey)
    pending.resolve()
  }
}

interface PendingPeerJoin {
  readonly promise: Promise<void>
  resolve(): void
}

function noop(): void {}

class GossipActor {
  readonly #endpoint: IrohEndpoint
  readonly #state: GossipProtocolState
  readonly #scheduler: GossipTimerScheduler
  readonly #subscriptions = new Map<string, Set<IrohGossipSubscription>>()
  readonly #addressBook = new Map<string, IrohEndpointAddress>()
  readonly #peers = new Map<string, PeerRuntime>()
  #closed = false

  constructor(endpoint: IrohEndpoint, options: IrohGossipOptions) {
    this.#endpoint = endpoint
    const stateOptions: GossipProtocolStateOptions = {
      me: endpoint.endpointId,
      peerData: encodeGossipPeerDataAddrInfo({ relayUrl: endpoint.relayUrl }),
      ...(options.activeViewCapacity === undefined
        ? {}
        : { activeViewCapacity: options.activeViewCapacity }),
      ...(options.maxMessageSize === undefined ? {} : { maxMessageSize: options.maxMessageSize }),
      ...(options.passiveViewCapacity === undefined
        ? {}
        : { passiveViewCapacity: options.passiveViewCapacity }),
    }
    this.#state = new GossipProtocolState(stateOptions)
    this.#scheduler = new GossipTimerScheduler({
      onTimer: (timer, nowMs) => {
        this.processOut(this.#state.handle({ type: 'timer-expired', timer }, nowMs))
      },
    })
    void this.acceptLoop()
  }

  subscribe(options: IrohGossipSubscribeOptions): IrohGossipSubscription {
    const topicId = validateGossipTopicId(options.topicId)
    const subscription = new IrohGossipSubscription(this, topicId)
    const key = bytesKey(topicId)
    let subscriptions = this.#subscriptions.get(key)
    if (subscriptions === undefined) {
      subscriptions = new Set()
      this.#subscriptions.set(key, subscriptions)
    }
    subscriptions.add(subscription)
    void this.joinPeers(topicId, options.bootstrap ?? [])
    return subscription
  }

  unsubscribe(topicId: Uint8Array, subscription: IrohGossipSubscription): void {
    const key = bytesKey(topicId)
    const subscriptions = this.#subscriptions.get(key)
    if (subscriptions === undefined) {
      return
    }
    subscriptions.delete(subscription)
    if (subscriptions.size !== 0) {
      return
    }
    this.#subscriptions.delete(key)
    this.processOut(
      this.#state.handle({
        type: 'command',
        topicId,
        command: { type: 'quit' },
      }),
    )
  }

  async joinPeer(topicId: Uint8Array, peer: IrohEndpointAddress): Promise<void> {
    await this.joinPeers(topicId, [peer])
  }

  async joinPeers(topicId: Uint8Array, peers: readonly IrohEndpointAddress[]): Promise<void> {
    for (const peer of peers) {
      this.rememberAddress(peer)
    }
    const command: GossipProtocolCommand =
      peers.length === 0
        ? { type: 'join', peers: [] }
        : { type: 'join', peers: peers.map((peer) => peer.endpointId) }
    this.processOut(
      this.#state.handle({
        type: 'command',
        topicId,
        command,
      }),
    )
    await Promise.all(peers.map((peer) => this.peerReady(peer.endpointId)))
  }

  broadcast(topicId: Uint8Array, payload: Uint8Array, scope?: GossipBroadcastScope): void {
    const command: GossipProtocolCommand =
      scope === undefined ? { type: 'broadcast', payload } : { type: 'broadcast', payload, scope }
    this.processOut(
      this.#state.handle({
        type: 'command',
        topicId,
        command,
      }),
    )
  }

  close(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    this.#scheduler.close()
    for (const runtime of this.#peers.values()) {
      closeRuntime(runtime)
    }
    this.#peers.clear()
    for (const subscriptions of this.#subscriptions.values()) {
      for (const subscription of subscriptions) {
        subscription.close()
      }
    }
    this.#subscriptions.clear()
  }

  private async acceptLoop(): Promise<void> {
    try {
      while (!this.#closed) {
        this.activateConnection(await this.#endpoint.accept({ alpn: gossipAlpn }), 'inbound')
      }
    } catch (error) {
      if (!this.#closed) {
        this.failAll(error)
      }
    }
  }

  private processOut(events: readonly GossipProtocolOutEvent[]): void {
    this.#scheduler.scheduleFrom(events)
    for (const event of events) {
      if (event.type === 'send-message') {
        this.sendMessage(event)
      } else if (event.type === 'emit-event') {
        this.emitEvent(event)
      } else if (event.type === 'disconnect-peer') {
        this.disconnectPeer(event.peer)
      } else if (event.type === 'peer-data') {
        this.updatePeerData(event.peer, event.peerData)
      }
    }
  }

  private emitEvent(event: GossipProtocolEmitEvent): void {
    const topicId = copyBytes(event.topicId)
    if (event.event.type === 'neighbor-up') {
      this.pushTopicEvent(topicId, {
        type: 'neighbor-up',
        topicId,
        peer: copyBytes(event.event.peer),
      })
      this.pushTopicEvent(topicId, { type: 'join', topicId, peerData: null })
    } else if (event.event.type === 'neighbor-down') {
      this.pushTopicEvent(topicId, {
        type: 'neighbor-down',
        topicId,
        peer: copyBytes(event.event.peer),
      })
    } else {
      this.pushTopicEvent(topicId, {
        type: 'message',
        topicId,
        deliveredFrom: copyBytes(event.event.deliveredFrom),
        id: copyBytes(event.event.id),
        payload: copyBytes(event.event.payload),
        scope: event.event.scope,
      })
    }
  }

  private pushTopicEvent(topicId: Uint8Array, event: IrohGossipEvent): void {
    const subscriptions = this.#subscriptions.get(bytesKey(topicId))
    if (subscriptions === undefined) {
      return
    }
    for (const subscription of subscriptions) {
      subscription.push(event)
    }
  }

  private sendMessage(event: GossipProtocolSendMessage): void {
    const runtime = this.requirePeer(event.peer)
    if (runtime.state.type === 'active') {
      runtime.state.sendQueue.push(event)
      this.flushRuntime(runtime, runtime.state)
      return
    }
    runtime.state.queue.push(event)
    this.dial(runtime, runtime.state)
  }

  private dial(runtime: PeerRuntime, state: PeerPendingState): void {
    if (state.dialing !== null) {
      return
    }
    const address = this.#addressBook.get(bytesKey(runtime.peer))
    if (address === undefined) {
      return
    }
    state.dialing = this.#endpoint
      .connect({ address, alpn: gossipAlpn })
      .then((connection) => {
        if (runtime.state !== state) {
          closeConnection(connection)
          return
        }
        state.dialing = null
        this.activateConnection(connection, 'outbound')
      })
      .catch(() => {
        if (runtime.state !== state) {
          return
        }
        state.dialing = null
        this.processOut(this.#state.handle({ type: 'peer-disconnected', peer: runtime.peer }))
      })
  }

  private activateConnection(connection: IrohConnection, direction: PeerConnectionDirection): void {
    const runtime = this.requirePeer(connection.peerEndpointId)
    if (runtime.state.type === 'active' && runtime.state.connection !== connection) {
      const preferred = this.preferredDirection(runtime.peer)
      if (runtime.state.direction === preferred) {
        closeConnection(connection)
        return
      }
      if (direction !== preferred) {
        closeConnection(connection)
        return
      }
      runtime.state.otherConnections.add(runtime.state.connection)
      closeWriterSet(runtime.state.writers)
      runtime.state = {
        type: 'active',
        sendQueue: runtime.state.sendQueue,
        connection,
        direction,
        writers: new Map(),
        otherConnections: runtime.state.otherConnections,
      }
    } else if (runtime.state.type === 'pending') {
      runtime.state = {
        type: 'active',
        sendQueue: runtime.state.queue,
        connection,
        direction,
        writers: new Map(),
        otherConnections: new Set(),
      }
    } else {
      runtime.state.direction = direction
    }
    void this.readIncoming(runtime, connection)
    if (runtime.state.type === 'active') {
      this.flushRuntime(runtime, runtime.state)
    }
  }

  private async readIncoming(runtime: PeerRuntime, connection: IrohConnection): Promise<void> {
    while (!this.#closed && this.hasRuntimeConnection(runtime, connection)) {
      try {
        const stream = await connection.acceptUniStream()
        void this.readIncomingStream(runtime, connection, stream)
      } catch {
        this.peerDisconnected(runtime, connection)
        return
      }
    }
  }

  private async readIncomingStream(
    runtime: PeerRuntime,
    connection: IrohConnection,
    stream: {
      read(): Promise<{ readonly data: Uint8Array; readonly complete: boolean }>
    },
  ): Promise<void> {
    try {
      const reader = new GossipFrameReader(stream)
      const headerPayload = await reader.readFrame()
      if (headerPayload === null) {
        return
      }
      const header = decodeGossipStreamHeader(headerPayload)
      while (!this.#closed && this.hasRuntimeConnection(runtime, connection)) {
        const payload = await reader.readFrame()
        if (payload === null) {
          return
        }
        this.processOut(
          this.#state.handle({
            type: 'recv-message',
            peer: runtime.peer,
            topicId: header.topicId,
            message: decodeGossipTopicMessage(payload),
          }),
        )
      }
    } catch {
      this.peerDisconnected(runtime, connection)
    }
  }

  private flushRuntime(runtime: PeerRuntime, state: PeerActiveState): void {
    while (state.sendQueue.length !== 0) {
      const event = state.sendQueue.shift()
      if (event === undefined) {
        return
      }
      try {
        this.writer(state, event.topicId).writeFrame(encodeTopicMessage(event.message))
      } catch {
        this.peerDisconnected(runtime, state.connection)
        return
      }
    }
  }

  private writer(state: PeerActiveState, topicId: Uint8Array): GossipTopicStreamWriter {
    const key = bytesKey(topicId)
    const writer = state.writers.get(key)
    if (writer !== undefined) {
      return writer
    }
    const nextWriter = new GossipTopicStreamWriter(state.connection.openUniStream(), topicId)
    state.writers.set(key, nextWriter)
    return nextWriter
  }

  private peerDisconnected(runtime: PeerRuntime, connection: IrohConnection): void {
    if (runtime.state.type !== 'active') {
      return
    }
    if (runtime.state.otherConnections.delete(connection)) {
      closeConnection(connection)
      return
    }
    if (runtime.state.connection !== connection) {
      return
    }
    const sendQueue = runtime.state.sendQueue
    closeRuntime(runtime)
    runtime.state = { type: 'pending', queue: sendQueue, dialing: null }
    this.processOut(this.#state.handle({ type: 'peer-disconnected', peer: runtime.peer }))
  }

  private disconnectPeer(peer: Uint8Array): void {
    const key = bytesKey(peer)
    const runtime = this.#peers.get(key)
    if (runtime === undefined) {
      return
    }
    closeRuntime(runtime)
    this.#peers.delete(key)
  }

  private updatePeerData(peer: Uint8Array, peerData: Uint8Array): void {
    let decoded: ReturnType<typeof decodeGossipPeerDataAddrInfo>
    try {
      decoded = decodeGossipPeerDataAddrInfo(peerData)
    } catch {
      return
    }
    if (decoded.relayUrl === null) {
      return
    }
    this.rememberAddress({ endpointId: peer, relayUrl: decoded.relayUrl })
  }

  private rememberAddress(address: IrohEndpointAddress): void {
    this.#addressBook.set(bytesKey(address.endpointId), {
      endpointId: copyBytes(address.endpointId),
      relayUrl: new URL(address.relayUrl),
    })
  }

  private requirePeer(peer: Uint8Array): PeerRuntime {
    const key = bytesKey(peer)
    const runtime = this.#peers.get(key)
    if (runtime !== undefined) {
      return runtime
    }
    const nextRuntime: PeerRuntime = {
      peer: copyBytes(peer),
      state: { type: 'pending', queue: [], dialing: null },
    }
    this.#peers.set(key, nextRuntime)
    return nextRuntime
  }

  private preferredDirection(peer: Uint8Array): PeerConnectionDirection {
    return bytesKey(this.#endpoint.endpointId) < bytesKey(peer) ? 'outbound' : 'inbound'
  }

  private async peerReady(peer: Uint8Array): Promise<void> {
    const runtime = this.requirePeer(peer)
    if (runtime.state.type === 'active') {
      return
    }
    if (runtime.state.dialing !== null) {
      await runtime.state.dialing
    }
  }

  private failAll(error: unknown): void {
    for (const subscriptions of this.#subscriptions.values()) {
      for (const subscription of subscriptions) {
        subscription.fail(error)
      }
    }
  }

  private hasRuntimeConnection(runtime: PeerRuntime, connection: IrohConnection): boolean {
    return (
      runtime.state.type === 'active' &&
      (runtime.state.connection === connection || runtime.state.otherConnections.has(connection))
    )
  }
}

interface PeerRuntime {
  readonly peer: Uint8Array
  state: PeerState
}

type PeerState = PeerPendingState | PeerActiveState

interface PeerPendingState {
  readonly type: 'pending'
  readonly queue: GossipProtocolSendMessage[]
  dialing: Promise<void> | null
}

interface PeerActiveState {
  readonly type: 'active'
  readonly sendQueue: GossipProtocolSendMessage[]
  readonly connection: IrohConnection
  direction: PeerConnectionDirection
  readonly writers: Map<string, GossipTopicStreamWriter>
  readonly otherConnections: Set<IrohConnection>
}

type PeerConnectionDirection = 'inbound' | 'outbound'

class AsyncQueue<T> implements AsyncIterable<T>, AsyncIterator<T> {
  readonly #values: T[] = []
  readonly #readers: PendingRead<T>[] = []
  #closed = false
  #error: unknown = null

  push(value: T): void {
    if (this.#closed) {
      return
    }
    const reader = this.#readers.shift()
    if (reader !== undefined) {
      reader.resolve({ done: false, value })
      return
    }
    this.#values.push(value)
  }

  fail(error: unknown): void {
    if (this.#closed) {
      return
    }
    this.#error = error
    this.#closed = true
    while (true) {
      const reader = this.#readers.shift()
      if (reader === undefined) {
        return
      }
      reader.reject(error)
    }
  }

  close(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    while (true) {
      const reader = this.#readers.shift()
      if (reader === undefined) {
        return
      }
      reader.resolve({ done: true, value: undefined })
    }
  }

  next(): Promise<IteratorResult<T, undefined>> {
    const value = this.#values.shift()
    if (value !== undefined) {
      return Promise.resolve({ done: false, value })
    }
    if (this.#error !== null) {
      return Promise.reject(this.#error)
    }
    if (this.#closed) {
      return Promise.resolve({ done: true, value: undefined })
    }
    return new Promise<IteratorResult<T, undefined>>((resolve, reject) => {
      this.#readers.push({ resolve, reject })
    })
  }

  [Symbol.asyncIterator](): AsyncIterator<T> {
    return this
  }
}

interface PendingRead<T> {
  resolve(result: IteratorResult<T, undefined>): void
  reject(error: unknown): void
}

function protocolScope(scope: GossipDeliveryScope | undefined): GossipBroadcastScope | undefined {
  if (scope === undefined) {
    return undefined
  }
  return scope.type === 'neighbors' ? 'neighbors' : 'swarm'
}

function encodeTopicMessage(message: GossipTopicMessage): Uint8Array {
  if (message.layer === 'swarm') {
    if (message.type === 'join') {
      return encodeGossipSwarmJoinMessage(message.peerData)
    }
    if (message.type === 'forward-join') {
      return encodeGossipSwarmForwardJoinMessage(message)
    }
    if (message.type === 'shuffle') {
      return encodeGossipSwarmShuffleMessage(message)
    }
    if (message.type === 'shuffle-reply') {
      return encodeGossipSwarmShuffleReplyMessage(message)
    }
    if (message.type === 'neighbor') {
      return encodeGossipSwarmNeighborMessage(message)
    }
    return encodeGossipSwarmDisconnectMessage(message)
  }
  if (message.type === 'gossip') {
    return encodeGossipBroadcastMessage({ content: message.content, scope: message.scope })
  }
  if (message.type === 'prune') {
    return encodeGossipPruneMessage()
  }
  if (message.type === 'graft') {
    return encodeGossipGraftMessage(message)
  }
  return encodeGossipIHaveMessage(message)
}

function closeRuntime(runtime: PeerRuntime): void {
  if (runtime.state.type !== 'active') {
    return
  }
  closeWriterSet(runtime.state.writers)
  closeConnection(runtime.state.connection)
  for (const connection of runtime.state.otherConnections) {
    closeConnection(connection)
  }
  runtime.state.otherConnections.clear()
}

function closeWriterSet(writers: Map<string, GossipTopicStreamWriter>): void {
  for (const writer of writers.values()) {
    finishWriter(writer)
  }
  writers.clear()
}

function closeConnection(connection: IrohConnection): void {
  try {
    connection.close()
  } catch {
    // Transport may already be closed by the opposite side.
  }
}

function bytesKey(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0')
  }
  return out
}

function finishWriter(writer: GossipTopicStreamWriter): void {
  try {
    writer.finish()
  } catch {
    // Connection teardown can race FIN.
  }
}

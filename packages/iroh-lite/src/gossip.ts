import { concatBytes, copyBytes } from './bytes'
import type { IrohEndpoint, IrohEndpointAddress, IrohConnection } from './endpoint'
import {
  decodeGossipStreamFrame,
  decodeGossipStreamHeader,
  decodeGossipTopicMessage,
  encodeGossipBroadcastMessage,
  encodeGossipStreamHeader,
  encodeGossipSwarmJoinMessage,
  gossipAlpn,
  validateGossipTopicId,
  type GossipBroadcastMessage,
  type GossipDeliveryScope,
  type GossipSwarmJoinMessage,
} from './gossip/wire'

export interface IrohGossipSubscribeOptions {
  readonly topicId: Uint8Array
}

export interface IrohGossipJoinPeerOptions {
  readonly peer: IrohEndpointAddress
}

export interface IrohGossipBroadcastOptions {
  readonly payload: Uint8Array
  readonly scope?: GossipDeliveryScope
}

export type IrohGossipEvent = IrohGossipJoinEvent | IrohGossipMessageEvent

export interface IrohGossipJoinEvent {
  readonly type: 'join'
  readonly topicId: Uint8Array
  readonly peerData: Uint8Array | null
}

export interface IrohGossipMessageEvent {
  readonly type: 'message'
  readonly topicId: Uint8Array
  readonly id: Uint8Array
  readonly payload: Uint8Array
  readonly scope: GossipDeliveryScope
}

export function createGossip(endpoint: IrohEndpoint): IrohGossip {
  return new IrohGossip(endpoint)
}

export class IrohGossip {
  readonly #endpoint: IrohEndpoint

  constructor(endpoint: IrohEndpoint) {
    this.#endpoint = endpoint
  }

  subscribe(options: IrohGossipSubscribeOptions): IrohGossipSubscription {
    return new IrohGossipSubscription(this.#endpoint, options.topicId)
  }
}

export class IrohGossipSubscription {
  readonly #endpoint: IrohEndpoint
  readonly #topicId: Uint8Array
  readonly #events = new AsyncQueue<IrohGossipEvent>()
  readonly #connections = new Set<IrohConnection>()
  #started = false
  #closed = false

  constructor(endpoint: IrohEndpoint, topicId: Uint8Array) {
    this.#endpoint = endpoint
    this.#topicId = validateGossipTopicId(topicId)
  }

  get topicId(): Uint8Array {
    return copyBytes(this.#topicId)
  }

  start(): void {
    if (this.#started) {
      return
    }
    this.#started = true
    void this.acceptLoop()
  }

  events(): AsyncIterable<IrohGossipEvent> {
    this.start()
    return this.#events
  }

  async joinPeer(options: IrohGossipJoinPeerOptions): Promise<void> {
    this.requireOpen()
    const connection = await this.#endpoint.connect({
      address: options.peer,
      alpn: gossipAlpn,
    })
    this.#connections.add(connection)
    this.sendFrame(connection, encodeGossipSwarmJoinMessage())
    void this.readIncoming(connection)
  }

  broadcast(options: IrohGossipBroadcastOptions): void {
    this.requireOpen()
    const frame = encodeGossipBroadcastMessage(broadcastInput(options))
    for (const connection of this.#connections) {
      this.trySendFrame(connection, frame)
    }
  }

  close(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    this.#connections.clear()
    this.#events.close()
  }

  private async acceptLoop(): Promise<void> {
    try {
      while (!this.#closed) {
        const connection = await this.#endpoint.accept({ alpn: gossipAlpn })
        this.#connections.add(connection)
        void this.readIncoming(connection)
      }
    } catch (error) {
      if (!this.#closed) {
        this.#events.fail(error)
      }
    }
  }

  private async readIncoming(connection: IrohConnection): Promise<void> {
    while (!this.#closed) {
      try {
        const stream = await connection.acceptUniStream()
        const bytes = await stream.readToEnd()
        this.pushStreamEvents(bytes)
      } catch {
        this.#connections.delete(connection)
        return
      }
    }
  }

  private pushStreamEvents(bytes: Uint8Array): void {
    let offset = 0
    const headerFrame = decodeGossipStreamFrame(bytes, offset)
    offset += headerFrame.bytesRead
    const header = decodeGossipStreamHeader(headerFrame.payload)
    if (!equalBytes(header.topicId, this.#topicId)) {
      return
    }
    while (offset < bytes.length) {
      const frame = decodeGossipStreamFrame(bytes, offset)
      offset += frame.bytesRead
      this.pushTopicEvent(header.topicId, decodeGossipTopicMessage(frame.payload))
    }
  }

  private pushTopicEvent(
    topicId: Uint8Array,
    message: GossipBroadcastMessage | GossipSwarmJoinMessage,
  ): void {
    if (message.type === 'join') {
      this.#events.push({
        type: 'join',
        topicId: copyBytes(topicId),
        peerData: message.peerData === null ? null : copyBytes(message.peerData),
      })
      return
    }
    this.#events.push({
      type: 'message',
      topicId: copyBytes(topicId),
      id: copyBytes(message.id),
      payload: copyBytes(message.content),
      scope: message.scope,
    })
  }

  private sendFrame(connection: IrohConnection, frame: Uint8Array): void {
    const stream = connection.openUniStream()
    stream.write(concatBytes([encodeGossipStreamHeader({ topicId: this.#topicId }), frame]), {
      fin: true,
    })
  }

  private trySendFrame(connection: IrohConnection, frame: Uint8Array): void {
    try {
      this.sendFrame(connection, frame)
    } catch {
      this.#connections.delete(connection)
    }
  }

  private requireOpen(): void {
    if (this.#closed) {
      throw new Error('gossip subscription is closed')
    }
  }
}

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

function broadcastInput(options: IrohGossipBroadcastOptions): {
  readonly content: Uint8Array
  readonly scope?: GossipDeliveryScope
} {
  if (options.scope === undefined) {
    return { content: options.payload }
  }
  return { content: options.payload, scope: options.scope }
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

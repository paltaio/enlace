import {
  createEndpoint,
  createGossip,
  type IrohEndpoint,
  type IrohGossipEvent,
  type IrohGossipSubscription,
} from '../../../packages/iroh-lite/src/index'
import type { RelayWebSocketConstructor } from '../../../packages/iroh-lite/src/relay/client'
import type { RelayUrlInput } from '../../../packages/iroh-lite/src/relay/url'

import type { ChatBackend, ChatMessage } from './backend'

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const inviteType = 'enlace-chat-iroh-lite-v1'
const hexPattern = /^[0-9a-f]*$/u

export interface IrohLiteChatBackendOptions {
  readonly seed: Uint8Array
  readonly channel: string
  readonly relayUrl: RelayUrlInput
  readonly WebSocket?: RelayWebSocketConstructor
}

export async function createIrohLiteChatBackend(
  options: IrohLiteChatBackendOptions,
): Promise<IrohLiteChatBackend> {
  const endpoint = await createEndpoint(endpointOptions(options))
  const topic = createGossip(endpoint).subscribe({
    topicId: await chatTopicId(options.seed, options.channel),
  })
  return new IrohLiteChatBackend(endpoint, topic)
}

export class IrohLiteChatBackend implements ChatBackend {
  readonly kind = 'iroh-lite'
  readonly localInvite: Uint8Array
  readonly #endpoint: IrohEndpoint
  readonly #topic: IrohGossipSubscription
  readonly #messages = new AsyncQueue<ChatMessage>()
  #closed = false
  #started = false

  constructor(endpoint: IrohEndpoint, topic: IrohGossipSubscription) {
    this.#endpoint = endpoint
    this.#topic = topic
    this.localInvite = encodeInvite(endpoint.address)
  }

  async addPeer(invite: Uint8Array): Promise<void> {
    this.requireOpen()
    await this.#topic.joinPeer({ peer: decodeInvite(invite) })
  }

  send(payload: Uint8Array): void {
    this.requireOpen()
    this.#topic.broadcast({ payload })
  }

  messages(): AsyncIterable<ChatMessage> {
    this.start()
    return this.#messages
  }

  close(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    this.#topic.close()
    this.#endpoint.close()
    this.#messages.close()
  }

  private start(): void {
    if (this.#started) {
      return
    }
    this.#started = true
    void this.pumpMessages()
  }

  private async pumpMessages(): Promise<void> {
    try {
      for await (const event of this.#topic.events()) {
        if (event.type === 'message') {
          this.#messages.push(messageEvent(event))
        }
      }
      this.#messages.close()
    } catch (error) {
      if (!this.#closed) {
        this.#messages.fail(error)
      }
    }
  }

  private requireOpen(): void {
    if (this.#closed) {
      throw new Error('chat backend is closed')
    }
  }
}

async function chatTopicId(seed: Uint8Array, channel: string): Promise<Uint8Array> {
  if (seed.length !== 32) {
    throw new RangeError('chat seed must be 32 bytes')
  }
  const channelBytes = encoder.encode(channel)
  const input = new Uint8Array(seed.length + 1 + channelBytes.length)
  input.set(seed, 0)
  input.set([0], seed.length)
  input.set(channelBytes, seed.length + 1)
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', input))
}

function messageEvent(event: Extract<IrohGossipEvent, { readonly type: 'message' }>): ChatMessage {
  return {
    payload: copyBytes(event.payload),
    via: 'iroh-lite',
  }
}

function endpointOptions(options: IrohLiteChatBackendOptions): {
  readonly relayUrl: RelayUrlInput
  readonly WebSocket?: RelayWebSocketConstructor
} {
  if (options.WebSocket === undefined) {
    return { relayUrl: options.relayUrl }
  }
  return { relayUrl: options.relayUrl, WebSocket: options.WebSocket }
}

function encodeInvite(address: {
  readonly endpointId: Uint8Array
  readonly relayUrl: URL
}): Uint8Array {
  return encoder.encode(
    JSON.stringify({
      type: inviteType,
      endpointId: bytesToHex(address.endpointId),
      relayUrl: address.relayUrl.toString(),
    }),
  )
}

function decodeInvite(invite: Uint8Array): {
  readonly endpointId: Uint8Array
  readonly relayUrl: URL
} {
  const value: unknown = JSON.parse(decoder.decode(invite))
  if (!isObject(value)) {
    throw new TypeError('chat invite must be an object')
  }
  const type = objectString(value, 'type')
  if (type !== inviteType) {
    throw new TypeError('chat invite type is unsupported')
  }
  return {
    endpointId: hexToBytes(objectString(value, 'endpointId')),
    relayUrl: new URL(objectString(value, 'relayUrl')),
  }
}

function objectString(value: object, key: string): string {
  const prop = Object.getOwnPropertyDescriptor(value, key)?.value
  if (typeof prop !== 'string') {
    throw new TypeError(`chat invite field ${key} must be a string`)
  }
  return prop
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !hexPattern.test(hex)) {
    throw new TypeError('hex string must contain complete lowercase bytes')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes)
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
    this.#closed = true
    this.#error = error
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

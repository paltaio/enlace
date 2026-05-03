import type { ChatBackend, ChatMessage } from './backend'

export type WasmChatNamespaceOptions = unknown

export interface WasmChatModule {
  readonly Namespace: {
    open(seed: Uint8Array, options: WasmChatNamespaceOptions): Promise<WasmChatNamespace>
  }
}

export interface WasmChatNamespace {
  addIrohPeer(invite: Uint8Array): void
  irohInvite(): Uint8Array | undefined
  mailboxRecv(channel: string): Promise<unknown>
  mailboxSend(channel: string, payload: Uint8Array): Promise<void>
  mailboxSubscribe(channel: string): Promise<void>
  waitIrohOnline(): Promise<void>
  free(): void
}

export interface WasmChatBackendOptions {
  readonly seed: Uint8Array
  readonly channel: string
  readonly module: WasmChatModule
  readonly options?: WasmChatNamespaceOptions
}

export async function createWasmChatBackend(
  options: WasmChatBackendOptions,
): Promise<WasmChatBackend> {
  const namespace = await options.module.Namespace.open(options.seed, options.options)
  await namespace.mailboxSubscribe(options.channel)
  await namespace.waitIrohOnline()
  return new WasmChatBackend(namespace, options.channel)
}

export class WasmChatBackend implements ChatBackend {
  readonly kind = 'wasm'
  readonly localInvite: Uint8Array | null
  readonly #namespace: WasmChatNamespace
  readonly #channel: string
  #closed = false

  constructor(namespace: WasmChatNamespace, channel: string) {
    this.#namespace = namespace
    this.#channel = channel
    this.localInvite = namespace.irohInvite() ?? null
  }

  addPeer(invite: Uint8Array): void {
    this.requireOpen()
    this.#namespace.addIrohPeer(invite)
  }

  async send(payload: Uint8Array): Promise<void> {
    this.requireOpen()
    await this.#namespace.mailboxSend(this.#channel, payload)
  }

  messages(): AsyncIterable<ChatMessage> {
    return this.receiveLoop()
  }

  close(): void {
    if (this.#closed) {
      return
    }
    this.#closed = true
    this.#namespace.free()
  }

  private async *receiveLoop(): AsyncIterable<ChatMessage> {
    while (!this.#closed) {
      const value = await this.#namespace.mailboxRecv(this.#channel)
      const payload = mailboxPayload(value)
      if (payload !== null) {
        yield {
          payload,
          via: 'wasm',
        }
      }
    }
  }

  private requireOpen(): void {
    if (this.#closed) {
      throw new Error('chat backend is closed')
    }
  }
}

function mailboxPayload(value: unknown): Uint8Array | null {
  if (typeof value !== 'object' || value === null) {
    return null
  }
  const payload = Object.getOwnPropertyDescriptor(value, 'payload')?.value
  if (payload instanceof Uint8Array) {
    return new Uint8Array(payload)
  }
  return null
}

import type { RelayWebSocketConstructor } from '../../../packages/iroh-lite/src/relay/client'
import type { RelayUrlInput } from '../../../packages/iroh-lite/src/relay/url'

import { createIrohLiteChatBackend } from './iroh-lite-backend'

export type ChatBackendKind = 'iroh-lite'

export interface ChatMessage {
  readonly payload: Uint8Array
  readonly via: ChatBackendKind
}

export interface ChatBackend {
  readonly kind: ChatBackendKind
  readonly localInvite: Uint8Array | null
  addPeer(invite: Uint8Array): void | Promise<void>
  send(payload: Uint8Array): void | Promise<void>
  messages(): AsyncIterable<ChatMessage>
  close(): void
}

interface ChatBackendBaseOptions {
  readonly seed: Uint8Array
  readonly channel: string
}

export interface IrohLiteChatBackendOptions extends ChatBackendBaseOptions {
  readonly kind: 'iroh-lite'
  readonly relayUrl?: RelayUrlInput
  readonly relayUrls?: readonly RelayUrlInput[]
  readonly secretKey?: Uint8Array
  readonly WebSocket?: RelayWebSocketConstructor
}

export type ChatBackendOptions = IrohLiteChatBackendOptions

export async function createChatBackend(options: ChatBackendOptions): Promise<ChatBackend> {
  return await createIrohLiteChatBackend(options)
}

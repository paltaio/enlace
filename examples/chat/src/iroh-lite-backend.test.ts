import { describe, expect, test } from 'bun:test'

import {
  startLocalIrohRelay,
  withTimeout,
} from '../../../packages/iroh-lite/src/testing/local-iroh-relay'
import {
  startNativeIrohGossipClientSender,
  startNativeIrohGossipServer,
  type NativeIrohGossipEvent,
} from '../../../packages/iroh-lite/src/testing/native-iroh-echo'

import { createChatBackend, type ChatMessage } from './backend'

const interopTest = Bun.env.IROH_NATIVE_INTEROP === '1' ? test : test.skip
const seed = new Uint8Array([
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
])
const channel = 'chat'
const leftPayload = new TextEncoder().encode('hello from left')
const rightPayload = new TextEncoder().encode('hello from right')
const nativePayload = new TextEncoder().encode('hello from native chat')
const inviteType = 'enlace-chat-iroh-lite-v1'

describe('chat iroh-lite backend', () => {
  test('selects TS backend and exchanges messages through relay', async () => {
    const relay = await startLocalIrohRelay()
    const left = await createChatBackend({
      kind: 'iroh-lite',
      seed,
      channel,
      relayUrl: relay.url,
    })
    const right = await createChatBackend({
      kind: 'iroh-lite',
      seed,
      channel,
      relayUrl: relay.url,
    })

    try {
      expect(left.kind).toBe('iroh-lite')
      expect(right.kind).toBe('iroh-lite')
      expect(left.localInvite).toBeInstanceOf(Uint8Array)
      expect(right.localInvite).toBeInstanceOf(Uint8Array)

      const leftMessage = nextMessage(left.messages())
      const rightMessage = nextMessage(right.messages())

      await Promise.all([
        left.addPeer(requireInvite(right.localInvite)),
        right.addPeer(requireInvite(left.localInvite)),
      ])
      left.send(leftPayload)
      right.send(rightPayload)

      expect(await withTimeout(leftMessage, 'left chat message', 5_000)).toEqual({
        payload: rightPayload,
        via: 'iroh-lite',
      })
      expect(await withTimeout(rightMessage, 'right chat message', 5_000)).toEqual({
        payload: leftPayload,
        via: 'iroh-lite',
      })
    } finally {
      left.close()
      right.close()
      await relay.stop()
    }
  })

  test('falls back to the next relay URL when the first one is unavailable', async () => {
    const relay = await startLocalIrohRelay()
    const relayUrls = ['http://127.0.0.1:9', relay.url]
    const left = await createChatBackend({
      kind: 'iroh-lite',
      seed,
      channel,
      relayUrls,
    })
    const right = await createChatBackend({
      kind: 'iroh-lite',
      seed,
      channel,
      relayUrls,
    })

    try {
      const leftMessage = nextMessage(left.messages())
      const rightMessage = nextMessage(right.messages())

      await Promise.all([
        left.addPeer(requireInvite(right.localInvite)),
        right.addPeer(requireInvite(left.localInvite)),
      ])
      left.send(leftPayload)
      right.send(rightPayload)

      expect(await withTimeout(leftMessage, 'left fallback chat message', 5_000)).toEqual({
        payload: rightPayload,
        via: 'iroh-lite',
      })
      expect(await withTimeout(rightMessage, 'right fallback chat message', 5_000)).toEqual({
        payload: leftPayload,
        via: 'iroh-lite',
      })
    } finally {
      left.close()
      right.close()
      await relay.stop()
    }
  })

  interopTest(
    'sends messages to native full gossip through relay',
    async () => {
      const relay = await startLocalIrohRelay()
      const topicId = await chatTopicId(seed, channel)
      const native = await startNativeIrohGossipServer(relay.url, topicId)
      const backend = await createChatBackend({
        kind: 'iroh-lite',
        seed,
        channel,
        relayUrl: relay.url,
      })

      try {
        const nativeMessage = nextNativeMessage(native)

        await backend.addPeer(nativeInvite(native.endpointId, relay.url))
        backend.send(leftPayload)

        expect(await withTimeout(nativeMessage, 'native chat message', 120_000)).toEqual({
          type: 'message',
          deliveredFrom: expect.any(Uint8Array),
          payload: leftPayload,
        })
      } finally {
        backend.close()
        await native.stop()
        await relay.stop()
      }
    },
    180_000,
  )

  interopTest(
    'receives messages from native full gossip through relay',
    async () => {
      const relay = await startLocalIrohRelay()
      const topicId = await chatTopicId(seed, channel)
      const backend = await createChatBackend({
        kind: 'iroh-lite',
        seed,
        channel,
        relayUrl: relay.url,
      })
      let nativeSender: Awaited<ReturnType<typeof startNativeIrohGossipClientSender>> | null = null

      try {
        const backendMessage = nextMessage(backend.messages())

        nativeSender = await startNativeIrohGossipClientSender({
          relayUrl: relay.url,
          serverEndpointId: decodeInviteEndpointId(requireInvite(backend.localInvite)),
          topicId,
          payload: nativePayload,
        })

        expect(await withTimeout(backendMessage, 'browser chat message', 120_000)).toEqual({
          payload: nativePayload,
          via: 'iroh-lite',
        })
      } finally {
        backend.close()
        await nativeSender?.stop()
        await relay.stop()
      }
    },
    180_000,
  )
})

function requireInvite(invite: Uint8Array | null): Uint8Array {
  if (invite === null) {
    throw new Error('expected local invite')
  }
  return invite
}

async function nextMessage(events: AsyncIterable<ChatMessage>): Promise<ChatMessage> {
  for await (const event of events) {
    return event
  }
  throw new Error('chat events closed before message')
}

async function nextNativeMessage(native: {
  nextEvent(): Promise<NativeIrohGossipEvent>
}): Promise<NativeIrohGossipEvent> {
  while (true) {
    const event = await native.nextEvent()
    if (event.type === 'message') {
      return event
    }
  }
}

async function chatTopicId(seedBytes: Uint8Array, channelName: string): Promise<Uint8Array> {
  const channelBytes = new TextEncoder().encode(channelName)
  const input = new Uint8Array(seedBytes.length + 1 + channelBytes.length)
  input.set(seedBytes, 0)
  input.set([0], seedBytes.length)
  input.set(channelBytes, seedBytes.length + 1)
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', input))
}

function nativeInvite(endpointId: Uint8Array, relayUrl: string): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      type: inviteType,
      endpointId: bytesToHex(endpointId),
      relayUrl,
    }),
  )
}

function decodeInviteEndpointId(invite: Uint8Array): Uint8Array {
  const value: unknown = JSON.parse(new TextDecoder().decode(invite))
  if (typeof value !== 'object' || value === null) {
    throw new TypeError('expected invite object')
  }
  const endpointId = Object.getOwnPropertyDescriptor(value, 'endpointId')?.value
  if (typeof endpointId !== 'string') {
    throw new TypeError('expected invite endpoint id')
  }
  return hexToBytes(endpointId)
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) {
    throw new TypeError('hex string must contain complete lowercase bytes')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

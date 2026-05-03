import { describe, expect, test } from 'bun:test'

import {
  startLocalIrohRelay,
  withTimeout,
} from '../../../packages/iroh-lite/src/testing/local-iroh-relay'

import { createChatBackend, type ChatMessage } from './backend'

const seed = new Uint8Array([
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
])
const channel = 'chat'
const leftPayload = new TextEncoder().encode('hello from left')
const rightPayload = new TextEncoder().encode('hello from right')

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

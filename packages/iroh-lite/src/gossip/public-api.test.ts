import { describe, expect, test } from 'bun:test'

import { createEndpoint, createGossip } from '@paltaio/iroh-lite'
import { IrohGossipSubscription } from '@paltaio/iroh-lite/gossip'

import { startLocalIrohRelay, withTimeout } from '../testing/local-iroh-relay'

const topicId = new Uint8Array([
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
])
const payload = new TextEncoder().encode('hello gossip api')

describe('public gossip API', () => {
  test('joins a peer and receives broadcast events', async () => {
    const relay = await startLocalIrohRelay()
    const sender = await createEndpoint({ relayUrl: relay.url })
    const receiver = await createEndpoint({ relayUrl: relay.url })
    const senderGossip = createGossip(sender)
    const receiverGossip = createGossip(receiver)
    const senderTopic = senderGossip.subscribe({ topicId })
    const receiverTopic = receiverGossip.subscribe({ topicId })

    try {
      expect(receiverTopic).toBeInstanceOf(IrohGossipSubscription)
      const event = nextMessage(receiverTopic.events())

      await senderTopic.joinPeer({ peer: receiver.address })
      senderTopic.broadcast({ payload })

      expect(await withTimeout(event, 'public gossip message', 5_000)).toEqual({
        type: 'message',
        topicId,
        id: expect.any(Uint8Array),
        payload,
        scope: { type: 'swarm', round: 0 },
      })
    } finally {
      senderTopic.close()
      receiverTopic.close()
      sender.close()
      receiver.close()
      await relay.stop()
    }
  })

  test('rejects sends after close', async () => {
    const relay = await startLocalIrohRelay()
    const sender = await createEndpoint({ relayUrl: relay.url })
    const receiver = await createEndpoint({ relayUrl: relay.url })
    const topic = createGossip(sender).subscribe({ topicId })

    try {
      topic.close()
      await expectRejects(
        topic.joinPeer({ peer: receiver.address }),
        'gossip subscription is closed',
      )
      expect(() => topic.broadcast({ payload })).toThrow('gossip subscription is closed')
    } finally {
      topic.close()
      sender.close()
      receiver.close()
      await relay.stop()
    }
  })
})

async function expectRejects(promise: Promise<unknown>, message: string): Promise<void> {
  try {
    await promise
  } catch (error) {
    expect(error).toEqual(expect.objectContaining({ message }))
    return
  }
  throw new Error(`expected promise to reject with: ${message}`)
}

async function nextMessage(events: AsyncIterable<{ readonly type: string }>): Promise<unknown> {
  for await (const event of events) {
    if (event.type === 'message') {
      return event
    }
  }
  throw new Error('gossip events closed before message')
}

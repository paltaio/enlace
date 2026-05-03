import { describe, expect, test } from 'bun:test'

import { createEndpoint, createGossip } from '@paltaio/iroh-lite'

import { startLocalIrohRelay, withTimeout } from '../testing/local-iroh-relay'
import {
  startNativeIrohGossipClientSender,
  startNativeIrohGossipClientReceiver,
  startNativeIrohGossipServer,
  type NativeIrohGossipEvent,
} from '../testing/native-iroh-echo'

const interopTest = Bun.env.IROH_NATIVE_INTEROP === '1' ? test : test.skip
const topicId = new Uint8Array([
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
])
const payload = new TextEncoder().encode('hello from native iroh gossip')

describe('native iroh gossip interop', () => {
  interopTest(
    'accepts native full gossip over relay',
    async () => {
      const relay = await startLocalIrohRelay()
      const endpoint = await createEndpoint({ relayUrl: relay.url })
      const gossip = createGossip(endpoint)
      const subscription = gossip.subscribe({ topicId })
      const message = nextMessage(subscription.events())
      let nativeSender: Awaited<ReturnType<typeof startNativeIrohGossipClientSender>> | null = null

      try {
        nativeSender = await startNativeIrohGossipClientSender({
          relayUrl: relay.url,
          serverEndpointId: endpoint.endpointId,
          topicId,
          payload,
        })
        const event = await withTimeout(message, 'native iroh gossip message', 120_000)

        expect(nativeSender.topicId).toEqual(topicId)
        expect(nativeSender.payload).toEqual(payload)
        expect(event).toEqual({
          type: 'message',
          topicId,
          deliveredFrom: nativeSender.endpointId,
          id: expect.any(Uint8Array),
          payload,
          scope: { type: 'swarm', round: 1 },
        })
      } finally {
        subscription.close()
        gossip.close()
        endpoint.close()
        await nativeSender?.stop()
        await relay.stop()
      }
    },
    150_000,
  )

  interopTest(
    'dials native full gossip over relay',
    async () => {
      const relay = await startLocalIrohRelay()
      const native = await startNativeIrohGossipServer(relay.url, topicId)
      const endpoint = await createEndpoint({ relayUrl: relay.url })
      const gossip = createGossip(endpoint)
      const subscription = gossip.subscribe({
        topicId,
        bootstrap: [{ endpointId: native.endpointId, relayUrl: new URL(relay.url) }],
      })
      const message = nextNativeMessage(native)

      try {
        await subscription.joined()
        subscription.broadcast({ payload })
        const event = await withTimeout(message, 'native iroh gossip message', 5_000)

        expect(native.topicId).toEqual(topicId)
        expect(event).toEqual({
          type: 'message',
          deliveredFrom: endpoint.endpointId,
          payload,
        })
      } finally {
        subscription.close()
        gossip.close()
        endpoint.close()
        await native.stop()
        await relay.stop()
      }
    },
    150_000,
  )

  interopTest(
    'accepts native leave and rejoin over relay',
    async () => {
      const relay = await startLocalIrohRelay()
      const endpoint = await createEndpoint({ relayUrl: relay.url })
      const gossip = createGossip(endpoint)
      const subscription = gossip.subscribe({ topicId })
      const events = subscription.events()
      const nextPayload = new TextEncoder().encode('hello again from native iroh gossip')
      let firstSender: Awaited<ReturnType<typeof startNativeIrohGossipClientSender>> | null = null
      let nativeSender: Awaited<ReturnType<typeof startNativeIrohGossipClientSender>> | null = null

      try {
        firstSender = await startNativeIrohGossipClientSender({
          relayUrl: relay.url,
          serverEndpointId: endpoint.endpointId,
          topicId,
          payload,
        })
        const first = await withTimeout(nextMessage(events), 'first native message', 120_000)
        expect(first).toEqual({
          type: 'message',
          topicId,
          deliveredFrom: firstSender.endpointId,
          id: expect.any(Uint8Array),
          payload,
          scope: { type: 'swarm', round: 1 },
        })
        await firstSender.stop()
        const firstSenderEndpointId = firstSender.endpointId
        firstSender = null

        expect(
          await withTimeout(nextNeighborDown(events), 'native neighbor-down', 120_000),
        ).toEqual(firstSenderEndpointId)

        nativeSender = await startNativeIrohGossipClientSender({
          relayUrl: relay.url,
          serverEndpointId: endpoint.endpointId,
          topicId,
          payload: nextPayload,
        })
        const second = await withTimeout(nextMessage(events), 'second native message', 120_000)
        expect(second).toEqual({
          type: 'message',
          topicId,
          deliveredFrom: nativeSender.endpointId,
          id: expect.any(Uint8Array),
          payload: nextPayload,
          scope: { type: 'swarm', round: 1 },
        })
      } finally {
        subscription.close()
        gossip.close()
        endpoint.close()
        await firstSender?.stop()
        await nativeSender?.stop()
        await relay.stop()
      }
    },
    180_000,
  )

  interopTest(
    'forwards native gossip through a relay-only TypeScript peer',
    async () => {
      const relay = await startLocalIrohRelay()
      const nativeA = await startNativeIrohGossipServer(relay.url, topicId)
      const endpointB = await createEndpoint({ relayUrl: relay.url })
      const gossipB = createGossip(endpointB)
      const subscriptionB = gossipB.subscribe({
        topicId,
        bootstrap: [{ endpointId: nativeA.endpointId, relayUrl: new URL(relay.url) }],
      })
      const eventsB = subscriptionB.events()
      let nativeC: Awaited<ReturnType<typeof startNativeIrohGossipClientReceiver>> | null = null

      try {
        await withTimeout(subscriptionB.joined(), 'TypeScript peer joined native A', 120_000)
        nativeC = await startNativeIrohGossipClientReceiver({
          relayUrl: relay.url,
          serverEndpointId: endpointB.endpointId,
          topicId,
          expectedPayload: payload,
        })
        await withTimeout(
          nextNeighborUp(eventsB, nativeC.endpointId),
          'native C joined TypeScript peer',
          120_000,
        )

        await nativeA.broadcast(payload)
        const received = await withTimeout(
          nativeC.received(),
          'native C forwarded gossip message',
          120_000,
        )

        expect(received).toEqual({
          endpointId: nativeC.endpointId,
          endpointIdHex: nativeC.endpointIdHex,
          topicId,
          deliveredFrom: endpointB.endpointId,
          payload,
        })
      } finally {
        subscriptionB.close()
        gossipB.close()
        endpointB.close()
        await nativeC?.stop()
        await nativeA.stop()
        await relay.stop()
      }
    },
    180_000,
  )
})

async function nextMessage(events: AsyncIterable<{ readonly type: string }>): Promise<unknown> {
  for await (const event of events) {
    if (event.type === 'message') {
      return event
    }
  }
  throw new Error('gossip events closed before message')
}

async function nextNeighborDown(
  events: AsyncIterable<{ readonly type: string; readonly peer?: Uint8Array }>,
): Promise<Uint8Array> {
  for await (const event of events) {
    if (event.type === 'neighbor-down' && event.peer !== undefined) {
      return event.peer
    }
  }
  throw new Error('gossip events closed before neighbor-down')
}

async function nextNeighborUp(
  events: AsyncIterable<{ readonly type: string; readonly peer?: Uint8Array }>,
  peer: Uint8Array,
): Promise<Uint8Array> {
  for await (const event of events) {
    if (event.type === 'neighbor-up' && event.peer !== undefined && bytesEqual(event.peer, peer)) {
      return event.peer
    }
  }
  throw new Error('gossip events closed before neighbor-up')
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

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false
    }
  }
  return true
}

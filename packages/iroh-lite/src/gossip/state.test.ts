import { describe, expect, test } from 'bun:test'
import { blake3 } from '@noble/hashes/blake3.js'

import { hexToBytes } from '../testing/hex'
import { GossipProtocolState, type GossipProtocolOutEvent } from './state'
import type { GossipBroadcastMessage } from './wire'

const topicA = hexToBytes('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f')
const topicB = hexToBytes('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
const peerA = hexToBytes('8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c')
const peerB = hexToBytes('ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1')
const peerC = hexToBytes('c352229ac4bcb6f633f773596a30ad8b2dfb0256f2ca8db78dd085eec828d838')
const peerD = hexToBytes('4ca37a63d42514dd1df5974786fe9f66098ab283429a5534f38e75c7b6f46735')
const peerData = hexToBytes('011a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f00')

describe('gossip protocol state', () => {
  test('join command creates topic state and sends native join messages', () => {
    const state = new GossipProtocolState({ me: peerA, peerData })

    const out = state.handle({
      type: 'command',
      topicId: topicA,
      command: { type: 'join', peers: [peerB] },
    })

    expect(state.topics()).toEqual([topicA])
    expect(out).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'swarm', type: 'join', peerData },
      },
    ])
  })

  test('drops network messages for topics that were not joined', () => {
    const state = new GossipProtocolState({ me: peerA })

    expect(
      state.handle({
        type: 'recv-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'swarm', type: 'join', peerData: new Uint8Array() },
      }),
    ).toEqual([])
  })

  test('receiving join emits neighbor and replies with neighbor message', () => {
    const state = joinedState()

    const out = state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'swarm', type: 'join', peerData },
    })

    expect(out).toEqual([
      {
        type: 'peer-data',
        peer: peerB,
        peerData,
      },
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-up', peer: peerB },
      },
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'neighbor',
          priority: 'high',
          peerData: new Uint8Array(),
        },
      },
    ])
    expect(state.hasActivePeers(topicA)).toBe(true)
  })

  test('broadcast sends to active neighbors and received swarm messages forward once', () => {
    const state = joinedStateWithNeighbors()
    const ownPayload = new TextEncoder().encode('own')
    const incomingPayload = new TextEncoder().encode('incoming')
    const incoming: GossipBroadcastMessage = {
      layer: 'gossip',
      type: 'gossip',
      id: blake3(incomingPayload),
      content: incomingPayload,
      scope: { type: 'swarm', round: 0 },
    }

    const sent = state.handle({
      type: 'command',
      topicId: topicA,
      command: { type: 'broadcast', payload: ownPayload },
    })
    const received = state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: incoming,
    })
    const duplicate = state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: incoming,
    })

    expect(sendMessages(sent)).toEqual([
      expect.objectContaining({
        peer: peerB,
        message: expect.objectContaining({ type: 'gossip' }),
      }),
      expect.objectContaining({
        peer: peerC,
        message: expect.objectContaining({ type: 'gossip' }),
      }),
    ])
    expect(received).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: {
          type: 'received',
          deliveredFrom: peerB,
          id: blake3(incomingPayload),
          payload: incomingPayload,
          scope: { type: 'swarm', round: 1 },
        },
      },
      {
        type: 'send-message',
        peer: peerC,
        topicId: topicA,
        message: {
          ...incoming,
          scope: { type: 'swarm', round: 1 },
        },
      },
    ])
    expect(duplicate).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'gossip', type: 'prune' },
      },
    ])
  })

  test('prune moves peer lazy and dispatches ihave instead of full payload', () => {
    const state = joinedStateWithNeighbors()
    const payload = new TextEncoder().encode('lazy')

    expect(
      state.handle({
        type: 'recv-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'gossip', type: 'prune' },
      }),
    ).toEqual([])

    const broadcast = state.handle({
      type: 'command',
      topicId: topicA,
      command: { type: 'broadcast', payload },
    })
    const schedule = onlyTimer(broadcast)

    expect(sendMessages(broadcast)).toEqual([
      expect.objectContaining({
        peer: peerC,
        message: expect.objectContaining({ type: 'gossip' }),
      }),
    ])
    expect(schedule.delayMs).toBe(5)

    expect(
      state.handle({
        type: 'timer-expired',
        timer: schedule.timer,
      }),
    ).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: {
          layer: 'gossip',
          type: 'ihave',
          messages: [{ id: blake3(payload), round: 0 }],
        },
      },
    ])
  })

  test('ihave schedules graft and graft replies from cache', () => {
    const state = joinedStateWithNeighbors()
    const payload = new TextEncoder().encode('repair')
    const id = blake3(payload)

    const ihave = state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'gossip', type: 'ihave', messages: [{ id, round: 2 }] },
    })
    const graftTimer = onlyTimer(ihave)

    expect(graftTimer.delayMs).toBe(80)
    expect(
      state.handle({
        type: 'timer-expired',
        timer: graftTimer.timer,
      }),
    ).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'gossip', type: 'graft', id, round: 2 },
      },
      {
        type: 'schedule-timer',
        delayMs: 40,
        timer: { topicId: topicA, value: { type: 'send-graft', id } },
      },
    ])

    state.handle({
      type: 'command',
      topicId: topicA,
      command: { type: 'broadcast', payload },
    })

    expect(
      state.handle({
        type: 'recv-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'gossip', type: 'graft', id, round: 0 },
      }),
    ).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: {
          layer: 'gossip',
          type: 'gossip',
          id,
          content: payload,
          scope: { type: 'swarm', round: 0 },
        },
      },
    ])
  })

  test('message id retention bounds dedupe window', () => {
    const state = joinedState()
    const payload = new TextEncoder().encode('expires')
    const incoming: GossipBroadcastMessage = {
      layer: 'gossip',
      type: 'gossip',
      id: blake3(payload),
      content: payload,
      scope: { type: 'swarm', round: 0 },
    }

    const first = state.handle(
      {
        type: 'recv-message',
        peer: peerB,
        topicId: topicA,
        message: incoming,
      },
      0,
    )
    const duplicate = state.handle(
      {
        type: 'recv-message',
        peer: peerB,
        topicId: topicA,
        message: incoming,
      },
      1,
    )
    const afterRetention = state.handle(
      {
        type: 'recv-message',
        peer: peerB,
        topicId: topicA,
        message: incoming,
      },
      90_001,
    )

    expect(first).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: {
          type: 'received',
          deliveredFrom: peerB,
          id: blake3(payload),
          payload,
          scope: { type: 'swarm', round: 1 },
        },
      },
    ])
    expect(duplicate).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'gossip', type: 'prune' },
      },
    ])
    expect(afterRetention).toEqual(first)
  })

  test('payload cache retention bounds graft replies', () => {
    const state = joinedStateWithNeighbors()
    const payload = new TextEncoder().encode('cached')
    const id = blake3(payload)

    state.handle(
      {
        type: 'command',
        topicId: topicA,
        command: { type: 'broadcast', payload },
      },
      0,
    )

    expect(
      state.handle(
        {
          type: 'recv-message',
          peer: peerB,
          topicId: topicA,
          message: { layer: 'gossip', type: 'graft', id, round: 0 },
        },
        30_000,
      ),
    ).toEqual([])
  })

  test('lazy ihave dispatch chunks by max message size', () => {
    const state = new GossipProtocolState({ me: peerA, maxMessageSize: 512 })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)
    receiveJoin(state, topicA, peerC)
    receiveJoin(state, topicA, peerD)

    state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'gossip', type: 'prune' },
    })
    let timer: Extract<GossipProtocolOutEvent, { readonly type: 'schedule-timer' }> | null = null
    for (let index = 0; index < 15; index += 1) {
      const out = state.handle({
        type: 'command',
        topicId: topicA,
        command: { type: 'broadcast', payload: new TextEncoder().encode(`chunk-${index}`) },
      })
      const timers = out.filter((event) => event.type === 'schedule-timer')
      if (timers.length > 0) {
        timer = timers[0] ?? null
      }
    }
    if (timer === null) {
      throw new Error('expected lazy dispatch timer')
    }

    const ihaves = sendMessages(
      state.handle({
        type: 'timer-expired',
        timer: timer.timer,
      }),
    )

    expect(ihaves).toHaveLength(2)
    expect(ihaves).toEqual([
      expect.objectContaining({
        peer: peerB,
        message: expect.objectContaining({
          type: 'ihave',
          messages: expect.any(Array),
        }),
      }),
      expect.objectContaining({
        peer: peerB,
        message: expect.objectContaining({
          type: 'ihave',
          messages: expect.any(Array),
        }),
      }),
    ])
    expect(ihaveMessageCount(ihaves[0])).toBe(14)
    expect(ihaveMessageCount(ihaves[1])).toBe(1)
  })

  test('peer disconnect clears pending lazy ihave dispatch', () => {
    const state = joinedStateWithNeighbors()
    const payload = new TextEncoder().encode('stale-lazy')

    state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'gossip', type: 'prune' },
    })
    const schedule = onlyTimer(
      state.handle({
        type: 'command',
        topicId: topicA,
        command: { type: 'broadcast', payload },
      }),
    )

    state.handle({ type: 'peer-disconnected', peer: peerB })

    expect(
      state.handle({
        type: 'timer-expired',
        timer: schedule.timer,
      }),
    ).toEqual([])
  })

  test('graft clears pending lazy ihave dispatch', () => {
    const state = joinedStateWithNeighbors()
    const payload = new TextEncoder().encode('lazy-to-eager')
    const id = blake3(payload)

    state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'gossip', type: 'prune' },
    })
    const schedule = onlyTimer(
      state.handle({
        type: 'command',
        topicId: topicA,
        command: { type: 'broadcast', payload },
      }),
    )

    state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'gossip', type: 'graft', id, round: 0 },
    })

    expect(
      state.handle({
        type: 'timer-expired',
        timer: schedule.timer,
      }),
    ).toEqual([])
  })

  test('rejects max message size below native minimum', () => {
    expect(() => new GossipProtocolState({ me: peerA, maxMessageSize: 511 })).toThrow(RangeError)
  })

  test('network disconnect waits until peer leaves all topics', () => {
    const state = new GossipProtocolState({ me: peerA })
    joinTopic(state, topicA)
    joinTopic(state, topicB)
    receiveJoin(state, topicA, peerB)
    receiveJoin(state, topicB, peerB)

    const out = state.handle({ type: 'peer-disconnected', peer: peerB })

    expect(out.filter((event) => event.type === 'disconnect-peer')).toEqual([
      { type: 'disconnect-peer', peer: peerB },
    ])
    expect(out.filter((event) => event.type === 'emit-event')).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-down', peer: peerB },
      },
      {
        type: 'emit-event',
        topicId: topicB,
        event: { type: 'neighbor-down', peer: peerB },
      },
    ])
  })

  test('quit clears outbound peers that never became neighbors', () => {
    const state = new GossipProtocolState({ me: peerA })

    state.handle({
      type: 'command',
      topicId: topicA,
      command: { type: 'join', peers: [peerB] },
    })
    expect(
      state.handle({
        type: 'command',
        topicId: topicA,
        command: { type: 'quit' },
      }),
    ).toEqual([{ type: 'disconnect-peer', peer: peerB }])

    joinTopic(state, topicB)
    receiveJoin(state, topicB, peerB)

    expect(
      state.handle({
        type: 'command',
        topicId: topicB,
        command: { type: 'quit' },
      }),
    ).toEqual([
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicB,
        message: { layer: 'swarm', type: 'disconnect', alive: false, respond: false },
      },
      { type: 'disconnect-peer', peer: peerB },
    ])
  })
})

function joinedState(): GossipProtocolState {
  const state = new GossipProtocolState({ me: peerA })
  joinTopic(state, topicA)
  return state
}

function joinedStateWithNeighbors(): GossipProtocolState {
  const state = joinedState()
  receiveJoin(state, topicA, peerB)
  receiveJoin(state, topicA, peerC)
  return state
}

function joinTopic(state: GossipProtocolState, topicId: Uint8Array): void {
  state.handle({
    type: 'command',
    topicId,
    command: { type: 'join', peers: [] },
  })
}

function receiveJoin(state: GossipProtocolState, topicId: Uint8Array, peer: Uint8Array): void {
  state.handle({
    type: 'recv-message',
    peer,
    topicId,
    message: { layer: 'swarm', type: 'join', peerData: new Uint8Array() },
  })
}

function sendMessages(
  events: readonly GossipProtocolOutEvent[],
): readonly GossipProtocolOutEvent[] {
  return events.filter((event) => event.type === 'send-message')
}

function onlyTimer(
  events: readonly GossipProtocolOutEvent[],
): Extract<GossipProtocolOutEvent, { readonly type: 'schedule-timer' }> {
  const timers = events.filter((event) => event.type === 'schedule-timer')
  expect(timers).toHaveLength(1)
  const timer = timers[0]
  if (timer === undefined || timer.type !== 'schedule-timer') {
    throw new Error('expected one schedule timer')
  }
  return timer
}

function ihaveMessageCount(event: GossipProtocolOutEvent | undefined): number {
  if (event?.type !== 'send-message' || event.message.type !== 'ihave') {
    throw new Error('expected ihave message')
  }
  return event.message.messages.length
}

import { describe, expect, test } from 'bun:test'
import { blake3 } from '@noble/hashes/blake3.js'

import { hexToBytes } from '../testing/hex'
import {
  GossipProtocolState,
  GossipTimerScheduler,
  type GossipProtocolOutEvent,
  type GossipRandomSource,
} from './state'
import type { GossipBroadcastMessage } from './wire'
import { encodeGossipIHaveMessage } from './wire'

const topicA = hexToBytes('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f')
const topicB = hexToBytes('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
const peerA = hexToBytes('8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c')
const peerB = hexToBytes('ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1')
const peerC = hexToBytes('c352229ac4bcb6f633f773596a30ad8b2dfb0256f2ca8db78dd085eec828d838')
const peerD = hexToBytes('4ca37a63d42514dd1df5974786fe9f66098ab283429a5534f38e75c7b6f46735')
const peerE = hexToBytes('630abef7d2ec016d768865e83187b6dbb82bb87e1b1179f4018536da6afc5f9b')
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
    for (let index = 0; index < 16; index += 1) {
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
    expect(ihaveMessageCount(ihaves[0])).toBe(15)
    expect(ihaveMessageCount(ihaves[1])).toBe(1)
    expect(ihavePayloadSize(ihaves[0])).toBeLessThanOrEqual(512)
    expect(ihavePayloadSize(ihaves[1])).toBeLessThanOrEqual(512)
  })

  test('timer scheduler feeds expired timers back into protocol state', () => {
    const state = joinedStateWithNeighbors()
    const clock = new FakeClock()
    const payload = new TextEncoder().encode('timer-dispatch')
    const expiredOut: GossipProtocolOutEvent[] = []

    const scheduler = new GossipTimerScheduler({
      now: () => clock.nowMs,
      setTimeout: (callback, delayMs) => clock.setTimeout(callback, delayMs),
      clearTimeout: (handle) => clock.clearTimeout(handle),
      onTimer: (timer, nowMs) => {
        expiredOut.push(...state.handle({ type: 'timer-expired', timer }, nowMs))
      },
    })

    state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: { layer: 'gossip', type: 'prune' },
    })
    scheduler.scheduleFrom(
      state.handle({
        type: 'command',
        topicId: topicA,
        command: { type: 'broadcast', payload },
      }),
    )

    expect(clock.pending()).toBe(1)
    clock.nowMs = 5
    clock.runNext()

    expect(sendMessages(expiredOut)).toEqual([
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

  test('timer scheduler cancels pending timers on close', () => {
    const clock = new FakeClock()
    let expired = false
    const scheduler = new GossipTimerScheduler({
      setTimeout: (callback, delayMs) => clock.setTimeout(callback, delayMs),
      clearTimeout: (handle) => clock.clearTimeout(handle),
      onTimer: () => {
        expired = true
      },
    })

    scheduler.schedule({
      type: 'schedule-timer',
      delayMs: 5,
      timer: { topicId: topicA, value: { type: 'dispatch-lazy-push' } },
    })
    scheduler.close()

    expect(clock.pending()).toBe(0)
    expect(expired).toBe(false)
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

  test('active view capacity evicts old high-priority neighbor to passive view', () => {
    const state = new GossipProtocolState({
      me: peerA,
      activeViewCapacity: 1,
      random: sequenceRandom(0),
    })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)

    const out = state.handle({
      type: 'recv-message',
      peer: peerC,
      topicId: topicA,
      message: { layer: 'swarm', type: 'join', peerData: new Uint8Array() },
    })

    expect(out).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-down', peer: peerB },
      },
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: { layer: 'swarm', type: 'disconnect', alive: true, respond: false },
      },
      { type: 'disconnect-peer', peer: peerB },
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-up', peer: peerC },
      },
      {
        type: 'send-message',
        peer: peerC,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'neighbor',
          priority: 'high',
          peerData: new Uint8Array(),
        },
      },
    ])
  })

  test('active view eviction uses injected random source', () => {
    const state = new GossipProtocolState({
      me: peerA,
      activeViewCapacity: 2,
      random: sequenceRandom(1),
    })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)
    receiveJoin(state, topicA, peerC)

    const out = state.handle({
      type: 'recv-message',
      peer: peerD,
      topicId: topicA,
      message: { layer: 'swarm', type: 'join', peerData: new Uint8Array() },
    })

    expect(out).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-down', peer: peerC },
      },
      {
        type: 'send-message',
        peer: peerC,
        topicId: topicA,
        message: { layer: 'swarm', type: 'disconnect', alive: true, respond: false },
      },
      { type: 'disconnect-peer', peer: peerC },
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-up', peer: peerD },
      },
      {
        type: 'send-message',
        peer: peerD,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'neighbor',
          priority: 'high',
          peerData: new Uint8Array(),
        },
      },
      {
        type: 'send-message',
        peer: peerB,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'forward-join',
          peer: { id: peerD, peerData: new Uint8Array() },
          ttl: 6,
        },
      },
    ])
  })

  test('low-priority neighbor request is refused when active view is full', () => {
    const state = new GossipProtocolState({ me: peerA, activeViewCapacity: 1 })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)

    expect(
      state.handle({
        type: 'recv-message',
        peer: peerC,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'neighbor',
          priority: 'low',
          peerData: new Uint8Array(),
        },
      }),
    ).toEqual([
      {
        type: 'send-message',
        peer: peerC,
        topicId: topicA,
        message: { layer: 'swarm', type: 'disconnect', alive: true, respond: false },
      },
      { type: 'disconnect-peer', peer: peerC },
    ])
  })

  test('forward join stores passive peers at PRWL and forwards with decremented TTL', () => {
    const state = joinedStateWithNeighbors()

    const out = state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: {
        layer: 'swarm',
        type: 'forward-join',
        peer: { id: peerD, peerData },
        ttl: 3,
      },
    })

    expect(out).toEqual([
      { type: 'peer-data', peer: peerD, peerData },
      {
        type: 'send-message',
        peer: peerC,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'forward-join',
          peer: { id: peerD, peerData },
          ttl: 2,
        },
      },
    ])
  })

  test('disconnect refills active view from passive peers', () => {
    const state = new GossipProtocolState({
      me: peerA,
      activeViewCapacity: 2,
      random: sequenceRandom(0),
    })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)
    receiveNeighbor(state, topicA, peerB)
    receiveJoin(state, topicA, peerC)
    receiveNeighbor(state, topicA, peerC)
    state.handle({
      type: 'recv-message',
      peer: peerB,
      topicId: topicA,
      message: {
        layer: 'swarm',
        type: 'forward-join',
        peer: { id: peerD, peerData },
        ttl: 3,
      },
    })

    const out = state.handle({ type: 'peer-disconnected', peer: peerB })
    const timer = onlyTimer(out)

    expect(out).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-down', peer: peerB },
      },
      { type: 'disconnect-peer', peer: peerB },
      {
        type: 'send-message',
        peer: peerD,
        topicId: topicA,
        message: {
          layer: 'swarm',
          type: 'neighbor',
          priority: 'low',
          peerData: new Uint8Array(),
        },
      },
      timer,
    ])
    expect(timer.delayMs).toBe(500)

    expect(
      state.handle({
        type: 'timer-expired',
        timer: timer.timer,
      }),
    ).toEqual([{ type: 'disconnect-peer', peer: peerD }])
  })

  test('alive disconnect keeps passive peer after connection close', () => {
    const state = new GossipProtocolState({
      me: peerA,
      activeViewCapacity: 1,
      random: sequenceRandom(0),
    })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)
    state.handle({
      type: 'recv-message',
      peer: peerC,
      topicId: topicA,
      message: { layer: 'swarm', type: 'join', peerData: new Uint8Array() },
    })

    expect(state.handle({ type: 'peer-disconnected', peer: peerB })).toEqual([])
    const out = state.handle({ type: 'peer-disconnected', peer: peerC })
    const timer = onlyTimer(out)

    expect(out).toEqual([
      {
        type: 'emit-event',
        topicId: topicA,
        event: { type: 'neighbor-down', peer: peerC },
      },
      { type: 'disconnect-peer', peer: peerC },
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
      timer,
    ])
  })

  test('pending neighbor timeout disconnects failed probe and skips pending passive peers', () => {
    const state = new GossipProtocolState({
      me: peerA,
      activeViewCapacity: 3,
      random: sequenceRandom(0),
    })
    joinTopic(state, topicA)
    receiveJoin(state, topicA, peerB)
    receiveNeighbor(state, topicA, peerB)
    receiveJoin(state, topicA, peerC)
    receiveNeighbor(state, topicA, peerC)
    receiveForwardJoin(state, topicA, peerB, peerD)
    receiveForwardJoin(state, topicA, peerB, peerE)

    const firstRefill = state.handle({ type: 'peer-disconnected', peer: peerB })
    const firstTimer = onlyTimer(firstRefill)
    expect(sendMessages(firstRefill)).toEqual([
      expect.objectContaining({
        peer: peerD,
        message: expect.objectContaining({ type: 'neighbor', priority: 'low' }),
      }),
    ])

    const secondRefill = state.handle({ type: 'peer-disconnected', peer: peerC })
    const secondTimer = onlyTimer(secondRefill)
    expect(sendMessages(secondRefill)).toEqual([
      expect.objectContaining({
        peer: peerE,
        message: expect.objectContaining({ type: 'neighbor', priority: 'high' }),
      }),
    ])

    expect(
      state.handle({
        type: 'timer-expired',
        timer: firstTimer.timer,
      }),
    ).toEqual([{ type: 'disconnect-peer', peer: peerD }])
    expect(
      state.handle({
        type: 'timer-expired',
        timer: secondTimer.timer,
      }),
    ).toEqual([{ type: 'disconnect-peer', peer: peerE }])
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

function receiveNeighbor(state: GossipProtocolState, topicId: Uint8Array, peer: Uint8Array): void {
  state.handle({
    type: 'recv-message',
    peer,
    topicId,
    message: {
      layer: 'swarm',
      type: 'neighbor',
      priority: 'high',
      peerData: new Uint8Array(),
    },
  })
}

function receiveForwardJoin(
  state: GossipProtocolState,
  topicId: Uint8Array,
  sender: Uint8Array,
  peer: Uint8Array,
): void {
  state.handle({
    type: 'recv-message',
    peer: sender,
    topicId,
    message: {
      layer: 'swarm',
      type: 'forward-join',
      peer: { id: peer, peerData },
      ttl: 3,
    },
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

function ihavePayloadSize(event: GossipProtocolOutEvent | undefined): number {
  if (event?.type !== 'send-message' || event.message.type !== 'ihave') {
    throw new Error('expected ihave message')
  }
  return encodeGossipIHaveMessage({ messages: event.message.messages }).length - 4
}

function sequenceRandom(...values: readonly number[]): GossipRandomSource {
  let index = 0
  return {
    nextUint32(): number {
      const value = values[index] ?? 0
      index += 1
      return value
    },
  }
}

class FakeClock {
  nowMs = 0
  readonly #timers = new Map<number, { readonly callback: () => void; readonly delayMs: number }>()
  #nextHandle = 0

  setTimeout(callback: () => void, delayMs: number): number {
    const handle = this.#nextHandle
    this.#nextHandle += 1
    this.#timers.set(handle, { callback, delayMs })
    return handle
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === 'number') {
      this.#timers.delete(handle)
    }
  }

  pending(): number {
    return this.#timers.size
  }

  runNext(): void {
    const next = this.#timers.entries().next().value
    if (next === undefined) {
      throw new Error('expected pending timer')
    }
    const [handle, timer] = next
    this.#timers.delete(handle)
    this.nowMs += timer.delayMs
    timer.callback()
  }
}

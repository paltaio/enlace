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
          scope: { type: 'swarm', round: 0 },
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

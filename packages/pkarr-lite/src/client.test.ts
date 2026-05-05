import { describe, expect, test } from 'bun:test'

import {
  cacheKey,
  Client,
  DEFAULT_CACHE_SIZE,
  EmptyListOfRelaysError,
  InMemoryCache,
  InvalidRelayUrlError,
  Keypair,
  NoNetworkError,
  SignedPacket,
} from '@paltaio/pkarr-lite'

describe('ClientBuilder', () => {
  test('builds default relay-only client with default cache', () => {
    const client = Client.builder().build()

    expect(client.relays()).toEqual(['https://pkarr.pubky.app', 'https://pkarr.pubky.org'])
    expect(client.cache()?.capacity()).toBe(DEFAULT_CACHE_SIZE)
  })

  test('supports relay replacement and extension', () => {
    const client = Client.builder()
      .relays(['http://localhost:8080/'])
      .extraRelays(['http://localhost:8080', 'https://example.com/pkarr/'])
      .build()

    expect(client.relays()).toEqual(['http://localhost:8080', 'https://example.com/pkarr'])
  })

  test('returns relay snapshots', () => {
    const client = Client.builder().relays(['https://example.com/pkarr']).build()
    const relays = client.relays()

    Array.prototype.push.call(relays, 'https://mutated.example')

    expect(client.relays()).toEqual(['https://example.com/pkarr'])
  })

  test('rejects no network, empty relays, and non-http relays', () => {
    expect(() => Client.builder().noDefaultNetwork().build()).toThrow(NoNetworkError)
    expect(() => Client.builder().relays([]).build()).toThrow(EmptyListOfRelaysError)
    expect(() => Client.builder().relays(['udp://relay.example']).build()).toThrow(
      InvalidRelayUrlError,
    )
  })

  test('cacheSize zero disables cache', () => {
    const client = Client.builder().cacheSize(0).build()

    expect(client.cache()).toBeUndefined()
  })

  test('custom cache wins over default cache size', () => {
    const cache = new InMemoryCache(3)
    const client = Client.builder().cacheSize(10).cache(cache).build()

    expect(client.cache()).toBe(cache)
    expect(client.cache()?.capacity()).toBe(3)
  })

  test('minimum and maximum ttl clamp each other', async () => {
    const packet = await signedPacket()
    const cache = new InMemoryCache(1)
    cache.put(cacheKey(packet.publicKey()), packet)

    const minimumClient = Client.builder().cache(cache).minimumTtl(600).maximumTtl(30).build()
    const maximumClient = Client.builder().cache(cache).maximumTtl(30).minimumTtl(600).build()

    expect(await minimumClient.resolve(packet.publicKey())).toBeDefined()
    expect(await maximumClient.resolve(packet.publicKey())).toBeDefined()
  })
})

describe('Client cache reads', () => {
  test('resolve returns cached packet even when expired', async () => {
    const packet = await signedPacket()
    packet.setLastSeen(BigInt(Date.now()) * 1_000n - 60_000_000n)
    const cache = new InMemoryCache(1)
    cache.put(cacheKey(packet.publicKey()), packet)
    const client = Client.builder().cache(cache).maximumTtl(0).build()

    expect((await client.resolve(packet.publicKey()))?.isSameAs(packet)).toBe(true)
  })

  test('resolveMostRecent returns newest cached packet', async () => {
    const oldPacket = await signedPacket(1, 'old')
    const newPacket = await signedPacket(2, 'new')
    const cache = new InMemoryCache(1)
    cache.put(cacheKey(oldPacket.publicKey()), oldPacket)
    cache.put(cacheKey(newPacket.publicKey()), newPacket)
    const client = Client.builder().cache(cache).build()

    expect((await client.resolveMostRecent(newPacket.publicKey()))?.isSameAs(newPacket)).toBe(true)
  })
})

async function signedPacket(timestamp = 1, text = 'value'): Promise<SignedPacket> {
  return SignedPacket.builder()
    .timestamp(timestamp)
    .txt('_client', text, 30)
    .sign(await Keypair.fromSecretKey(new Uint8Array(32).fill(9)))
}

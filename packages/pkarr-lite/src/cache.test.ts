import { describe, expect, test } from 'bun:test'

import { cacheKey, InMemoryCache, Keypair, SignedPacket } from '@paltaio/pkarr-lite'

import { bytesToHex } from './testing/hex'

const SECRET_KEY = new Uint8Array(32).fill(7)
const CACHE_KEY_HEX = '4c5ece4023a0341ee2acffcc4d17154a854f02e5'

describe('InMemoryCache', () => {
  test('keys packets by sha1 of the public key bytes', async () => {
    const publicKey = (await Keypair.fromSecretKey(SECRET_KEY)).publicKey()

    expect(bytesToHex(cacheKey(publicKey))).toBe(CACHE_KEY_HEX)
  })

  test('stores clones and refreshes lastSeen for identical signed bytes', async () => {
    const packet = await signedPacket('one', 1)
    const key = cacheKey(packet.publicKey())
    const cache = new InMemoryCache(2)

    packet.setLastSeen(10)
    cache.put(key, packet)
    packet.setLastSeen(20)

    expect(cache.getReadOnly(key)?.lastSeen()).toBe(10n)

    const refreshed = SignedPacket.deserialize(packet.serialize())
    refreshed.setLastSeen(30)
    cache.put(key, refreshed)

    expect(cache.len()).toBe(1)
    expect(cache.getReadOnly(key)?.lastSeen()).toBe(30n)
  })

  test('evicts least recently used packet', async () => {
    const first = await signedPacket('one', 1)
    const second = await signedPacket('two', 2)
    const third = await signedPacket('three', 3)
    const firstKey = cacheKey(first.publicKey())
    const secondKey = cacheKey(second.publicKey())
    const thirdKey = cacheKey(third.publicKey())
    const cache = new InMemoryCache(2)

    cache.put(firstKey, first)
    cache.put(secondKey, second)
    expect(cache.get(firstKey)?.isSameAs(first)).toBe(true)
    cache.put(thirdKey, third)

    expect(cache.getReadOnly(firstKey)?.isSameAs(first)).toBe(true)
    expect(cache.getReadOnly(secondKey)).toBeUndefined()
    expect(cache.getReadOnly(thirdKey)?.isSameAs(third)).toBe(true)
  })
})

async function signedPacket(text: string, secretByte: number): Promise<SignedPacket> {
  return SignedPacket.builder()
    .timestamp(secretByte)
    .txt('_cache', text, 30)
    .sign(await Keypair.fromSecretKey(new Uint8Array(32).fill(secretByte)))
}

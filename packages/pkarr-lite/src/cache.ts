import { sha1 } from '@noble/hashes/legacy.js'

import { DEFAULT_CACHE_SIZE } from './constants'
import { PublicKey } from './keys'
import { SignedPacket } from './signed-packet'
import { bytesToKey, compareBytes, requireLength } from './bytes'

export const CACHE_KEY_BYTES = 20

export type CacheKey = Uint8Array

export interface Cache {
  capacity(): number
  len(): number
  isEmpty(): boolean
  put(key: CacheKey, signedPacket: SignedPacket): void
  get(key: CacheKey): SignedPacket | undefined
  getReadOnly(key: CacheKey): SignedPacket | undefined
}

export function cacheKey(publicKey: PublicKey): CacheKey {
  return sha1(publicKey.toBytes())
}

export class InMemoryCache implements Cache {
  readonly #capacity: number
  readonly #packets = new Map<string, SignedPacket>()

  constructor(capacity = DEFAULT_CACHE_SIZE) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new RangeError('cache capacity must be a positive integer')
    }
    this.#capacity = capacity
  }

  capacity(): number {
    return this.#capacity
  }

  len(): number {
    return this.#packets.size
  }

  isEmpty(): boolean {
    return this.len() === 0
  }

  put(key: CacheKey, signedPacket: SignedPacket): void {
    const mapKey = cacheMapKey(key)
    const existing = this.#packets.get(mapKey)
    if (existing !== undefined && compareBytes(existing.asBytes(), signedPacket.asBytes()) === 0) {
      existing.setLastSeen(signedPacket.lastSeen())
      this.#packets.delete(mapKey)
      this.#packets.set(mapKey, existing)
      return
    }

    this.#packets.delete(mapKey)
    this.#packets.set(mapKey, cloneSignedPacket(signedPacket))
    this.#evictOverflow()
  }

  get(key: CacheKey): SignedPacket | undefined {
    const mapKey = cacheMapKey(key)
    const packet = this.#packets.get(mapKey)
    if (packet === undefined) {
      return undefined
    }
    this.#packets.delete(mapKey)
    this.#packets.set(mapKey, packet)
    return cloneSignedPacket(packet)
  }

  getReadOnly(key: CacheKey): SignedPacket | undefined {
    const packet = this.#packets.get(cacheMapKey(key))
    return packet === undefined ? undefined : cloneSignedPacket(packet)
  }

  #evictOverflow(): void {
    while (this.#packets.size > this.#capacity) {
      const oldest = this.#packets.keys().next().value
      if (oldest === undefined) {
        return
      }
      this.#packets.delete(oldest)
    }
  }
}

function cacheMapKey(key: CacheKey): string {
  requireLength(key, CACHE_KEY_BYTES, 'cache key')
  return bytesToKey(key)
}

function cloneSignedPacket(packet: SignedPacket): SignedPacket {
  return SignedPacket.deserialize(packet.serialize())
}

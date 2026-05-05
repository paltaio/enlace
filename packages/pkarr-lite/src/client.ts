import {
  DEFAULT_CACHE_SIZE,
  DEFAULT_MAXIMUM_TTL,
  DEFAULT_MINIMUM_TTL,
  DEFAULT_RELAYS,
} from './constants'
import { type Cache, cacheKey, InMemoryCache } from './cache'
import { PublicKey } from './keys'
import { SignedPacket } from './signed-packet'

export const DEFAULT_REQUEST_TIMEOUT_MS = 2_000

const CLIENT_FROM_CONFIG = Symbol('Client.fromConfig')

type NetworkConfig = readonly string[] | null

interface ClientConfig {
  cacheSize: number
  minimumTtl: number
  maximumTtl: number
  cache: Cache | null
  relays: NetworkConfig
  requestTimeout: number
}

export class BuildError extends Error {}

export class NoNetworkError extends BuildError {
  constructor() {
    super('client configured without relays')
  }
}

export class EmptyListOfRelaysError extends BuildError {
  constructor() {
    super('passed an empty list of relays')
  }
}

export class InvalidRelayUrlError extends BuildError {
  constructor(url: string) {
    super(`relay URL must use http or https: ${url}`)
  }
}

export class ClientBuilder {
  #config: ClientConfig = defaultClientConfig()

  noDefaultNetwork(): this {
    return this.noRelays()
  }

  noRelays(): this {
    this.#config.relays = null
    return this
  }

  relays(relays: readonly string[]): this {
    this.#config.relays = relays.map(normalizeRelayUrl)
    return this
  }

  extraRelays(relays: readonly string[]): this {
    if (this.#config.relays === null) {
      return this
    }
    const next = [...this.#config.relays]
    for (const relay of relays.map(normalizeRelayUrl)) {
      if (!next.includes(relay)) {
        next.push(relay)
      }
    }
    this.#config.relays = next
    return this
  }

  cacheSize(cacheSize: number): this {
    if (!Number.isInteger(cacheSize) || cacheSize < 0) {
      throw new RangeError('cache size must be a non-negative integer')
    }
    this.#config.cacheSize = cacheSize
    return this
  }

  minimumTtl(ttl: number): this {
    requireTtl(ttl, 'minimum TTL')
    this.#config.minimumTtl = ttl
    this.#config.maximumTtl = Math.max(this.#config.maximumTtl, ttl)
    return this
  }

  maximumTtl(ttl: number): this {
    requireTtl(ttl, 'maximum TTL')
    this.#config.maximumTtl = ttl
    this.#config.minimumTtl = Math.min(this.#config.minimumTtl, ttl)
    return this
  }

  cache(cache: Cache): this {
    this.#config.cache = cache
    return this
  }

  requestTimeout(timeout: number): this {
    if (!Number.isFinite(timeout) || timeout < 0) {
      throw new RangeError('request timeout must be a non-negative number')
    }
    this.#config.requestTimeout = timeout
    return this
  }

  build(): Client {
    return Client[CLIENT_FROM_CONFIG](this.#config)
  }
}

function defaultClientConfig(): ClientConfig {
  return {
    cacheSize: DEFAULT_CACHE_SIZE,
    minimumTtl: DEFAULT_MINIMUM_TTL,
    maximumTtl: DEFAULT_MAXIMUM_TTL,
    cache: null,
    relays: [...DEFAULT_RELAYS],
    requestTimeout: DEFAULT_REQUEST_TIMEOUT_MS,
  }
}

export class Client {
  readonly #minimumTtl: number
  readonly #maximumTtl: number
  readonly #cache: Cache | null
  readonly #relays: readonly string[]
  readonly #requestTimeout: number

  private constructor(config: ClientConfig) {
    if (!Number.isInteger(config.cacheSize) || config.cacheSize < 0) {
      throw new RangeError('cache size must be a non-negative integer')
    }
    requireTtl(config.minimumTtl, 'minimum TTL')
    requireTtl(config.maximumTtl, 'maximum TTL')
    if (config.minimumTtl > config.maximumTtl) {
      throw new RangeError('minimum TTL must be less than or equal to maximum TTL')
    }
    if (!Number.isFinite(config.requestTimeout) || config.requestTimeout < 0) {
      throw new RangeError('request timeout must be a non-negative number')
    }
    if (config.relays === null) {
      throw new NoNetworkError()
    }
    if (config.relays.length === 0) {
      throw new EmptyListOfRelaysError()
    }
    const relays = config.relays.map(normalizeRelayUrl)

    this.#minimumTtl = config.minimumTtl
    this.#maximumTtl = config.maximumTtl
    this.#cache =
      config.cacheSize === 0 || config.cache?.capacity() === 0
        ? null
        : (config.cache ?? new InMemoryCache(config.cacheSize || DEFAULT_CACHE_SIZE))
    this.#relays = relays
    this.#requestTimeout = config.requestTimeout
  }

  static [CLIENT_FROM_CONFIG](config: ClientConfig): Client {
    return new Client(config)
  }

  static builder(): ClientBuilder {
    return new ClientBuilder()
  }

  cache(): Cache | undefined {
    return this.#cache ?? undefined
  }

  relays(): readonly string[] {
    return [...this.#relays]
  }

  requestTimeout(): number {
    return this.#requestTimeout
  }

  async resolve(publicKey: PublicKey): Promise<SignedPacket | undefined> {
    const cached = this.#cache?.get(cacheKey(publicKey))
    if (cached === undefined) {
      return undefined
    }
    return cached.isExpired(this.#minimumTtl, this.#maximumTtl)
      ? this.#cache?.get(cacheKey(publicKey))
      : cached
  }

  async resolveMostRecent(publicKey: PublicKey): Promise<SignedPacket | undefined> {
    return this.#cache?.get(cacheKey(publicKey))
  }
}

function normalizeRelayUrl(input: string): string {
  const url = new URL(input)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InvalidRelayUrlError(input)
  }
  return url.toString().replace(/\/$/u, '')
}

function requireTtl(ttl: number, name: string): void {
  if (!Number.isInteger(ttl) || ttl < 0) {
    throw new RangeError(`${name} must be a non-negative integer`)
  }
}

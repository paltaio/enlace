import {
  DEFAULT_CACHE_SIZE,
  DEFAULT_MAXIMUM_TTL,
  DEFAULT_MINIMUM_TTL,
  DEFAULT_RELAYS,
  RELAY_PAYLOAD_MAX_BYTES,
} from './constants'
import { type Cache, cacheKey, InMemoryCache } from './cache'
import { PublicKey } from './keys'
import { SignedPacket, type TimestampInput } from './signed-packet'

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

type RelayResolveResult =
  | {
      packet: SignedPacket
      notModified?: never
    }
  | {
      packet?: never
      notModified: true
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

export class PublishError extends Error {}

export type QueryErrorCode = 'BadRequest' | 'Timeout'

export class QueryError extends PublishError {
  readonly code: QueryErrorCode

  constructor(code: QueryErrorCode) {
    super(queryErrorMessage(code))
    this.code = code
  }
}

export type ConcurrencyErrorCode = 'CasFailed' | 'ConflictRisk' | 'NotMostRecent'

export class ConcurrencyError extends PublishError {
  readonly code: ConcurrencyErrorCode

  constructor(code: ConcurrencyErrorCode) {
    super(concurrencyErrorMessage(code))
    this.code = code
  }
}

export class UnexpectedResponsesError extends PublishError {
  constructor() {
    super('all relays responded with unexpected responses')
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
    const key = cacheKey(publicKey)
    const cached = this.#cache?.get(key)
    if (cached !== undefined) {
      if (cached.isExpired(this.#minimumTtl, this.#maximumTtl)) {
        void this.#drainResolve(publicKey, this.#cache, key, cached.timestamp()).catch(() => {})
      }
      return this.#cache?.get(key)
    }

    const first = await this.#resolveFirst(publicKey, this.#cache, key, undefined)
    return this.#cache?.get(key) ?? first
  }

  async resolveMostRecent(publicKey: PublicKey): Promise<SignedPacket | undefined> {
    const key = cacheKey(publicKey)
    const cache = this.#cache ?? new InMemoryCache(1)
    const cached = cache.get(key)

    await this.#drainResolve(publicKey, cache, key, cached?.timestamp())

    return cache.get(key)
  }

  async publish(signedPacket: SignedPacket, cas?: TimestampInput): Promise<void> {
    const publicKey = signedPacket.publicKey()
    const key = cacheKey(publicKey)
    const casTimestamp = cas === undefined ? undefined : timestampMicros(cas)
    const cached = this.#cache?.getReadOnly(key)

    if (cached !== undefined) {
      if (cached.moreRecentThan(signedPacket)) {
        throw new ConcurrencyError('NotMostRecent')
      }
      if (casTimestamp !== undefined && cached.timestamp() !== casTimestamp) {
        throw new ConcurrencyError('CasFailed')
      }
    }

    await Promise.all(
      this.#relays.map((relay) => this.#publishToRelay(relay, signedPacket, casTimestamp)),
    )
    this.#cache?.put(key, signedPacket)
  }

  async #resolveFirst(
    publicKey: PublicKey,
    cache: Cache | null,
    key: Uint8Array,
    moreRecentThan: bigint | undefined,
  ): Promise<SignedPacket | undefined> {
    const pending = this.#relays.map((relay) =>
      this.#resolveFromRelay(relay, publicKey, moreRecentThan),
    )

    while (pending.length > 0) {
      const indexed = pending.map(async (promise, index) => ({
        index,
        packet: await promise,
      }))
      const { index, packet } = await Promise.race(indexed)
      void pending.splice(index, 1)
      const incoming = this.#cacheIncoming(cache, key, packet)
      if (incoming !== undefined) {
        return incoming
      }
    }

    return undefined
  }

  async #drainResolve(
    publicKey: PublicKey,
    cache: Cache | null,
    key: Uint8Array,
    moreRecentThan: bigint | undefined,
  ): Promise<void> {
    const results = await Promise.all(
      this.#relays.map((relay) => this.#resolveFromRelay(relay, publicKey, moreRecentThan)),
    )

    for (const packet of results) {
      this.#cacheIncoming(cache, key, packet)
    }
  }

  #cacheIncoming(
    cache: Cache | null,
    key: Uint8Array,
    result: RelayResolveResult | undefined,
  ): SignedPacket | undefined {
    if (result === undefined) {
      return undefined
    }

    const cached = cache?.getReadOnly(key)
    if (result.notModified === true) {
      cached?.refresh()
      if (cached !== undefined) {
        cache?.put(key, cached)
      }
      return undefined
    }

    const { packet } = result
    if (cached !== undefined && packet.isSameAs(cached)) {
      cache?.put(key, packet)
      return undefined
    }
    if (cached !== undefined && !packet.moreRecentThan(cached)) {
      return undefined
    }

    cache?.put(key, packet)
    return packet
  }

  async #resolveFromRelay(
    relay: string,
    publicKey: PublicKey,
    moreRecentThan: bigint | undefined,
  ): Promise<RelayResolveResult | undefined> {
    const url = relayUrl(relay, publicKey)
    const headers = new Headers()
    if (moreRecentThan !== undefined) {
      headers.set('If-Modified-Since', httpDate(moreRecentThan))
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await this.#fetchRelay(url, headers)
      if (response === undefined) {
        return undefined
      }
      if (shouldRetryWithoutRelayCache(response, moreRecentThan, headers)) {
        headers.set('Cache-Control', 'no-cache, no-store, must-revalidate')
        continue
      }
      if (response.status === 304) {
        return moreRecentThan === undefined ? undefined : { notModified: true }
      }
      if (!response.ok) {
        return undefined
      }

      const contentLength = response.headers.get('Content-Length')
      if (contentLength !== null && Number(contentLength) > RELAY_PAYLOAD_MAX_BYTES) {
        return undefined
      }

      let payload: Uint8Array
      try {
        payload = new Uint8Array(await response.arrayBuffer())
      } catch {
        return undefined
      }
      if (payload.length === 0 && !headers.has('Cache-Control')) {
        headers.set('Cache-Control', 'no-cache, no-store, must-revalidate')
        continue
      }
      if (payload.length > RELAY_PAYLOAD_MAX_BYTES) {
        return undefined
      }

      try {
        return { packet: await SignedPacket.fromRelayPayload(publicKey, payload) }
      } catch {
        return undefined
      }
    }

    return undefined
  }

  async #fetchRelay(url: string, headers: Headers): Promise<Response | undefined> {
    const controller = new AbortController()
    const timeout =
      this.#requestTimeout === 0
        ? undefined
        : setTimeout(() => controller.abort(), this.#requestTimeout)

    try {
      return await fetch(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      })
    } catch {
      return undefined
    } finally {
      if (timeout !== undefined) {
        clearTimeout(timeout)
      }
    }
  }

  async #publishToRelay(
    relay: string,
    signedPacket: SignedPacket,
    cas: bigint | undefined,
  ): Promise<void> {
    const controller = new AbortController()
    const timeout =
      this.#requestTimeout === 0
        ? undefined
        : setTimeout(() => controller.abort(), this.#requestTimeout * 3)

    const headers = new Headers()
    if (cas !== undefined) {
      headers.set('If-Match', cas.toString())
    }

    let response: Response
    try {
      const payload = signedPacket.toRelayPayload()
      const body = new ArrayBuffer(payload.byteLength)
      new Uint8Array(body).set(payload)
      response = await fetch(relayUrl(relay, signedPacket.publicKey()), {
        method: 'PUT',
        headers,
        body,
        signal: controller.signal,
      })
    } catch (error) {
      if (isAbortError(error)) {
        throw new QueryError('Timeout')
      }
      throw new UnexpectedResponsesError()
    } finally {
      if (timeout !== undefined) {
        clearTimeout(timeout)
      }
    }

    if (response.ok) {
      return
    }

    throw publishErrorForStatus(response.status)
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

function relayUrl(relay: string, publicKey: PublicKey): string {
  const url = new URL(relay)
  const path = url.pathname.replace(/\/$/u, '')
  url.pathname = `${path}/${publicKey.toZ32()}`
  return url.toString()
}

function httpDate(timestampMicros: bigint): string {
  return new Date(Number(timestampMicros / 1_000n)).toUTCString()
}

function shouldRetryWithoutRelayCache(
  response: Response,
  moreRecentThan: bigint | undefined,
  headers: Headers,
): boolean {
  if (headers.has('Cache-Control')) {
    return false
  }
  if (response.status === 304 && moreRecentThan === undefined) {
    return true
  }

  return response.ok && response.headers.get('Content-Length') === '0'
}

function timestampMicros(value: TimestampInput): bigint {
  if (value instanceof Date) {
    return BigInt(value.getTime()) * 1_000n
  }
  const timestamp = typeof value === 'bigint' ? value : BigInt(value)
  if (timestamp < 0n) {
    throw new RangeError(`timestamp out of range: ${value}`)
  }
  return timestamp
}

function publishErrorForStatus(status: number): PublishError {
  if (status === 400) {
    return new QueryError('BadRequest')
  }
  if (status === 409) {
    return new ConcurrencyError('NotMostRecent')
  }
  if (status === 412) {
    return new ConcurrencyError('CasFailed')
  }
  if (status === 428) {
    return new ConcurrencyError('ConflictRisk')
  }
  return new UnexpectedResponsesError()
}

function queryErrorMessage(code: QueryErrorCode): string {
  if (code === 'BadRequest') {
    return 'most relays responded with bad request'
  }
  return 'publish query timed out with no responses'
}

function concurrencyErrorMessage(code: ConcurrencyErrorCode): string {
  if (code === 'CasFailed') {
    return 'compare and swap failed'
  }
  if (code === 'ConflictRisk') {
    return 'a different SignedPacket is being concurrently published'
  }
  return "found a more recent SignedPacket in the client's cache"
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError'
}

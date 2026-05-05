import { describe, expect, test } from 'bun:test'

import {
  cacheKey,
  Client,
  ConcurrencyError,
  DEFAULT_CACHE_SIZE,
  EmptyListOfRelaysError,
  InMemoryCache,
  InvalidRelayUrlError,
  Keypair,
  NoNetworkError,
  QueryError,
  SignedPacket,
  UnexpectedResponsesError,
} from '@paltaio/pkarr-lite'

type FetchMock = (
  input: Parameters<typeof fetch>[0],
  init?: Parameters<typeof fetch>[1],
) => Promise<Response>

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
  test('resolve returns relay packet on cache miss', async () => {
    const packet = await signedPacket()
    const relay = relayServer(() => packetResponse(packet))
    try {
      const client = Client.builder()
        .relays([relay.url])
        .cache(new InMemoryCache(1))
        .requestTimeout(1_000)
        .build()

      const resolved = await client.resolve(packet.publicKey())

      expect(resolved?.isSameAs(packet)).toBe(true)
      expect(relay.requests).toHaveLength(1)
    } finally {
      relay.stop()
    }
  })

  test('resolve formats relay URL and rejects mismatched relay payloads', async () => {
    const packet = await signedPacket()
    const otherPacket = await signedPacketWithSecret(2, 'other', 8)
    const requests: string[] = []

    await withMockFetch(
      async (input) => {
        requests.push(requestUrl(input))
        return packetResponse(otherPacket)
      },
      async () => {
        const client = Client.builder()
          .relays(['https://relay.example/pkarr/'])
          .cache(new InMemoryCache(1))
          .requestTimeout(0)
          .build()

        expect(await client.resolve(packet.publicKey())).toBeUndefined()
      },
    )

    const requestedUrl = requests[0]
    expect(requestedUrl).toBeDefined()
    if (requestedUrl === undefined) {
      throw new Error('relay request not recorded')
    }
    expect(new URL(requestedUrl).pathname).toBe(`/pkarr/${packet.publicKey().toZ32()}`)
  })

  test('resolve ignores relay failures', async () => {
    const packet = await signedPacket()

    for (const response of [
      new Response(null, { status: 404 }),
      new Response(null, { status: 500 }),
      new Response(new Uint8Array(RELAY_OVERSIZED_BYTES)),
    ]) {
      await withMockFetch(
        async () => response,
        async () => {
          const client = Client.builder()
            .relays(['https://relay.example'])
            .cache(new InMemoryCache(1))
            .requestTimeout(0)
            .build()

          expect(await client.resolve(packet.publicKey())).toBeUndefined()
        },
      )
    }

    await withMockFetch(
      async () => {
        throw new TypeError('network failed')
      },
      async () => {
        const client = Client.builder()
          .relays(['https://relay.example'])
          .cache(new InMemoryCache(1))
          .requestTimeout(0)
          .build()

        expect(await client.resolve(packet.publicKey())).toBeUndefined()
      },
    )
  })

  test('resolve retries unexpected not-modified and empty success responses without relay cache', async () => {
    const packet = await signedPacket()
    const notModifiedHeaders: string[] = []

    await withMockFetch(
      async (_input, init) => {
        notModifiedHeaders.push(new Headers(init?.headers).get('Cache-Control') ?? '')
        if (notModifiedHeaders.length === 1) {
          return new Response(null, { status: 304 })
        }
        return packetResponse(packet)
      },
      async () => {
        const client = Client.builder()
          .relays(['https://relay.example'])
          .cache(new InMemoryCache(1))
          .requestTimeout(0)
          .build()

        expect((await client.resolve(packet.publicKey()))?.isSameAs(packet)).toBe(true)
      },
    )

    const emptySuccessHeaders: string[] = []

    await withMockFetch(
      async (_input, init) => {
        emptySuccessHeaders.push(new Headers(init?.headers).get('Cache-Control') ?? '')
        if (emptySuccessHeaders.length === 1) {
          return new Response(null, { status: 200, headers: { 'Content-Length': '0' } })
        }
        return packetResponse(packet)
      },
      async () => {
        const client = Client.builder()
          .relays(['https://relay.example'])
          .cache(new InMemoryCache(1))
          .requestTimeout(0)
          .build()

        expect((await client.resolve(packet.publicKey()))?.isSameAs(packet)).toBe(true)
      },
    )

    expect(notModifiedHeaders).toEqual(['', 'no-cache, no-store, must-revalidate'])
    expect(emptySuccessHeaders).toEqual(['', 'no-cache, no-store, must-revalidate'])
  })

  test('resolve returns cached packet even when expired', async () => {
    const packet = await signedPacket()
    packet.setLastSeen(BigInt(Date.now()) * 1_000n - 60_000_000n)
    const cache = new InMemoryCache(1)
    cache.put(cacheKey(packet.publicKey()), packet)
    const client = Client.builder().cache(cache).maximumTtl(0).build()

    expect((await client.resolve(packet.publicKey()))?.isSameAs(packet)).toBe(true)
  })

  test('resolve refreshes expired cache from relay in background', async () => {
    const oldPacket = await signedPacket(1, 'old')
    const newPacket = await signedPacket(2, 'new')
    const key = cacheKey(oldPacket.publicKey())
    const cache = new InMemoryCache(1)
    oldPacket.setLastSeen(BigInt(Date.now()) * 1_000n - 60_000_000n)
    cache.put(key, oldPacket)

    const relay = relayServer(() => packetResponse(newPacket))
    try {
      const client = Client.builder()
        .relays([relay.url])
        .cache(cache)
        .maximumTtl(0)
        .requestTimeout(1_000)
        .build()

      const resolved = await client.resolve(oldPacket.publicKey())

      expect(resolved?.isSameAs(oldPacket)).toBe(true)
      await waitFor(() => cache.getReadOnly(key)?.isSameAs(newPacket) === true)
      expect(relay.requests[0]?.headers.get('If-Modified-Since')).toBeTruthy()
    } finally {
      relay.stop()
    }
  })

  test('resolve refreshes unchanged expired cache from relay in background', async () => {
    const packet = await signedPacket(1, 'same')
    const key = cacheKey(packet.publicKey())
    const cache = new InMemoryCache(1)
    const expiredLastSeen = BigInt(Date.now()) * 1_000n - 60_000_000n
    packet.setLastSeen(expiredLastSeen)
    cache.put(key, packet)

    const relay = relayServer(() => packetResponse(packet))
    try {
      const client = Client.builder()
        .relays([relay.url])
        .cache(cache)
        .maximumTtl(0)
        .requestTimeout(1_000)
        .build()

      const resolved = await client.resolve(packet.publicKey())

      expect(resolved?.isSameAs(packet)).toBe(true)
      await waitFor(() => (cache.getReadOnly(key)?.lastSeen() ?? 0n) > expiredLastSeen)
    } finally {
      relay.stop()
    }
  })

  test('resolve refreshes expired cache on relay not-modified response', async () => {
    const packet = await signedPacket(1, 'not-modified')
    const key = cacheKey(packet.publicKey())
    const cache = new InMemoryCache(1)
    const expiredLastSeen = BigInt(Date.now()) * 1_000n - 60_000_000n
    packet.setLastSeen(expiredLastSeen)
    cache.put(key, packet)

    const relay = relayServer(() => new Response(null, { status: 304 }))
    try {
      const client = Client.builder()
        .relays([relay.url])
        .cache(cache)
        .maximumTtl(0)
        .requestTimeout(1_000)
        .build()

      const resolved = await client.resolve(packet.publicKey())

      expect(resolved?.isSameAs(packet)).toBe(true)
      await waitFor(() => (cache.getReadOnly(key)?.lastSeen() ?? 0n) > expiredLastSeen)
    } finally {
      relay.stop()
    }
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

  test('resolveMostRecent drains relay responses and keeps newest packet', async () => {
    const oldPacket = await signedPacket(1, 'old')
    const newPacket = await signedPacket(2, 'new')
    const slowOld = relayServer(async () => {
      await delay(5)
      return packetResponse(oldPacket)
    })
    const fastNew = relayServer(() => packetResponse(newPacket))

    try {
      const client = Client.builder()
        .relays([slowOld.url, fastNew.url])
        .cache(new InMemoryCache(1))
        .build()

      const resolved = await client.resolveMostRecent(oldPacket.publicKey())

      expect(resolved?.isSameAs(newPacket)).toBe(true)
      expect(slowOld.requests).toHaveLength(1)
      expect(fastNew.requests).toHaveLength(1)
    } finally {
      slowOld.stop()
      fastNew.stop()
    }
  })
})

describe('Client publish', () => {
  test('sends relay payload with public-key URL and CAS header', async () => {
    const packet = await signedPacket()
    const relay = relayServer(() => new Response(null, { status: 204 }))
    try {
      const client = Client.builder().relays([relay.url]).requestTimeout(1_000).build()

      await client.publish(packet, packet.timestamp())

      expect(relay.requests).toHaveLength(1)
      expect(relay.requests[0]?.method).toBe('PUT')
      expect(new URL(relay.requests[0]?.url ?? '').pathname).toBe(`/${packet.publicKey().toZ32()}`)
      expect(relay.requests[0]?.headers.get('If-Match')).toBe(packet.timestamp().toString())
      expect(relay.requests[0]?.body).toEqual(packet.toRelayPayload())
    } finally {
      relay.stop()
    }
  })

  test('omits CAS header when publish has no CAS timestamp', async () => {
    const packet = await signedPacket()
    const relay = relayServer(() => new Response(null, { status: 204 }))
    try {
      const client = Client.builder().relays([relay.url]).requestTimeout(1_000).build()

      await client.publish(packet)

      expect(relay.requests[0]?.headers.has('If-Match')).toBe(false)
    } finally {
      relay.stop()
    }
  })

  test('maps relay publish status codes', async () => {
    const packet = await signedPacket()
    const cases = [
      [400, (error: unknown) => expectQueryError(error, 'BadRequest')],
      [409, (error: unknown) => expectConcurrencyError(error, 'NotMostRecent')],
      [412, (error: unknown) => expectConcurrencyError(error, 'CasFailed')],
      [428, (error: unknown) => expectConcurrencyError(error, 'ConflictRisk')],
      [500, (error: unknown) => expect(error).toBeInstanceOf(UnexpectedResponsesError)],
    ] as const

    for (const [status, checkError] of cases) {
      const relay = relayServer(() => new Response(null, { status }))
      try {
        const client = Client.builder().relays([relay.url]).requestTimeout(1_000).build()

        const error = await rejected(client.publish(packet))

        checkError(error)
      } finally {
        relay.stop()
      }
    }
  })

  test('maps publish timeout and network failures', async () => {
    const packet = await signedPacket()

    await withMockFetch(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError')),
          )
        }),
      async () => {
        const client = Client.builder().relays(['https://relay.example']).requestTimeout(1).build()

        const error = await rejected(client.publish(packet))
        expectQueryError(error, 'Timeout')
      },
    )

    await withMockFetch(
      async () => {
        throw new TypeError('network failed')
      },
      async () => {
        const client = Client.builder().relays(['https://relay.example']).requestTimeout(0).build()

        expect(await rejected(client.publish(packet))).toBeInstanceOf(UnexpectedResponsesError)
      },
    )
  })

  test('checks cache conflicts before publishing', async () => {
    const oldPacket = await signedPacket(1, 'old')
    const newPacket = await signedPacket(2, 'new')
    const cache = new InMemoryCache(1)
    cache.put(cacheKey(oldPacket.publicKey()), newPacket)

    const client = Client.builder()
      .relays(['https://relay.example'])
      .cache(cache)
      .requestTimeout(0)
      .build()

    const staleError = await rejected(client.publish(oldPacket))
    expectConcurrencyError(staleError, 'NotMostRecent')

    const casError = await rejected(client.publish(newPacket, oldPacket.timestamp()))
    expectConcurrencyError(casError, 'CasFailed')
  })

  test('does not update cache when relay publish fails', async () => {
    const oldPacket = await signedPacket(1, 'old')
    const newPacket = await signedPacket(2, 'new')
    const key = cacheKey(oldPacket.publicKey())
    const cache = new InMemoryCache(1)
    cache.put(key, oldPacket)

    const relay = relayServer(() => new Response(null, { status: 500 }))
    try {
      const client = Client.builder().relays([relay.url]).cache(cache).requestTimeout(1_000).build()

      expect(await rejected(client.publish(newPacket, oldPacket.timestamp()))).toBeInstanceOf(
        UnexpectedResponsesError,
      )
      expect(cache.getReadOnly(key)?.isSameAs(oldPacket)).toBe(true)
    } finally {
      relay.stop()
    }
  })
})

async function signedPacket(timestamp = 1, text = 'value'): Promise<SignedPacket> {
  return signedPacketWithSecret(timestamp, text, 9)
}

const RELAY_OVERSIZED_BYTES = 1_073

async function signedPacketWithSecret(
  timestamp: number,
  text: string,
  secretByte: number,
): Promise<SignedPacket> {
  return SignedPacket.builder()
    .timestamp(timestamp)
    .txt('_client', text, 30)
    .sign(await Keypair.fromSecretKey(new Uint8Array(32).fill(secretByte)))
}

function relayServer(handler: (request: Request) => Response | Promise<Response>): {
  url: string
  requests: { body: Uint8Array; headers: Headers; method: string; url: string }[]
  stop: () => void
} {
  const requests: { body: Uint8Array; headers: Headers; method: string; url: string }[] = []
  const server = Bun.serve({
    port: 0,
    error(error) {
      return new Response(error instanceof Error ? error.message : String(error), { status: 500 })
    },
    async fetch(request) {
      const body = new Uint8Array(await request.clone().arrayBuffer())
      requests.push({
        body,
        headers: new Headers(request.headers),
        method: request.method,
        url: request.url,
      })
      return handler(request)
    },
  })

  return {
    url: server.url.toString().replace(/\/$/u, ''),
    requests,
    stop: () => {
      void server.stop(true)
    },
  }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 20; i += 1) {
    if (predicate()) {
      return
    }
    await delay(5)
  }
  throw new Error('condition not met')
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function packetResponse(packet: SignedPacket): Response {
  const payload = packet.toRelayPayload()
  const body = new ArrayBuffer(payload.byteLength)
  new Uint8Array(body).set(payload)
  return new Response(body)
}

async function withMockFetch<T>(mock: FetchMock, run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch
  const replacement: typeof fetch = Object.assign(mock, {
    preconnect: originalFetch.preconnect,
  })
  globalThis.fetch = replacement
  try {
    return await run()
  } finally {
    globalThis.fetch = originalFetch
  }
}

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  return input instanceof Request ? input.url : input.toString()
}

async function rejected(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error('expected promise to reject')
}

function expectQueryError(error: unknown, code: QueryError['code']): void {
  expect(error).toBeInstanceOf(QueryError)
  if (!(error instanceof QueryError)) {
    throw new Error('expected QueryError')
  }
  expect(error.code).toBe(code)
}

function expectConcurrencyError(error: unknown, code: ConcurrencyError['code']): void {
  expect(error).toBeInstanceOf(ConcurrencyError)
  if (!(error instanceof ConcurrencyError)) {
    throw new Error('expected ConcurrencyError')
  }
  expect(error.code).toBe(code)
}

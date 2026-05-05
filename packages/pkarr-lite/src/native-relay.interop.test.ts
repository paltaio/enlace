import { describe, expect, test } from 'bun:test'

import { Client, Keypair, PublicKey, SignedPacket } from '@paltaio/pkarr-lite'

import { bytesToHex, hexToBytes } from './testing/hex'
import { isNativeVectors, isPacketVector, runNative } from './testing/native'

describe('native relay interop', () => {
  test('Rust resolves a TS-published packet from a local relay', async () => {
    const relay = pkarrRelayServer()
    try {
      const packet = await SignedPacket.builder()
        .timestamp(234_567_890)
        .txt('_interop', 'from-ts', 30)
        .sign(await Keypair.fromSecretKey(new Uint8Array(32).fill(11)))
      const client = Client.builder().relays([relay.url]).cacheSize(0).requestTimeout(2_000).build()

      await client.publish(packet)

      const value: unknown = JSON.parse(
        await runNative(
          ['resolve-relay'],
          JSON.stringify({
            relay_url: relay.url,
            public_key_hex: bytesToHex(packet.publicKey().toBytes()),
          }),
        ),
      )
      if (!isPacketVector(value)) {
        throw new Error('native harness returned invalid packet vector')
      }

      expect(value.signed_packet_hex).toBe(bytesToHex(packet.asBytes()))
      expect(value.relay_payload_hex).toBe(bytesToHex(packet.toRelayPayload()))
    } finally {
      relay.stop()
    }
  }, 120_000)

  test('TS resolves a Rust-published packet from a local relay', async () => {
    const relay = pkarrRelayServer()
    try {
      const value: unknown = JSON.parse(
        await runNative(['publish-relay'], JSON.stringify({ relay_url: relay.url })),
      )
      if (!isNativeVectors(value)) {
        throw new Error('native harness returned invalid vectors')
      }

      const client = Client.builder().relays([relay.url]).cacheSize(0).requestTimeout(2_000).build()
      const publicKey = PublicKey.fromBytes(hexToBytes(value.key.public_key_hex))
      const resolved = await client.resolve(publicKey)

      if (resolved === undefined) {
        throw new Error('TS client did not resolve native packet')
      }
      expect(bytesToHex(resolved.asBytes())).toBe(value.packet.signed_packet_hex)
      expect(bytesToHex(resolved.toRelayPayload())).toBe(value.packet.relay_payload_hex)
    } finally {
      relay.stop()
    }
  }, 120_000)

  test('Rust publishes a CAS update over a TS-published packet', async () => {
    const relay = pkarrRelayServer()
    try {
      const oldPacket = await casPacket(10, 'from-ts')
      const client = Client.builder().relays([relay.url]).cacheSize(0).requestTimeout(2_000).build()

      await client.publish(oldPacket)

      const value: unknown = JSON.parse(
        await runNative(
          ['publish-relay-cas'],
          JSON.stringify({
            relay_url: relay.url,
            cas_micros: Number(oldPacket.timestamp()),
            timestamp_micros: 20,
            text: 'from-rust-cas',
          }),
        ),
      )
      if (!isNativeVectors(value)) {
        throw new Error('native harness returned invalid vectors')
      }

      const resolved = await client.resolve(
        PublicKey.fromBytes(hexToBytes(value.key.public_key_hex)),
      )

      if (resolved === undefined) {
        throw new Error('TS client did not resolve native CAS packet')
      }
      expect(bytesToHex(resolved.asBytes())).toBe(value.packet.signed_packet_hex)
      expect(relay.requests.some((request) => request.headers.get('If-Match') === '10')).toBe(true)
    } finally {
      relay.stop()
    }
  }, 120_000)

  test('TS publishes a CAS update over a Rust-published packet', async () => {
    const relay = pkarrRelayServer()
    try {
      const value: unknown = JSON.parse(
        await runNative(['publish-relay'], JSON.stringify({ relay_url: relay.url })),
      )
      if (!isNativeVectors(value)) {
        throw new Error('native harness returned invalid vectors')
      }

      const client = Client.builder().relays([relay.url]).cacheSize(0).requestTimeout(2_000).build()
      const oldPacket = await client.resolve(
        PublicKey.fromBytes(hexToBytes(value.key.public_key_hex)),
      )
      if (oldPacket === undefined) {
        throw new Error('TS client did not resolve native packet')
      }

      const newPacket = await casPacket(value.packet.timestamp_micros + 1, 'from-ts-cas')

      await client.publish(newPacket, oldPacket.timestamp())

      const resolved: unknown = JSON.parse(
        await runNative(
          ['resolve-relay'],
          JSON.stringify({
            relay_url: relay.url,
            public_key_hex: bytesToHex(newPacket.publicKey().toBytes()),
          }),
        ),
      )
      if (!isPacketVector(resolved)) {
        throw new Error('native harness returned invalid packet vector')
      }

      expect(resolved.signed_packet_hex).toBe(bytesToHex(newPacket.asBytes()))
      expect(
        relay.requests.some(
          (request) => request.headers.get('If-Match') === value.packet.timestamp_micros.toString(),
        ),
      ).toBe(true)
    } finally {
      relay.stop()
    }
  }, 120_000)
})

function pkarrRelayServer(): {
  url: string
  requests: { headers: Headers; method: string; url: string }[]
  stop: () => void
} {
  const packets = new Map<string, Uint8Array>()
  const requests: { headers: Headers; method: string; url: string }[] = []
  const server = Bun.serve({
    port: 0,
    error(error) {
      return new Response(error instanceof Error ? error.message : String(error), { status: 500 })
    },
    async fetch(request) {
      const key = new URL(request.url).pathname.split('/').filter(Boolean).at(-1)
      requests.push({
        headers: new Headers(request.headers),
        method: request.method,
        url: request.url,
      })
      if (key === undefined) {
        return new Response(null, { status: 400 })
      }
      if (request.method === 'GET') {
        const payload = packets.get(key)
        return payload === undefined ? new Response(null, { status: 404 }) : bytesResponse(payload)
      }
      if (request.method === 'PUT') {
        let publicKey: PublicKey
        let incoming: SignedPacket
        const payload = new Uint8Array(await request.arrayBuffer())
        try {
          publicKey = PublicKey.fromZ32(key)
          incoming = await SignedPacket.fromRelayPayload(publicKey, payload)
        } catch {
          return new Response(null, { status: 400 })
        }
        const currentPayload = packets.get(key)
        if (currentPayload !== undefined) {
          const current = await SignedPacket.fromRelayPayload(publicKey, currentPayload)
          const ifMatch = request.headers.get('If-Match')
          if (ifMatch !== null) {
            try {
              if (BigInt(ifMatch) !== current.timestamp()) {
                return new Response(null, { status: 412 })
              }
            } catch {
              return new Response(null, { status: 400 })
            }
          }
          if (!incoming.isSameAs(current) && !incoming.moreRecentThan(current)) {
            return new Response(null, { status: 409 })
          }
        }
        packets.set(key, payload)
        return new Response(null, { status: 204 })
      }
      return new Response(null, { status: 405 })
    },
  })

  return {
    url: server.url.toString().replace('localhost', '127.0.0.1').replace(/\/$/u, ''),
    requests,
    stop: () => {
      void server.stop(true)
    },
  }
}

function bytesResponse(bytes: Uint8Array): Response {
  const body = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(body).set(bytes)
  return new Response(body)
}

async function casPacket(timestamp: number, text: string): Promise<SignedPacket> {
  return SignedPacket.builder()
    .timestamp(timestamp)
    .txt('_cas', text, 30)
    .sign(await Keypair.fromSecretKey(new Uint8Array(32).fill(7)))
}

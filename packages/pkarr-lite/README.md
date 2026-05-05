# @paltaio/pkarr-lite

Browser-compatible TypeScript pkarr packet, DNS record, cache, and HTTP relay client.

The package implements signed pkarr packets and relay publish/resolve behavior in TypeScript. It is tested against Rust `pkarr = 5.0.4` vectors and local relay interop. Network support is relay-only: it uses `fetch` against HTTP relays and does not query the Mainline DHT or open UDP sockets.

## Import

```ts
import { Client, Keypair, PublicKey, SignedPacket } from '@paltaio/pkarr-lite'
```

## Keys

```ts
const keypair = await Keypair.random()

const publicKey = keypair.publicKey()
const z32 = publicKey.toZ32()
const uri = publicKey.toUriString()

const samePublicKey = PublicKey.parse(uri)
```

`PublicKey.parse()` accepts z-base32 public keys, `pk:` URIs, and URL-like strings whose host or final domain label is a pkarr public key.

## Publish and Resolve TXT

```ts
const client = Client.builder().build()
const keypair = await Keypair.random()

const packet = await SignedPacket.builder().txt('_profile', 'hello', 300).sign(keypair)

await client.publish(packet)

const resolved = await client.resolve(keypair.publicKey())
const records = resolved?.resourceRecords('_profile') ?? []
```

`Client.builder().build()` uses the default pkarr HTTP relays and an in-memory cache. `resolve()` returns a cached packet immediately when one exists; expired cached packets refresh in the background. On cache miss, `resolve()` returns the first usable relay packet. `resolveMostRecent()` waits for every configured relay response and keeps the newest packet.

## Multi-Record Packet

```ts
const packet = await SignedPacket.builder()
  .a('@', '203.0.113.10', 300)
  .aaaa('@', '2001:db8::10', 300)
  .txt('_status', 'online', 300)
  .cname('www', 'example.com', 300)
  .https(
    '@',
    {
      priority: 1,
      target: '.',
      params: [
        { type: 'alpn', ids: ['h2', 'http/1.1'] },
        { type: 'port', port: 443 },
      ],
    },
    300,
  )
  .sign(keypair)

const allRecords = packet.allResourceRecords()
const freshStatus = packet.freshResourceRecords('_status')
```

Supported record types are `A`, `AAAA`, `CNAME`, `TXT`, `HTTPS`, and `SVCB`.

## Compare-and-Swap Publish

```ts
const oldPacket = await client.resolve(keypair.publicKey())
if (oldPacket === undefined) {
  throw new Error('packet must exist before CAS update')
}

const nextPacket = await SignedPacket.builder()
  .timestamp(oldPacket.timestamp() + 1n)
  .txt('_profile', 'updated', 300)
  .sign(keypair)

await client.publish(nextPacket, oldPacket.timestamp())
```

The optional second `publish()` argument sends an `If-Match` timestamp to every relay. Stale packets and failed CAS checks reject with `ConcurrencyError`.

## Custom Relays and Cache

```ts
const client = Client.builder()
  .relays(['https://relay.example/pkarr'])
  .extraRelays(['https://backup-relay.example/pkarr'])
  .requestTimeout(5_000)
  .cacheSize(500)
  .build()
```

`relays()` replaces the current relay list. `extraRelays()` appends unique relays to the current list and is ignored only after relay networking has been disabled. `cacheSize(0)` disables the in-memory cache.

## Packets

```ts
const bytes = packet.asBytes()
const relayPayload = packet.toRelayPayload()

const parsedPacket = await SignedPacket.fromBytes(bytes)
const parsedRelayPayload = await SignedPacket.fromRelayPayload(packet.publicKey(), relayPayload)
```

Full signed packets contain `publicKey || signature || timestamp || dnsPacket`. Relay payloads contain `signature || timestamp || dnsPacket`.

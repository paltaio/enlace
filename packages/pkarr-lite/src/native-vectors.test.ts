import { describe, expect, test } from 'bun:test'

import { Keypair, PublicKey, SignedPacket, type SignedPacketBuilder } from '@paltaio/pkarr-lite'

import { bytesToHex, hexToBytes } from './testing/hex'
import { nativeVectors, runNative, type RecordSummary } from './testing/native'
const TIMESTAMP = 123_456_789n

describe('native pkarr vectors', () => {
  test('parses Rust-generated packet vectors', async () => {
    const vectors = await nativeVectors()
    const publicKey = PublicKey.fromBytes(hexToBytes(vectors.key.public_key_hex))
    const packet = await SignedPacket.fromRelayPayload(
      publicKey,
      hexToBytes(vectors.packet.relay_payload_hex),
    )
    packet.setLastSeen(vectors.packet.last_seen_micros)

    expect(
      bytesToHex(
        (await Keypair.fromSecretKey(hexToBytes(vectors.key.secret_key_hex))).publicKey().toBytes(),
      ),
    ).toBe(vectors.key.public_key_hex)
    expect(publicKey.toZ32()).toBe(vectors.key.z32)
    expect(publicKey.toUriString()).toBe(vectors.key.uri)
    expect(packet.timestamp()).toBe(BigInt(vectors.packet.timestamp_micros))
    expect(bytesToHex(packet.signature())).toBe(vectors.packet.signature_hex)
    expect(bytesToHex(signableBytes(packet.timestamp(), packet.encodedPacket()))).toBe(
      vectors.packet.signable_hex,
    )
    expect(bytesToHex(packet.encodedPacket())).toBe(vectors.packet.encoded_packet_hex)
    expect(bytesToHex(packet.asBytes())).toBe(vectors.packet.signed_packet_hex)
    expect(bytesToHex(packet.toRelayPayload())).toBe(vectors.packet.relay_payload_hex)
    expect(bytesToHex(packet.serialize())).toBe(vectors.packet.serialized_hex)
    expect(packet.ttl()).toBe(vectors.packet.ttl_default)
    expect(packet.ttl(0, 86_400)).toBe(vectors.packet.ttl_unclamped)
    expect(recordSummaries(packet)).toEqual(vectors.packet.records)

    for (const lookup of vectors.packet.lookups) {
      expect(packet.resourceRecords(lookup.name).map((record) => record.name)).toEqual(lookup.names)
    }
  }, 30_000)

  test('Rust verifies TS-generated relay payloads', async () => {
    const keypair = await Keypair.fromSecretKey(new Uint8Array(32).fill(7))
    const packet = await vectorBuilder().sign(keypair)
    const verifyVector = {
      public_key_hex: bytesToHex(packet.publicKey().toBytes()),
      packet: {
        timestamp_micros: Number(packet.timestamp()),
        signature_hex: bytesToHex(packet.signature()),
        signable_hex: bytesToHex(signableBytes(packet.timestamp(), packet.encodedPacket())),
        encoded_packet_hex: bytesToHex(packet.encodedPacket()),
        signed_packet_hex: bytesToHex(packet.asBytes()),
        relay_payload_hex: bytesToHex(packet.toRelayPayload()),
        ttl_default: packet.ttl(),
        ttl_unclamped: packet.ttl(0, 86_400),
        records: recordSummaries(packet),
        lookups: ['@', '_svc', `*.${packet.publicKey().toZ32()}`].map((name) => ({
          name,
          names: packet.resourceRecords(name).map((record) => record.name),
        })),
      },
    }

    await runNative(['verify-ts'], JSON.stringify(verifyVector))
  }, 30_000)
})

function vectorBuilder(): SignedPacketBuilder {
  return SignedPacket.builder()
    .address('.', '1.2.3.4', 30)
    .address('www', '::1', 60)
    .cname('alias.', 'target.example.com', 70)
    .txt('_proto', 'foo=bar', 80)
    .https(
      '.',
      {
        priority: 1,
        target: 'svc.example.com',
        params: [
          { type: 'alpn', ids: ['h2', 'h3'] },
          { type: 'port', port: 443 },
          { type: 'ipv4hint', addresses: ['192.0.2.1'] },
          { type: 'ipv6hint', addresses: ['2001:db8::1'] },
        ],
      },
      90,
    )
    .svcb(
      '_svc',
      {
        priority: 0,
        target: '.',
        params: [
          {
            type: 'unknown',
            key: 667,
            value: new Uint8Array([104, 101, 108, 108, 111, 210, 113, 111, 111]),
          },
        ],
      },
      100,
    )
    .timestamp(TIMESTAMP)
}

function recordSummaries(packet: SignedPacket): RecordSummary[] {
  return packet.allResourceRecords().map((record) => ({
    name: record.name,
    record_type: record.type,
    ttl: record.ttl,
  }))
}

function signableBytes(timestamp: bigint, encodedPacket: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`3:seqi${timestamp}e1:v${encodedPacket.length}:`)
  const signable = new Uint8Array(prefix.length + encodedPacket.length)
  signable.set(prefix)
  signable.set(encodedPacket, prefix.length)
  return signable
}

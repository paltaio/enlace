import { describe, expect, test } from 'bun:test'

import { Keypair, PublicKey, SignedPacket, type SignedPacketBuilder } from '@paltaio/pkarr-lite'

import { bytesToHex, hexToBytes } from './testing/hex'

interface NativeVectors {
  key: {
    secret_key_hex: string
    public_key_hex: string
    z32: string
    uri: string
  }
  packet: PacketVector
}

interface PacketVector {
  timestamp_micros: number
  last_seen_micros: number
  signature_hex: string
  signable_hex: string
  encoded_packet_hex: string
  signed_packet_hex: string
  relay_payload_hex: string
  serialized_hex: string
  ttl_default: number
  ttl_unclamped: number
  records: RecordSummary[]
  lookups: LookupVector[]
}

interface RecordSummary {
  name: string
  record_type: string
  ttl: number
}

interface LookupVector {
  name: string
  names: string[]
}

const NATIVE_MANIFEST = Bun.fileURLToPath(new URL('../native/Cargo.toml', import.meta.url))
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

async function nativeVectors(): Promise<NativeVectors> {
  const value: unknown = JSON.parse(await runNative(['vectors']))
  if (!isNativeVectors(value)) {
    throw new Error('native harness returned invalid vectors')
  }
  return value
}

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

async function runNative(args: string[], stdin?: string): Promise<string> {
  const proc = Bun.spawn(
    ['cargo', 'run', '--quiet', '--manifest-path', NATIVE_MANIFEST, '--', ...args],
    {
      stdin: stdin === undefined ? undefined : 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )
  if (stdin !== undefined) {
    const stdinWriter = proc.stdin
    if (stdinWriter === undefined) {
      throw new Error('native harness stdin unavailable')
    }
    stdinWriter.write(stdin)
    await stdinWriter.end()
  }
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  if (exitCode !== 0) {
    throw new Error(stderr || `native harness exited with ${exitCode}`)
  }
  return stdout
}

function isNativeVectors(value: unknown): value is NativeVectors {
  if (!isRecord(value) || !isRecord(value.key) || !isPacketVector(value.packet)) {
    return false
  }
  return (
    typeof value.key.secret_key_hex === 'string' &&
    typeof value.key.public_key_hex === 'string' &&
    typeof value.key.z32 === 'string' &&
    typeof value.key.uri === 'string'
  )
}

function isPacketVector(value: unknown): value is PacketVector {
  if (!isRecord(value)) {
    return false
  }
  return (
    typeof value.timestamp_micros === 'number' &&
    typeof value.last_seen_micros === 'number' &&
    typeof value.signature_hex === 'string' &&
    typeof value.signable_hex === 'string' &&
    typeof value.encoded_packet_hex === 'string' &&
    typeof value.signed_packet_hex === 'string' &&
    typeof value.relay_payload_hex === 'string' &&
    typeof value.serialized_hex === 'string' &&
    typeof value.ttl_default === 'number' &&
    typeof value.ttl_unclamped === 'number' &&
    isRecordSummaryArray(value.records) &&
    isLookupVectorArray(value.lookups)
  )
}

function isRecordSummaryArray(value: unknown): value is RecordSummary[] {
  return Array.isArray(value) && value.every(isRecordSummary)
}

function isRecordSummary(value: unknown): value is RecordSummary {
  return (
    isRecord(value) &&
    typeof value.name === 'string' &&
    typeof value.record_type === 'string' &&
    typeof value.ttl === 'number'
  )
}

function isLookupVectorArray(value: unknown): value is LookupVector[] {
  return Array.isArray(value) && value.every(isLookupVector)
}

function isLookupVector(value: unknown): value is LookupVector {
  return (
    isRecord(value) &&
    typeof value.name === 'string' &&
    Array.isArray(value.names) &&
    value.names.every((name) => typeof name === 'string')
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

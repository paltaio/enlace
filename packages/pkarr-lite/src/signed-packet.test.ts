import { describe, expect, test } from 'bun:test'

import {
  Keypair,
  PublicKey,
  SignedPacket,
  type SignedPacketBuilder,
  type ServiceBinding,
} from '@paltaio/pkarr-lite'
import { RELAY_PAYLOAD_MAX_BYTES, SIGNED_PACKET_MAX_BYTES } from '@paltaio/pkarr-lite/constants'

import { bytesToHex, hexToBytes } from './testing/hex'

const ORIGIN = '7jfgaa9nutjyixzikb7tgmsf9gkwq7iqz498zr1nd5ig1fng4esy'
const SECRET_KEY = new Uint8Array(32).fill(7)
const TIMESTAMP = 123_456_789n
const LAST_SEEN = 987_654_321n
const PUBLIC_KEY_HEX = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c'
const SIGNATURE_HEX =
  '49586283ea4a6b769ef9220e23a9be3096530ea6eb60b33d5254215f89ae4a6e11a7e866d6eceb03c0d66a594e50bd17c9a38aae1f2f3b953d139875f7512e05'
const DNS_HEX =
  '00008000000000060000000034376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900000100010000001e00040102030403777777c00c001c00010000003c00100000000000000000000000000000000105616c696173c00c0005000100000046001406746172676574076578616d706c6503636f6d00065f70726f746fc00c0010000100000050000807666f6f3d626172c00c004100010000005a003f000103737663076578616d706c6503636f6d00000100060268320268330003000201bb00040004c00002010006001020010db8000000000000000000000001045f737663c00c00400001000000640010000000029b000968656c6c6fd2716f6f'
const SIGNED_HEX =
  'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c49586283ea4a6b769ef9220e23a9be3096530ea6eb60b33d5254215f89ae4a6e11a7e866d6eceb03c0d66a594e50bd17c9a38aae1f2f3b953d139875f7512e0500000000075bcd1500008000000000060000000034376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900000100010000001e00040102030403777777c00c001c00010000003c00100000000000000000000000000000000105616c696173c00c0005000100000046001406746172676574076578616d706c6503636f6d00065f70726f746fc00c0010000100000050000807666f6f3d626172c00c004100010000005a003f000103737663076578616d706c6503636f6d00000100060268320268330003000201bb00040004c00002010006001020010db8000000000000000000000001045f737663c00c00400001000000640010000000029b000968656c6c6fd2716f6f'
const RELAY_HEX =
  '49586283ea4a6b769ef9220e23a9be3096530ea6eb60b33d5254215f89ae4a6e11a7e866d6eceb03c0d66a594e50bd17c9a38aae1f2f3b953d139875f7512e0500000000075bcd1500008000000000060000000034376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900000100010000001e00040102030403777777c00c001c00010000003c00100000000000000000000000000000000105616c696173c00c0005000100000046001406746172676574076578616d706c6503636f6d00065f70726f746fc00c0010000100000050000807666f6f3d626172c00c004100010000005a003f000103737663076578616d706c6503636f6d00000100060268320268330003000201bb00040004c00002010006001020010db8000000000000000000000001045f737663c00c00400001000000640010000000029b000968656c6c6fd2716f6f'
const SERIALIZED_HEX = `000000003ade68b1${SIGNED_HEX}`

const HTTPS_BINDING: ServiceBinding = {
  priority: 1,
  target: 'svc.example.com',
  params: [
    { type: 'alpn', ids: ['h2', 'h3'] },
    { type: 'port', port: 443 },
    { type: 'ipv4hint', addresses: ['192.0.2.1'] },
    { type: 'ipv6hint', addresses: ['2001:db8::1'] },
  ],
}

const SVCB_BINDING: ServiceBinding = {
  priority: 0,
  target: '.',
  params: [
    {
      type: 'unknown',
      key: 667,
      value: new Uint8Array([104, 101, 108, 108, 111, 210, 113, 111, 111]),
    },
  ],
}

const PARSED_HTTPS_BINDING: ServiceBinding = {
  priority: 1,
  target: 'svc.example.com',
  params: [
    { type: 'alpn', ids: [new TextEncoder().encode('h2'), new TextEncoder().encode('h3')] },
    { type: 'port', port: 443 },
    { type: 'ipv4hint', addresses: [new Uint8Array([192, 0, 2, 1])] },
    {
      type: 'ipv6hint',
      addresses: [new Uint8Array([32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])],
    },
  ],
}
const PARSED_SVCB_BINDING: ServiceBinding = { ...SVCB_BINDING, target: '' }

describe('SignedPacket', () => {
  test('builds Rust-compatible signed bytes and relay payloads', async () => {
    const packet = await vectorBuilder().sign(await Keypair.fromSecretKey(SECRET_KEY))

    expect(bytesToHex(packet.publicKey().toBytes())).toBe(PUBLIC_KEY_HEX)
    expect(bytesToHex(packet.signature())).toBe(SIGNATURE_HEX)
    expect(packet.timestamp()).toBe(TIMESTAMP)
    expect(bytesToHex(packet.encodedPacket())).toBe(DNS_HEX)
    expect(bytesToHex(packet.asBytes())).toBe(SIGNED_HEX)
    expect(bytesToHex(packet.toRelayPayload())).toBe(RELAY_HEX)
  })

  test('parses Rust relay payloads with the expected public key', async () => {
    const packet = await SignedPacket.fromRelayPayload(
      PublicKey.fromBytes(hexToBytes(PUBLIC_KEY_HEX)),
      hexToBytes(RELAY_HEX),
    )

    expect(bytesToHex(packet.asBytes())).toBe(SIGNED_HEX)
    expect(packet.resourceRecords('@')).toEqual([
      { type: 'A', name: ORIGIN, ttl: 30, address: new Uint8Array([1, 2, 3, 4]) },
      { type: 'HTTPS', name: ORIGIN, ttl: 90, binding: PARSED_HTTPS_BINDING },
    ])
    expect(packet.resourceRecords('_svc')).toEqual([
      { type: 'SVCB', name: `_svc.${ORIGIN}`, ttl: 100, binding: PARSED_SVCB_BINDING },
    ])
  })

  test('serializes storage bytes with lastSeen before signed bytes', async () => {
    const packet = await vectorBuilder().build(await Keypair.fromSecretKey(SECRET_KEY))
    packet.setLastSeen(LAST_SEEN)

    expect(packet.lastSeen()).toBe(LAST_SEEN)
    expect(bytesToHex(packet.serialize())).toBe(SERIALIZED_HEX)
    expect(SignedPacket.deserialize(packet.serialize()).lastSeen()).toBe(LAST_SEEN)
    expect(bytesToHex(SignedPacket.deserialize(packet.serialize()).asBytes())).toBe(SIGNED_HEX)
  })

  test('orders equal timestamps by encoded DNS packet bytes', async () => {
    const keypair = await Keypair.fromSecretKey(SECRET_KEY)
    const lower = await SignedPacket.builder().timestamp(7).txt('_same', 'a', 30).sign(keypair)
    const higher = await SignedPacket.builder().timestamp(7).txt('_same', 'b', 30).sign(keypair)
    const newer = await SignedPacket.builder().timestamp(8).txt('_same', 'a', 30).sign(keypair)

    expect(higher.moreRecentThan(lower)).toBe(true)
    expect(lower.moreRecentThan(higher)).toBe(false)
    expect(newer.moreRecentThan(higher)).toBe(true)
    expect(newer.isSameAs(await SignedPacket.fromBytes(newer.asBytes()))).toBe(true)
  })

  test('filters fresh records by record TTL and lastSeen', async () => {
    const packet = await SignedPacket.builder()
      .timestamp(1)
      .txt('_foo', 'old', 30)
      .txt('_foo', 'fresh', 60)
      .txt('_bar', 'fresh', 60)
      .sign(await Keypair.fromSecretKey(SECRET_KEY))
    packet.setLastSeen(BigInt(Date.now()) * 1_000n - 30_000_000n)

    expect(packet.freshResourceRecords('_foo')).toEqual([
      { type: 'TXT', name: `_foo.${ORIGIN}`, ttl: 60, text: [new TextEncoder().encode('fresh')] },
    ])
    expect(packet.ttl()).toBe(300)
    expect(packet.ttl(0, 86_400)).toBe(30)
    expect(packet.expiresIn(0, 86_400)).toBe(0)
    expect(packet.isExpired(0, 86_400)).toBe(true)
  })

  test('rejects invalid signatures and oversized payloads', async () => {
    const badPayload = hexToBytes(RELAY_HEX)
    badPayload[0] = (badPayload[0] ?? 0) ^ 1

    await expectRejects(
      SignedPacket.fromRelayPayload(PublicKey.fromBytes(hexToBytes(PUBLIC_KEY_HEX)), badPayload),
      'invalid SignedPacket signature',
    )
    await expectRejects(
      SignedPacket.fromRelayPayload(
        PublicKey.fromBytes(hexToBytes(PUBLIC_KEY_HEX)),
        new Uint8Array(RELAY_PAYLOAD_MAX_BYTES + 1),
      ),
      `${SIGNED_PACKET_MAX_BYTES}`,
    )
  })

  test('rejects packets over the DNS size limit while building', async () => {
    const builder = SignedPacket.builder().timestamp(1)
    for (let i = 0; i < 30; i += 1) {
      builder.txt(`_${i}`, 'x'.repeat(40), 1)
    }

    await expectRejects(
      builder.sign(await Keypair.fromSecretKey(SECRET_KEY)),
      'expected max 1000 bytes',
    )
  })
})

function vectorBuilder(): SignedPacketBuilder {
  return SignedPacket.builder()
    .address('.', '1.2.3.4', 30)
    .address('www', '::1', 60)
    .cname('alias.', 'target.example.com', 70)
    .txt('_proto', 'foo=bar', 80)
    .https('.', HTTPS_BINDING, 90)
    .svcb('_svc', SVCB_BINDING, 100)
    .timestamp(TIMESTAMP)
}

async function expectRejects(promise: Promise<unknown>, message: string): Promise<void> {
  let error: unknown
  try {
    await promise
  } catch (caught) {
    error = caught
  }
  expect(error).toBeInstanceOf(Error)
  expect(error instanceof Error ? error.message : String(error)).toContain(message)
}

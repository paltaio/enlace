import { describe, expect, test } from 'bun:test'

import {
  encodeDnsResponse,
  findResourceRecords,
  normalizeDnsName,
  parseDnsResponse,
  type DnsRecord,
} from '@paltaio/pkarr-lite'
import { DNS_PACKET_MAX_BYTES } from '@paltaio/pkarr-lite/constants'

const ORIGIN = '7jfgaa9nutjyixzikb7tgmsf9gkwq7iqz498zr1nd5ig1fng4esy'
const RUST_PACKET_HEX =
  '00008000000000060000000034376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900000100010000001e00040102030403777777c00c001c00010000003c00100000000000000000000000000000000105616c696173c00c0005000100000046001406746172676574076578616d706c6503636f6d00065f70726f746fc00c0010000100000050000807666f6f3d626172c00c004100010000005a003f000103737663076578616d706c6503636f6d00000100060268320268330003000201bb00040004c00002010006001020010db8000000000000000000000001045f737663c00c00400001000000640010000000029b000968656c6c6fd2716f6f'
const RUST_UNCOMPRESSED_PACKET_HEX =
  '00008000000000060000000034376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900000100010000001e0004010203040377777734376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900001c00010000003c00100000000000000000000000000000000105616c69617334376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e6734657379000005000100000046001406746172676574076578616d706c6503636f6d00065f70726f746f34376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e6734657379000010000100000050000807666f6f3d62617234376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900004100010000005a003f000103737663076578616d706c6503636f6d00000100060268320268330003000201bb00040004c00002010006001020010db8000000000000000000000001045f73766334376a66676161396e75746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e67346573790000400001000000640010000000029b000968656c6c6fd2716f6f'

const RECORDS: DnsRecord[] = [
  { type: 'A', name: '.', ttl: 30, address: '1.2.3.4' },
  { type: 'AAAA', name: 'www', ttl: 60, address: '::1' },
  { type: 'CNAME', name: 'alias.', ttl: 70, cname: 'target.example.com' },
  { type: 'TXT', name: '_proto', ttl: 80, text: 'foo=bar' },
  {
    type: 'HTTPS',
    name: '.',
    ttl: 90,
    binding: {
      priority: 1,
      target: 'svc.example.com',
      params: [
        { type: 'alpn', ids: ['h2', 'h3'] },
        { type: 'port', port: 443 },
        { type: 'ipv4hint', addresses: ['192.0.2.1'] },
        { type: 'ipv6hint', addresses: ['2001:db8::1'] },
      ],
    },
  },
  {
    type: 'SVCB',
    name: '_svc',
    ttl: 100,
    binding: {
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
  },
]

describe('DNS packet codec', () => {
  test('encodes answer packets byte-identically with Rust simple-dns', () => {
    expect(bytesToHex(encodeDnsResponse(ORIGIN, RECORDS))).toBe(RUST_PACKET_HEX)
  })

  test('parses Rust compressed answer packets', () => {
    const records = parseDnsResponse(hexToBytes(RUST_PACKET_HEX))

    expect(records).toHaveLength(6)
    expect(records[0]).toEqual({
      type: 'A',
      name: ORIGIN,
      ttl: 30,
      address: new Uint8Array([1, 2, 3, 4]),
    })
    expect(records[1]).toEqual({
      type: 'AAAA',
      name: `www.${ORIGIN}`,
      ttl: 60,
      address: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    })
    expect(records[2]).toEqual({
      type: 'CNAME',
      name: `alias.${ORIGIN}`,
      ttl: 70,
      cname: 'target.example.com',
    })
    expect(records[3]).toEqual({
      type: 'TXT',
      name: `_proto.${ORIGIN}`,
      ttl: 80,
      text: [new Uint8Array([102, 111, 111, 61, 98, 97, 114])],
    })
    expect(records[4]).toMatchObject({
      type: 'HTTPS',
      name: ORIGIN,
      ttl: 90,
      binding: { priority: 1, target: 'svc.example.com' },
    })
    expect(records[5]).toMatchObject({
      type: 'SVCB',
      name: `_svc.${ORIGIN}`,
      ttl: 100,
      binding: { priority: 0, target: '' },
    })
  })

  test('accepts uncompressed packets emitted from the same records', () => {
    const compressed = encodeDnsResponse(ORIGIN, RECORDS)
    const uncompressed = hexToBytes(RUST_UNCOMPRESSED_PACKET_HEX)

    expect(parseDnsResponse(uncompressed)).toEqual(parseDnsResponse(compressed))
  })

  test('normalizes names like Rust pkarr', () => {
    expect(normalizeDnsName(ORIGIN, '')).toBe(ORIGIN)
    expect(normalizeDnsName(ORIGIN, '.')).toBe(ORIGIN)
    expect(normalizeDnsName(ORIGIN, '@')).toBe(ORIGIN)
    expect(normalizeDnsName(ORIGIN, `foo.${ORIGIN}`)).toBe(`foo.${ORIGIN}`)
    expect(normalizeDnsName(ORIGIN, 'foo.')).toBe(`foo.${ORIGIN}`)
    expect(normalizeDnsName(ORIGIN, 'foo')).toBe(`foo.${ORIGIN}`)
  })

  test('matches one wildcard label before the suffix', () => {
    const records = parseDnsResponse(hexToBytes(RUST_PACKET_HEX))

    expect(findResourceRecords(records, ORIGIN, `*.${ORIGIN}`)).toHaveLength(4)
    expect(findResourceRecords(records, ORIGIN, `*.example.${ORIGIN}`)).toHaveLength(0)
    expect(
      findResourceRecords(records, ORIGIN, `*.${ORIGIN}`).map((record) => record.name),
    ).toEqual([`www.${ORIGIN}`, `alias.${ORIGIN}`, `_proto.${ORIGIN}`, `_svc.${ORIGIN}`])
  })

  test('keeps non-wildcard asterisk labels literal', () => {
    const records: DnsRecord[] = [
      { type: 'A', name: `xfoo.${ORIGIN}`, ttl: 1, address: new Uint8Array([1, 1, 1, 1]) },
      { type: 'A', name: `*foo.${ORIGIN}`, ttl: 1, address: new Uint8Array([2, 2, 2, 2]) },
    ]

    expect(findResourceRecords(records, ORIGIN, '*foo')).toEqual([
      { type: 'A', name: `*foo.${ORIGIN}`, ttl: 1, address: new Uint8Array([2, 2, 2, 2]) },
    ])
  })

  test('rejects inconsistent SVCB parameters', () => {
    const base = {
      type: 'SVCB',
      name: '_svc',
      ttl: 100,
      binding: { priority: 1, target: '.', params: [] },
    } satisfies DnsRecord

    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { ...base, binding: { ...base.binding, params: [{ type: 'mandatory', keys: [123] }] } },
      ]),
    ).toThrow('mandatory SVCB parameter is missing')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { ...base, binding: { ...base.binding, params: [{ type: 'mandatory', keys: [0] }] } },
      ]),
    ).toThrow('mandatory must not include mandatory')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { ...base, binding: { ...base.binding, params: [{ type: 'mandatory', keys: [3, 3] }] } },
      ]),
    ).toThrow('duplicate mandatory SVCB key')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { ...base, binding: { ...base.binding, params: [{ type: 'no-default-alpn' }] } },
      ]),
    ).toThrow('no-default-alpn requires alpn')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { ...base, binding: { ...base.binding, params: [{ type: 'alpn', ids: [] }] } },
      ]),
    ).toThrow('alpn must not be empty')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { ...base, binding: { ...base.binding, params: [{ type: 'ipv4hint', addresses: [] }] } },
      ]),
    ).toThrow('ipv4hint must not be empty')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        {
          ...base,
          binding: {
            ...base.binding,
            params: [{ type: 'unknown', key: 2, value: new Uint8Array() }],
          },
        },
      ]),
    ).toThrow('unknown SVCB parameter uses known key')
  })

  test('rejects parsed packets with inconsistent SVCB parameters', () => {
    expect(() =>
      parseDnsResponse(
        hexToBytes('00008000000000010000000001780000400001000000010009000100000000020000'),
      ),
    ).toThrow('mandatory must not include mandatory')
    expect(() =>
      parseDnsResponse(
        hexToBytes(
          '000080000000000100000000017800004000010000000100180001000000000400030001000100030268320003000201bb',
        ),
      ),
    ).toThrow('mandatory SVCB keys must be sorted')
  })

  test('rejects malformed IP strings', () => {
    expect(() =>
      encodeDnsResponse(ORIGIN, [{ type: 'A', name: '.', ttl: 1, address: '1.2.3.4foo' }]),
    ).toThrow('invalid IPv4 segment')
    expect(() =>
      encodeDnsResponse(ORIGIN, [{ type: 'A', name: '.', ttl: 1, address: '1e2.2.3.4' }]),
    ).toThrow('invalid IPv4 segment')
    expect(() =>
      encodeDnsResponse(ORIGIN, [
        { type: 'AAAA', name: '.', ttl: 1, address: '2001:db8:1:2:3:4:5:6::' },
      ]),
    ).toThrow('invalid IPv6 address')
  })

  test('rejects packets over the DNS size limit', () => {
    const oversized: DnsRecord[] = []
    for (let i = 0; i < 30; i += 1) {
      oversized.push({ type: 'TXT', name: `_${i}`, ttl: 1, text: 'x'.repeat(40) })
    }

    expect(() => encodeDnsResponse(ORIGIN, oversized)).toThrow(
      `expected max ${DNS_PACKET_MAX_BYTES} bytes`,
    )
  })
})

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

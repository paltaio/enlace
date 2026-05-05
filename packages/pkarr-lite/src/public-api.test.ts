import { describe, expect, test } from 'bun:test'

import {
  DEFAULT_CACHE_SIZE,
  DEFAULT_MAXIMUM_TTL,
  DEFAULT_MINIMUM_TTL,
  DEFAULT_RELAYS,
  DNS_PACKET_MAX_BYTES,
  PUBLIC_KEY_BYTES,
  RELAY_PAYLOAD_MAX_BYTES,
  SIGNATURE_BYTES,
  SIGNED_PACKET_MAX_BYTES,
  TIMESTAMP_BYTES,
} from '@paltaio/pkarr-lite'
import { DEFAULT_RELAYS as constantExportRelays } from '@paltaio/pkarr-lite/constants'

describe('public API', () => {
  test('exports pkarr constants from root and subpath exports', () => {
    expect(DEFAULT_MINIMUM_TTL).toBe(300)
    expect(DEFAULT_MAXIMUM_TTL).toBe(86_400)
    expect(DEFAULT_CACHE_SIZE).toBe(1_000)
    expect(DEFAULT_RELAYS).toEqual(['https://pkarr.pubky.app', 'https://pkarr.pubky.org'])
    expect(constantExportRelays).toBe(DEFAULT_RELAYS)

    expect(PUBLIC_KEY_BYTES).toBe(32)
    expect(SIGNATURE_BYTES).toBe(64)
    expect(TIMESTAMP_BYTES).toBe(8)
    expect(SIGNED_PACKET_MAX_BYTES).toBe(1_104)
    expect(RELAY_PAYLOAD_MAX_BYTES).toBe(1_072)
    expect(DNS_PACKET_MAX_BYTES).toBe(1_000)
  })
})

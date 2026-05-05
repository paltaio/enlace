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
  SignedPacket,
  TIMESTAMP_BYTES,
} from '@paltaio/pkarr-lite'
import * as constantsExport from '@paltaio/pkarr-lite/constants'
import { SignedPacket as SubpathSignedPacket } from '@paltaio/pkarr-lite/signed-packet'

describe('public API', () => {
  test('exports root and subpath APIs', () => {
    expect(DEFAULT_MINIMUM_TTL).toBe(constantsExport.DEFAULT_MINIMUM_TTL)
    expect(DEFAULT_MAXIMUM_TTL).toBe(constantsExport.DEFAULT_MAXIMUM_TTL)
    expect(DEFAULT_CACHE_SIZE).toBe(constantsExport.DEFAULT_CACHE_SIZE)
    expect(DEFAULT_RELAYS).toBe(constantsExport.DEFAULT_RELAYS)

    expect(PUBLIC_KEY_BYTES).toBe(constantsExport.PUBLIC_KEY_BYTES)
    expect(SIGNATURE_BYTES).toBe(constantsExport.SIGNATURE_BYTES)
    expect(TIMESTAMP_BYTES).toBe(constantsExport.TIMESTAMP_BYTES)
    expect(SIGNED_PACKET_MAX_BYTES).toBe(constantsExport.SIGNED_PACKET_MAX_BYTES)
    expect(RELAY_PAYLOAD_MAX_BYTES).toBe(constantsExport.RELAY_PAYLOAD_MAX_BYTES)
    expect(DNS_PACKET_MAX_BYTES).toBe(constantsExport.DNS_PACKET_MAX_BYTES)
    expect(SubpathSignedPacket).toBe(SignedPacket)
  })
})

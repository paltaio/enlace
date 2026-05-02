import { describe, expect, test } from 'bun:test'

import { RELAY_SUBPROTOCOLS, RelayConnectAbortedError } from '@paltaio/iroh-lite'
import { RelayAuthDeniedError } from '@paltaio/iroh-lite/relay/client'
import { FrameType } from '@paltaio/iroh-lite/relay/frames'
import { RELAY_PATH } from '@paltaio/iroh-lite/relay/handshake'
import { encodeVarInt } from '@paltaio/iroh-lite/relay/varint'

describe('public relay API', () => {
  test('resolves browser relay entry points from root and relay subpaths', () => {
    expect(RELAY_SUBPROTOCOLS).toEqual(['iroh-relay-v2', 'iroh-relay-v1'])
    expect(new RelayConnectAbortedError().name).toBe('RelayConnectAbortedError')
    expect(new RelayAuthDeniedError('denied').reason).toBe('denied')
    expect(FrameType.Ping).toBe(9)
    expect(RELAY_PATH).toBe('/relay')
    expect(encodeVarInt(FrameType.Ping)).toEqual(new Uint8Array([9]))
  })
})

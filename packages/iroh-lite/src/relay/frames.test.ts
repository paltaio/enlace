import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  FrameType,
  MAX_PACKET_SIZE,
  decodeClientToRelayFrame,
  decodeRelayToClientFrame,
  encodeClientToRelayFrame,
  encodeRelayToClientFrame,
} from './frames'

const endpointId = hexToBytes('197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61')
const helloWorld = new TextEncoder().encode('Hello World!')

describe('relay frame tags', () => {
  test('matches pinned iroh-relay frame ids', () => {
    expect(FrameType).toEqual({
      ServerChallenge: 0,
      ClientAuth: 1,
      ServerConfirmsAuth: 2,
      ServerDeniesAuth: 3,
      ClientToRelayDatagram: 4,
      ClientToRelayDatagramBatch: 5,
      RelayToClientDatagram: 6,
      RelayToClientDatagramBatch: 7,
      EndpointGone: 8,
      Ping: 9,
      Pong: 10,
      Health: 11,
      Restarting: 12,
      Status: 13,
    })
  })
})

describe('relay-to-client frames', () => {
  test('encodes and decodes ping', () => {
    const encoded = encodeRelayToClientFrame({ type: 'ping', data: new Uint8Array(8).fill(42) })
    expect(bytesToHex(encoded)).toBe('092a2a2a2a2a2a2a2a')
    expect(decodeRelayToClientFrame(encoded)).toEqual({
      type: 'ping',
      data: new Uint8Array(8).fill(42),
    })
  })

  test('encodes and decodes pong', () => {
    const encoded = encodeRelayToClientFrame({ type: 'pong', data: new Uint8Array(8).fill(42) })
    expect(bytesToHex(encoded)).toBe('0a2a2a2a2a2a2a2a2a')
    expect(decodeRelayToClientFrame(encoded)).toEqual({
      type: 'pong',
      data: new Uint8Array(8).fill(42),
    })
  })

  test('encodes and decodes endpoint gone', () => {
    const encoded = encodeRelayToClientFrame({ type: 'endpoint-gone', endpointId })
    expect(bytesToHex(encoded)).toBe(
      '08197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61',
    )
    expect(decodeRelayToClientFrame(encoded)).toEqual({ type: 'endpoint-gone', endpointId })
  })

  test('encodes and decodes datagram batch', () => {
    const encoded = encodeRelayToClientFrame({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld },
    })
    expect(bytesToHex(encoded)).toBe(
      '07197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6103000648656c6c6f20576f726c6421',
    )
    expect(decodeRelayToClientFrame(encoded)).toEqual({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld },
    })
  })

  test('encodes and decodes single datagram', () => {
    const encoded = encodeRelayToClientFrame({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, contents: helloWorld },
    })
    expect(bytesToHex(encoded)).toBe(
      '06197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d610348656c6c6f20576f726c6421',
    )
    expect(decodeRelayToClientFrame(encoded)).toEqual({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, contents: helloWorld },
    })
  })

  test('encodes and decodes restarting', () => {
    const encoded = encodeRelayToClientFrame({
      type: 'restarting',
      reconnectInMs: 10,
      tryForMs: 20,
    })
    expect(bytesToHex(encoded)).toBe('0c0000000a00000014')
    expect(decodeRelayToClientFrame(encoded)).toEqual({
      type: 'restarting',
      reconnectInMs: 10,
      tryForMs: 20,
    })
  })

  test('encodes and decodes status', () => {
    const encoded = encodeRelayToClientFrame({
      type: 'status',
      status: { type: 'same-endpoint-id-connected' },
    })
    expect(bytesToHex(encoded)).toBe('0d01')
    expect(decodeRelayToClientFrame(encoded)).toEqual({
      type: 'status',
      status: { type: 'same-endpoint-id-connected' },
    })
  })

  test('encodes and decodes v1 health', () => {
    const encoded = encodeRelayToClientFrame({ type: 'health', problem: 'warming up' })
    expect(bytesToHex(encoded)).toBe('0b7761726d696e67207570')
    expect(decodeRelayToClientFrame(encoded, 'iroh-relay-v1')).toEqual({
      type: 'health',
      problem: 'warming up',
    })
  })

  test('rejects version-specific relay frames on the wrong subprotocol', () => {
    const health = encodeRelayToClientFrame({ type: 'health', problem: 'warming up' })
    const status = encodeRelayToClientFrame({
      type: 'status',
      status: { type: 'healthy' },
    })

    expect(() => decodeRelayToClientFrame(health, 'iroh-relay-v2')).toThrow(
      'relay frame not allowed for selected protocol',
    )
    expect(() => decodeRelayToClientFrame(status, 'iroh-relay-v1')).toThrow(
      'relay frame not allowed for selected protocol',
    )
  })

  test('rejects oversized and malformed v1 health frames', () => {
    expect(() =>
      encodeRelayToClientFrame({ type: 'health', problem: 'x'.repeat(MAX_PACKET_SIZE) }),
    ).toThrow(`relay frame exceeds ${MAX_PACKET_SIZE} bytes`)

    expect(() => decodeRelayToClientFrame(hexToBytes('0bff'), 'iroh-relay-v1')).toThrow()
  })
})

describe('client-to-relay frames', () => {
  test('encodes datagram batch with client tag', () => {
    const encoded = encodeClientToRelayFrame({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld },
    })
    expect(bytesToHex(encoded)).toBe(
      '05197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6103000648656c6c6f20576f726c6421',
    )
    expect(decodeClientToRelayFrame(encoded)).toEqual({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld },
    })
  })

  test('encodes single datagram with client tag', () => {
    const encoded = encodeClientToRelayFrame({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, contents: helloWorld },
    })
    expect(bytesToHex(encoded)).toBe(
      '04197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d610348656c6c6f20576f726c6421',
    )
    expect(decodeClientToRelayFrame(encoded)).toEqual({
      type: 'datagrams',
      datagrams: { endpointId, ecn: 3, contents: helloWorld },
    })
  })

  test('rejects empty datagrams', () => {
    expect(() =>
      encodeClientToRelayFrame({
        type: 'datagrams',
        datagrams: { endpointId, ecn: null, contents: new Uint8Array() },
      }),
    ).toThrow('relay datagram contents must not be empty')
  })

  test('rejects encoded frames over packet limit', () => {
    const contents = new Uint8Array(MAX_PACKET_SIZE)

    expect(() =>
      encodeClientToRelayFrame({
        type: 'datagrams',
        datagrams: { endpointId, ecn: null, contents },
      }),
    ).toThrow(`relay frame exceeds ${MAX_PACKET_SIZE} bytes`)
  })
})

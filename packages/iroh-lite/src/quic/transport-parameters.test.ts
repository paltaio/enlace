import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import { decryptQuicInitialPacket } from './initial'
import { parseQuicFrames } from './frame'
import { parseTlsHandshakes, TlsExtensionType, TlsHandshakeKind } from './tls'
import {
  defaultQuicTransportParameters,
  encodeQuicTransportParameters,
  parseQuicTransportParameters,
  QuicEndpointRole,
} from './transport-parameters'

describe('QUIC transport parameters', () => {
  test('parses ClientHello transport parameters from RFC 9001 vector', () => {
    const params = parseQuicTransportParameters(rfc9001ClientTransportParameters(), 'client')

    expect(params.maxIdleTimeout).toBe(30000n)
    expect(params.initialMaxData).toBe(4611686018427387903n)
    expect(params.initialMaxStreamDataBidiLocal).toBe(65535n)
    expect(params.initialMaxStreamDataBidiRemote).toBe(65535n)
    expect(params.initialMaxStreamDataUni).toBe(65535n)
    expect(params.initialMaxStreamsBidi).toBe(16n)
    expect(params.initialMaxStreamsUni).toBe(16n)
    expect(params.maxUdpPayloadSize).toBe(65527n)
    expect(params.ackDelayExponent).toBe(3n)
    expect(params.maxAckDelay).toBe(25n)
    expect(params.activeConnectionIdLimit).toBe(2n)
    expect(params.initialSourceConnectionId).toEqual(rfc9001DestinationConnectionId)
  })

  test('encodes parser-compatible transport parameters', () => {
    const encoded = encodeQuicTransportParameters({
      initialMaxData: 0x4000n,
      initialMaxStreamDataBidiRemote: 0x2000n,
      initialMaxStreamsBidi: 4n,
      disableActiveMigration: true,
      initialSourceConnectionId: hexToBytes('01020304'),
    })

    expect(bytesToHex(encoded)).toBe('040480004000060260000801040c000f0401020304')
    expect(parseQuicTransportParameters(encoded, QuicEndpointRole.Client)).toEqual({
      ...defaultQuicTransportParameters(),
      initialMaxData: 0x4000n,
      initialMaxStreamDataBidiRemote: 0x2000n,
      initialMaxStreamsBidi: 4n,
      disableActiveMigration: true,
      initialSourceConnectionId: hexToBytes('01020304'),
    })
  })

  test('ignores unknown parameters and rejects duplicates', () => {
    const withUnknown = hexToBytes('1b02aabb040104')
    expect(parseQuicTransportParameters(withUnknown).initialMaxData).toBe(4n)

    expect(() => parseQuicTransportParameters(hexToBytes('040104040105'))).toThrow(
      'duplicate QUIC transport parameter',
    )
  })

  test('rejects malformed parameter lengths', () => {
    expect(() => parseQuicTransportParameters(hexToBytes('04020000'))).toThrow(
      'QUIC transport parameter varint length mismatch',
    )
    expect(() => parseQuicTransportParameters(hexToBytes('0c01ff'))).toThrow(
      'QUIC disable_active_migration length mismatch',
    )
    expect(() =>
      parseQuicTransportParameters(hexToBytes('020f000000000000000000000000000000')),
    ).toThrow('QUIC stateless reset token length mismatch')
  })

  test('rejects illegal values and client server-only fields', () => {
    expect(() =>
      parseQuicTransportParameters(encodeQuicTransportParameters({ ackDelayExponent: 21n })),
    ).toThrow('QUIC ack_delay_exponent out of range')
    expect(() =>
      parseQuicTransportParameters(encodeQuicTransportParameters({ activeConnectionIdLimit: 1n })),
    ).toThrow('QUIC active_connection_id_limit out of range')
    expect(() =>
      parseQuicTransportParameters(hexToBytes('000101'), QuicEndpointRole.Client),
    ).toThrow('client QUIC transport parameters contain server-only field')
  })

  test('requires connection-id authentication parameters for role-aware parsing', () => {
    expect(() => parseQuicTransportParameters(new Uint8Array(), QuicEndpointRole.Client)).toThrow(
      'QUIC initial_source_connection_id transport parameter is required',
    )
    expect(() =>
      parseQuicTransportParameters(
        encodeQuicTransportParameters({ initialSourceConnectionId: hexToBytes('01020304') }),
        QuicEndpointRole.Server,
      ),
    ).toThrow('QUIC original_destination_connection_id transport parameter is required')

    const server = parseQuicTransportParameters(
      encodeQuicTransportParameters({
        originalDestinationConnectionId: hexToBytes('09080706'),
        initialSourceConnectionId: hexToBytes('01020304'),
      }),
      QuicEndpointRole.Server,
    )

    expect(server.originalDestinationConnectionId).toEqual(hexToBytes('09080706'))
    expect(server.initialSourceConnectionId).toEqual(hexToBytes('01020304'))
  })
})

function rfc9001ClientTransportParameters(): Uint8Array {
  const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
  const packet = decryptQuicInitialPacket(rfc9001ProtectedClientInitialPacket, keys.client)
  const frames = parseQuicFrames(packet.payload).frames
  const crypto = frames[0]
  if (crypto?.type !== 'crypto') {
    throw new Error('expected CRYPTO frame')
  }
  const result = parseTlsHandshakes(crypto.data)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== TlsHandshakeKind.ClientHello) {
    throw new Error('expected ClientHello')
  }
  for (const extension of handshake.body.extensions) {
    if (extension.extensionType === TlsExtensionType.QuicTransportParameters) {
      return extension.data
    }
  }
  throw new Error('expected QUIC transport parameters')
}

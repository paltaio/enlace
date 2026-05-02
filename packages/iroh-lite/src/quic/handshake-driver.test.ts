import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey, rfc8448ServerPrivateKey } from '../testing/rfc8448-tls'
import { encodeQuicStreamFrame } from './frame'
import {
  QuicClientHandshakeDriver,
  QuicServerHandshakeDriver,
  type QuicClientHandshakeDriverOptions,
  type QuicServerHandshakeDriverOptions,
} from './handshake-driver'
import { encodeQuicTransportParameters, type QuicTransportParameters } from './transport-parameters'

const testAlpn = new TextEncoder().encode('/iroh-gossip/1')
const otherAlpn = new TextEncoder().encode('/iroh-test/1')
const clientConnectionId = hexToBytes('c1c2c3c4')
const serverConnectionId = hexToBytes('d1d2d3d4')
const initialDestinationConnectionId = hexToBytes('a1a2a3a4')
const serverEndpointSecretKey = hexToBytes(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
)
const clientEndpointSecretKey = hexToBytes(
  '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
)

describe('QUIC handshake driver', () => {
  test('drives synthetic Initial and Handshake flights into 1-RTT stream state', async () => {
    const pair = await handshakePair()
    const sent = pair.clientConnection.sendStream(0, hexToBytes('70696e67'), true)
    const received = pair.serverConnection.receive(sent.packet)
    const response = pair.serverConnection.sendStream(
      1,
      received.streamOutputs[0]?.data ?? new Uint8Array(),
      true,
    )
    const echoed = pair.clientConnection.receive(response.packet)

    expect(pair.start.packetNumber).toBe(0n)
    expect(pair.start.packet).toHaveLength(1200)
    expect(pair.serverFlight.initialPacketNumber).toBe(0n)
    expect(pair.serverFlight.handshakePacketNumber).toBe(0n)
    expect(pair.flight.packetNumber).toBe(0n)
    expect(pair.clientConnection.handshakeArtifacts().negotiatedAlpn).toEqual(testAlpn)
    expect(pair.serverConnection.handshakeArtifacts().negotiatedAlpn).toEqual(testAlpn)
    expect(received.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(echoed.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e67')
    expect(echoed.streamOutputs[0]?.complete).toBe(true)
  })

  test('seeds connection stream credit from transport parameters', async () => {
    const pair = await handshakePair({
      serverTransportParameters: encodeQuicTransportParameters({
        originalDestinationConnectionId: initialDestinationConnectionId,
        initialSourceConnectionId: serverConnectionId,
        initialMaxData: 2n,
        initialMaxStreamDataBidiRemote: 2n,
      }),
    })
    const transportParameters = requireTransportParameters(
      pair.clientConnection.handshakeArtifacts().transportParameters?.server,
    )

    pair.clientConnection.sendStream(0, hexToBytes('6869'))

    expect(transportParameters.initialMaxData).toBe(2n)
    expect(() => pair.clientConnection.sendStream(0, hexToBytes('21'))).toThrow(
      'QUIC STREAM data exceeds MAX_STREAM_DATA',
    )
  })

  test('rejects ClientHello transport parameters that do not match packet source id', async () => {
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const client = new QuicClientHandshakeDriver(
      clientOptions({
        expectedServerEndpointId: serverEndpointId,
        transportParameters: clientTransportParameters(hexToBytes('01020304')),
      }),
    )
    const server = new QuicServerHandshakeDriver(serverOptions())
    const start = await client.start()

    await expectRejects(
      server.receiveClientInitial(start.packet),
      'client QUIC initial_source_connection_id does not match Initial source connection id',
    )
    expect(server.connection).toBeNull()
  })

  test('rejects server transport parameters that do not match packet connection ids', async () => {
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const client = new QuicClientHandshakeDriver(
      clientOptions({ expectedServerEndpointId: serverEndpointId }),
    )
    const server = new QuicServerHandshakeDriver(
      serverOptions({
        transportParameters: serverTransportParameters({
          initialSourceConnectionId: hexToBytes('01020304'),
        }),
      }),
    )
    const start = await client.start()

    await expectRejects(
      server.receiveClientInitial(start.packet),
      'server QUIC initial_source_connection_id does not match Initial source connection id',
    )
    expect(server.connection).toBeNull()
  })

  test('rejects ALPN mismatch before committing client connection state', async () => {
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const client = new QuicClientHandshakeDriver(
      clientOptions({
        expectedServerEndpointId: serverEndpointId,
        alpnProtocols: [testAlpn, otherAlpn],
        expectedAlpn: testAlpn,
      }),
    )
    const server = new QuicServerHandshakeDriver(
      serverOptions({
        selectedAlpn: otherAlpn,
      }),
    )
    const start = await client.start()
    const serverFlight = await server.receiveClientInitial(start.packet)

    await expectRejects(
      client.receiveServerFlights(serverFlight.initialPacket, serverFlight.handshakePacket),
      'TLS selected ALPN mismatch',
    )
    expect(client.connection).toBeNull()
    expect(client.messages().map((message) => message.handshake.kind)).toEqual(['client-hello'])
  })

  test('accepts any offered ALPN when caller does not pin expected ALPN', async () => {
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const client = new QuicClientHandshakeDriver(
      clientOptions({
        expectedServerEndpointId: serverEndpointId,
        alpnProtocols: [testAlpn, otherAlpn],
      }),
    )
    const server = new QuicServerHandshakeDriver(
      serverOptions({
        selectedAlpn: otherAlpn,
      }),
    )
    const start = await client.start()
    const serverFlight = await server.receiveClientInitial(start.packet)
    const clientFlight = await client.receiveServerFlights(
      serverFlight.initialPacket,
      serverFlight.handshakePacket,
    )
    const complete = await server.receiveClientHandshake(clientFlight.packet)

    expect(client.connection?.handshakeArtifacts().negotiatedAlpn).toEqual(otherAlpn)
    expect(complete.connection.handshakeArtifacts().negotiatedAlpn).toEqual(otherAlpn)
  })

  test('rejects endpoint mismatch before committing client connection state', async () => {
    const wrongEndpointId = await endpointIdFromSecretKey(
      hexToBytes('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'),
    )
    const client = new QuicClientHandshakeDriver(
      clientOptions({
        expectedServerEndpointId: wrongEndpointId,
      }),
    )
    const server = new QuicServerHandshakeDriver(serverOptions())
    const start = await client.start()
    const serverFlight = await server.receiveClientInitial(start.packet)

    await expectRejects(
      client.receiveServerFlights(serverFlight.initialPacket, serverFlight.handshakePacket),
      'TLS raw public key does not match expected endpoint id',
    )
    expect(client.connection).toBeNull()
  })

  test('rejects malformed client Handshake packet without server state mutation', async () => {
    const client = new QuicClientHandshakeDriver(
      clientOptions({
        expectedServerEndpointId: await endpointIdFromSecretKey(serverEndpointSecretKey),
      }),
    )
    const server = new QuicServerHandshakeDriver(serverOptions())
    const start = await client.start()
    const serverFlight = await server.receiveClientInitial(start.packet)
    const clientFlight = await client.receiveServerFlights(
      serverFlight.initialPacket,
      serverFlight.handshakePacket,
    )
    const beforeMessages = server.messages().map((message) => message.handshake.kind)
    const brokenPacket = flipLastByte(clientFlight.packet)

    await expectRejects(server.receiveClientHandshake(brokenPacket), 'aes/gcm: invalid ghash tag')
    expect(server.connection).toBeNull()
    expect(server.messages().map((message) => message.handshake.kind)).toEqual(beforeMessages)

    const complete = await server.receiveClientHandshake(clientFlight.packet)
    expect(complete.connection.handshakeArtifacts().negotiatedAlpn).toEqual(testAlpn)
  })

  test('rejects malformed 1-RTT stream frame through resulting connection state', async () => {
    const pair = await handshakePair()
    const malformed = pair.clientConnection.sendFrames(new Uint8Array([0x0a, 0x01, 0x05, 0xaa]))

    expect(() => pair.serverConnection.receive(malformed.packet)).toThrow(
      'not enough bytes for QUIC STREAM frame data',
    )
  })

  test('sends frame bytes parseable by existing receive path after handshake', async () => {
    const pair = await handshakePair()
    const packet = pair.clientConnection.sendFrames(
      encodeQuicStreamFrame(0, 0, hexToBytes('6f6b'), true),
    )
    const received = pair.serverConnection.receive(packet.packet)

    expect(received.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(received.streamOutputs[0]?.data ?? new Uint8Array())).toBe('6f6b')
  })
})

async function handshakePair(
  options: {
    readonly serverTransportParameters?: Uint8Array
  } = {},
): Promise<{
  readonly start: Awaited<ReturnType<QuicClientHandshakeDriver['start']>>
  readonly serverFlight: Awaited<ReturnType<QuicServerHandshakeDriver['receiveClientInitial']>>
  readonly flight: Awaited<ReturnType<QuicClientHandshakeDriver['receiveServerFlights']>>
  readonly clientConnection: NonNullable<QuicClientHandshakeDriver['connection']>
  readonly serverConnection: NonNullable<QuicServerHandshakeDriver['connection']>
}> {
  const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
  const client = new QuicClientHandshakeDriver(
    clientOptions({
      expectedServerEndpointId: serverEndpointId,
    }),
  )
  const server = new QuicServerHandshakeDriver(
    options.serverTransportParameters === undefined
      ? serverOptions()
      : serverOptions({ transportParameters: options.serverTransportParameters }),
  )
  const start = await client.start()
  const serverFlight = await server.receiveClientInitial(start.packet)
  const clientFlight = await client.receiveServerFlights(
    serverFlight.initialPacket,
    serverFlight.handshakePacket,
  )
  await server.receiveClientHandshake(clientFlight.packet)
  const clientConnection = requireConnection(client.connection)
  const serverConnection = requireConnection(server.connection)

  return {
    start,
    serverFlight,
    flight: clientFlight,
    clientConnection,
    serverConnection,
  }
}

function clientOptions(
  overrides: Partial<QuicClientHandshakeDriverOptions> & {
    readonly expectedServerEndpointId: Uint8Array
  },
): QuicClientHandshakeDriverOptions {
  return {
    x25519PrivateKey: rfc8448ClientPrivateKey,
    endpointSecretKey: clientEndpointSecretKey,
    alpnProtocols: [testAlpn],
    transportParameters: clientTransportParameters(),
    sourceConnectionId: clientConnectionId,
    initialDestinationConnectionId,
    ...overrides,
  }
}

function serverOptions(
  overrides: Partial<QuicServerHandshakeDriverOptions> = {},
): QuicServerHandshakeDriverOptions {
  return {
    x25519PrivateKey: rfc8448ServerPrivateKey,
    endpointSecretKey: serverEndpointSecretKey,
    selectedAlpn: testAlpn,
    transportParameters: serverTransportParameters(),
    sourceConnectionId: serverConnectionId,
    ...overrides,
  }
}

function clientTransportParameters(initialSourceConnectionId = clientConnectionId): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: 65536n,
    initialMaxStreamDataBidiLocal: 65536n,
    initialMaxStreamDataBidiRemote: 65536n,
    initialMaxStreamDataUni: 65536n,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    initialSourceConnectionId,
  })
}

function serverTransportParameters(
  overrides: {
    readonly originalDestinationConnectionId?: Uint8Array
    readonly initialSourceConnectionId?: Uint8Array
  } = {},
): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: 65536n,
    initialMaxStreamDataBidiLocal: 65536n,
    initialMaxStreamDataBidiRemote: 65536n,
    initialMaxStreamDataUni: 65536n,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    originalDestinationConnectionId:
      overrides.originalDestinationConnectionId ?? initialDestinationConnectionId,
    initialSourceConnectionId: overrides.initialSourceConnectionId ?? serverConnectionId,
  })
}

function requireConnection<T>(connection: T | null): T {
  if (connection === null) {
    throw new Error('expected connection')
  }
  return connection
}

function requireTransportParameters(
  transportParameters: QuicTransportParameters | undefined,
): QuicTransportParameters {
  if (transportParameters === undefined) {
    throw new Error('expected transport parameters')
  }
  return transportParameters
}

function flipLastByte(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes)
  const index = out.length - 1
  out[index] = (out[index] ?? 0) ^ 0xff
  return out
}

async function expectRejects(promise: Promise<unknown>, message: string): Promise<void> {
  await promise.then(
    () => {
      throw new Error('expected rejection')
    },
    (error: unknown) => {
      expect(error).toBeInstanceOf(Error)
      expect(errorMessage(error)).toBe(message)
    },
  )
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

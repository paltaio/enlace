import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { endpointIdFromSecretKey } from '../crypto/ed25519'
import type { Datagrams } from '../relay/frames'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey, rfc8448ServerPrivateKey } from '../testing/rfc8448-tls'
import { QuicClientHandshakeDriver, QuicServerHandshakeDriver } from './handshake-driver'
import {
  QuicRelayClientDriver,
  QuicRelayServerDriver,
  splitRelayDatagramPackets,
  splitQuicRelayDatagram,
} from './relay-driver'
import { encodeQuicTransportParameters } from './transport-parameters'

const testAlpn = new TextEncoder().encode('/iroh/echo/1')
const clientConnectionId = hexToBytes('c1c2c3c4')
const serverConnectionId = hexToBytes('d1d2d3d4')
const initialDestinationConnectionId = hexToBytes('a1a2a3a4')
const serverEndpointSecretKey = hexToBytes(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
)
const clientEndpointSecretKey = hexToBytes(
  '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
)

describe('QUIC relay datagram driver', () => {
  test('drives handshake and bidirectional stream echo through relay-shaped datagrams', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const client = new QuicRelayClientDriver({
      peerEndpointId: serverEndpointId,
      handshake: new QuicClientHandshakeDriver({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        endpointSecretKey: clientEndpointSecretKey,
        expectedServerEndpointId: serverEndpointId,
        alpnProtocols: [testAlpn],
        expectedAlpn: testAlpn,
        transportParameters: clientTransportParameters(),
        sourceConnectionId: clientConnectionId,
        initialDestinationConnectionId,
      }),
    })
    const server = new QuicRelayServerDriver({
      handshake: new QuicServerHandshakeDriver({
        x25519PrivateKey: rfc8448ServerPrivateKey,
        endpointSecretKey: serverEndpointSecretKey,
        selectedAlpn: testAlpn,
        transportParameters: serverTransportParameters(),
        sourceConnectionId: serverConnectionId,
      }),
    })

    const clientInitial = await client.start()
    expect(clientInitial.endpointId).toEqual(serverEndpointId)

    const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
    expect(serverFlight.outgoing).toHaveLength(2)
    expect(serverFlight.connected).toBe(false)

    const coalescedServerFlight = coalesceDatagrams(serverFlight.outgoing, serverEndpointId)
    expect(splitQuicRelayDatagram(coalescedServerFlight.contents)).toHaveLength(2)

    const clientFlight = await client.receive(coalescedServerFlight)
    expect(clientFlight.outgoing).toHaveLength(1)
    expect(clientFlight.connected).toBe(true)

    const serverComplete = await server.receive(
      relayDeliver(clientEndpointId, requireDatagram(clientFlight.outgoing[0])),
    )
    expect(serverComplete.connected).toBe(true)

    const request = client.sendStream(0, hexToBytes('70696e67'), true)
    const serverReceived = await server.receive(relayDeliver(clientEndpointId, request.datagrams))
    expect(serverReceived.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(serverReceived.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e67')
    expect(serverReceived.outgoing).toHaveLength(1)

    const response = server.sendStream(
      0,
      serverReceived.streamOutputs[0]?.data ?? new Uint8Array(),
      true,
    )
    const clientReceived = await client.receive(relayDeliver(serverEndpointId, response.datagrams))
    expect(clientReceived.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(clientReceived.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e67')
    expect(clientReceived.outgoing).toHaveLength(1)
  })

  test('honors relay batch segments around handshake packets', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const { client, server } = relayPair(clientEndpointId, serverEndpointId)
    const clientInitial = await client.start()
    const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
    const batchedServerFlight = batchDatagrams(
      sortDatagramsByDescendingPacketLength(serverFlight.outgoing),
      serverEndpointId,
    )

    expect(splitRelayDatagramPackets(batchedServerFlight)).toHaveLength(2)

    const clientFlight = await client.receive(batchedServerFlight)
    const serverComplete = await server.receive(
      relayDeliver(clientEndpointId, requireDatagram(clientFlight.outgoing[0])),
    )

    expect(clientFlight.connected).toBe(true)
    expect(serverComplete.connected).toBe(true)
  })

  test('accepts a client Handshake packet coalesced with first 1-RTT stream packet', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const { client, server } = relayPair(clientEndpointId, serverEndpointId)
    const clientInitial = await client.start()
    const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
    const clientFlight = await client.receive(
      coalesceDatagrams(serverFlight.outgoing, serverEndpointId),
    )
    const request = client.sendStream(0, hexToBytes('70696e67'), true)
    const received = await server.receive(
      batchDatagrams(
        [requireDatagram(clientFlight.outgoing[0]), request.datagrams],
        clientEndpointId,
      ),
    )

    expect(received.connected).toBe(true)
    expect(received.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(received.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e67')
  })

  test('buffers first 1-RTT stream packet until client Handshake packet arrives', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const { client, server } = relayPair(clientEndpointId, serverEndpointId)
    const clientInitial = await client.start()
    const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
    const clientFlight = await client.receive(
      coalesceDatagrams(serverFlight.outgoing, serverEndpointId),
    )
    const request = client.sendStream(0, hexToBytes('70696e67'), true)
    const buffered = await server.receive(relayDeliver(clientEndpointId, request.datagrams))

    expect(buffered.connected).toBe(false)
    expect(buffered.streamOutputs).toEqual([])

    const received = await server.receive(
      relayDeliver(clientEndpointId, requireDatagram(clientFlight.outgoing[0])),
    )

    expect(received.connected).toBe(true)
    expect(received.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(received.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e67')
  })

  test('ignores client Handshake packet that arrives before client Initial', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const { client, server } = relayPair(clientEndpointId, serverEndpointId)
    const { client: reorderedClient, server: referenceServer } = relayPair(
      clientEndpointId,
      serverEndpointId,
    )
    const reorderedClientInitial = await reorderedClient.start()
    const referenceServerFlight = await referenceServer.receive(
      relayDeliver(clientEndpointId, reorderedClientInitial),
    )
    const reorderedClientFlight = await reorderedClient.receive(
      coalesceDatagrams(referenceServerFlight.outgoing, serverEndpointId),
    )
    const preInitialHandshake = requireDatagram(reorderedClientFlight.outgoing[0])
    const clientInitial = await client.start()

    const ignored = await server.receive(relayDeliver(clientEndpointId, preInitialHandshake))
    expect(ignored.connected).toBe(false)
    expect(ignored.outgoing).toEqual([])

    const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
    expect(serverFlight.connected).toBe(false)

    const clientFlight = await client.receive(
      coalesceDatagrams(serverFlight.outgoing, serverEndpointId),
    )
    const connected = await server.receive(
      relayDeliver(clientEndpointId, requireDatagram(clientFlight.outgoing[0])),
    )
    expect(connected.connected).toBe(true)
  })

  test('ignores duplicate long-header packets after connection is established', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const { client, server } = relayPair(clientEndpointId, serverEndpointId)
    const clientInitial = await client.start()
    const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
    const clientFlight = await client.receive(
      coalesceDatagrams(serverFlight.outgoing, serverEndpointId),
    )
    const clientHandshake = requireDatagram(clientFlight.outgoing[0])
    const serverComplete = await server.receive(relayDeliver(clientEndpointId, clientHandshake))
    expect(serverComplete.connected).toBe(true)

    const request = client.sendStream(0, hexToBytes('70696e67'), true)
    const received = await server.receive(
      batchDatagrams([clientHandshake, request.datagrams], clientEndpointId),
    )

    expect(received.connected).toBe(true)
    expect(received.streamOutputs[0]?.complete).toBe(true)
    expect(bytesToHex(received.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e67')
  })

  test('honors relay batch segments around 1-RTT packets', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const { client, server } = relayPair(clientEndpointId, serverEndpointId)
    await connectRelayPair(client, server, clientEndpointId, serverEndpointId)

    const first = client.sendStream(0, hexToBytes('70696e'))
    const second = client.sendStream(0, hexToBytes('67'), true)
    const received = await server.receive(
      relayDeliver(
        clientEndpointId,
        batchDatagrams([first.datagrams, second.datagrams], clientEndpointId),
      ),
    )

    expect(received.streamOutputs).toHaveLength(2)
    expect(bytesToHex(received.streamOutputs[0]?.data ?? new Uint8Array())).toBe('70696e')
    expect(bytesToHex(received.streamOutputs[1]?.data ?? new Uint8Array())).toBe('67')
    expect(received.streamOutputs[1]?.complete).toBe(true)
    expect(received.outgoing).toHaveLength(2)
  })

  test('rejects datagrams from an unexpected relay endpoint id', async () => {
    const clientEndpointId = await endpointIdFromSecretKey(clientEndpointSecretKey)
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const client = new QuicRelayClientDriver({
      peerEndpointId: serverEndpointId,
      handshake: new QuicClientHandshakeDriver({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        endpointSecretKey: clientEndpointSecretKey,
        expectedServerEndpointId: serverEndpointId,
        alpnProtocols: [testAlpn],
        transportParameters: clientTransportParameters(),
        sourceConnectionId: clientConnectionId,
        initialDestinationConnectionId,
      }),
    })

    await expectRejects(
      client.receive({ endpointId: clientEndpointId, ecn: null, contents: hexToBytes('c0') }),
      'relay datagram endpoint id does not match QUIC peer',
    )
  })
})

function relayPair(
  clientEndpointId: Uint8Array,
  serverEndpointId: Uint8Array,
): {
  readonly client: QuicRelayClientDriver
  readonly server: QuicRelayServerDriver
} {
  return {
    client: new QuicRelayClientDriver({
      peerEndpointId: serverEndpointId,
      handshake: new QuicClientHandshakeDriver({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        endpointSecretKey: clientEndpointSecretKey,
        expectedServerEndpointId: serverEndpointId,
        alpnProtocols: [testAlpn],
        expectedAlpn: testAlpn,
        transportParameters: clientTransportParameters(),
        sourceConnectionId: clientConnectionId,
        initialDestinationConnectionId,
      }),
    }),
    server: new QuicRelayServerDriver({
      handshake: new QuicServerHandshakeDriver({
        x25519PrivateKey: rfc8448ServerPrivateKey,
        endpointSecretKey: serverEndpointSecretKey,
        selectedAlpn: testAlpn,
        transportParameters: serverTransportParameters(),
        sourceConnectionId: serverConnectionId,
      }),
    }),
  }
}

async function connectRelayPair(
  client: QuicRelayClientDriver,
  server: QuicRelayServerDriver,
  clientEndpointId: Uint8Array,
  serverEndpointId: Uint8Array,
): Promise<void> {
  const clientInitial = await client.start()
  const serverFlight = await server.receive(relayDeliver(clientEndpointId, clientInitial))
  const clientFlight = await client.receive(
    coalesceDatagrams(serverFlight.outgoing, serverEndpointId),
  )
  await server.receive(relayDeliver(clientEndpointId, requireDatagram(clientFlight.outgoing[0])))
}

function clientTransportParameters(): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: 65536n,
    initialMaxStreamDataBidiLocal: 65536n,
    initialMaxStreamDataBidiRemote: 65536n,
    initialMaxStreamDataUni: 65536n,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    initialSourceConnectionId: clientConnectionId,
  })
}

function serverTransportParameters(): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: 65536n,
    initialMaxStreamDataBidiLocal: 65536n,
    initialMaxStreamDataBidiRemote: 65536n,
    initialMaxStreamDataUni: 65536n,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    originalDestinationConnectionId: initialDestinationConnectionId,
    initialSourceConnectionId: serverConnectionId,
  })
}

function relayDeliver(senderEndpointId: Uint8Array, datagrams: Datagrams): Datagrams {
  return {
    ...datagrams,
    endpointId: senderEndpointId,
  }
}

function coalesceDatagrams(
  datagrams: readonly Datagrams[],
  senderEndpointId: Uint8Array,
): Datagrams {
  return {
    endpointId: senderEndpointId,
    ecn: datagrams[0]?.ecn ?? null,
    contents: concatBytes(datagrams.map((datagram) => datagram.contents)),
  }
}

function batchDatagrams(datagrams: readonly Datagrams[], senderEndpointId: Uint8Array): Datagrams {
  const first = requireDatagram(datagrams[0])
  return {
    endpointId: senderEndpointId,
    ecn: first.ecn,
    segmentSize: first.contents.length,
    contents: concatBytes(datagrams.map((datagram) => datagram.contents)),
  }
}

function sortDatagramsByDescendingPacketLength(
  datagrams: readonly Datagrams[],
): readonly Datagrams[] {
  return [...datagrams].sort((left, right) => right.contents.length - left.contents.length)
}

function requireDatagram(datagrams: Datagrams | undefined): Datagrams {
  if (datagrams === undefined) {
    throw new Error('expected relay datagram')
  }
  return datagrams
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

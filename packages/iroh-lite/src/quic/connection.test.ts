import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey, rfc8448ServerPrivateKey } from '../testing/rfc8448-tls'
import { tlsHandshakeStateFixture, tlsTestAlpn } from '../testing/tls-handshake-fixtures'
import { concatBytes, readU8 } from '../bytes'
import { encodeQuicMaxStreamDataFrame, encodeQuicPaddingFrame, encodeQuicPingFrame } from './frame'
import { createQuicConnectionStateFromHandshake, QuicConnectionState } from './connection'
import { deriveTls13ApplicationTrafficFromHandshakeState } from './tls-application-traffic'
import {
  verifyTls13ClientHandshakeState,
  verifyTls13ServerHandshakeState,
  type Tls13ClientHandshakeState,
  type Tls13ServerHandshakeState,
} from './tls-handshake-state'
import {
  defaultQuicTransportParameters,
  encodeQuicTransportParameters,
  QuicEndpointRole,
} from './transport-parameters'

describe('QUIC connection state', () => {
  test('builds 1-RTT state from verified handshake artifacts', async () => {
    const states = await verifiedHandshakeStates()
    const clientConnectionId = hexToBytes('c1c2c3c4')
    const serverConnectionId = hexToBytes('d1d2d3d4')
    const client = createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Client,
      handshakeState: states.client,
      localConnectionId: clientConnectionId,
      peerConnectionId: serverConnectionId,
    })

    expect(client.role).toBe(QuicEndpointRole.Client)
    expect(bytesToHex(requireBytes(client.handshakeArtifacts().negotiatedAlpn))).toBe(
      bytesToHex(tlsTestAlpn),
    )
    expect(client.transportParameters?.server.initialMaxData).toBe(65536n)
    expect(client.nextPacketNumber).toBe(0n)
    expect(client.largestReceivedPacketNumber).toBeNull()
  })

  test('sends small stream packets and receives stream outputs with ACK packets', async () => {
    const pair = await connectionPair()
    const sent = pair.client.sendStream(0, hexToBytes('6869'), true)
    const received = pair.server.receive(sent.packet, 3)
    const ackPacket = received.ackPacket
    const ackFrame = received.ackFrame
    if (ackPacket === null || ackFrame === null) {
      throw new Error('expected ACK packet')
    }
    const ackReceived = pair.client.receive(ackPacket.packet)

    expect(sent.packetNumber).toBe(0n)
    expect(received.packetNumber).toBe(0n)
    expect(received.streamOutputs.map(streamOutputHex)).toEqual([
      {
        streamId: 0,
        streamOffset: 0,
        data: '6869',
        fin: true,
        finalSize: 2,
        complete: true,
      },
    ])
    expect(pair.server.ackSnapshot()).toEqual({
      receivedPacketNumbers: [0n],
      largestReceivedPacketNumber: 0n,
    })
    expect(ackReceived.frames).toEqual([
      {
        type: 'ack',
        largestAcknowledged: 0n,
        ackDelay: 3,
        firstAckRange: 0n,
        ranges: [],
        offset: 0,
        endOffset: ackFrame.length,
      },
    ])
    expect(ackReceived.ackPacket).toBeNull()
  })

  test('runs a small in-memory bidirectional stream echo', async () => {
    const pair = await connectionPair()
    const request = pair.client.sendStream(0, hexToBytes('70696e67'), true)
    const serverRequest = pair.server.receive(request.packet)
    const requestOutput = serverRequest.streamOutputs[0]
    if (requestOutput === undefined) {
      throw new Error('expected request stream output')
    }
    const response = pair.server.sendStream(1, requestOutput.data, true)
    const clientResponse = pair.client.receive(response.packet)

    expect(clientResponse.streamOutputs.map(streamOutputHex)).toEqual([
      {
        streamId: 1,
        streamOffset: 0,
        data: '70696e67',
        fin: true,
        finalSize: 4,
        complete: true,
      },
    ])
    expect(pair.client.nextPacketNumber).toBe(2n)
    expect(pair.server.nextPacketNumber).toBe(2n)
    expect(pair.client.largestReceivedPacketNumber).toBe(1n)
    expect(pair.server.largestReceivedPacketNumber).toBe(0n)
  })

  test('rejects malformed frame bytes without connection receive mutation', async () => {
    const pair = await connectionPair()
    const valid = pair.client.sendFrames(
      concatBytes([encodeQuicPaddingFrame(2), encodeQuicPingFrame()]),
    )
    pair.server.receive(valid.packet)
    const largestReceivedPacketNumber = pair.server.largestReceivedPacketNumber
    const ackSnapshot = pair.server.ackSnapshot()
    const malformed = pair.client.sendFrames(new Uint8Array([0x0a, 0x01, 0x05, 0xaa]))

    expect(() => pair.server.receive(malformed.packet)).toThrow(
      'not enough bytes for QUIC STREAM frame data',
    )
    expect(pair.server.largestReceivedPacketNumber).toBe(largestReceivedPacketNumber)
    expect(pair.server.ackSnapshot()).toEqual(ackSnapshot)
  })

  test('rejects undecryptable packets without connection receive mutation', async () => {
    const pair = await connectionPair()
    const valid = pair.client.sendStream(0, hexToBytes('6869'))
    pair.server.receive(valid.packet)
    const largestReceivedPacketNumber = pair.server.largestReceivedPacketNumber
    const ackSnapshot = pair.server.ackSnapshot()
    const broken = new Uint8Array(pair.client.sendStream(0, hexToBytes('21')).packet)
    const lastIndex = broken.length - 1
    broken[lastIndex] = readU8(broken, lastIndex) ^ 0xff

    expect(() => pair.server.receive(broken)).toThrow('aes/gcm: invalid ghash tag')
    expect(pair.server.largestReceivedPacketNumber).toBe(largestReceivedPacketNumber)
    expect(pair.server.ackSnapshot()).toEqual(ackSnapshot)
  })

  test('honors peer transport parameter stream credit', async () => {
    const states = await verifiedHandshakeStates({
      serverTransportParameters: encodeQuicTransportParameters({
        originalDestinationConnectionId: hexToBytes('01020304'),
        initialSourceConnectionId: hexToBytes('d1d2d3d4'),
        initialMaxData: 2n,
        initialMaxStreamDataBidiRemote: 2n,
      }),
    })
    const client = createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Client,
      handshakeState: states.client,
      localConnectionId: hexToBytes('c1c2c3c4'),
      peerConnectionId: hexToBytes('d1d2d3d4'),
    })

    client.sendStream(0, hexToBytes('6869'))

    expect(client.streamSendOffset(0)).toBe(2)
    expect(() => client.sendStream(0, hexToBytes('21'))).toThrow(
      'QUIC STREAM data exceeds MAX_STREAM_DATA',
    )
    expect(client.nextPacketNumber).toBe(1n)
  })

  test('applies MAX_STREAM_DATA through received connection frames', async () => {
    const pair = await connectionPair({
      serverTransportParameters: encodeQuicTransportParameters({
        originalDestinationConnectionId: hexToBytes('01020304'),
        initialSourceConnectionId: hexToBytes('d1d2d3d4'),
        initialMaxData: 5n,
        initialMaxStreamDataBidiRemote: 1n,
      }),
    })
    expect(() => pair.client.sendStream(0, hexToBytes('6869'))).toThrow(
      'QUIC STREAM data exceeds MAX_STREAM_DATA',
    )
    const credit = pair.server.sendFrames(encodeQuicMaxStreamDataFrame(0, 4))

    pair.client.receive(credit.packet)
    const sent = pair.client.sendStream(0, hexToBytes('6869'), true)

    expect(sent.stream.nextStreamOffset).toBe(2)
  })

  test('can be constructed directly from application traffic keys', async () => {
    const states = await verifiedHandshakeStates()
    const keys = deriveTls13ApplicationTrafficFromHandshakeState(states.client).keys
    const client = new QuicConnectionState({
      role: QuicEndpointRole.Client,
      keys,
      localConnectionId: hexToBytes('c1c2c3c4'),
      peerConnectionId: hexToBytes('d1d2d3d4'),
      peerTransportParameters: {
        ...defaultQuicTransportParameters(),
        initialMaxData: 4n,
        initialMaxStreamDataBidiRemote: 4n,
      },
    })
    const packet = client.sendStream(0, hexToBytes('6f6b'), true)

    expect(packet.packetNumber).toBe(0n)
    expect(client.nextPacketNumber).toBe(1n)
  })
})

async function connectionPair(
  options: {
    readonly serverTransportParameters?: Uint8Array
  } = {},
): Promise<{
  readonly client: QuicConnectionState
  readonly server: QuicConnectionState
}> {
  const states = await verifiedHandshakeStates(options)
  const clientConnectionId = hexToBytes('c1c2c3c4')
  const serverConnectionId = hexToBytes('d1d2d3d4')
  return {
    client: createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Client,
      handshakeState: states.client,
      localConnectionId: clientConnectionId,
      peerConnectionId: serverConnectionId,
    }),
    server: createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Server,
      handshakeState: states.server,
      localConnectionId: serverConnectionId,
      peerConnectionId: clientConnectionId,
    }),
  }
}

async function verifiedHandshakeStates(
  options: {
    readonly serverTransportParameters?: Uint8Array
  } = {},
): Promise<{
  readonly client: Tls13ClientHandshakeState
  readonly server: Tls13ServerHandshakeState
}> {
  const fixture = await tlsHandshakeStateFixture({
    certificateRequest: false,
    ...(options.serverTransportParameters === undefined
      ? {}
      : { serverTransportParameters: options.serverTransportParameters }),
  })
  return {
    client: await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    }),
    server: await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    }),
  }
}

function requireBytes(bytes: Uint8Array | null): Uint8Array {
  if (bytes === null) {
    throw new Error('expected bytes')
  }
  return bytes
}

function streamOutputHex(output: {
  readonly streamId: number
  readonly streamOffset: number
  readonly data: Uint8Array
  readonly fin: boolean
  readonly finalSize: number | null
  readonly complete: boolean
}): {
  readonly streamId: number
  readonly streamOffset: number
  readonly data: string
  readonly fin: boolean
  readonly finalSize: number | null
  readonly complete: boolean
} {
  return {
    streamId: output.streamId,
    streamOffset: output.streamOffset,
    data: bytesToHex(output.data),
    fin: output.fin,
    finalSize: output.finalSize,
    complete: output.complete,
  }
}

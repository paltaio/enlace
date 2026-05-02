import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey, randomSecretKey } from '../crypto/ed25519'
import type { RelayWebSocketClient, RelayWebSocketReceiveFrame } from '../relay/client'
import { connectRelayWebSocket } from '../relay/client'
import type { Datagrams } from '../relay/frames'
import { hexToBytes } from '../testing/hex'
import { startLocalIrohRelay, withTimeout } from '../testing/local-iroh-relay'
import { nativeIrohEchoAlpn, startNativeIrohEchoServer } from '../testing/native-iroh-echo'
import { rfc8448ClientPrivateKey } from '../testing/rfc8448-tls'
import { QuicClientHandshakeDriver } from './handshake-driver'
import { QuicRelayClientDriver, type QuicRelayReceiveResult } from './relay-driver'
import { encodeQuicTransportParameters } from './transport-parameters'

const interopTest = Bun.env.IROH_NATIVE_INTEROP === '1' ? test : test.skip
const clientConnectionId = hexToBytes('c1c2c3c4c5c6c7c8')
const initialDestinationConnectionId = hexToBytes('a1a2a3a4a5a6a7a8')
const requestPayload = new TextEncoder().encode('ping from iroh-lite')

describe('native iroh QUIC interop', () => {
  interopTest('dials native Rust iroh echo over relay', async () => {
    const relay = await startLocalIrohRelay()
    const native = await startNativeIrohEchoServer(relay.url)
    const clientSecretKey = randomSecretKey()
    const clientEndpointId = await endpointIdFromSecretKey(clientSecretKey)
    let relayClient: RelayWebSocketClient | null = null

    try {
      relayClient = await withTimeout(
        connectRelayWebSocket({ url: relay.url, secretKey: clientSecretKey }),
        'TS relay client connect',
      )
      expect(relayClient.endpointId).toEqual(clientEndpointId)

      const quic = new QuicRelayClientDriver({
        peerEndpointId: native.endpointId,
        handshake: new QuicClientHandshakeDriver({
          x25519PrivateKey: rfc8448ClientPrivateKey,
          endpointSecretKey: clientSecretKey,
          expectedServerEndpointId: native.endpointId,
          alpnProtocols: [nativeIrohEchoAlpn],
          expectedAlpn: nativeIrohEchoAlpn,
          transportParameters: clientTransportParameters(),
          sourceConnectionId: clientConnectionId,
          initialDestinationConnectionId,
        }),
      })

      relayClient.sendDatagrams(await quic.start())
      await driveUntilConnected(relayClient, quic)

      relayClient.sendDatagrams(quic.sendStream(0, requestPayload, true).datagrams)
      const response = await driveUntilStreamComplete(relayClient, quic, 0)
      expect(response).toEqual(requestPayload)
    } finally {
      relayClient?.close()
      await native.stop()
      await relay.stop()
    }
  })
})

async function driveUntilConnected(
  relayClient: RelayWebSocketClient,
  quic: QuicRelayClientDriver,
): Promise<void> {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const received = await receiveQuicDatagrams(relayClient)
    const result = await quic.receive(received)
    sendOutgoing(relayClient, result)
    if (result.connected) {
      return
    }
  }
  throw new Error('native iroh QUIC handshake did not complete')
}

async function driveUntilStreamComplete(
  relayClient: RelayWebSocketClient,
  quic: QuicRelayClientDriver,
  streamId: number,
): Promise<Uint8Array> {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const received = await receiveQuicDatagrams(relayClient)
    const result = await quic.receive(received)
    sendOutgoing(relayClient, result)
    for (const output of result.streamOutputs) {
      if (output.streamId === streamId && output.complete) {
        return output.data
      }
    }
  }
  throw new Error('native iroh echo response did not complete')
}

async function receiveQuicDatagrams(relayClient: RelayWebSocketClient): Promise<Datagrams> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const frame = await withTimeout(relayClient.receive(), 'relay datagram receive', 30_000)
    if (frame === null) {
      throw new Error('relay websocket closed before QUIC datagram')
    }
    if (frame.type === 'datagrams') {
      return frame.datagrams
    }
    ignoreRelayControlFrame(frame)
  }
  throw new Error('relay did not deliver QUIC datagrams')
}

function sendOutgoing(relayClient: RelayWebSocketClient, result: QuicRelayReceiveResult): void {
  for (const datagrams of result.outgoing) {
    relayClient.sendDatagrams(datagrams)
  }
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

function ignoreRelayControlFrame(
  frame: Exclude<RelayWebSocketReceiveFrame, { type: 'datagrams' }>,
) {
  if (frame.type === 'status' || frame.type === 'pong' || frame.type === 'restarting') {
    return
  }
  if (frame.type === 'endpoint-gone') {
    throw new Error('native iroh endpoint disconnected from relay')
  }
  if (frame.type === 'health') {
    throw new Error(`relay reported health problem: ${frame.problem}`)
  }
}

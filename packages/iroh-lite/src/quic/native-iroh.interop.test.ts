import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey, randomSecretKey } from '../crypto/ed25519'
import { Endpoint } from '../endpoint/internal'
import {
  decodeGossipStreamFrame,
  decodeGossipStreamHeader,
  decodeGossipTopicMessage,
  gossipAlpn,
} from '../gossip/wire'
import { startLocalIrohRelay } from '../testing/local-iroh-relay'
import {
  nativeIrohEchoAlpn,
  runNativeIrohEchoClient,
  runNativeIrohGossipSender,
  startNativeIrohEchoServer,
} from '../testing/native-iroh-echo'

const interopTest = Bun.env.IROH_NATIVE_INTEROP === '1' ? test : test.skip
const requestPayload = new TextEncoder().encode('ping from iroh-lite')

describe('native iroh QUIC interop', () => {
  interopTest('dials native Rust iroh echo over relay', async () => {
    const relay = await startLocalIrohRelay()
    const native = await startNativeIrohEchoServer(relay.url)
    const clientSecretKey = randomSecretKey()
    const clientEndpointId = await endpointIdFromSecretKey(clientSecretKey)
    let endpoint: Endpoint | null = null

    try {
      endpoint = await Endpoint.createRelayOnly({
        relayUrl: relay.url,
        secretKey: clientSecretKey,
      })
      expect(endpoint.endpointId).toEqual(clientEndpointId)

      const connection = await endpoint.connect({
        endpointId: native.endpointId,
        relayUrl: relay.url,
        alpn: nativeIrohEchoAlpn,
      })
      const stream = connection.openBidiStream()
      stream.write(requestPayload, { fin: true })
      expect(await stream.readToEnd()).toEqual(requestPayload)
    } finally {
      endpoint?.close()
      await native.stop()
      await relay.stop()
    }
  })

  interopTest('accepts native Rust iroh echo over relay', async () => {
    const relay = await startLocalIrohRelay()
    const serverSecretKey = randomSecretKey()
    const serverEndpointId = await endpointIdFromSecretKey(serverSecretKey)
    let endpoint: Endpoint | null = null
    let nativeClient: ReturnType<typeof runNativeIrohEchoClient> | null = null

    try {
      endpoint = await Endpoint.createRelayOnly({
        relayUrl: relay.url,
        secretKey: serverSecretKey,
      })
      expect(endpoint.endpointId).toEqual(serverEndpointId)

      nativeClient = runNativeIrohEchoClient({
        relayUrl: relay.url,
        serverEndpointId,
        payload: requestPayload,
      })

      const connection = await endpoint.accept({ alpn: nativeIrohEchoAlpn })
      const stream = await connection.acceptBidiStream()
      const request = await stream.readToEnd()
      expect(request).toEqual(requestPayload)
      stream.write(request, { fin: true })

      const result = await nativeClient
      expect(result.payload).toEqual(requestPayload)
    } finally {
      endpoint?.close()
      await nativeClient?.catch(() => undefined)
      await relay.stop()
    }
  })

  interopTest('decodes native Rust gossip message over relay', async () => {
    const relay = await startLocalIrohRelay()
    const serverSecretKey = randomSecretKey()
    const serverEndpointId = await endpointIdFromSecretKey(serverSecretKey)
    let endpoint: Endpoint | null = null
    let nativeSender: ReturnType<typeof runNativeIrohGossipSender> | null = null

    try {
      endpoint = await Endpoint.createRelayOnly({
        relayUrl: relay.url,
        secretKey: serverSecretKey,
      })
      expect(endpoint.endpointId).toEqual(serverEndpointId)

      nativeSender = runNativeIrohGossipSender({
        relayUrl: relay.url,
        serverEndpointId,
      })

      const connection = await endpoint.accept({ alpn: gossipAlpn })
      const stream = await connection.acceptUniStream()
      const bytes = await stream.readToEnd()
      const headerFrame = decodeGossipStreamFrame(bytes)
      const header = decodeGossipStreamHeader(headerFrame.payload)
      const messageFrame = decodeGossipStreamFrame(bytes, headerFrame.bytesRead)
      const message = decodeGossipTopicMessage(messageFrame.payload)
      const result = await nativeSender

      expect(messageFrame.bytesRead + headerFrame.bytesRead).toBe(bytes.length)
      expect(header.topicId).toEqual(result.topicId)
      expect(message.layer).toBe('gossip')
      expect(message.type).toBe('gossip')
      if (message.type !== 'gossip') {
        throw new Error('expected gossip message')
      }
      expect(message.content).toEqual(result.payload)
      expect(message.scope).toEqual({ type: 'swarm', round: 0 })
    } finally {
      endpoint?.close()
      await nativeSender?.catch(() => undefined)
      await relay.stop()
    }
  })
})

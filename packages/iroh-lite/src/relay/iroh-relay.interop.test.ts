import { describe, expect, test } from 'bun:test'

import type { RelayWebSocketClient } from './client'
import { connectRelayWebSocket } from './client'
import { endpointIdFromSecretKey, randomSecretKey } from '../crypto/ed25519'
import { startLocalIrohRelay, withTimeout } from '../testing/local-iroh-relay'

const interopTest = Bun.env.IROH_RELAY_INTEROP === '1' ? test : test.skip
const relayVersion = 'iroh-relay-v2'

describe('iroh-relay interop', () => {
  interopTest('authenticates two browser clients and relays raw datagrams', async () => {
    const relay = await startLocalIrohRelay()
    const firstSecretKey = randomSecretKey()
    const secondSecretKey = randomSecretKey()
    const firstEndpointId = await endpointIdFromSecretKey(firstSecretKey)
    const secondEndpointId = await endpointIdFromSecretKey(secondSecretKey)
    const firstPayload = new TextEncoder().encode('from browser client one')
    const secondPayload = new TextEncoder().encode('from browser client two')

    let firstClient: RelayWebSocketClient | null = null
    let secondClient: RelayWebSocketClient | null = null
    try {
      firstClient = await withTimeout(
        connectRelayWebSocket({ url: relay.url, secretKey: firstSecretKey }),
        'first relay client connect',
      )
      secondClient = await withTimeout(
        connectRelayWebSocket({ url: relay.url, secretKey: secondSecretKey }),
        'second relay client connect',
      )

      expect(firstClient.protocol).toBe(relayVersion)
      expect(secondClient.protocol).toBe(relayVersion)
      expect(firstClient.endpointId).toEqual(firstEndpointId)
      expect(secondClient.endpointId).toEqual(secondEndpointId)

      const firstToSecond = receiveNextDatagrams(secondClient)
      firstClient.sendDatagrams({
        endpointId: secondEndpointId,
        ecn: null,
        contents: firstPayload,
      })
      expect(await withTimeout(firstToSecond, 'first datagram relay')).toEqual({
        endpointId: firstEndpointId,
        ecn: null,
        contents: firstPayload,
      })

      const secondToFirst = receiveNextDatagrams(firstClient)
      secondClient.sendDatagrams({
        endpointId: firstEndpointId,
        ecn: 3,
        segmentSize: 8,
        contents: secondPayload,
      })
      expect(await withTimeout(secondToFirst, 'second datagram relay')).toEqual({
        endpointId: secondEndpointId,
        ecn: 3,
        segmentSize: 8,
        contents: secondPayload,
      })
    } finally {
      firstClient?.close()
      secondClient?.close()
      await relay.stop()
    }
  })
})

async function receiveNextDatagrams(client: RelayWebSocketClient) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const frame = await client.receive()
    if (frame === null) {
      throw new Error('relay websocket closed before datagrams')
    }
    if (frame.type === 'datagrams') {
      return frame.datagrams
    }
  }
  throw new Error('relay did not deliver datagrams')
}

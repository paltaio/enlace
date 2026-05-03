import { describe, expect, test } from 'bun:test'

import { createEndpoint } from '@paltaio/iroh-lite'
import { IrohEndpoint } from '@paltaio/iroh-lite/endpoint'

import { startLocalIrohRelay } from '../testing/local-iroh-relay'

const alpn = new TextEncoder().encode('/paltaio/test')
const payload = new TextEncoder().encode('hello endpoint')

describe('public endpoint API', () => {
  test('exposes relay-only endpoint identity and protects address bytes', async () => {
    const relay = await startLocalIrohRelay()
    const endpoint = await createEndpoint({ relayUrl: relay.url })

    try {
      expect(endpoint).toBeInstanceOf(IrohEndpoint)
      expect(endpoint.endpointId).toHaveLength(32)
      expect(endpoint.relayUrl.toString()).toBe(new URL(relay.url).toString())

      const endpointId = endpoint.endpointId
      endpointId.fill(0)
      expect(endpoint.endpointId).not.toEqual(endpointId)

      const address = endpoint.address
      address.endpointId.fill(0)
      address.relayUrl.pathname = '/mutated'
      expect(endpoint.address.endpointId).not.toEqual(address.endpointId)
      expect(endpoint.address.relayUrl.toString()).toBe(new URL(relay.url).toString())
    } finally {
      endpoint.close()
      await relay.stop()
    }
  })

  test('falls back to the next relay URL when the first one is unavailable', async () => {
    const relay = await startLocalIrohRelay()
    const endpoint = await createEndpoint({ relayUrls: ['http://127.0.0.1:9', relay.url] })

    try {
      expect(endpoint.relayUrl.toString()).toBe(new URL(relay.url).toString())
    } finally {
      endpoint.close()
      await relay.stop()
    }
  })

  test('rejects empty relay URL lists', async () => {
    await expect(createEndpoint({ relayUrls: [] })).rejects.toThrow(
      'at least one relay URL is required',
    )
  })

  test('connects, accepts, and exchanges one bidi stream', async () => {
    const relay = await startLocalIrohRelay()
    const client = await createEndpoint({ relayUrl: relay.url })
    const server = await createEndpoint({ relayUrl: relay.url })

    try {
      const accepted = server.accept({ alpn })
      const clientConnection = await client.connect({
        address: server.address,
        alpn,
      })
      const serverConnection = await accepted
      expect(clientConnection.peerEndpointId).toEqual(server.endpointId)
      expect(serverConnection.peerEndpointId).toEqual(client.endpointId)

      const clientStream = clientConnection.openBidiStream()
      clientStream.write(payload, { fin: true })

      const serverStream = await serverConnection.acceptBidiStream()
      expect(await serverStream.readToEnd()).toEqual(payload)
      serverStream.write(payload, { fin: true })
      expect(await clientStream.readToEnd()).toEqual(payload)
    } finally {
      client.close()
      server.close()
      await relay.stop()
    }
  })
})

import { describe, expect, test } from 'bun:test'

import type { RelayBrowserWebSocket } from './client'
import { RelayAuthDeniedError, connectRelayWebSocket } from './client'
import { encodeClientToRelayFrame, encodeRelayToClientFrame } from './frames'
import {
  RELAY_SUBPROTOCOLS,
  encodeServerChallengeFrame,
  encodeServerConfirmsAuthFrame,
} from './handshake'
import { hexToBytes } from '../testing/hex'

const secretKey = hexToBytes('2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a')
const endpointId = hexToBytes('197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61')
const challenge = hexToBytes('07070707070707070707070707070707')
const clientAuth = hexToBytes(
  '01197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6140425fda43adca848e71a65ded8c4fb4f4434ca7f248aa6aec7c547ff96aa0b33bd3245943b407b12a9d8a55522f1bd07fa03180b01793ed572a8068bc49319205',
)
const helloWorld = new TextEncoder().encode('Hello World!')

class FakeWebSocket extends EventTarget implements RelayBrowserWebSocket {
  static instances: FakeWebSocket[] = []

  binaryType: 'blob' | 'arraybuffer' = 'blob'
  protocol = 'iroh-relay-v2'
  readyState = 0
  readonly url: string | URL
  readonly protocols: string | string[] | undefined
  readonly sent: Uint8Array[] = []

  constructor(url: string | URL, protocols?: string | string[]) {
    super()
    this.url = url
    this.protocols = protocols
    FakeWebSocket.instances.push(this)
  }

  send(data: string | ArrayBuffer | ArrayBufferView | Blob): void {
    if (typeof data === 'string' || data instanceof Blob) {
      throw new TypeError('fake websocket expects bytes')
    }
    if (data instanceof ArrayBuffer) {
      this.sent.push(new Uint8Array(data.slice(0)))
      return
    }
    const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    this.sent.push(new Uint8Array(bytes))
  }

  close(): void {
    this.readyState = 3
    this.dispatchEvent(new Event('close'))
  }

  open(): void {
    this.readyState = 1
    this.dispatchEvent(new Event('open'))
  }

  message(bytes: Uint8Array): void {
    const data = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
    this.dispatchEvent(new MessageEvent('message', { data }))
  }
}

function resetFakeSockets(): void {
  FakeWebSocket.instances = []
}

function latestSocket(): FakeWebSocket {
  const socket = FakeWebSocket.instances.at(-1)
  if (socket === undefined) {
    throw new Error('fake websocket was not created')
  }
  return socket
}

async function drainMicrotasks(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
}

async function connectWithServerHandshake(): Promise<{
  readonly client: Awaited<ReturnType<typeof connectRelayWebSocket>>
  readonly socket: FakeWebSocket
}> {
  resetFakeSockets()
  const connecting = connectRelayWebSocket({
    url: 'https://relay.example.com/ping?ignored=1',
    secretKey,
    WebSocket: FakeWebSocket,
  })
  const socket = latestSocket()
  socket.open()
  socket.message(encodeServerChallengeFrame({ challenge }))
  await drainMicrotasks()
  socket.message(encodeServerConfirmsAuthFrame())
  return { client: await connecting, socket }
}

describe('relay websocket connect', () => {
  test('connects to /relay with relay subprotocols and challenge auth', async () => {
    const { client, socket } = await connectWithServerHandshake()

    expect(socket.url.toString()).toBe('wss://relay.example.com/relay')
    expect(socket.protocols).toEqual([...RELAY_SUBPROTOCOLS])
    expect(socket.binaryType).toBe('arraybuffer')
    expect(socket.sent).toEqual([clientAuth])
    expect(client.protocol).toBe('iroh-relay-v2')
    expect(client.endpointId).toEqual(endpointId)
  })

  test('surfaces server auth denial reason', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'wss://relay.example.com/relay',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.message(encodeServerChallengeFrame({ challenge }))
    await drainMicrotasks()
    socket.message(hexToBytes('030e6e6f7420617574686f72697a6564'))

    await expect(connecting).rejects.toEqual(new RelayAuthDeniedError('not authorized'))
  })
})

describe('relay websocket frames', () => {
  test('replies to ping and exposes incoming pong', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()
    const pingData = new Uint8Array(8).fill(42)

    socket.message(encodeRelayToClientFrame({ type: 'ping', data: pingData }))
    await drainMicrotasks()
    expect(socket.sent.at(-1)).toEqual(encodeClientToRelayFrame({ type: 'pong', data: pingData }))

    socket.message(encodeRelayToClientFrame({ type: 'pong', data: pingData }))
    await expect(received).resolves.toEqual({ type: 'pong', data: pingData })
  })

  test('sends and receives datagrams as relay payloads', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const datagrams = { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld } as const

    client.sendDatagrams(datagrams)
    expect(socket.sent.at(-1)).toEqual(encodeClientToRelayFrame({ type: 'datagrams', datagrams }))

    const received = client.receive()
    socket.message(encodeRelayToClientFrame({ type: 'datagrams', datagrams }))
    await expect(received).resolves.toEqual({ type: 'datagrams', datagrams })
  })
})

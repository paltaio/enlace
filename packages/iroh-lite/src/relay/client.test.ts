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
const authDenied = hexToBytes('030e6e6f7420617574686f72697a6564')
const helloWorld = new TextEncoder().encode('Hello World!')

class FakeWebSocket extends EventTarget implements RelayBrowserWebSocket {
  static instances: FakeWebSocket[] = []

  binaryType: 'blob' | 'arraybuffer' = 'blob'
  protocol = 'iroh-relay-v2'
  readyState = 0
  readonly url: string | URL
  readonly protocols: string | string[] | null
  readonly sent: Uint8Array[] = []

  constructor(url: string | URL, protocols?: string | string[]) {
    super()
    this.url = url
    this.protocols = protocols ?? null
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

  close(_code?: number, _reason?: string): void {
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

  messageData(data: unknown): void {
    this.dispatchEvent(new MessageEvent('message', { data }))
  }

  fail(): void {
    this.dispatchEvent(new Event('error'))
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

async function waitForSent(socket: FakeWebSocket, count: number): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (socket.sent.length >= count) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  throw new Error('fake websocket did not send expected frame')
}

function rejectionReason(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => new Error('expected promise rejection'),
    (error: unknown) => error,
  )
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
    socket.message(authDenied)

    await expect(connecting).rejects.toEqual(new RelayAuthDeniedError('not authorized'))
  })

  test('rejects unsupported selected relay subprotocol', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.protocol = 'other-protocol'
    socket.open()

    await expect(connecting).rejects.toThrow(
      'relay selected unsupported subprotocol: other-protocol',
    )
    expect(socket.readyState).toBe(3)
  })

  test('rejects missing selected relay subprotocol', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.protocol = ''
    socket.open()

    await expect(connecting).rejects.toThrow('relay selected unsupported subprotocol: <none>')
    expect(socket.readyState).toBe(3)
  })

  test('rejects open failure and close before open', async () => {
    resetFakeSockets()
    const failedOpen = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    latestSocket().fail()
    await expect(failedOpen).rejects.toThrow('relay websocket failed to open')

    resetFakeSockets()
    const closedBeforeOpen = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    latestSocket().close()
    await expect(closedBeforeOpen).rejects.toThrow('relay websocket closed before open')
  })

  test('rejects close before server challenge', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.close()

    await expect(connecting).rejects.toThrow('relay websocket closed before server challenge')
  })

  test('rejects close before auth confirmation', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.message(encodeServerChallengeFrame({ challenge }))
    await waitForSent(socket, 1)
    socket.close()

    await expect(connecting).rejects.toThrow('relay websocket closed before auth confirmation')
    expect(socket.sent).toEqual([clientAuth])
  })

  test('does not send auth after close during auth creation', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.message(encodeServerChallengeFrame({ challenge }))
    socket.close()

    await expect(connecting).rejects.toThrow('relay websocket is not open')
    expect(socket.sent).toEqual([])
  })

  test('surfaces server auth denial before challenge', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.message(authDenied)

    await expect(connecting).rejects.toEqual(new RelayAuthDeniedError('not authorized'))
    expect(socket.sent).toEqual([])
  })

  test('rejects unexpected handshake frames', async () => {
    resetFakeSockets()
    const missingChallenge = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.message(encodeServerConfirmsAuthFrame())
    await expect(missingChallenge).rejects.toThrow(
      'unexpected relay handshake frame: server-confirms-auth',
    )

    resetFakeSockets()
    const missingConfirmation = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const nextSocket = latestSocket()
    nextSocket.open()
    nextSocket.message(encodeServerChallengeFrame({ challenge }))
    await drainMicrotasks()
    nextSocket.message(encodeServerChallengeFrame({ challenge }))
    await expect(missingConfirmation).rejects.toThrow(
      'unexpected relay handshake frame: server-challenge',
    )
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

  test('resolves pending receive with null on close', async () => {
    const { client } = await connectWithServerHandshake()
    const received = client.receive()

    client.close(1000, 'done')

    await expect(received).resolves.toBeNull()
  })

  test('resolves all pending and future receives with null on close', async () => {
    const { client } = await connectWithServerHandshake()
    const first = client.receive()
    const second = client.receive()

    client.close()

    await expect(first).resolves.toBeNull()
    await expect(second).resolves.toBeNull()
    await expect(client.receive()).resolves.toBeNull()
  })

  test('does not pong a queued ping after close', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.message(encodeRelayToClientFrame({ type: 'ping', data: new Uint8Array(8) }))
    socket.close()

    await expect(received).resolves.toBeNull()
    expect(socket.sent).toEqual([clientAuth])
  })

  test('delivers binary message that arrives before close', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()
    const datagrams = { endpointId, ecn: null, contents: helloWorld } as const

    socket.message(encodeRelayToClientFrame({ type: 'datagrams', datagrams }))
    socket.close()

    await expect(received).resolves.toEqual({ type: 'datagrams', datagrams })
    await expect(client.receive()).resolves.toBeNull()
  })

  test('rejects pending receive on websocket error', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.fail()

    await expect(received).rejects.toThrow('relay websocket error')
  })

  test('rejects all pending and future receives on websocket error', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const first = client.receive()
    const second = client.receive()
    const firstRejected = rejectionReason(first)
    const secondRejected = rejectionReason(second)

    socket.fail()

    for (const error of await Promise.all([firstRejected, secondRejected])) {
      expect(error).toBeInstanceOf(Error)
      if (error instanceof Error) {
        expect(error.message).toBe('relay websocket error')
      }
    }
    await expect(client.receive()).rejects.toThrow('relay websocket error')
  })

  test('rejects non-binary websocket messages', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.messageData('text frame')

    await expect(received).rejects.toThrow('relay websocket message must be binary')
  })

  test('throws when sending after close', async () => {
    const { client } = await connectWithServerHandshake()

    client.close()

    expect(() => client.sendPing(new Uint8Array(8))).toThrow('relay websocket is not open')
    expect(() => client.sendPong(new Uint8Array())).toThrow('relay websocket is not open')
    expect(() =>
      client.sendDatagrams({
        endpointId: new Uint8Array(),
        ecn: null,
        contents: new Uint8Array(),
      }),
    ).toThrow('relay websocket is not open')
  })

  test('validates outgoing frames while open', async () => {
    const { client } = await connectWithServerHandshake()

    expect(() => client.sendPing(new Uint8Array())).toThrow('ping/pong payload must be 8 bytes')
  })
})

import { describe, expect, test } from 'bun:test'

import type { RelayBrowserWebSocket } from './client'
import { RelayAuthDeniedError, RelayConnectAbortedError, connectRelayWebSocket } from './client'
import { challengeMessageToSign, decodeHandshakeFrame } from './handshake'
import {
  MAX_FRAME_SIZE,
  decodeClientToRelayFrame,
  encodeClientToRelayFrame,
  encodeRelayToClientFrame,
} from './frames'
import {
  RELAY_SUBPROTOCOLS,
  encodeServerChallengeFrame,
  encodeServerConfirmsAuthFrame,
} from './handshake'
import { verify } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'

const secretKey = hexToBytes('2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a')
const secondSecretKey = hexToBytes(
  '4343434343434343434343434343434343434343434343434343434343434343',
)
const endpointId = hexToBytes('197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61')
const secondEndpointId = hexToBytes(
  '22fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6',
)
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

function bunWebSocketMessageBytes(message: string | ArrayBufferView): Uint8Array {
  if (typeof message === 'string') {
    throw new TypeError('relay server expected bytes')
  }
  return new Uint8Array(
    message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength),
  )
}

function deferred<T>(): {
  readonly promise: Promise<T>
  readonly resolve: (value: T) => void
  readonly reject: (reason: unknown) => void
} {
  let resolveFn: ((value: T) => void) | null = null
  let rejectFn: ((reason: unknown) => void) | null = null
  const promise = new Promise<T>((resolve, reject) => {
    resolveFn = resolve
    rejectFn = reject
  })
  if (resolveFn === null || rejectFn === null) {
    throw new Error('deferred promise was not initialized')
  }
  return { promise, resolve: resolveFn, reject: rejectFn }
}

async function withTestTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | null = null
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`${label} timed out`))
    }, 500)
  })
  try {
    return await Promise.race([promise, timeout])
  } finally {
    if (timeoutId !== null) {
      clearTimeout(timeoutId)
    }
  }
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

    expect(await rejectionReason(connecting)).toEqual(new RelayAuthDeniedError('not authorized'))
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

    expect(await rejectionReason(connecting)).toEqual(
      new Error('relay selected unsupported subprotocol: other-protocol'),
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

    expect(await rejectionReason(connecting)).toEqual(
      new Error('relay selected unsupported subprotocol: <none>'),
    )
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
    expect(await rejectionReason(failedOpen)).toEqual(new Error('relay websocket failed to open'))

    resetFakeSockets()
    const closedBeforeOpen = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    latestSocket().close()
    expect(await rejectionReason(closedBeforeOpen)).toEqual(
      new Error('relay websocket closed before open'),
    )
  })

  test('rejects aborted connect before opening websocket', async () => {
    resetFakeSockets()
    const controller = new AbortController()
    controller.abort()

    expect(
      await rejectionReason(
        connectRelayWebSocket({
          url: 'https://relay.example.com',
          secretKey,
          signal: controller.signal,
          WebSocket: FakeWebSocket,
        }),
      ),
    ).toEqual(new RelayConnectAbortedError())
    expect(FakeWebSocket.instances).toEqual([])
  })

  test('rejects aborted connect while opening websocket', async () => {
    resetFakeSockets()
    const controller = new AbortController()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      signal: controller.signal,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()

    controller.abort()

    expect(await rejectionReason(connecting)).toEqual(new RelayConnectAbortedError())
    expect(socket.readyState).toBe(3)
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

    expect(await rejectionReason(connecting)).toEqual(
      new Error('relay websocket closed before server challenge'),
    )
  })

  test('rejects aborted connect while waiting for server challenge', async () => {
    resetFakeSockets()
    const controller = new AbortController()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      signal: controller.signal,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()

    controller.abort()

    expect(await rejectionReason(connecting)).toEqual(new RelayConnectAbortedError())
    expect(socket.readyState).toBe(3)
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

    expect(await rejectionReason(connecting)).toEqual(
      new Error('relay websocket closed before auth confirmation'),
    )
    expect(socket.sent).toEqual([clientAuth])
  })

  test('rejects aborted connect before auth confirmation', async () => {
    resetFakeSockets()
    const controller = new AbortController()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      signal: controller.signal,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.open()
    socket.message(encodeServerChallengeFrame({ challenge }))
    await waitForSent(socket, 1)

    controller.abort()

    expect(await rejectionReason(connecting)).toEqual(new RelayConnectAbortedError())
    expect(socket.sent).toEqual([clientAuth])
    expect(socket.readyState).toBe(3)
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

    expect(await rejectionReason(connecting)).toEqual(new Error('relay websocket is not open'))
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

    expect(await rejectionReason(connecting)).toEqual(new RelayAuthDeniedError('not authorized'))
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
    expect(await rejectionReason(missingChallenge)).toEqual(
      new Error('unexpected relay handshake frame: server-confirms-auth'),
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
    expect(await rejectionReason(missingConfirmation)).toEqual(
      new Error('unexpected relay handshake frame: server-challenge'),
    )
  })
})

describe('relay websocket integration', () => {
  test('connects through a real websocket upgrade path', async () => {
    const pingData = new Uint8Array(8).fill(9)
    const clientDatagrams = { endpointId, ecn: 2, contents: helloWorld } as const
    const relayDatagrams = { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld } as const
    const authBytes = deferred<Uint8Array>()
    const pongFrame = deferred<ReturnType<typeof decodeClientToRelayFrame>>()
    const datagramsFrame = deferred<ReturnType<typeof decodeClientToRelayFrame>>()
    const protocolHeader = deferred<string | null>()

    const server = Bun.serve<{ confirmed: boolean }>({
      hostname: '127.0.0.1',
      port: 0,
      fetch(request, server) {
        const url = new URL(request.url)
        if (url.pathname !== '/relay') {
          return new Response('not found', { status: 404 })
        }
        protocolHeader.resolve(request.headers.get('sec-websocket-protocol'))
        const upgraded = server.upgrade(request, {
          headers: { 'Sec-WebSocket-Protocol': 'iroh-relay-v2' },
          data: { confirmed: false },
        })
        if (upgraded) {
          return
        }
        return new Response('upgrade failed', { status: 400 })
      },
      websocket: {
        open(ws) {
          ws.send(encodeServerChallengeFrame({ challenge }))
        },
        message(ws, message) {
          try {
            const bytes = bunWebSocketMessageBytes(message)
            if (!ws.data.confirmed) {
              ws.data.confirmed = true
              authBytes.resolve(bytes)
              ws.send(encodeServerConfirmsAuthFrame())
              setTimeout(() => {
                ws.send(encodeRelayToClientFrame({ type: 'ping', data: pingData }))
              }, 0)
              return
            }

            const frame = decodeClientToRelayFrame(bytes)
            if (frame.type === 'pong') {
              pongFrame.resolve(frame)
              ws.send(encodeRelayToClientFrame({ type: 'datagrams', datagrams: relayDatagrams }))
              return
            }
            datagramsFrame.resolve(frame)
            setTimeout(() => {
              ws.close(1000, 'done')
            }, 0)
          } catch (error) {
            authBytes.reject(error)
            pongFrame.reject(error)
            datagramsFrame.reject(error)
            ws.close(1011, 'test failure')
          }
        },
      },
    })

    try {
      const client = await withTestTimeout(
        connectRelayWebSocket({
          url: `${server.url}ignored?query=removed`,
          secretKey,
        }),
        'connect',
      )

      expect(await withTestTimeout(protocolHeader.promise, 'protocol header')).toBe(
        'iroh-relay-v2, iroh-relay-v1',
      )
      expect(await withTestTimeout(authBytes.promise, 'auth')).toEqual(clientAuth)
      const expectedClientUrl = new URL(server.url)
      expectedClientUrl.protocol = 'ws:'
      expectedClientUrl.pathname = '/relay'
      expect(client.url.toString()).toBe(expectedClientUrl.toString())
      expect(client.protocol).toBe('iroh-relay-v2')
      expect(client.endpointId).toEqual(endpointId)

      const received = client.receive()
      expect(await withTestTimeout(pongFrame.promise, 'pong')).toEqual({
        type: 'pong',
        data: pingData,
      })
      expect(await received).toEqual({ type: 'datagrams', datagrams: relayDatagrams })

      const closed = client.receive()
      client.sendDatagrams(clientDatagrams)
      expect(await withTestTimeout(datagramsFrame.promise, 'datagrams')).toEqual({
        type: 'datagrams',
        datagrams: clientDatagrams,
      })
      expect(await withTestTimeout(closed, 'close')).toBeNull()
      client.close()
    } finally {
      void server.stop(true)
    }
  })

  test('routes datagrams between two relay clients', async () => {
    type RelayPeerData = {
      endpointId: Uint8Array | null
    }

    const firstPayload = new TextEncoder().encode('from first client')
    const secondPayload = new TextEncoder().encode('from second client')
    const peers = new Map<string, Bun.ServerWebSocket<RelayPeerData>>()
    const authFrames = deferred<Uint8Array[]>()
    const protocolHeaders: (string | null)[] = []
    const authenticated: Uint8Array[] = []

    const server = Bun.serve<RelayPeerData>({
      hostname: '127.0.0.1',
      port: 0,
      fetch(request, server) {
        const url = new URL(request.url)
        if (url.pathname !== '/relay') {
          return new Response('not found', { status: 404 })
        }
        protocolHeaders.push(request.headers.get('sec-websocket-protocol'))
        const upgraded = server.upgrade(request, {
          headers: { 'Sec-WebSocket-Protocol': 'iroh-relay-v2' },
          data: { endpointId: null },
        })
        if (upgraded) {
          return
        }
        return new Response('upgrade failed', { status: 400 })
      },
      websocket: {
        open(ws) {
          ws.send(encodeServerChallengeFrame({ challenge }))
        },
        async message(ws, message) {
          try {
            const bytes = bunWebSocketMessageBytes(message)
            if (ws.data.endpointId === null) {
              const frame = decodeHandshakeFrame(bytes)
              if (frame.type !== 'client-auth') {
                throw new Error(`expected client auth, got ${frame.type}`)
              }
              const verified = await verify(
                frame.auth.endpointId,
                challengeMessageToSign(challenge),
                frame.auth.signature,
              )
              if (!verified) {
                throw new Error('client auth signature did not verify')
              }
              ws.data.endpointId = frame.auth.endpointId
              authenticated.push(bytes)
              peers.set(bytesToHex(frame.auth.endpointId), ws)
              if (authenticated.length === 2) {
                authFrames.resolve(authenticated)
              }
              ws.send(encodeServerConfirmsAuthFrame())
              return
            }

            const frame = decodeClientToRelayFrame(bytes)
            if (frame.type !== 'datagrams') {
              throw new Error(`expected datagrams, got ${frame.type}`)
            }
            const recipient = peers.get(bytesToHex(frame.datagrams.endpointId))
            if (recipient === undefined) {
              throw new Error('missing relay recipient')
            }
            const forwardedDatagrams =
              frame.datagrams.segmentSize === undefined
                ? {
                    endpointId: ws.data.endpointId,
                    ecn: frame.datagrams.ecn,
                    contents: frame.datagrams.contents,
                  }
                : {
                    endpointId: ws.data.endpointId,
                    ecn: frame.datagrams.ecn,
                    segmentSize: frame.datagrams.segmentSize,
                    contents: frame.datagrams.contents,
                  }
            recipient.send(
              encodeRelayToClientFrame({
                type: 'datagrams',
                datagrams: forwardedDatagrams,
              }),
            )
          } catch (error) {
            authFrames.reject(error)
            ws.close(1011, 'test failure')
          }
        },
      },
    })

    try {
      const firstClientPromise = connectRelayWebSocket({ url: server.url, secretKey })
      const secondClientPromise = connectRelayWebSocket({
        url: server.url,
        secretKey: secondSecretKey,
      })
      const [firstClient, secondClient] = await withTestTimeout(
        Promise.all([firstClientPromise, secondClientPromise]),
        'connect clients',
      )

      expect(protocolHeaders).toEqual([
        'iroh-relay-v2, iroh-relay-v1',
        'iroh-relay-v2, iroh-relay-v1',
      ])
      const receivedAuthFrames = await withTestTimeout(authFrames.promise, 'auth frames')
      expect(receivedAuthFrames).toHaveLength(2)
      const [firstAuth, secondAuth] = receivedAuthFrames
      if (firstAuth === undefined || secondAuth === undefined) {
        throw new Error('missing auth frame')
      }
      const secondAuthFrame = decodeHandshakeFrame(secondAuth)
      expect(firstAuth).toEqual(clientAuth)
      if (secondAuthFrame.type !== 'client-auth') {
        throw new Error(`expected second client auth, got ${secondAuthFrame.type}`)
      }
      expect(secondAuthFrame.auth.endpointId).toEqual(secondEndpointId)
      expect(secondAuthFrame.auth.signature).toHaveLength(64)
      expect(firstClient.endpointId).toEqual(endpointId)
      expect(secondClient.endpointId).toEqual(secondEndpointId)

      const fromFirst = secondClient.receive()
      firstClient.sendDatagrams({
        endpointId: secondEndpointId,
        ecn: 1,
        contents: firstPayload,
      })
      expect(await withTestTimeout(fromFirst, 'first datagram')).toEqual({
        type: 'datagrams',
        datagrams: {
          endpointId,
          ecn: 1,
          contents: firstPayload,
        },
      })

      const fromSecond = firstClient.receive()
      secondClient.sendDatagrams({
        endpointId,
        ecn: 3,
        segmentSize: 7,
        contents: secondPayload,
      })
      expect(await withTestTimeout(fromSecond, 'second datagram')).toEqual({
        type: 'datagrams',
        datagrams: {
          endpointId: secondEndpointId,
          ecn: 3,
          segmentSize: 7,
          contents: secondPayload,
        },
      })

      firstClient.close()
      secondClient.close()
    } finally {
      void server.stop(true)
    }
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
    expect(await received).toEqual({ type: 'pong', data: pingData })
  })

  test('decodes frames using selected relay subprotocol', async () => {
    resetFakeSockets()
    const connecting = connectRelayWebSocket({
      url: 'https://relay.example.com',
      secretKey,
      WebSocket: FakeWebSocket,
    })
    const socket = latestSocket()
    socket.protocol = 'iroh-relay-v1'
    socket.open()
    socket.message(encodeServerChallengeFrame({ challenge }))
    await drainMicrotasks()
    socket.message(encodeServerConfirmsAuthFrame())
    const client = await connecting

    const received = client.receive()
    socket.message(encodeRelayToClientFrame({ type: 'health', problem: 'warming up' }))

    expect(client.protocol).toBe('iroh-relay-v1')
    expect(await received).toEqual({ type: 'health', problem: 'warming up' })
  })

  test('sends and receives datagrams as relay payloads', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const datagrams = { endpointId, ecn: 3, segmentSize: 6, contents: helloWorld } as const

    client.sendDatagrams(datagrams)
    expect(socket.sent.at(-1)).toEqual(encodeClientToRelayFrame({ type: 'datagrams', datagrams }))

    const received = client.receive()
    socket.message(encodeRelayToClientFrame({ type: 'datagrams', datagrams }))
    expect(await received).toEqual({ type: 'datagrams', datagrams })
  })

  test('resolves pending receive with null on close', async () => {
    const { client } = await connectWithServerHandshake()
    const received = client.receive()

    client.close(1000, 'done')

    expect(await received).toBeNull()
  })

  test('resolves all pending and future receives with null on close', async () => {
    const { client } = await connectWithServerHandshake()
    const first = client.receive()
    const second = client.receive()

    client.close()

    expect(await first).toBeNull()
    expect(await second).toBeNull()
    expect(await client.receive()).toBeNull()
  })

  test('does not pong a queued ping after close', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.message(encodeRelayToClientFrame({ type: 'ping', data: new Uint8Array(8) }))
    socket.close()

    expect(await received).toBeNull()
    expect(socket.sent).toEqual([clientAuth])
  })

  test('delivers binary message that arrives before close', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()
    const datagrams = { endpointId, ecn: null, contents: helloWorld } as const

    socket.message(encodeRelayToClientFrame({ type: 'datagrams', datagrams }))
    socket.close()

    expect(await received).toEqual({ type: 'datagrams', datagrams })
    expect(await client.receive()).toBeNull()
  })

  test('rejects pending receive on websocket error', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.fail()

    expect(await rejectionReason(received)).toEqual(new Error('relay websocket error'))
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
    expect(await rejectionReason(client.receive())).toEqual(new Error('relay websocket error'))
  })

  test('rejects non-binary websocket messages', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.messageData('text frame')

    expect(await rejectionReason(received)).toEqual(
      new TypeError('relay websocket message must be binary'),
    )
  })

  test('rejects websocket messages over frame limit', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.messageData(new Uint8Array(MAX_FRAME_SIZE + 1))

    expect(await rejectionReason(received)).toEqual(
      new RangeError(`relay websocket message exceeds ${MAX_FRAME_SIZE} bytes`),
    )
  })

  test('rejects blobs over frame limit', async () => {
    const { client, socket } = await connectWithServerHandshake()
    const received = client.receive()

    socket.messageData(new Blob([new Uint8Array(MAX_FRAME_SIZE + 1)]))

    expect(await rejectionReason(received)).toEqual(
      new RangeError(`relay websocket message exceeds ${MAX_FRAME_SIZE} bytes`),
    )
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
    expect(() =>
      client.sendDatagrams({
        endpointId,
        ecn: null,
        contents: new Uint8Array(),
      }),
    ).toThrow('relay datagram contents must not be empty')
  })
})

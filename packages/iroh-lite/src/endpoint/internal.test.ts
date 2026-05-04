import { describe, expect, test } from 'bun:test'

import { ReconnectingRelayTransport } from './internal'
import { connectRelayWebSocket, type RelayBrowserWebSocket } from '../relay/client'
import { encodeRelayToClientFrame } from '../relay/frames'
import { encodeServerChallengeFrame, encodeServerConfirmsAuthFrame } from '../relay/handshake'
import { decodeClientToRelayFrame } from '../relay/frames'
import { hexToBytes } from '../testing/hex'

const secretKey = hexToBytes('2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a')
const endpointId = hexToBytes('197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61')
const challenge = hexToBytes('07070707070707070707070707070707')
const payload = new TextEncoder().encode('relay data')

class FakeWebSocket extends EventTarget implements RelayBrowserWebSocket {
  static instances: FakeWebSocket[] = []

  binaryType: 'blob' | 'arraybuffer' = 'blob'
  protocol = 'iroh-relay-v2'
  readyState = 0
  readonly sent: Uint8Array[] = []

  constructor(
    readonly url: string | URL,
    readonly protocols?: string | string[],
  ) {
    super()
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
}

describe('reconnecting relay transport', () => {
  test('reconnects after websocket close and receives frames on the new socket', async () => {
    FakeWebSocket.instances = []
    const initialClient = await connectClient()
    const firstSocket = latestSocket()
    const transport = new ReconnectingRelayTransport({
      connectOptions: {
        url: 'https://relay.example.com',
        secretKey,
        WebSocket: FakeWebSocket,
      },
      endpointId,
      initialClient,
    })

    const received = transport.receive()
    firstSocket.close()
    await waitForSocketCount(2)
    const secondSocket = latestSocket()
    completeHandshake(secondSocket)
    await waitForSentFrame(secondSocket, 'ping')

    const datagrams = { endpointId, ecn: 3, segmentSize: payload.length, contents: payload } as const
    secondSocket.message(encodeRelayToClientFrame({ type: 'datagrams', datagrams }))

    expect(await withTestTimeout(received, 'reconnected receive')).toEqual({
      type: 'datagrams',
      datagrams,
    })
    transport.close()
  })
})

async function connectClient(): Promise<Awaited<ReturnType<typeof connectRelayWebSocket>>> {
  const connecting = connectRelayWebSocket({
    url: 'https://relay.example.com',
    secretKey,
    WebSocket: FakeWebSocket,
  })
  completeHandshake(latestSocket())
  return await connecting
}

function completeHandshake(socket: FakeWebSocket): void {
  socket.open()
  socket.message(encodeServerChallengeFrame({ challenge }))
  socket.message(encodeServerConfirmsAuthFrame())
}

function latestSocket(): FakeWebSocket {
  const socket = FakeWebSocket.instances.at(-1)
  if (socket === undefined) {
    throw new Error('fake websocket was not created')
  }
  return socket
}

async function waitForSocketCount(count: number): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (FakeWebSocket.instances.length >= count) {
      return
    }
    await sleep(0)
  }
  throw new Error('fake websocket was not created')
}

async function waitForSentFrame(socket: FakeWebSocket, type: 'ping'): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (socket.sent.some((frame) => isClientFrameType(frame, type))) {
      return
    }
    await sleep(0)
  }
  throw new Error('fake websocket did not send expected frame')
}

function isClientFrameType(frame: Uint8Array, type: 'ping'): boolean {
  try {
    return decodeClientToRelayFrame(frame).type === type
  } catch {
    return false
  }
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

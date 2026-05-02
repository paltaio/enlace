import { copyBytes } from '../bytes'
import type { Datagrams, RelayFrame } from './frames'
import { MAX_FRAME_SIZE, decodeRelayToClientFrame, encodeClientToRelayFrame } from './frames'
import {
  RELAY_SUBPROTOCOLS,
  createClientAuth,
  decodeHandshakeFrame,
  encodeClientAuth,
  relayHttpUrlToWebSocketUrl,
} from './handshake'

const WEBSOCKET_CONNECTING = 0
const WEBSOCKET_OPEN = 1
const WEBSOCKET_CLOSING = 2
const WEBSOCKET_CLOSED = 3

export type RelayProtocolVersion = (typeof RELAY_SUBPROTOCOLS)[number]
export type RelayWebSocketReceiveFrame = Exclude<RelayFrame, { readonly type: 'ping' }>

export interface RelayBrowserWebSocket {
  binaryType: 'blob' | 'arraybuffer'
  readonly protocol: string
  readonly readyState: number
  send(data: string | ArrayBuffer | ArrayBufferView | Blob): void
  close(code?: number, reason?: string): void
  addEventListener(
    type: string,
    listener: EventListener,
    options?: boolean | AddEventListenerOptions,
  ): void
  removeEventListener(
    type: string,
    listener: EventListener,
    options?: boolean | EventListenerOptions,
  ): void
}

export interface RelayWebSocketConstructor {
  new (url: string | URL, protocols?: string | string[]): RelayBrowserWebSocket
}

export interface ConnectRelayWebSocketOptions {
  readonly url: string | URL
  readonly secretKey: Uint8Array
  readonly WebSocket?: RelayWebSocketConstructor
}

export class RelayAuthDeniedError extends Error {
  readonly reason: string

  constructor(reason: string) {
    super(`relay denied authentication: ${reason}`)
    this.name = 'RelayAuthDeniedError'
    this.reason = reason
  }
}

type ReaderItem = Uint8Array | null | Error
interface TerminalReaderItem {
  readonly item: ReaderItem
}

class RelayWebSocketReader {
  private readonly socket: RelayBrowserWebSocket
  private readonly queue: ReaderItem[] = []
  private readonly waiters: ((item: ReaderItem) => void)[] = []
  private readonly onMessage: EventListener
  private readonly onError: EventListener
  private readonly onClose: EventListener
  private terminal: TerminalReaderItem | null = null

  constructor(socket: RelayBrowserWebSocket) {
    this.socket = socket
    this.onMessage = (event) => {
      this.acceptMessage(event)
    }
    this.onError = () => {
      this.finish(new Error('relay websocket error'))
    }
    this.onClose = () => {
      this.finish(null)
    }
    socket.addEventListener('message', this.onMessage)
    socket.addEventListener('error', this.onError)
    socket.addEventListener('close', this.onClose)
  }

  read(): Promise<Uint8Array | null> {
    const item = this.queue.shift()
    if (item !== undefined) {
      if (item instanceof Error) {
        return Promise.reject(item)
      }
      return Promise.resolve(item)
    }
    if (this.terminal !== null) {
      if (this.terminal.item instanceof Error) {
        return Promise.reject(this.terminal.item)
      }
      return Promise.resolve(this.terminal.item)
    }
    return new Promise((resolve, reject) => {
      this.waiters.push((next) => {
        if (next instanceof Error) {
          reject(next)
        } else {
          resolve(next)
        }
      })
    })
  }

  dispose(): void {
    this.socket.removeEventListener('message', this.onMessage)
    this.socket.removeEventListener('error', this.onError)
    this.socket.removeEventListener('close', this.onClose)
    this.finish(null)
  }

  private acceptMessage(event: Event): void {
    try {
      const bytes = messageEventBytes(event)
      if (bytes instanceof Promise) {
        void bytes.then(
          (resolved) => {
            this.push(resolved)
          },
          (error: unknown) => {
            this.push(error instanceof Error ? error : new Error(String(error)))
          },
        )
        return
      }
      this.push(bytes)
    } catch (error) {
      this.push(error instanceof Error ? error : new Error(String(error)))
    }
  }

  private finish(item: ReaderItem): void {
    if (this.terminal !== null) {
      return
    }
    this.terminal = { item }
    for (const waiter of this.waiters.splice(0)) {
      waiter(item)
    }
  }

  private push(item: ReaderItem): void {
    if (this.terminal !== null) {
      return
    }
    const waiter = this.waiters.shift()
    if (waiter === undefined) {
      this.queue.push(item)
      return
    }
    waiter(item)
  }
}

export class RelayWebSocketClient {
  readonly url: URL
  readonly protocol: RelayProtocolVersion
  readonly endpointId: Uint8Array
  private readonly socket: RelayBrowserWebSocket
  private readonly reader: RelayWebSocketReader

  constructor(
    socket: RelayBrowserWebSocket,
    reader: RelayWebSocketReader,
    url: URL,
    protocol: RelayProtocolVersion,
    endpointId: Uint8Array,
  ) {
    this.socket = socket
    this.reader = reader
    this.url = new URL(url)
    this.protocol = protocol
    this.endpointId = copyBytes(endpointId)
  }

  async receive(): Promise<RelayWebSocketReceiveFrame | null> {
    while (true) {
      const bytes = await this.reader.read()
      if (bytes === null) {
        return null
      }
      const frame = decodeRelayToClientFrame(bytes, this.protocol)
      if (frame.type !== 'ping') {
        return frame
      }
      if (this.socket.readyState === WEBSOCKET_OPEN) {
        this.sendPong(frame.data)
      }
    }
  }

  sendDatagrams(datagrams: Datagrams): void {
    this.assertOpen()
    this.sendFrame(encodeClientToRelayFrame({ type: 'datagrams', datagrams }))
  }

  sendPing(data: Uint8Array): void {
    this.assertOpen()
    this.sendFrame(encodeClientToRelayFrame({ type: 'ping', data }))
  }

  sendPong(data: Uint8Array): void {
    this.assertOpen()
    this.sendFrame(encodeClientToRelayFrame({ type: 'pong', data }))
  }

  close(code?: number, reason?: string): void {
    this.socket.close(code, reason)
    this.reader.dispose()
  }

  private assertOpen(): void {
    if (this.socket.readyState !== WEBSOCKET_OPEN) {
      throw new Error('relay websocket is not open')
    }
  }

  private sendFrame(frame: Uint8Array): void {
    sendSocketFrame(this.socket, frame)
  }
}

export async function connectRelayWebSocket(
  options: ConnectRelayWebSocketOptions,
): Promise<RelayWebSocketClient> {
  const url = relayHttpUrlToWebSocketUrl(options.url)
  const WebSocketCtor = options.WebSocket ?? defaultWebSocketConstructor()
  const socket = new WebSocketCtor(url, [...RELAY_SUBPROTOCOLS])
  socket.binaryType = 'arraybuffer'

  const reader = new RelayWebSocketReader(socket)
  try {
    await waitForOpen(socket)
    const protocol = parseRelayProtocol(socket.protocol)
    const challenge = await readServerChallenge(reader)
    const auth = await createClientAuth(options.secretKey, { challenge })
    sendSocketFrame(socket, encodeClientAuth(auth))
    await readServerConfirmation(reader)
    return new RelayWebSocketClient(socket, reader, url, protocol, auth.endpointId)
  } catch (error) {
    reader.dispose()
    closeQuietly(socket)
    throw error
  }
}

async function readServerChallenge(reader: RelayWebSocketReader): Promise<Uint8Array> {
  const bytes = await reader.read()
  if (bytes === null) {
    throw new Error('relay websocket closed before server challenge')
  }
  const frame = decodeHandshakeFrame(bytes)
  if (frame.type === 'server-challenge') {
    return frame.challenge
  }
  if (frame.type === 'server-denies-auth') {
    throw new RelayAuthDeniedError(frame.reason)
  }
  throw new Error(`unexpected relay handshake frame: ${frame.type}`)
}

async function readServerConfirmation(reader: RelayWebSocketReader): Promise<void> {
  const bytes = await reader.read()
  if (bytes === null) {
    throw new Error('relay websocket closed before auth confirmation')
  }
  const frame = decodeHandshakeFrame(bytes)
  if (frame.type === 'server-confirms-auth') {
    return
  }
  if (frame.type === 'server-denies-auth') {
    throw new RelayAuthDeniedError(frame.reason)
  }
  throw new Error(`unexpected relay handshake frame: ${frame.type}`)
}

function defaultWebSocketConstructor(): RelayWebSocketConstructor {
  const WebSocketCtor = globalThis.WebSocket
  if (WebSocketCtor === undefined) {
    throw new Error('global WebSocket constructor is not available')
  }
  return WebSocketCtor
}

function parseRelayProtocol(protocol: string): RelayProtocolVersion {
  for (const supported of RELAY_SUBPROTOCOLS) {
    if (protocol === supported) {
      return supported
    }
  }
  const selected = protocol.length === 0 ? '<none>' : protocol
  throw new Error(`relay selected unsupported subprotocol: ${selected}`)
}

function waitForOpen(socket: RelayBrowserWebSocket): Promise<void> {
  if (socket.readyState === WEBSOCKET_OPEN) {
    return Promise.resolve()
  }
  if (socket.readyState === WEBSOCKET_CLOSING || socket.readyState === WEBSOCKET_CLOSED) {
    return Promise.reject(new Error('relay websocket is already closed'))
  }
  if (socket.readyState !== WEBSOCKET_CONNECTING) {
    return Promise.reject(new Error('relay websocket is in an invalid state'))
  }

  return new Promise((resolve, reject) => {
    const cleanup = (): void => {
      socket.removeEventListener('open', onOpen)
      socket.removeEventListener('error', onError)
      socket.removeEventListener('close', onClose)
    }
    const onOpen = (): void => {
      cleanup()
      resolve()
    }
    const onError = (): void => {
      cleanup()
      reject(new Error('relay websocket failed to open'))
    }
    const onClose = (): void => {
      cleanup()
      reject(new Error('relay websocket closed before open'))
    }
    socket.addEventListener('open', onOpen)
    socket.addEventListener('error', onError)
    socket.addEventListener('close', onClose)
  })
}

function closeQuietly(socket: RelayBrowserWebSocket): void {
  try {
    socket.close()
  } catch {
    // Ignore close failures while surfacing the original connection error.
  }
}

function sendSocketFrame(socket: RelayBrowserWebSocket, frame: Uint8Array): void {
  if (socket.readyState !== WEBSOCKET_OPEN) {
    throw new Error('relay websocket is not open')
  }
  socket.send(frame)
}

function messageEventBytes(event: Event): Uint8Array | Promise<Uint8Array> {
  if (!('data' in event)) {
    throw new TypeError('websocket message event has no data')
  }
  const data = event.data
  if (data instanceof ArrayBuffer) {
    assertWebSocketMessageSize(data.byteLength)
    return new Uint8Array(data.slice(0))
  }
  if (data instanceof Uint8Array) {
    assertWebSocketMessageSize(data.byteLength)
    return copyBytes(data)
  }
  if (ArrayBuffer.isView(data)) {
    assertWebSocketMessageSize(data.byteLength)
    const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    return copyBytes(bytes)
  }
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    assertWebSocketMessageSize(data.size)
    return data.arrayBuffer().then((buffer) => {
      assertWebSocketMessageSize(buffer.byteLength)
      return new Uint8Array(buffer)
    })
  }
  throw new TypeError('relay websocket message must be binary')
}

function assertWebSocketMessageSize(size: number): void {
  if (size > MAX_FRAME_SIZE) {
    throw new RangeError(`relay websocket message exceeds ${MAX_FRAME_SIZE} bytes`)
  }
}

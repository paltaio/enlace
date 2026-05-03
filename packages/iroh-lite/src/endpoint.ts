import { copyBytes } from './bytes'
import { validateEndpointId } from './crypto/ed25519'
import {
  BidiStream as InternalBidiStream,
  Connection as InternalConnection,
  Endpoint as InternalEndpoint,
  UniStream as InternalUniStream,
  type BidiStreamWriteOptions,
  type EndpointCreateRelayOnlyOptions,
} from './endpoint/internal'
import type { QuicStreamReceiveOutput } from './quic/streams'
import type { RelayWebSocketConstructor } from './relay/client'
import type { RelayUrlInput } from './relay/url'

export interface IrohEndpointBaseOptions {
  readonly secretKey?: Uint8Array
  readonly WebSocket?: RelayWebSocketConstructor
}

export interface IrohEndpointRelayUrlOptions extends IrohEndpointBaseOptions {
  readonly relayUrl: RelayUrlInput
  readonly relayUrls?: never
}

export interface IrohEndpointRelayUrlsOptions extends IrohEndpointBaseOptions {
  readonly relayUrl?: never
  readonly relayUrls: readonly RelayUrlInput[]
}

export type IrohEndpointOptions = IrohEndpointRelayUrlOptions | IrohEndpointRelayUrlsOptions

export interface IrohEndpointAddress {
  readonly endpointId: Uint8Array
  readonly relayUrl: URL
}

export interface IrohEndpointConnectOptions {
  readonly address: IrohEndpointAddress
  readonly alpn: Uint8Array
}

export interface IrohEndpointAcceptOptions {
  readonly alpn: Uint8Array
}

export interface IrohStreamRead {
  readonly data: Uint8Array
  readonly complete: boolean
}

export async function createEndpoint(options: IrohEndpointOptions): Promise<IrohEndpoint> {
  const failures: string[] = []
  for (const relayUrl of relayUrlCandidates(options)) {
    try {
      return new IrohEndpoint(
        await InternalEndpoint.createRelayOnly(endpointOptions(options, relayUrl)),
      )
    } catch (error) {
      failures.push(errorMessage(error))
    }
  }
  throw new Error(`no relay URL connected: ${failures.join('; ')}`)
}

export class IrohEndpoint {
  readonly #endpoint: InternalEndpoint

  constructor(endpoint: InternalEndpoint) {
    this.#endpoint = endpoint
  }

  get endpointId(): Uint8Array {
    return copyBytes(this.#endpoint.endpointId)
  }

  get relayUrl(): URL {
    return new URL(this.#endpoint.relayUrl)
  }

  get address(): IrohEndpointAddress {
    return {
      endpointId: this.endpointId,
      relayUrl: this.relayUrl,
    }
  }

  async connect(options: IrohEndpointConnectOptions): Promise<IrohConnection> {
    const connection = await this.#endpoint.connect({
      endpointId: validateEndpointId(options.address.endpointId),
      relayUrl: options.address.relayUrl,
      alpn: copyBytes(options.alpn),
    })
    return new IrohConnection(connection)
  }

  async accept(options: IrohEndpointAcceptOptions): Promise<IrohConnection> {
    return new IrohConnection(
      await this.#endpoint.accept({
        alpn: copyBytes(options.alpn),
      }),
    )
  }

  close(code?: number, reason?: string): void {
    this.#endpoint.close(code, reason)
  }
}

export class IrohConnection {
  readonly #connection: InternalConnection

  constructor(connection: InternalConnection) {
    this.#connection = connection
  }

  openBidiStream(): IrohBidiStream {
    return new IrohBidiStream(this.#connection.openBidiStream())
  }

  openUniStream(): IrohUniStream {
    return new IrohUniStream(this.#connection.openUniStream())
  }

  async acceptBidiStream(): Promise<IrohBidiStream> {
    return new IrohBidiStream(await this.#connection.acceptBidiStream())
  }

  async acceptUniStream(): Promise<IrohUniStream> {
    return new IrohUniStream(await this.#connection.acceptUniStream())
  }
}

export class IrohBidiStream {
  readonly #stream: InternalBidiStream

  constructor(stream: InternalBidiStream) {
    this.#stream = stream
  }

  get streamId(): number {
    return this.#stream.streamId
  }

  write(data: Uint8Array, options: BidiStreamWriteOptions = {}): void {
    this.#stream.write(data, options)
  }

  async read(): Promise<IrohStreamRead> {
    return streamRead(await this.#stream.read())
  }

  async readToEnd(): Promise<Uint8Array> {
    return await this.#stream.readToEnd()
  }
}

export class IrohUniStream {
  readonly #stream: InternalUniStream

  constructor(stream: InternalUniStream) {
    this.#stream = stream
  }

  get streamId(): number {
    return this.#stream.streamId
  }

  write(data: Uint8Array, options: BidiStreamWriteOptions = {}): void {
    this.#stream.write(data, options)
  }

  async read(): Promise<IrohStreamRead> {
    return streamRead(await this.#stream.read())
  }

  async readToEnd(): Promise<Uint8Array> {
    return await this.#stream.readToEnd()
  }
}

function endpointOptions(
  options: IrohEndpointOptions,
  relayUrl: RelayUrlInput,
): EndpointCreateRelayOnlyOptions {
  const out: EndpointCreateRelayOnlyOptions = { relayUrl }
  if (options.secretKey !== undefined) {
    Object.assign(out, { secretKey: options.secretKey })
  }
  if (options.WebSocket !== undefined) {
    Object.assign(out, { WebSocket: options.WebSocket })
  }
  return out
}

function relayUrlCandidates(options: IrohEndpointOptions): readonly RelayUrlInput[] {
  if (options.relayUrls !== undefined) {
    if (options.relayUrls.length === 0) {
      throw new Error('at least one relay URL is required')
    }
    return options.relayUrls
  }
  return [options.relayUrl]
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

function streamRead(output: QuicStreamReceiveOutput): IrohStreamRead {
  return {
    data: copyBytes(output.data),
    complete: output.complete,
  }
}

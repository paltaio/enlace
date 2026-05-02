import { copyBytes } from '../bytes'
import { MAX_QUIC_VARINT } from '../varint'
import {
  encodeQuicStreamFrame,
  parseQuicFrames,
  type QuicFrame,
  type QuicMaxDataFrame,
  type QuicMaxStreamDataFrame,
  type QuicStreamFrame,
} from './frame'
import {
  quicTransportParameterToSaturatingSafeNumber,
  QuicEndpointRole,
  type QuicEndpointRoleValue,
  type QuicTransportParameters,
} from './transport-parameters'

export interface QuicStreamReceiveOutput {
  readonly streamId: number
  readonly streamOffset: number
  readonly data: Uint8Array
  readonly fin: boolean
  readonly finalSize: number | null
  readonly complete: boolean
}

export interface QuicStreamReceiveSnapshot {
  readonly streamId: number
  readonly readOffset: number
  readonly finalSize: number | null
  readonly complete: boolean
}

export interface QuicStreamPayloadReceiveResult {
  readonly frames: readonly QuicFrame[]
  readonly streamOutputs: readonly QuicStreamReceiveOutput[]
  readonly endOffset: number
}

export interface QuicStreamSendResult {
  readonly streamId: number
  readonly streamOffset: number
  readonly data: Uint8Array
  readonly fin: boolean
  readonly frameBytes: Uint8Array
  readonly nextStreamOffset: number
}

export interface QuicStreamSendStateOptions {
  readonly maxData?: number | null
  readonly peerTransportParameters?: QuicTransportParameters
  readonly localRole?: QuicEndpointRoleValue
}

export class QuicStreamState {
  readonly #receiveState: QuicStreamReceiveState
  readonly #sendState: QuicStreamSendState

  constructor(sendOptions: QuicStreamSendStateOptions = {}) {
    this.#receiveState = new QuicStreamReceiveState()
    this.#sendState = new QuicStreamSendState(sendOptions)
  }

  receiveFrame(frame: QuicStreamFrame): QuicStreamReceiveOutput | null {
    return this.#receiveState.receive(frame)
  }

  receiveFrames(frames: readonly QuicFrame[]): readonly QuicStreamReceiveOutput[] {
    return this.#receiveState.receiveFrames(frames)
  }

  receiveFrameBytes(frameBytes: Uint8Array): QuicStreamPayloadReceiveResult {
    return this.#receiveState.receiveFrameBytes(frameBytes)
  }

  receiveSnapshot(streamId: number): QuicStreamReceiveSnapshot {
    return this.#receiveState.snapshot(streamId)
  }

  send(streamId: number, data: Uint8Array, fin = false): QuicStreamSendResult {
    return this.#sendState.send(streamId, data, fin)
  }

  applyMaxData(frame: QuicMaxDataFrame): void {
    this.#sendState.applyMaxData(frame)
  }

  applyMaxStreamData(frame: QuicMaxStreamDataFrame): void {
    this.#sendState.applyMaxStreamData(frame)
  }

  applyFlowControlFrames(frames: readonly QuicFrame[]): void {
    this.#sendState.applyFlowControlFrames(frames)
  }

  sendOffset(streamId: number): number {
    return this.#sendState.offset(streamId)
  }
}

export class QuicStreamReceiveState {
  readonly #streams = new Map<number, QuicStreamReceiveBuffer>()

  receive(frame: QuicStreamFrame): QuicStreamReceiveOutput | null {
    validateStreamId(frame.streamId)
    const buffer = this.stream(frame.streamId)
    return buffer.receive(frame)
  }

  receiveFrames(frames: readonly QuicFrame[]): readonly QuicStreamReceiveOutput[] {
    const outputs: QuicStreamReceiveOutput[] = []
    for (const frame of frames) {
      if (frame.type !== 'stream') {
        continue
      }
      const output = this.receive(frame)
      if (output !== null) {
        outputs.push(output)
      }
    }
    return outputs
  }

  receiveFrameBytes(frameBytes: Uint8Array): QuicStreamPayloadReceiveResult {
    const parsed = parseQuicFrames(frameBytes)
    return {
      frames: parsed.frames,
      streamOutputs: this.receiveFrames(parsed.frames),
      endOffset: parsed.endOffset,
    }
  }

  snapshot(streamId: number): QuicStreamReceiveSnapshot {
    validateStreamId(streamId)
    const stream = this.#streams.get(streamId)
    if (stream === undefined) {
      return {
        streamId,
        readOffset: 0,
        finalSize: null,
        complete: false,
      }
    }
    return stream.snapshot()
  }

  private stream(streamId: number): QuicStreamReceiveBuffer {
    const existing = this.#streams.get(streamId)
    if (existing !== undefined) {
      return existing
    }
    const created = new QuicStreamReceiveBuffer(streamId)
    this.#streams.set(streamId, created)
    return created
  }
}

export class QuicStreamSendState {
  readonly #streams = new Map<number, QuicStreamSendCursor>()
  readonly #streamLimits = new Map<number, number>()
  #maxData: number | null
  #sentData = 0
  #localRole: QuicEndpointRoleValue | null = null
  #initialMaxStreamDataBidiLocal: number | null = null
  #initialMaxStreamDataBidiRemote: number | null = null
  #initialMaxStreamDataUni: number | null = null

  constructor(options: QuicStreamSendStateOptions | number | null = {}) {
    const sendOptions = normalizeSendStateOptions(options)
    this.#maxData = validateOptionalStreamLimit(sendOptions.maxData ?? null, 'QUIC MAX_DATA')
    if (sendOptions.peerTransportParameters !== undefined) {
      this.applyPeerTransportParameters(sendOptions.peerTransportParameters, sendOptions.localRole)
    }
  }

  send(streamId: number, data: Uint8Array, fin = false): QuicStreamSendResult {
    validateStreamId(streamId)
    if (data.length === 0 && !fin) {
      throw new RangeError('QUIC STREAM frame requires data or FIN')
    }
    this.validateCredit(streamId, data.length)
    const cursor = this.stream(streamId)
    const result = cursor.send(data, fin)
    this.#sentData += data.length
    return result
  }

  offset(streamId: number): number {
    validateStreamId(streamId)
    return this.#streams.get(streamId)?.offset ?? 0
  }

  applyMaxData(frame: QuicMaxDataFrame): void {
    this.#maxData = maxLimit(this.#maxData, frame.maximumData, 'QUIC MAX_DATA')
  }

  applyMaxStreamData(frame: QuicMaxStreamDataFrame): void {
    validateStreamId(frame.streamId)
    this.#streamLimits.set(
      frame.streamId,
      maxLimit(
        this.maxStreamDataForSend(frame.streamId),
        frame.maximumStreamData,
        'QUIC MAX_STREAM_DATA',
      ),
    )
  }

  applyFlowControlFrames(frames: readonly QuicFrame[]): void {
    for (const frame of frames) {
      if (frame.type === 'max-data') {
        this.applyMaxData(frame)
        continue
      }
      if (frame.type === 'max-stream-data') {
        this.applyMaxStreamData(frame)
      }
    }
  }

  applyPeerTransportParameters(
    params: QuicTransportParameters,
    localRole: QuicEndpointRoleValue = QuicEndpointRole.Client,
  ): void {
    this.#localRole = localRole
    this.#maxData = maxLimit(
      this.#maxData,
      quicTransportParameterToSaturatingSafeNumber(params.initialMaxData),
      'QUIC MAX_DATA',
    )
    this.#initialMaxStreamDataBidiLocal = quicTransportParameterToSaturatingSafeNumber(
      params.initialMaxStreamDataBidiLocal,
    )
    this.#initialMaxStreamDataBidiRemote = quicTransportParameterToSaturatingSafeNumber(
      params.initialMaxStreamDataBidiRemote,
    )
    this.#initialMaxStreamDataUni = quicTransportParameterToSaturatingSafeNumber(
      params.initialMaxStreamDataUni,
    )
  }

  maxData(): number | null {
    return this.#maxData
  }

  sentData(): number {
    return this.#sentData
  }

  maxStreamData(streamId: number): number | null {
    validateStreamId(streamId)
    return this.maxStreamDataForSend(streamId)
  }

  private stream(streamId: number): QuicStreamSendCursor {
    const existing = this.#streams.get(streamId)
    if (existing !== undefined) {
      return existing
    }
    const created = new QuicStreamSendCursor(streamId)
    this.#streams.set(streamId, created)
    return created
  }

  private validateCredit(streamId: number, length: number): void {
    const currentOffset = this.offset(streamId)
    const nextStreamOffset = checkedStreamEndOffset(currentOffset, length)
    const maxStreamData = this.maxStreamDataForSend(streamId)
    if (maxStreamData !== null && nextStreamOffset > maxStreamData) {
      throw new RangeError('QUIC STREAM data exceeds MAX_STREAM_DATA')
    }
    const nextSentData = checkedStreamEndOffset(this.#sentData, length)
    if (this.#maxData !== null && nextSentData > this.#maxData) {
      throw new RangeError('QUIC STREAM data exceeds MAX_DATA')
    }
  }

  private maxStreamDataForSend(streamId: number): number | null {
    const explicit = this.#streamLimits.get(streamId)
    if (explicit !== undefined) {
      return explicit
    }
    if (this.#localRole === null) {
      return null
    }
    return initialStreamLimitForSend(
      streamId,
      this.#localRole,
      this.#initialMaxStreamDataBidiLocal,
      this.#initialMaxStreamDataBidiRemote,
      this.#initialMaxStreamDataUni,
    )
  }
}

class QuicStreamReceiveBuffer {
  readonly #streamId: number
  readonly #bytes = new Map<number, number>()
  #readOffset = 0
  #finalSize: number | null = null
  #finEmitted = false

  constructor(streamId: number) {
    this.#streamId = streamId
  }

  receive(frame: QuicStreamFrame): QuicStreamReceiveOutput | null {
    validateStreamOffset(frame.streamOffset)
    const endOffset = checkedStreamEndOffset(frame.streamOffset, frame.data.length)
    const nextFinalSize = frame.fin ? endOffset : this.#finalSize
    if (frame.fin) {
      this.validateFinalSize(endOffset)
    }
    if (nextFinalSize !== null && endOffset > nextFinalSize) {
      throw new RangeError('QUIC STREAM data exceeds final size')
    }

    for (let index = 0; index < frame.data.length; index += 1) {
      const value = frame.data[index]
      if (value === undefined) {
        throw new RangeError('not enough bytes for QUIC STREAM data')
      }
      const offset = frame.streamOffset + index
      const existing = this.#bytes.get(offset)
      if (existing !== undefined && existing !== value) {
        throw new RangeError('conflicting QUIC STREAM data')
      }
    }

    if (frame.fin) {
      this.#finalSize = endOffset
    }
    for (let index = 0; index < frame.data.length; index += 1) {
      const value = frame.data[index]
      if (value === undefined) {
        throw new RangeError('not enough bytes for QUIC STREAM data')
      }
      const offset = frame.streamOffset + index
      this.#bytes.set(offset, value)
    }

    return this.contiguousOutput()
  }

  snapshot(): QuicStreamReceiveSnapshot {
    return {
      streamId: this.#streamId,
      readOffset: this.#readOffset,
      finalSize: this.#finalSize,
      complete: this.complete(),
    }
  }

  private validateFinalSize(finalSize: number): void {
    if (this.#finalSize !== null && this.#finalSize !== finalSize) {
      throw new RangeError('conflicting QUIC STREAM final size')
    }
  }

  private contiguousOutput(): QuicStreamReceiveOutput | null {
    const streamOffset = this.#readOffset
    const bytes: number[] = []
    let next = this.#readOffset
    while (true) {
      const value = this.#bytes.get(next)
      if (value === undefined) {
        break
      }
      bytes.push(value)
      next += 1
    }
    this.#readOffset = next

    const complete = this.complete()
    const fin = complete && !this.#finEmitted
    if (fin) {
      this.#finEmitted = true
    }
    if (bytes.length === 0 && !fin) {
      return null
    }

    return {
      streamId: this.#streamId,
      streamOffset,
      data: new Uint8Array(bytes),
      fin,
      finalSize: this.#finalSize,
      complete,
    }
  }

  private complete(): boolean {
    return this.#finalSize !== null && this.#readOffset === this.#finalSize
  }
}

class QuicStreamSendCursor {
  readonly #streamId: number
  #offset = 0
  #finished = false

  constructor(streamId: number) {
    this.#streamId = streamId
  }

  get offset(): number {
    return this.#offset
  }

  send(data: Uint8Array, fin: boolean): QuicStreamSendResult {
    if (this.#finished) {
      throw new RangeError('QUIC stream is already finished')
    }
    const streamOffset = this.#offset
    const nextOffset = checkedStreamEndOffset(streamOffset, data.length)
    const frameBytes = encodeQuicStreamFrame(this.#streamId, streamOffset, data, fin)

    this.#offset = nextOffset
    if (fin) {
      this.#finished = true
    }

    return {
      streamId: this.#streamId,
      streamOffset,
      data: copyBytes(data),
      fin,
      frameBytes,
      nextStreamOffset: nextOffset,
    }
  }
}

function validateStreamId(streamId: number): void {
  if (!Number.isSafeInteger(streamId) || streamId < 0 || BigInt(streamId) > MAX_QUIC_VARINT) {
    throw new RangeError('QUIC stream id out of range')
  }
}

function validateStreamOffset(streamOffset: number): void {
  if (
    !Number.isSafeInteger(streamOffset) ||
    streamOffset < 0 ||
    BigInt(streamOffset) > MAX_QUIC_VARINT
  ) {
    throw new RangeError('QUIC stream offset out of range')
  }
}

function checkedStreamEndOffset(streamOffset: number, length: number): number {
  validateStreamOffset(streamOffset)
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError('QUIC STREAM length out of range')
  }
  const endOffset = streamOffset + length
  if (!Number.isSafeInteger(endOffset) || BigInt(endOffset) > MAX_QUIC_VARINT) {
    throw new RangeError('QUIC STREAM final size out of range')
  }
  return endOffset
}

function validateOptionalStreamLimit(value: number | null, name: string): number | null {
  if (value === null) {
    return null
  }
  return validateStreamLimit(value, name)
}

function validateStreamLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || BigInt(value) > MAX_QUIC_VARINT) {
    throw new RangeError(`${name} limit out of range`)
  }
  return value
}

function maxLimit(current: number | null, next: number, name: string): number {
  const validated = validateStreamLimit(next, name)
  if (current === null || validated > current) {
    return validated
  }
  return current
}

function normalizeSendStateOptions(
  options: QuicStreamSendStateOptions | number | null,
): QuicStreamSendStateOptions {
  if (typeof options === 'number' || options === null) {
    return { maxData: options }
  }
  return options
}

function initialStreamLimitForSend(
  streamId: number,
  localRole: QuicEndpointRoleValue,
  bidiLocal: number | null,
  bidiRemote: number | null,
  uni: number | null,
): number | null {
  const direction = streamId & 0x02
  if (direction === 0x02) {
    if (!isLocalInitiatedStream(streamId, localRole)) {
      throw new RangeError('QUIC cannot send on peer-initiated unidirectional stream')
    }
    return uni
  }
  return isLocalInitiatedStream(streamId, localRole) ? bidiRemote : bidiLocal
}

function isLocalInitiatedStream(streamId: number, localRole: QuicEndpointRoleValue): boolean {
  const initiator = streamId & 0x01
  return (
    (localRole === QuicEndpointRole.Client && initiator === 0) ||
    (localRole === QuicEndpointRole.Server && initiator === 1)
  )
}

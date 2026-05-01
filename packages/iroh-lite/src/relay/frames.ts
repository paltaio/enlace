import {
  concatBytes,
  copyBytes,
  readU8,
  readU16BE,
  readU32BE,
  requireLength,
  writeU16BE,
  writeU32BE,
} from '../bytes'
import { ENDPOINT_ID_LENGTH, validateEndpointId } from '../crypto/ed25519'
import { decodeVarIntNumber, encodeVarInt } from './varint'

export const MAX_PACKET_SIZE = 64 * 1024
export const MAX_FRAME_SIZE = 1024 * 1024

export const FrameType = {
  ServerChallenge: 0,
  ClientAuth: 1,
  ServerConfirmsAuth: 2,
  ServerDeniesAuth: 3,
  ClientToRelayDatagram: 4,
  ClientToRelayDatagramBatch: 5,
  RelayToClientDatagram: 6,
  RelayToClientDatagramBatch: 7,
  EndpointGone: 8,
  Ping: 9,
  Pong: 10,
  Health: 11,
  Restarting: 12,
  Status: 13,
} as const

export type FrameTypeValue = (typeof FrameType)[keyof typeof FrameType]

export const RelayStatus = {
  Healthy: 0,
  SameEndpointIdConnected: 1,
} as const

export type RelayStatusValue =
  | { readonly type: 'healthy' }
  | { readonly type: 'same-endpoint-id-connected' }
  | { readonly type: 'unknown'; readonly value: number }

export type EcnCodepoint = 1 | 2 | 3

export interface Datagrams {
  readonly endpointId: Uint8Array
  readonly ecn: EcnCodepoint | null
  readonly segmentSize?: number
  readonly contents: Uint8Array
}

export type RelayFrame =
  | { readonly type: 'ping'; readonly data: Uint8Array }
  | { readonly type: 'pong'; readonly data: Uint8Array }
  | { readonly type: 'status'; readonly status: RelayStatusValue }
  | { readonly type: 'restarting'; readonly reconnectInMs: number; readonly tryForMs: number }
  | { readonly type: 'endpoint-gone'; readonly endpointId: Uint8Array }
  | { readonly type: 'datagrams'; readonly datagrams: Datagrams }

export type ClientRelayFrame =
  | { readonly type: 'ping'; readonly data: Uint8Array }
  | { readonly type: 'pong'; readonly data: Uint8Array }
  | { readonly type: 'datagrams'; readonly datagrams: Datagrams }

function assertPayloadLimit(payloadLength: number): void {
  if (payloadLength > MAX_PACKET_SIZE) {
    throw new RangeError(`relay frame payload exceeds ${MAX_PACKET_SIZE} bytes`)
  }
}

function frameTag(tag: FrameTypeValue): Uint8Array {
  return encodeVarInt(tag)
}

function encodePingPong(
  tag: typeof FrameType.Ping | typeof FrameType.Pong,
  data: Uint8Array,
): Uint8Array {
  requireLength(data, 8, 'ping/pong payload')
  return concatBytes([frameTag(tag), data])
}

function encodeDatagrams(
  singleTag: typeof FrameType.ClientToRelayDatagram | typeof FrameType.RelayToClientDatagram,
  batchTag:
    | typeof FrameType.ClientToRelayDatagramBatch
    | typeof FrameType.RelayToClientDatagramBatch,
  datagrams: Datagrams,
): Uint8Array {
  const endpointId = validateEndpointId(datagrams.endpointId)
  const segmentSize = datagrams.segmentSize
  const hasSegmentSize = segmentSize !== undefined
  const ecn = datagrams.ecn ?? 0
  if (!Number.isInteger(ecn) || ecn < 0 || ecn > 3) {
    throw new RangeError('ECN codepoint out of range')
  }
  if (
    hasSegmentSize &&
    (!Number.isInteger(segmentSize) || segmentSize < 1 || segmentSize > 0xffff)
  ) {
    throw new RangeError('segment size out of range')
  }

  const tag = hasSegmentSize ? batchTag : singleTag
  const payload = hasSegmentSize
    ? concatBytes([endpointId, new Uint8Array([ecn]), writeU16BE(segmentSize), datagrams.contents])
    : concatBytes([endpointId, new Uint8Array([ecn]), datagrams.contents])
  assertPayloadLimit(payload.length)
  return concatBytes([frameTag(tag), payload])
}

function decodeDatagrams(payload: Uint8Array, isBatch: boolean): Datagrams {
  const minLength = ENDPOINT_ID_LENGTH + (isBatch ? 3 : 1)
  if (payload.length < minLength) {
    throw new RangeError('invalid datagrams frame')
  }
  const endpointId = validateEndpointId(payload.subarray(0, ENDPOINT_ID_LENGTH))
  const ecnByte = readU8(payload, ENDPOINT_ID_LENGTH)
  const maskedEcn = ecnByte & 0b11
  const ecn = maskedEcn === 0 ? null : parseEcn(maskedEcn)
  if (isBatch) {
    const segmentSize = readU16BE(payload, ENDPOINT_ID_LENGTH + 1)
    const contents = copyBytes(payload.subarray(ENDPOINT_ID_LENGTH + 3))
    return segmentSize === 0
      ? { endpointId, ecn, contents }
      : { endpointId, ecn, segmentSize, contents }
  }
  return {
    endpointId,
    ecn,
    contents: copyBytes(payload.subarray(ENDPOINT_ID_LENGTH + 1)),
  }
}

function parseEcn(value: number): EcnCodepoint {
  if (value === 1 || value === 2 || value === 3) {
    return value
  }
  throw new RangeError('invalid ECN codepoint')
}

function parseStatus(payload: Uint8Array): RelayStatusValue {
  if (payload.length < 1) {
    throw new RangeError('invalid status frame')
  }
  const value = readU8(payload, 0)
  if (value === RelayStatus.Healthy) {
    return { type: 'healthy' }
  }
  if (value === RelayStatus.SameEndpointIdConnected) {
    return { type: 'same-endpoint-id-connected' }
  }
  return { type: 'unknown', value }
}

function encodeStatus(status: RelayStatusValue): Uint8Array {
  switch (status.type) {
    case 'healthy':
      return concatBytes([frameTag(FrameType.Status), new Uint8Array([RelayStatus.Healthy])])
    case 'same-endpoint-id-connected':
      return concatBytes([
        frameTag(FrameType.Status),
        new Uint8Array([RelayStatus.SameEndpointIdConnected]),
      ])
    case 'unknown':
      if (!Number.isInteger(status.value) || status.value < 0 || status.value > 0xff) {
        throw new RangeError('status value out of range')
      }
      return concatBytes([frameTag(FrameType.Status), new Uint8Array([status.value])])
  }
}

function decodeTaggedFrame(bytes: Uint8Array): {
  readonly tag: number
  readonly payload: Uint8Array
} {
  const decoded = decodeVarIntNumber(bytes)
  const payload = bytes.subarray(decoded.bytesRead)
  assertPayloadLimit(payload.length)
  return { tag: decoded.value, payload }
}

export function encodeRelayToClientFrame(frame: RelayFrame): Uint8Array {
  switch (frame.type) {
    case 'ping':
      return encodePingPong(FrameType.Ping, frame.data)
    case 'pong':
      return encodePingPong(FrameType.Pong, frame.data)
    case 'status':
      return encodeStatus(frame.status)
    case 'restarting':
      return concatBytes([
        frameTag(FrameType.Restarting),
        writeU32BE(frame.reconnectInMs),
        writeU32BE(frame.tryForMs),
      ])
    case 'endpoint-gone':
      return concatBytes([frameTag(FrameType.EndpointGone), validateEndpointId(frame.endpointId)])
    case 'datagrams':
      return encodeDatagrams(
        FrameType.RelayToClientDatagram,
        FrameType.RelayToClientDatagramBatch,
        frame.datagrams,
      )
  }
}

export function encodeClientToRelayFrame(frame: ClientRelayFrame): Uint8Array {
  switch (frame.type) {
    case 'ping':
      return encodePingPong(FrameType.Ping, frame.data)
    case 'pong':
      return encodePingPong(FrameType.Pong, frame.data)
    case 'datagrams':
      return encodeDatagrams(
        FrameType.ClientToRelayDatagram,
        FrameType.ClientToRelayDatagramBatch,
        frame.datagrams,
      )
  }
}

export function decodeRelayToClientFrame(bytes: Uint8Array): RelayFrame {
  const { tag, payload } = decodeTaggedFrame(bytes)
  switch (tag) {
    case FrameType.RelayToClientDatagram:
      return { type: 'datagrams', datagrams: decodeDatagrams(payload, false) }
    case FrameType.RelayToClientDatagramBatch:
      return { type: 'datagrams', datagrams: decodeDatagrams(payload, true) }
    case FrameType.EndpointGone:
      requireLength(payload, ENDPOINT_ID_LENGTH, 'endpoint gone payload')
      return { type: 'endpoint-gone', endpointId: validateEndpointId(payload) }
    case FrameType.Ping:
      requireLength(payload, 8, 'ping payload')
      return { type: 'ping', data: copyBytes(payload) }
    case FrameType.Pong:
      requireLength(payload, 8, 'pong payload')
      return { type: 'pong', data: copyBytes(payload) }
    case FrameType.Restarting:
      requireLength(payload, 8, 'restarting payload')
      return {
        type: 'restarting',
        reconnectInMs: readU32BE(payload, 0),
        tryForMs: readU32BE(payload, 4),
      }
    case FrameType.Status:
      return { type: 'status', status: parseStatus(payload) }
    default:
      throw new RangeError(`invalid relay-to-client frame tag ${tag}`)
  }
}

export function decodeClientToRelayFrame(bytes: Uint8Array): ClientRelayFrame {
  const { tag, payload } = decodeTaggedFrame(bytes)
  switch (tag) {
    case FrameType.ClientToRelayDatagram:
      return { type: 'datagrams', datagrams: decodeDatagrams(payload, false) }
    case FrameType.ClientToRelayDatagramBatch:
      return { type: 'datagrams', datagrams: decodeDatagrams(payload, true) }
    case FrameType.Ping:
      requireLength(payload, 8, 'ping payload')
      return { type: 'ping', data: copyBytes(payload) }
    case FrameType.Pong:
      requireLength(payload, 8, 'pong payload')
      return { type: 'pong', data: copyBytes(payload) }
    default:
      throw new RangeError(`invalid client-to-relay frame tag ${tag}`)
  }
}

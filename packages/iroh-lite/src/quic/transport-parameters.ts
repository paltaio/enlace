import { concatBytes, copyBytes } from '../bytes'
import { decodeVarInt, encodeVarInt, MAX_QUIC_VARINT } from '../varint'

export const QuicTransportParameterId = {
  OriginalDestinationConnectionId: 0x00,
  MaxIdleTimeout: 0x01,
  StatelessResetToken: 0x02,
  MaxUdpPayloadSize: 0x03,
  InitialMaxData: 0x04,
  InitialMaxStreamDataBidiLocal: 0x05,
  InitialMaxStreamDataBidiRemote: 0x06,
  InitialMaxStreamDataUni: 0x07,
  InitialMaxStreamsBidi: 0x08,
  InitialMaxStreamsUni: 0x09,
  AckDelayExponent: 0x0a,
  MaxAckDelay: 0x0b,
  DisableActiveMigration: 0x0c,
  PreferredAddress: 0x0d,
  ActiveConnectionIdLimit: 0x0e,
  InitialSourceConnectionId: 0x0f,
  RetrySourceConnectionId: 0x10,
  MaxDatagramFrameSize: 0x20,
  GreaseQuicBit: 0x2ab2,
  MinAckDelayDraft07: 0xff04de1b,
} as const

export const QuicEndpointRole = {
  Client: 'client',
  Server: 'server',
} as const

export type QuicEndpointRoleValue = (typeof QuicEndpointRole)[keyof typeof QuicEndpointRole]

export interface QuicTransportParameters {
  readonly maxIdleTimeout: bigint
  readonly maxUdpPayloadSize: bigint
  readonly initialMaxData: bigint
  readonly initialMaxStreamDataBidiLocal: bigint
  readonly initialMaxStreamDataBidiRemote: bigint
  readonly initialMaxStreamDataUni: bigint
  readonly initialMaxStreamsBidi: bigint
  readonly initialMaxStreamsUni: bigint
  readonly ackDelayExponent: bigint
  readonly maxAckDelay: bigint
  readonly activeConnectionIdLimit: bigint
  readonly disableActiveMigration: boolean
  readonly maxDatagramFrameSize: bigint | null
  readonly greaseQuicBit: boolean
  readonly minAckDelay: bigint | null
  readonly originalDestinationConnectionId: Uint8Array | null
  readonly initialSourceConnectionId: Uint8Array | null
  readonly retrySourceConnectionId: Uint8Array | null
  readonly statelessResetToken: Uint8Array | null
}

export type QuicTransportParametersInput = Partial<QuicTransportParameters>

const MAX_STREAM_COUNT = 1n << 60n
const MAX_CONNECTION_ID_LENGTH = 20
const RESET_TOKEN_LENGTH = 16

const INTEGER_PARAMETER_DEFAULTS = new Map<number, bigint>([
  [QuicTransportParameterId.MaxIdleTimeout, 0n],
  [QuicTransportParameterId.MaxUdpPayloadSize, 65527n],
  [QuicTransportParameterId.InitialMaxData, 0n],
  [QuicTransportParameterId.InitialMaxStreamDataBidiLocal, 0n],
  [QuicTransportParameterId.InitialMaxStreamDataBidiRemote, 0n],
  [QuicTransportParameterId.InitialMaxStreamDataUni, 0n],
  [QuicTransportParameterId.InitialMaxStreamsBidi, 0n],
  [QuicTransportParameterId.InitialMaxStreamsUni, 0n],
  [QuicTransportParameterId.AckDelayExponent, 3n],
  [QuicTransportParameterId.MaxAckDelay, 25n],
  [QuicTransportParameterId.ActiveConnectionIdLimit, 2n],
])

const INTEGER_PARAMETER_ORDER = [
  QuicTransportParameterId.MaxIdleTimeout,
  QuicTransportParameterId.MaxUdpPayloadSize,
  QuicTransportParameterId.InitialMaxData,
  QuicTransportParameterId.InitialMaxStreamDataBidiLocal,
  QuicTransportParameterId.InitialMaxStreamDataBidiRemote,
  QuicTransportParameterId.InitialMaxStreamDataUni,
  QuicTransportParameterId.InitialMaxStreamsBidi,
  QuicTransportParameterId.InitialMaxStreamsUni,
  QuicTransportParameterId.AckDelayExponent,
  QuicTransportParameterId.MaxAckDelay,
  QuicTransportParameterId.ActiveConnectionIdLimit,
]

export function defaultQuicTransportParameters(): QuicTransportParameters {
  return {
    maxIdleTimeout: 0n,
    maxUdpPayloadSize: 65527n,
    initialMaxData: 0n,
    initialMaxStreamDataBidiLocal: 0n,
    initialMaxStreamDataBidiRemote: 0n,
    initialMaxStreamDataUni: 0n,
    initialMaxStreamsBidi: 0n,
    initialMaxStreamsUni: 0n,
    ackDelayExponent: 3n,
    maxAckDelay: 25n,
    activeConnectionIdLimit: 2n,
    disableActiveMigration: false,
    maxDatagramFrameSize: null,
    greaseQuicBit: false,
    minAckDelay: null,
    originalDestinationConnectionId: null,
    initialSourceConnectionId: null,
    retrySourceConnectionId: null,
    statelessResetToken: null,
  }
}

export function parseQuicTransportParameters(
  bytes: Uint8Array,
  senderRole: QuicEndpointRoleValue | null = null,
): QuicTransportParameters {
  const params = mutableTransportParameters(defaultQuicTransportParameters())
  const seen = new Set<number>()
  let pos = 0

  while (pos < bytes.length) {
    const id = decodeVarInt(bytes, pos)
    pos += id.bytesRead
    const length = decodeVarInt(bytes, pos)
    pos += length.bytesRead
    if (length.value > BigInt(bytes.length - pos)) {
      throw new RangeError('not enough bytes for QUIC transport parameter')
    }
    const dataLength = Number(length.value)
    const data = bytes.subarray(pos, pos + dataLength)
    pos += dataLength

    if (!isKnownTransportParameterId(id.value)) {
      continue
    }
    const idNumber = Number(id.value)
    if (seen.has(idNumber)) {
      throw new RangeError('duplicate QUIC transport parameter')
    }
    seen.add(idNumber)

    readTransportParameter(params, idNumber, data)
  }

  validateTransportParameters(params, senderRole)
  return immutableTransportParameters(params)
}

export function encodeQuicTransportParameters(
  input: QuicTransportParametersInput = {},
): Uint8Array {
  const params = mutableTransportParameters({
    ...defaultQuicTransportParameters(),
    ...input,
  })
  validateTransportParameters(params, null)

  const parts: Uint8Array[] = []
  for (const id of INTEGER_PARAMETER_ORDER) {
    const value = parameterValue(params, id)
    const defaultValue = INTEGER_PARAMETER_DEFAULTS.get(id)
    if (defaultValue === undefined) {
      throw new RangeError('unknown QUIC transport parameter default')
    }
    if (value !== defaultValue) {
      parts.push(encodeTransportParameter(id, encodeVarInt(value)))
    }
  }
  if (params.disableActiveMigration) {
    parts.push(encodeTransportParameter(QuicTransportParameterId.DisableActiveMigration))
  }
  if (params.maxDatagramFrameSize !== null) {
    parts.push(
      encodeTransportParameter(
        QuicTransportParameterId.MaxDatagramFrameSize,
        encodeVarInt(params.maxDatagramFrameSize),
      ),
    )
  }
  if (params.originalDestinationConnectionId !== null) {
    parts.push(
      encodeTransportParameter(
        QuicTransportParameterId.OriginalDestinationConnectionId,
        params.originalDestinationConnectionId,
      ),
    )
  }
  if (params.initialSourceConnectionId !== null) {
    parts.push(
      encodeTransportParameter(
        QuicTransportParameterId.InitialSourceConnectionId,
        params.initialSourceConnectionId,
      ),
    )
  }
  if (params.retrySourceConnectionId !== null) {
    parts.push(
      encodeTransportParameter(
        QuicTransportParameterId.RetrySourceConnectionId,
        params.retrySourceConnectionId,
      ),
    )
  }
  if (params.statelessResetToken !== null) {
    parts.push(
      encodeTransportParameter(
        QuicTransportParameterId.StatelessResetToken,
        params.statelessResetToken,
      ),
    )
  }
  if (params.greaseQuicBit) {
    parts.push(encodeTransportParameter(QuicTransportParameterId.GreaseQuicBit))
  }
  if (params.minAckDelay !== null) {
    parts.push(
      encodeTransportParameter(
        QuicTransportParameterId.MinAckDelayDraft07,
        encodeVarInt(params.minAckDelay),
      ),
    )
  }

  return concatBytes(parts)
}

export function quicTransportParameterToSafeNumber(value: bigint, name: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`${name} exceeds safe integer range`)
  }
  return Number(value)
}

function readTransportParameter(
  params: MutableQuicTransportParameters,
  id: number,
  data: Uint8Array,
): void {
  if (id === QuicTransportParameterId.DisableActiveMigration) {
    requireLength(data, 0, 'QUIC disable_active_migration')
    params.disableActiveMigration = true
    return
  }
  if (id === QuicTransportParameterId.GreaseQuicBit) {
    requireLength(data, 0, 'QUIC grease_quic_bit')
    params.greaseQuicBit = true
    return
  }
  if (id === QuicTransportParameterId.MaxDatagramFrameSize) {
    params.maxDatagramFrameSize = readParameterVarInt(data)
    return
  }
  if (id === QuicTransportParameterId.MinAckDelayDraft07) {
    params.minAckDelay = readParameterVarInt(data)
    return
  }
  if (id === QuicTransportParameterId.OriginalDestinationConnectionId) {
    params.originalDestinationConnectionId = readConnectionId(data)
    return
  }
  if (id === QuicTransportParameterId.InitialSourceConnectionId) {
    params.initialSourceConnectionId = readConnectionId(data)
    return
  }
  if (id === QuicTransportParameterId.RetrySourceConnectionId) {
    params.retrySourceConnectionId = readConnectionId(data)
    return
  }
  if (id === QuicTransportParameterId.StatelessResetToken) {
    requireLength(data, RESET_TOKEN_LENGTH, 'QUIC stateless reset token')
    params.statelessResetToken = copyBytes(data)
    return
  }
  if (id === QuicTransportParameterId.PreferredAddress) {
    throw new RangeError('unsupported QUIC preferred address transport parameter')
  }

  setIntegerParameter(params, id, readParameterVarInt(data))
}

function validateTransportParameters(
  params: QuicTransportParameters,
  senderRole: QuicEndpointRoleValue | null,
): void {
  for (const id of INTEGER_PARAMETER_ORDER) {
    validateTransportParameterValue(parameterValue(params, id), parameterName(id))
  }
  validateOptionalTransportParameterValue(
    params.maxDatagramFrameSize,
    'QUIC max_datagram_frame_size',
  )
  validateOptionalTransportParameterValue(params.minAckDelay, 'QUIC min_ack_delay')
  validateConnectionId(params.originalDestinationConnectionId)
  validateConnectionId(params.initialSourceConnectionId)
  validateConnectionId(params.retrySourceConnectionId)
  if (params.statelessResetToken !== null) {
    requireLength(params.statelessResetToken, RESET_TOKEN_LENGTH, 'QUIC stateless reset token')
  }

  if (params.ackDelayExponent > 20n) {
    throw new RangeError('QUIC ack_delay_exponent out of range')
  }
  if (params.maxAckDelay >= 1n << 14n) {
    throw new RangeError('QUIC max_ack_delay out of range')
  }
  if (params.activeConnectionIdLimit < 2n) {
    throw new RangeError('QUIC active_connection_id_limit out of range')
  }
  if (params.maxUdpPayloadSize < 1200n) {
    throw new RangeError('QUIC max_udp_payload_size out of range')
  }
  if (params.initialMaxStreamsBidi > MAX_STREAM_COUNT) {
    throw new RangeError('QUIC initial_max_streams_bidi out of range')
  }
  if (params.initialMaxStreamsUni > MAX_STREAM_COUNT) {
    throw new RangeError('QUIC initial_max_streams_uni out of range')
  }
  if (params.minAckDelay !== null && params.minAckDelay > params.maxAckDelay * 1000n) {
    throw new RangeError('QUIC min_ack_delay out of range')
  }
  if (
    senderRole === QuicEndpointRole.Client &&
    (params.originalDestinationConnectionId !== null ||
      params.retrySourceConnectionId !== null ||
      params.statelessResetToken !== null)
  ) {
    throw new RangeError('client QUIC transport parameters contain server-only field')
  }
  if (senderRole !== null && params.initialSourceConnectionId === null) {
    throw new RangeError('QUIC initial_source_connection_id transport parameter is required')
  }
  if (senderRole === QuicEndpointRole.Server && params.originalDestinationConnectionId === null) {
    throw new RangeError('QUIC original_destination_connection_id transport parameter is required')
  }
}

function encodeTransportParameter(id: number, data: Uint8Array = new Uint8Array()): Uint8Array {
  return concatBytes([encodeVarInt(id), encodeVarInt(data.length), data])
}

function readParameterVarInt(data: Uint8Array): bigint {
  const value = decodeVarInt(data, 0)
  if (value.bytesRead !== data.length) {
    throw new RangeError('QUIC transport parameter varint length mismatch')
  }
  return value.value
}

function readConnectionId(data: Uint8Array): Uint8Array {
  validateConnectionId(data)
  return copyBytes(data)
}

function validateConnectionId(value: Uint8Array | null): void {
  if (value !== null && value.length > MAX_CONNECTION_ID_LENGTH) {
    throw new RangeError('QUIC connection id too long')
  }
}

function requireLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) {
    throw new RangeError(`${name} length mismatch`)
  }
}

function validateOptionalTransportParameterValue(value: bigint | null, name: string): void {
  if (value !== null) {
    validateTransportParameterValue(value, name)
  }
}

function validateTransportParameterValue(value: bigint, name: string): void {
  if (value < 0n || value > MAX_QUIC_VARINT) {
    throw new RangeError(`${name} out of range`)
  }
}

function isKnownTransportParameterId(id: bigint): boolean {
  return (
    id === BigInt(QuicTransportParameterId.OriginalDestinationConnectionId) ||
    id === BigInt(QuicTransportParameterId.MaxIdleTimeout) ||
    id === BigInt(QuicTransportParameterId.StatelessResetToken) ||
    id === BigInt(QuicTransportParameterId.MaxUdpPayloadSize) ||
    id === BigInt(QuicTransportParameterId.InitialMaxData) ||
    id === BigInt(QuicTransportParameterId.InitialMaxStreamDataBidiLocal) ||
    id === BigInt(QuicTransportParameterId.InitialMaxStreamDataBidiRemote) ||
    id === BigInt(QuicTransportParameterId.InitialMaxStreamDataUni) ||
    id === BigInt(QuicTransportParameterId.InitialMaxStreamsBidi) ||
    id === BigInt(QuicTransportParameterId.InitialMaxStreamsUni) ||
    id === BigInt(QuicTransportParameterId.AckDelayExponent) ||
    id === BigInt(QuicTransportParameterId.MaxAckDelay) ||
    id === BigInt(QuicTransportParameterId.DisableActiveMigration) ||
    id === BigInt(QuicTransportParameterId.PreferredAddress) ||
    id === BigInt(QuicTransportParameterId.ActiveConnectionIdLimit) ||
    id === BigInt(QuicTransportParameterId.InitialSourceConnectionId) ||
    id === BigInt(QuicTransportParameterId.RetrySourceConnectionId) ||
    id === BigInt(QuicTransportParameterId.MaxDatagramFrameSize) ||
    id === BigInt(QuicTransportParameterId.GreaseQuicBit) ||
    id === BigInt(QuicTransportParameterId.MinAckDelayDraft07)
  )
}

function parameterValue(params: QuicTransportParameters, id: number): bigint {
  if (id === QuicTransportParameterId.MaxIdleTimeout) {
    return params.maxIdleTimeout
  }
  if (id === QuicTransportParameterId.MaxUdpPayloadSize) {
    return params.maxUdpPayloadSize
  }
  if (id === QuicTransportParameterId.InitialMaxData) {
    return params.initialMaxData
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataBidiLocal) {
    return params.initialMaxStreamDataBidiLocal
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataBidiRemote) {
    return params.initialMaxStreamDataBidiRemote
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataUni) {
    return params.initialMaxStreamDataUni
  }
  if (id === QuicTransportParameterId.InitialMaxStreamsBidi) {
    return params.initialMaxStreamsBidi
  }
  if (id === QuicTransportParameterId.InitialMaxStreamsUni) {
    return params.initialMaxStreamsUni
  }
  if (id === QuicTransportParameterId.AckDelayExponent) {
    return params.ackDelayExponent
  }
  if (id === QuicTransportParameterId.MaxAckDelay) {
    return params.maxAckDelay
  }
  if (id === QuicTransportParameterId.ActiveConnectionIdLimit) {
    return params.activeConnectionIdLimit
  }
  throw new RangeError('unknown QUIC transport parameter')
}

function setIntegerParameter(
  params: MutableQuicTransportParameters,
  id: number,
  value: bigint,
): void {
  if (id === QuicTransportParameterId.MaxIdleTimeout) {
    params.maxIdleTimeout = value
    return
  }
  if (id === QuicTransportParameterId.MaxUdpPayloadSize) {
    params.maxUdpPayloadSize = value
    return
  }
  if (id === QuicTransportParameterId.InitialMaxData) {
    params.initialMaxData = value
    return
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataBidiLocal) {
    params.initialMaxStreamDataBidiLocal = value
    return
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataBidiRemote) {
    params.initialMaxStreamDataBidiRemote = value
    return
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataUni) {
    params.initialMaxStreamDataUni = value
    return
  }
  if (id === QuicTransportParameterId.InitialMaxStreamsBidi) {
    params.initialMaxStreamsBidi = value
    return
  }
  if (id === QuicTransportParameterId.InitialMaxStreamsUni) {
    params.initialMaxStreamsUni = value
    return
  }
  if (id === QuicTransportParameterId.AckDelayExponent) {
    params.ackDelayExponent = value
    return
  }
  if (id === QuicTransportParameterId.MaxAckDelay) {
    params.maxAckDelay = value
    return
  }
  if (id === QuicTransportParameterId.ActiveConnectionIdLimit) {
    params.activeConnectionIdLimit = value
    return
  }
  throw new RangeError('unknown QUIC transport parameter')
}

function parameterName(id: number): string {
  if (id === QuicTransportParameterId.MaxIdleTimeout) {
    return 'QUIC max_idle_timeout'
  }
  if (id === QuicTransportParameterId.MaxUdpPayloadSize) {
    return 'QUIC max_udp_payload_size'
  }
  if (id === QuicTransportParameterId.InitialMaxData) {
    return 'QUIC initial_max_data'
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataBidiLocal) {
    return 'QUIC initial_max_stream_data_bidi_local'
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataBidiRemote) {
    return 'QUIC initial_max_stream_data_bidi_remote'
  }
  if (id === QuicTransportParameterId.InitialMaxStreamDataUni) {
    return 'QUIC initial_max_stream_data_uni'
  }
  if (id === QuicTransportParameterId.InitialMaxStreamsBidi) {
    return 'QUIC initial_max_streams_bidi'
  }
  if (id === QuicTransportParameterId.InitialMaxStreamsUni) {
    return 'QUIC initial_max_streams_uni'
  }
  if (id === QuicTransportParameterId.AckDelayExponent) {
    return 'QUIC ack_delay_exponent'
  }
  if (id === QuicTransportParameterId.MaxAckDelay) {
    return 'QUIC max_ack_delay'
  }
  if (id === QuicTransportParameterId.ActiveConnectionIdLimit) {
    return 'QUIC active_connection_id_limit'
  }
  throw new RangeError('unknown QUIC transport parameter')
}

type MutableQuicTransportParameters = {
  -readonly [Key in keyof QuicTransportParameters]: QuicTransportParameters[Key]
}

function mutableTransportParameters(
  params: QuicTransportParameters,
): MutableQuicTransportParameters {
  return {
    maxIdleTimeout: params.maxIdleTimeout,
    maxUdpPayloadSize: params.maxUdpPayloadSize,
    initialMaxData: params.initialMaxData,
    initialMaxStreamDataBidiLocal: params.initialMaxStreamDataBidiLocal,
    initialMaxStreamDataBidiRemote: params.initialMaxStreamDataBidiRemote,
    initialMaxStreamDataUni: params.initialMaxStreamDataUni,
    initialMaxStreamsBidi: params.initialMaxStreamsBidi,
    initialMaxStreamsUni: params.initialMaxStreamsUni,
    ackDelayExponent: params.ackDelayExponent,
    maxAckDelay: params.maxAckDelay,
    activeConnectionIdLimit: params.activeConnectionIdLimit,
    disableActiveMigration: params.disableActiveMigration,
    maxDatagramFrameSize: params.maxDatagramFrameSize,
    greaseQuicBit: params.greaseQuicBit,
    minAckDelay: params.minAckDelay,
    originalDestinationConnectionId: copyOptionalBytes(params.originalDestinationConnectionId),
    initialSourceConnectionId: copyOptionalBytes(params.initialSourceConnectionId),
    retrySourceConnectionId: copyOptionalBytes(params.retrySourceConnectionId),
    statelessResetToken: copyOptionalBytes(params.statelessResetToken),
  }
}

function immutableTransportParameters(
  params: MutableQuicTransportParameters,
): QuicTransportParameters {
  return {
    ...params,
    originalDestinationConnectionId: copyOptionalBytes(params.originalDestinationConnectionId),
    initialSourceConnectionId: copyOptionalBytes(params.initialSourceConnectionId),
    retrySourceConnectionId: copyOptionalBytes(params.retrySourceConnectionId),
    statelessResetToken: copyOptionalBytes(params.statelessResetToken),
  }
}

function copyOptionalBytes(bytes: Uint8Array | null): Uint8Array | null {
  return bytes === null ? null : copyBytes(bytes)
}

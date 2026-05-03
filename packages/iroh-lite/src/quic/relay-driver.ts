import { copyBytes } from '../bytes'
import type { Datagrams, EcnCodepoint } from '../relay/frames'
import type { QuicConnectionState } from './connection'
import {
  QuicClientHandshakeDriver,
  QuicServerHandshakeDriver,
  type QuicClientHandshakeFlight,
  type QuicServerHandshakeFlight,
} from './handshake-driver'
import {
  parseQuicHandshakePacketHeaderPrefix,
  parseQuicInitialPacketHeaderPrefix,
  parseQuicLongHeader,
  QuicLongHeaderPacketType,
  type QuicLongHeaderPacketTypeValue,
} from './packet'
import type { QuicStreamReceiveOutput, QuicStreamSendResult } from './streams'

export interface QuicRelayClientDriverOptions {
  readonly peerEndpointId: Uint8Array
  readonly handshake: QuicClientHandshakeDriver
  readonly ecn?: EcnCodepoint | null
}

export interface QuicRelayServerDriverOptions {
  readonly handshake: QuicServerHandshakeDriver
  readonly ecn?: EcnCodepoint | null
}

export interface QuicRelayReceiveResult {
  readonly outgoing: readonly Datagrams[]
  readonly streamOutputs: readonly QuicStreamReceiveOutput[]
  readonly connected: boolean
  readonly closed: boolean
}

export interface QuicRelayStreamSendResult {
  readonly datagrams: Datagrams
  readonly packetNumber: bigint
  readonly stream: QuicStreamSendResult
}

export interface QuicRelayConnectionCloseResult {
  readonly datagrams: Datagrams
}

export class QuicRelayClientDriver {
  readonly #handshake: QuicClientHandshakeDriver
  readonly #peerEndpointId: Uint8Array
  readonly #ecn: EcnCodepoint | null
  #serverInitialPacket: Uint8Array | null = null
  #serverHandshakePacket: Uint8Array | null = null
  #pendingConnectedPackets: Uint8Array[] = []
  #connection: QuicConnectionState | null = null

  constructor(options: QuicRelayClientDriverOptions) {
    this.#handshake = options.handshake
    this.#peerEndpointId = copyBytes(options.peerEndpointId)
    this.#ecn = options.ecn ?? null
  }

  get connection(): QuicConnectionState | null {
    return this.#connection
  }

  async start(): Promise<Datagrams> {
    const start = await this.#handshake.start()
    return this.outgoing(start.packet)
  }

  async receive(datagrams: Datagrams): Promise<QuicRelayReceiveResult> {
    this.validatePeer(datagrams)
    if (this.#connection !== null) {
      return receiveConnectedDatagram(this.#connection, this.#peerEndpointId, this.#ecn, datagrams)
    }

    const outgoing: Datagrams[] = []
    const streamOutputs: QuicStreamReceiveOutput[] = []
    let closed = false
    for (const packet of splitRelayDatagramPackets(datagrams)) {
      if (this.#connection !== null) {
        closed = receiveConnectedPacket(
          this.#connection,
          this.#peerEndpointId,
          this.#ecn,
          packet,
          outgoing,
          streamOutputs,
        )
        if (closed) {
          break
        }
        continue
      }
      if (isShortHeaderPacket(packet)) {
        this.#pendingConnectedPackets.push(packet)
        continue
      }

      const packetType = quicRelayPacketType(packet)
      if (packetType === QuicLongHeaderPacketType.Initial) {
        this.#serverInitialPacket = packet
      } else if (packetType === QuicLongHeaderPacketType.Handshake) {
        this.#serverHandshakePacket = packet
      } else {
        throw new RangeError(`unsupported QUIC relay handshake packet type ${packetType}`)
      }
      const clientFlight = await this.maybeCompleteHandshake()
      if (clientFlight !== null) {
        this.#connection = clientFlight.connection
        outgoing.push(this.outgoing(clientFlight.packet))
        closed = drainPendingConnectedPackets(
          this.#connection,
          this.#peerEndpointId,
          this.#ecn,
          this.#pendingConnectedPackets,
          outgoing,
          streamOutputs,
        )
      }
    }

    return {
      outgoing,
      streamOutputs,
      connected: this.#connection !== null,
      closed,
    }
  }

  sendStream(streamId: number, data: Uint8Array, fin = false): QuicRelayStreamSendResult {
    const connection = requireConnection(this.#connection)
    const sent = connection.sendStream(streamId, data, fin)
    return {
      datagrams: this.outgoing(sent.packet),
      packetNumber: sent.packetNumber,
      stream: sent.stream,
    }
  }

  close(errorCode = 0, reasonPhrase = new Uint8Array()): QuicRelayConnectionCloseResult {
    const connection = requireConnection(this.#connection)
    const sent = connection.sendApplicationClose(errorCode, reasonPhrase)
    return {
      datagrams: this.outgoing(sent.packet),
    }
  }

  private async maybeCompleteHandshake(): Promise<QuicClientHandshakeFlight | null> {
    if (this.#serverInitialPacket === null || this.#serverHandshakePacket === null) {
      return null
    }
    return await this.#handshake.receiveServerFlights(
      this.#serverInitialPacket,
      this.#serverHandshakePacket,
    )
  }

  private outgoing(packet: Uint8Array): Datagrams {
    return packetToRelayDatagrams(this.#peerEndpointId, this.#ecn, packet)
  }

  private validatePeer(datagrams: Datagrams): void {
    if (!equalBytes(datagrams.endpointId, this.#peerEndpointId)) {
      throw new RangeError('relay datagram endpoint id does not match QUIC peer')
    }
  }
}

export class QuicRelayServerDriver {
  readonly #handshake: QuicServerHandshakeDriver
  readonly #ecn: EcnCodepoint | null
  #peerEndpointId: Uint8Array | null = null
  #pendingConnectedPackets: Uint8Array[] = []
  #connection: QuicConnectionState | null = null

  constructor(options: QuicRelayServerDriverOptions) {
    this.#handshake = options.handshake
    this.#ecn = options.ecn ?? null
  }

  get connection(): QuicConnectionState | null {
    return this.#connection
  }

  async receive(datagrams: Datagrams): Promise<QuicRelayReceiveResult> {
    this.bindPeer(datagrams.endpointId)
    const peerEndpointId = requireEndpointId(this.#peerEndpointId)
    if (this.#connection !== null) {
      return receiveConnectedDatagram(this.#connection, peerEndpointId, this.#ecn, datagrams)
    }

    const outgoing: Datagrams[] = []
    const streamOutputs: QuicStreamReceiveOutput[] = []
    let closed = false
    for (const packet of splitRelayDatagramPackets(datagrams)) {
      if (this.#connection !== null) {
        closed = receiveConnectedPacket(
          this.#connection,
          peerEndpointId,
          this.#ecn,
          packet,
          outgoing,
          streamOutputs,
        )
        if (closed) {
          break
        }
        continue
      }
      if (isShortHeaderPacket(packet)) {
        this.#pendingConnectedPackets.push(packet)
        continue
      }

      const packetType = quicRelayPacketType(packet)
      if (packetType === QuicLongHeaderPacketType.Initial) {
        const flight = await this.#handshake.receiveClientInitial(packet)
        outgoing.push(...serverFlightToDatagrams(peerEndpointId, this.#ecn, flight))
        continue
      }
      if (packetType === QuicLongHeaderPacketType.Handshake) {
        const complete = await this.#handshake.receiveClientHandshake(packet)
        this.#connection = complete.connection
        closed = drainPendingConnectedPackets(
          this.#connection,
          peerEndpointId,
          this.#ecn,
          this.#pendingConnectedPackets,
          outgoing,
          streamOutputs,
        )
        continue
      }
      throw new RangeError(`unsupported QUIC relay handshake packet type ${packetType}`)
    }

    return {
      outgoing,
      streamOutputs,
      connected: this.#connection !== null,
      closed,
    }
  }

  sendStream(streamId: number, data: Uint8Array, fin = false): QuicRelayStreamSendResult {
    const connection = requireConnection(this.#connection)
    const peerEndpointId = requireEndpointId(this.#peerEndpointId)
    const sent = connection.sendStream(streamId, data, fin)
    return {
      datagrams: packetToRelayDatagrams(peerEndpointId, this.#ecn, sent.packet),
      packetNumber: sent.packetNumber,
      stream: sent.stream,
    }
  }

  close(errorCode = 0, reasonPhrase = new Uint8Array()): QuicRelayConnectionCloseResult {
    const connection = requireConnection(this.#connection)
    const peerEndpointId = requireEndpointId(this.#peerEndpointId)
    const sent = connection.sendApplicationClose(errorCode, reasonPhrase)
    return {
      datagrams: packetToRelayDatagrams(peerEndpointId, this.#ecn, sent.packet),
    }
  }

  private bindPeer(endpointId: Uint8Array): void {
    if (this.#peerEndpointId === null) {
      this.#peerEndpointId = copyBytes(endpointId)
      return
    }
    if (!equalBytes(endpointId, this.#peerEndpointId)) {
      throw new RangeError('relay datagram endpoint id does not match QUIC peer')
    }
  }
}

export function splitQuicRelayDatagram(contents: Uint8Array): readonly Uint8Array[] {
  if (contents.length === 0) {
    throw new RangeError('relay QUIC datagram is empty')
  }

  const packets: Uint8Array[] = []
  let offset = 0
  while (offset < contents.length) {
    const firstByte = contents[offset]
    if (firstByte === undefined) {
      throw new RangeError('relay QUIC datagram offset out of range')
    }
    if ((firstByte & 0x80) === 0) {
      packets.push(copyBytes(contents.subarray(offset)))
      break
    }

    const endOffset = longHeaderPacketEndOffset(contents, offset)
    packets.push(copyBytes(contents.subarray(offset, endOffset)))
    offset = endOffset
  }

  return packets
}

export function splitRelayDatagramPackets(datagrams: Datagrams): readonly Uint8Array[] {
  const segmentSize = datagrams.segmentSize
  if (segmentSize === undefined) {
    return splitQuicRelayDatagram(datagrams.contents)
  }
  if (!Number.isSafeInteger(segmentSize) || segmentSize < 1) {
    throw new RangeError('relay QUIC datagram segment size out of range')
  }
  if (datagrams.contents.length === 0) {
    throw new RangeError('relay QUIC datagram is empty')
  }

  const packets: Uint8Array[] = []
  for (let offset = 0; offset < datagrams.contents.length; offset += segmentSize) {
    const segment = datagrams.contents.subarray(offset, offset + segmentSize)
    packets.push(...splitQuicRelayDatagram(segment))
  }
  return packets
}

function receiveConnectedDatagram(
  connection: QuicConnectionState,
  peerEndpointId: Uint8Array,
  ecn: EcnCodepoint | null,
  datagrams: Datagrams,
): QuicRelayReceiveResult {
  const outgoing: Datagrams[] = []
  const streamOutputs: QuicStreamReceiveOutput[] = []
  let closed = false
  for (const packet of splitRelayDatagramPackets(datagrams)) {
    closed = receiveConnectedPacket(
      connection,
      peerEndpointId,
      ecn,
      packet,
      outgoing,
      streamOutputs,
    )
    if (closed) {
      break
    }
  }
  return {
    outgoing,
    streamOutputs,
    connected: true,
    closed,
  }
}

function receiveConnectedPacket(
  connection: QuicConnectionState,
  peerEndpointId: Uint8Array,
  ecn: EcnCodepoint | null,
  packet: Uint8Array,
  outgoing: Datagrams[],
  streamOutputs: QuicStreamReceiveOutput[],
): boolean {
  const received = connection.receive(packet)
  streamOutputs.push(...received.streamOutputs)
  if (received.ackPacket !== null) {
    outgoing.push(packetToRelayDatagrams(peerEndpointId, ecn, received.ackPacket.packet))
  }
  return received.connectionClosed
}

function drainPendingConnectedPackets(
  connection: QuicConnectionState,
  peerEndpointId: Uint8Array,
  ecn: EcnCodepoint | null,
  packets: Uint8Array[],
  outgoing: Datagrams[],
  streamOutputs: QuicStreamReceiveOutput[],
): boolean {
  for (const packet of packets.splice(0)) {
    if (receiveConnectedPacket(connection, peerEndpointId, ecn, packet, outgoing, streamOutputs)) {
      return true
    }
  }
  return false
}

function serverFlightToDatagrams(
  peerEndpointId: Uint8Array,
  ecn: EcnCodepoint | null,
  flight: QuicServerHandshakeFlight,
): readonly Datagrams[] {
  return [
    packetToRelayDatagrams(peerEndpointId, ecn, flight.initialPacket),
    packetToRelayDatagrams(peerEndpointId, ecn, flight.handshakePacket),
  ]
}

function packetToRelayDatagrams(
  endpointId: Uint8Array,
  ecn: EcnCodepoint | null,
  packet: Uint8Array,
): Datagrams {
  return {
    endpointId: copyBytes(endpointId),
    ecn,
    contents: copyBytes(packet),
  }
}

function longHeaderPacketEndOffset(contents: Uint8Array, offset: number): number {
  const packetType = parseQuicLongHeader(contents, offset).packetType
  if (packetType === QuicLongHeaderPacketType.Initial) {
    const prefix = parseQuicInitialPacketHeaderPrefix(contents, offset)
    return checkedPacketEndOffset(contents, prefix.packetNumberOffset + prefix.length)
  }
  if (packetType === QuicLongHeaderPacketType.Handshake) {
    const prefix = parseQuicHandshakePacketHeaderPrefix(contents, offset)
    return checkedPacketEndOffset(contents, prefix.packetNumberOffset + prefix.length)
  }
  throw new RangeError(`unsupported QUIC relay long-header packet type ${packetType}`)
}

function checkedPacketEndOffset(contents: Uint8Array, endOffset: number): number {
  if (endOffset > contents.length) {
    throw new RangeError('not enough bytes for coalesced QUIC packet')
  }
  return endOffset
}

function quicRelayPacketType(packet: Uint8Array): QuicLongHeaderPacketTypeValue {
  return parseQuicLongHeader(packet).packetType
}

function isShortHeaderPacket(packet: Uint8Array): boolean {
  const firstByte = packet[0]
  if (firstByte === undefined) {
    throw new RangeError('relay QUIC datagram is empty')
  }
  return (firstByte & 0x80) === 0
}

function requireConnection(connection: QuicConnectionState | null): QuicConnectionState {
  if (connection === null) {
    throw new RangeError('QUIC relay driver is not connected')
  }
  return connection
}

function requireEndpointId(endpointId: Uint8Array | null): Uint8Array {
  if (endpointId === null) {
    throw new RangeError('QUIC relay peer endpoint id is not known')
  }
  return endpointId
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false
    }
  }
  return true
}

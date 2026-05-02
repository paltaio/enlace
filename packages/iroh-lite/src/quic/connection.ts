import { copyBytes } from '../bytes'
import type { QuicDirectionalKeys } from './crypto'
import {
  QuicOneRttState,
  type QuicOneRttPacketSendResult,
  type QuicOneRttPacketStreamReceiveResult,
  type QuicOneRttStreamPacketSendResult,
} from './one-rtt'
import type { QuicAckReceiveSnapshot } from './ack'
import type { QuicStreamReceiveSnapshot } from './streams'
import { deriveTls13ApplicationTrafficFromHandshakeState } from './tls-application-traffic'
import type {
  Tls13ClientHandshakeState,
  Tls13HandshakeTransportParameters,
  Tls13ServerHandshakeState,
} from './tls-handshake-state'
import {
  QuicEndpointRole,
  type QuicEndpointRoleValue,
  type QuicTransportParameters,
} from './transport-parameters'

export interface QuicConnectionStateOptions {
  readonly role: QuicEndpointRoleValue
  readonly keys: QuicConnectionDirectionalKeys
  readonly localConnectionId: Uint8Array
  readonly peerConnectionId: Uint8Array
  readonly peerTransportParameters?: QuicTransportParameters
  readonly transportParameters?: Tls13HandshakeTransportParameters
  readonly negotiatedAlpn?: Uint8Array
  readonly peerEndpointId?: Uint8Array | null
  readonly nextPacketNumber?: number | bigint
  readonly largestReceivedPacketNumber?: number | bigint | null
}

export interface QuicConnectionFromHandshakeOptions {
  readonly role: QuicEndpointRoleValue
  readonly handshakeState: Tls13ClientHandshakeState | Tls13ServerHandshakeState
  readonly localConnectionId: Uint8Array
  readonly peerConnectionId: Uint8Array
  readonly nextPacketNumber?: number | bigint
  readonly largestReceivedPacketNumber?: number | bigint | null
}

export interface QuicConnectionDirectionalKeys {
  readonly client: QuicDirectionalKeys
  readonly server: QuicDirectionalKeys
}

export interface QuicConnectionReceiveResult extends QuicOneRttPacketStreamReceiveResult {
  readonly ackPacket: QuicOneRttPacketSendResult | null
}

export interface QuicConnectionHandshakeArtifacts {
  readonly negotiatedAlpn: Uint8Array | null
  readonly peerEndpointId: Uint8Array | null
  readonly transportParameters: Tls13HandshakeTransportParameters | null
}

export class QuicConnectionState {
  readonly #role: QuicEndpointRoleValue
  readonly #keys: QuicConnectionDirectionalKeys
  readonly #localConnectionId: Uint8Array
  readonly #peerConnectionId: Uint8Array
  readonly #oneRtt: QuicOneRttState
  readonly #negotiatedAlpn: Uint8Array | null
  readonly #peerEndpointId: Uint8Array | null
  readonly #transportParameters: Tls13HandshakeTransportParameters | null

  constructor(options: QuicConnectionStateOptions) {
    this.#role = options.role
    this.#keys = options.keys
    this.#localConnectionId = copyBytes(options.localConnectionId)
    this.#peerConnectionId = copyBytes(options.peerConnectionId)
    this.#negotiatedAlpn =
      options.negotiatedAlpn === undefined ? null : copyBytes(options.negotiatedAlpn)
    this.#peerEndpointId =
      options.peerEndpointId === undefined || options.peerEndpointId === null
        ? null
        : copyBytes(options.peerEndpointId)
    this.#transportParameters = options.transportParameters ?? null
    this.#oneRtt = new QuicOneRttState(
      options.nextPacketNumber ?? 0,
      options.largestReceivedPacketNumber ?? null,
      {
        localRole: options.role,
        ...(options.peerTransportParameters === undefined
          ? {}
          : { peerTransportParameters: options.peerTransportParameters }),
      },
    )
  }

  get role(): QuicEndpointRoleValue {
    return this.#role
  }

  get transportParameters(): Tls13HandshakeTransportParameters | null {
    return this.#transportParameters
  }

  handshakeArtifacts(): QuicConnectionHandshakeArtifacts {
    return {
      negotiatedAlpn: this.#negotiatedAlpn === null ? null : copyBytes(this.#negotiatedAlpn),
      peerEndpointId: this.#peerEndpointId === null ? null : copyBytes(this.#peerEndpointId),
      transportParameters: this.#transportParameters,
    }
  }

  get nextPacketNumber(): bigint {
    return this.#oneRtt.nextPacketNumber
  }

  get largestReceivedPacketNumber(): bigint | null {
    return this.#oneRtt.largestReceivedPacketNumber
  }

  ackSnapshot(): QuicAckReceiveSnapshot {
    return this.#oneRtt.ackSnapshot()
  }

  streamSnapshot(streamId: number): QuicStreamReceiveSnapshot {
    return this.#oneRtt.streamSnapshot(streamId)
  }

  streamSendOffset(streamId: number): number {
    return this.#oneRtt.streamSendOffset(streamId)
  }

  receive(packet: Uint8Array, ackDelay = 0): QuicConnectionReceiveResult {
    const result = this.#oneRtt.receive(
      packet,
      this.receiveKeys(),
      this.#localConnectionId.length,
      0,
      ackDelay,
    )
    this.#oneRtt.applyStreamFlowControl(result.frames)
    return {
      ...result,
      ackPacket: result.ackFrame === null ? null : this.sendFrames(result.ackFrame),
    }
  }

  sendFrames(frameBytes: Uint8Array): QuicOneRttPacketSendResult {
    return this.#oneRtt.send(this.sendKeys(), this.#peerConnectionId, frameBytes)
  }

  sendStream(streamId: number, data: Uint8Array, fin = false): QuicOneRttStreamPacketSendResult {
    return this.#oneRtt.sendStream(this.sendKeys(), this.#peerConnectionId, streamId, data, fin)
  }
  private sendKeys(): QuicDirectionalKeys {
    return this.#role === QuicEndpointRole.Client ? this.#keys.client : this.#keys.server
  }

  private receiveKeys(): QuicDirectionalKeys {
    return this.#role === QuicEndpointRole.Client ? this.#keys.server : this.#keys.client
  }
}

export function createQuicConnectionStateFromHandshake(
  options: QuicConnectionFromHandshakeOptions,
): QuicConnectionState {
  const applicationTraffic = deriveTls13ApplicationTrafficFromHandshakeState(options.handshakeState)
  return new QuicConnectionState({
    role: options.role,
    keys: applicationTraffic.keys,
    localConnectionId: options.localConnectionId,
    peerConnectionId: options.peerConnectionId,
    peerTransportParameters:
      options.role === QuicEndpointRole.Client
        ? options.handshakeState.transportParameters.server
        : options.handshakeState.transportParameters.client,
    transportParameters: options.handshakeState.transportParameters,
    negotiatedAlpn: options.handshakeState.negotiatedAlpn,
    peerEndpointId: options.handshakeState.peerEndpointId,
    ...(options.nextPacketNumber === undefined
      ? {}
      : { nextPacketNumber: options.nextPacketNumber }),
    ...(options.largestReceivedPacketNumber === undefined
      ? {}
      : { largestReceivedPacketNumber: options.largestReceivedPacketNumber }),
  })
}

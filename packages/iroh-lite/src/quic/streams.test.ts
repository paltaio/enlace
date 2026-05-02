import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey } from '../testing/rfc8448-tls'
import { tlsHandshakeStateFixture } from '../testing/tls-handshake-fixtures'
import type { QuicDirectionalKeys } from './crypto'
import {
  encodeQuicMaxDataFrame,
  encodeQuicMaxStreamDataFrame,
  encodeQuicPingFrame,
  encodeQuicStreamFrame,
  parseQuicFrames,
} from './frame'
import { decryptQuicOneRttPacket, encryptQuicOneRttPacket } from './one-rtt'
import {
  QuicStreamReceiveState,
  QuicStreamSendState,
  QuicStreamState,
  type QuicStreamReceiveOutput,
} from './streams'
import { QuicEndpointRole, defaultQuicTransportParameters } from './transport-parameters'
import { deriveTls13ApplicationTrafficFromHandshakeState } from './tls-application-traffic'
import { verifyTls13ClientHandshakeState } from './tls-handshake-state'

describe('QUIC stream receive state', () => {
  test('emits contiguous stream data and FIN state in order', () => {
    const state = new QuicStreamReceiveState()
    const first = state.receive(streamFrame(4, 0, '6865', false))
    const second = state.receive(streamFrame(4, 2, '6c6c6f', true))

    expect(outputHex(first)).toEqual({
      streamId: 4,
      streamOffset: 0,
      data: '6865',
      fin: false,
      finalSize: null,
      complete: false,
    })
    expect(outputHex(second)).toEqual({
      streamId: 4,
      streamOffset: 2,
      data: '6c6c6f',
      fin: true,
      finalSize: 5,
      complete: true,
    })
    expect(state.snapshot(4)).toEqual({
      streamId: 4,
      readOffset: 5,
      finalSize: 5,
      complete: true,
    })
  })

  test('buffers out-of-order stream fragments until gaps fill', () => {
    const state = new QuicStreamReceiveState()
    const outOfOrder = state.receive(streamFrame(8, 2, '6c6c6f', true))
    const filled = state.receive(streamFrame(8, 0, '6865', false))

    expect(outOfOrder).toBeNull()
    expect(outputHex(filled)).toEqual({
      streamId: 8,
      streamOffset: 0,
      data: '68656c6c6f',
      fin: true,
      finalSize: 5,
      complete: true,
    })
  })

  test('accepts duplicate identical overlaps and rejects conflicts', () => {
    const state = new QuicStreamReceiveState()
    expect(outputHex(state.receive(streamFrame(0, 0, '68656c6c6f', false)))?.data).toBe(
      '68656c6c6f',
    )
    expect(state.receive(streamFrame(0, 1, '656c6c', false))).toBeNull()

    expect(() => state.receive(streamFrame(0, 1, '006c6c', false))).toThrow(
      'conflicting QUIC STREAM data',
    )
  })

  test('rejects FIN final-size changes and data beyond final size', () => {
    const state = new QuicStreamReceiveState()
    expect(state.receive(streamFrame(0, 3, '6c6f', true))).toBeNull()

    expect(() => state.receive(streamFrame(0, 0, '68656c', true))).toThrow(
      'conflicting QUIC STREAM final size',
    )
    expect(() => state.receive(streamFrame(0, 5, '21', false))).toThrow(
      'QUIC STREAM data exceeds final size',
    )
  })

  test('tracks multiple streams independently', () => {
    const state = new QuicStreamReceiveState()
    const outputs = state.receiveFrames([
      streamFrame(0, 0, '6869', false),
      { type: 'ping', offset: 0, endOffset: 1 },
      streamFrame(4, 0, '6f6b', true),
    ])

    expect(outputs.map(outputHex)).toEqual([
      {
        streamId: 0,
        streamOffset: 0,
        data: '6869',
        fin: false,
        finalSize: null,
        complete: false,
      },
      {
        streamId: 4,
        streamOffset: 0,
        data: '6f6b',
        fin: true,
        finalSize: 2,
        complete: true,
      },
    ])
    expect(state.snapshot(0).readOffset).toBe(2)
    expect(state.snapshot(4).complete).toBe(true)
  })
})

describe('QUIC stream send state', () => {
  test('produces parser-compatible STREAM frames and advances offsets', () => {
    const state = new QuicStreamSendState()
    const first = state.send(0, hexToBytes('6865'))
    const second = state.send(0, hexToBytes('6c6c6f'), true)

    expect(first.streamOffset).toBe(0)
    expect(first.nextStreamOffset).toBe(2)
    expect(second.streamOffset).toBe(2)
    expect(second.nextStreamOffset).toBe(5)
    expect(state.offset(0)).toBe(5)
    expect(parseQuicFrames(concatBytes([first.frameBytes, second.frameBytes])).frames).toEqual([
      {
        type: 'stream',
        streamId: 0,
        streamOffset: 0,
        data: hexToBytes('6865'),
        fin: false,
        offset: 0,
        endOffset: first.frameBytes.length,
      },
      {
        type: 'stream',
        streamId: 0,
        streamOffset: 2,
        data: hexToBytes('6c6c6f'),
        fin: true,
        offset: first.frameBytes.length,
        endOffset: first.frameBytes.length + second.frameBytes.length,
      },
    ])
  })

  test('advances send offsets only after frame bytes are produced', () => {
    const state = new QuicStreamSendState()

    expect(() => state.send(0, new Uint8Array())).toThrow('QUIC STREAM frame requires data or FIN')
    expect(state.offset(0)).toBe(0)

    const finished = state.send(0, new Uint8Array(), true)
    expect(finished.nextStreamOffset).toBe(0)
    expect(state.offset(0)).toBe(0)
    expect(() => state.send(0, hexToBytes('61'))).toThrow('QUIC stream is already finished')
    expect(state.offset(0)).toBe(0)
  })

  test('rejects invalid stream identifiers before mutating send state', () => {
    const state = new QuicStreamSendState()

    expect(() => state.send(-1, hexToBytes('61'))).toThrow('QUIC stream id out of range')
    expect(state.offset(0)).toBe(0)
  })

  test('enforces connection and stream send credit', () => {
    const state = new QuicStreamSendState(4)
    state.applyMaxStreamData({
      type: 'max-stream-data',
      streamId: 0,
      maximumStreamData: 3,
      offset: 0,
      endOffset: 0,
    })

    const first = state.send(0, hexToBytes('6865'))
    expect(first.nextStreamOffset).toBe(2)
    expect(state.sentData()).toBe(2)
    expect(() => state.send(0, hexToBytes('6c6c'))).toThrow(
      'QUIC STREAM data exceeds MAX_STREAM_DATA',
    )
    expect(state.offset(0)).toBe(2)
    expect(state.sentData()).toBe(2)

    state.applyMaxStreamData({
      type: 'max-stream-data',
      streamId: 0,
      maximumStreamData: 5,
      offset: 0,
      endOffset: 0,
    })
    state.send(0, hexToBytes('6c6c'))
    expect(state.offset(0)).toBe(4)
    expect(state.sentData()).toBe(4)
    expect(() => state.send(4, hexToBytes('21'))).toThrow('QUIC STREAM data exceeds MAX_DATA')
  })

  test('applies parsed MAX_DATA and MAX_STREAM_DATA frame envelopes', () => {
    const state = new QuicStreamSendState(1)
    const frames = parseQuicFrames(
      concatBytes([encodeQuicMaxDataFrame(5), encodeQuicMaxStreamDataFrame(4, 2)]),
    ).frames

    state.applyFlowControlFrames(frames)
    const sent = state.send(4, hexToBytes('6869'), true)

    expect(state.maxData()).toBe(5)
    expect(state.maxStreamData(4)).toBe(2)
    expect(sent.nextStreamOffset).toBe(2)
  })

  test('does not lower existing flow-control limits', () => {
    const state = new QuicStreamSendState(5)

    state.applyMaxData({ type: 'max-data', maximumData: 3, offset: 0, endOffset: 0 })
    state.applyMaxStreamData({
      type: 'max-stream-data',
      streamId: 0,
      maximumStreamData: 4,
      offset: 0,
      endOffset: 0,
    })
    state.applyMaxStreamData({
      type: 'max-stream-data',
      streamId: 0,
      maximumStreamData: 2,
      offset: 0,
      endOffset: 0,
    })

    expect(state.maxData()).toBe(5)
    expect(state.maxStreamData(0)).toBe(4)
  })

  test('uses peer transport parameters as initial send credit', () => {
    const state = new QuicStreamSendState({
      localRole: QuicEndpointRole.Client,
      peerTransportParameters: {
        ...defaultQuicTransportParameters(),
        initialMaxData: 6n,
        initialMaxStreamDataBidiLocal: 1n,
        initialMaxStreamDataBidiRemote: 3n,
        initialMaxStreamDataUni: 2n,
      },
    })

    expect(state.maxData()).toBe(6)
    expect(state.maxStreamData(0)).toBe(3)
    expect(state.maxStreamData(1)).toBe(1)
    expect(state.maxStreamData(2)).toBe(2)
    state.send(0, hexToBytes('616263'))
    expect(() => state.send(0, hexToBytes('64'))).toThrow(
      'QUIC STREAM data exceeds MAX_STREAM_DATA',
    )
    expect(() => state.send(3, hexToBytes('61'))).toThrow(
      'QUIC cannot send on peer-initiated unidirectional stream',
    )
  })

  test('lets MAX_STREAM_DATA raise initial stream credit', () => {
    const state = new QuicStreamSendState({
      localRole: QuicEndpointRole.Server,
      peerTransportParameters: {
        ...defaultQuicTransportParameters(),
        initialMaxData: 5n,
        initialMaxStreamDataBidiRemote: 1n,
      },
    })

    expect(state.maxStreamData(1)).toBe(1)
    state.applyMaxStreamData({
      type: 'max-stream-data',
      streamId: 1,
      maximumStreamData: 4,
      offset: 0,
      endOffset: 0,
    })

    expect(state.maxStreamData(1)).toBe(4)
    expect(state.send(1, hexToBytes('61626364')).nextStreamOffset).toBe(4)
  })

  test('does not lower initial stream credit with MAX_STREAM_DATA', () => {
    const state = new QuicStreamSendState({
      localRole: QuicEndpointRole.Client,
      peerTransportParameters: {
        ...defaultQuicTransportParameters(),
        initialMaxData: 8n,
        initialMaxStreamDataBidiRemote: 4n,
      },
    })

    state.applyMaxStreamData({
      type: 'max-stream-data',
      streamId: 0,
      maximumStreamData: 2,
      offset: 0,
      endOffset: 0,
    })

    expect(state.maxStreamData(0)).toBe(4)
    expect(state.send(0, hexToBytes('61626364')).nextStreamOffset).toBe(4)
  })
})

describe('QUIC stream payload integration', () => {
  test('parses decrypted 1-RTT payload bytes into stream state', async () => {
    const keys = await applicationTrafficKeys()
    const destinationConnectionId = hexToBytes('01020304')
    const streamState = new QuicStreamState()
    const payload = concatBytes([
      encodeQuicPingFrame(),
      encodeQuicStreamFrame(0, 0, hexToBytes('6865'), false),
      encodeQuicStreamFrame(0, 2, hexToBytes('6c6c6f'), true),
    ])
    const packet = encryptQuicOneRttPacket(keys.client, {
      destinationConnectionId,
      packetNumber: 4,
      packetNumberLength: 2,
      payload,
    })
    const decrypted = decryptQuicOneRttPacket(packet, keys.client, destinationConnectionId.length)
    const result = streamState.receiveFrameBytes(decrypted.payload)

    expect(result.frames.map((frame) => frame.type)).toEqual(['ping', 'stream', 'stream'])
    expect(result.streamOutputs.map(outputHex)).toEqual([
      {
        streamId: 0,
        streamOffset: 0,
        data: '6865',
        fin: false,
        finalSize: null,
        complete: false,
      },
      {
        streamId: 0,
        streamOffset: 2,
        data: '6c6c6f',
        fin: true,
        finalSize: 5,
        complete: true,
      },
    ])
    expect(streamState.receiveSnapshot(0).complete).toBe(true)
  })

  test('rejects malformed STREAM bytes through the existing parser', () => {
    const state = new QuicStreamReceiveState()

    expect(() => state.receiveFrameBytes(hexToBytes('0a0105aabbcc'))).toThrow(
      'not enough bytes for QUIC STREAM frame data',
    )
  })
})

function streamFrame(
  streamId: number,
  streamOffset: number,
  data: string,
  fin: boolean,
): {
  readonly type: 'stream'
  readonly streamId: number
  readonly streamOffset: number
  readonly data: Uint8Array
  readonly fin: boolean
  readonly offset: number
  readonly endOffset: number
} {
  return {
    type: 'stream',
    streamId,
    streamOffset,
    data: hexToBytes(data),
    fin,
    offset: 0,
    endOffset: 0,
  }
}

function outputHex(output: QuicStreamReceiveOutput | null): {
  readonly streamId: number
  readonly streamOffset: number
  readonly data: string
  readonly fin: boolean
  readonly finalSize: number | null
  readonly complete: boolean
} | null {
  if (output === null) {
    return null
  }
  return {
    streamId: output.streamId,
    streamOffset: output.streamOffset,
    data: bytesToHex(output.data),
    fin: output.fin,
    finalSize: output.finalSize,
    complete: output.complete,
  }
}

async function applicationTrafficKeys(): Promise<{
  readonly client: QuicDirectionalKeys
  readonly server: QuicDirectionalKeys
}> {
  const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
  const state = await verifyTls13ClientHandshakeState({
    x25519PrivateKey: rfc8448ClientPrivateKey,
    expectedServerEndpointId: fixture.server.endpointId,
    messages: fixture.messages,
  })
  return deriveTls13ApplicationTrafficFromHandshakeState(state).keys
}

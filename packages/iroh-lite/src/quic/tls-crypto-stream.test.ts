import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientHello } from '../testing/rfc8448-tls'
import { rfc9001ClientInitialFrames, rfc9001ServerInitialFrames } from '../testing/rfc9001-quic'
import { parseQuicFrames, type QuicCryptoFrame } from './frame'
import {
  collectQuicTlsHandshakeMessages,
  type QuicTlsHandshakeMessage,
  type QuicTlsHandshakeMessages,
} from './tls-crypto-stream'

describe('TLS handshake collection from QUIC CRYPTO frames', () => {
  test('collects RFC 9001 ClientHello from Initial CRYPTO frames', () => {
    const result = collectQuicTlsHandshakeMessages(cryptoFrames(rfc9001ClientInitialFrames))

    expect(result.endOffset).toBe(result.cryptoStream.length)
    expect(result.messages).toHaveLength(1)
    const message = firstMessage(result)
    expect(message.handshake.kind).toBe('client-hello')
    expect(bytesToHex(message.message)).toStartWith('010000ed0303')
  })

  test('collects RFC 9001 ServerHello from Initial CRYPTO frames', () => {
    const result = collectQuicTlsHandshakeMessages(cryptoFrames(rfc9001ServerInitialFrames))

    expect(result.endOffset).toBe(result.cryptoStream.length)
    expect(result.messages).toHaveLength(1)
    const message = firstMessage(result)
    expect(message.handshake.kind).toBe('server-hello')
    expect(bytesToHex(message.message)).toStartWith('020000560303')
  })

  test('collects split RFC 8448 handshakes in stream order', () => {
    const splitOffset = 16
    const result = collectQuicTlsHandshakeMessages([
      cryptoFrame(splitOffset, rfc8448ClientHello.subarray(splitOffset)),
      cryptoFrame(0, rfc8448ClientHello.subarray(0, splitOffset)),
    ])

    expect(result.messages).toHaveLength(1)
    const message = firstMessage(result)
    expect(message.handshake.kind).toBe('client-hello')
    expect(message.message).toEqual(rfc8448ClientHello)
  })

  test('accepts duplicate identical CRYPTO overlap', () => {
    const result = collectQuicTlsHandshakeMessages([
      cryptoFrame(0, rfc8448ClientHello),
      cryptoFrame(4, rfc8448ClientHello.subarray(4)),
    ])

    expect(firstMessage(result).message).toEqual(rfc8448ClientHello)
  })

  test('rejects conflicting CRYPTO overlap', () => {
    expect(() =>
      collectQuicTlsHandshakeMessages([
        cryptoFrame(0, rfc8448ClientHello),
        cryptoFrame(4, hexToBytes('00')),
      ]),
    ).toThrow('conflicting QUIC CRYPTO stream data')
  })

  test('rejects incomplete TLS handshake messages', () => {
    expect(() =>
      collectQuicTlsHandshakeMessages([
        cryptoFrame(0, rfc8448ClientHello.subarray(0, rfc8448ClientHello.length - 1)),
      ]),
    ).toThrow('not enough bytes for TLS handshake body')
  })
})

function cryptoFrames(bytes: Uint8Array): QuicCryptoFrame[] {
  return parseQuicFrames(bytes).frames.filter(
    (frame): frame is QuicCryptoFrame => frame.type === 'crypto',
  )
}

function firstMessage(result: QuicTlsHandshakeMessages): QuicTlsHandshakeMessage {
  const message = result.messages[0]
  if (message === undefined) {
    throw new Error('expected TLS handshake message')
  }
  return message
}

function cryptoFrame(cryptoOffset: number, data: Uint8Array): QuicCryptoFrame {
  return {
    type: 'crypto',
    cryptoOffset,
    data,
    offset: 0,
    endOffset: data.length,
  }
}

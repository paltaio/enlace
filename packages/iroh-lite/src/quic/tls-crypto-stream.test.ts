import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientHello } from '../testing/rfc8448-tls'
import { rfc9001ClientInitialFrames, rfc9001ServerInitialFrames } from '../testing/rfc9001-quic'
import { parseQuicFrames, type QuicCryptoFrame } from './frame'
import { TlsHandshakeKind, TlsHandshakeType } from './tls'
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

  test('collects multiple opaque encrypted handshakes in stream order', () => {
    const encryptedExtensions = tlsHandshakeMessage(
      TlsHandshakeType.EncryptedExtensions,
      hexToBytes('0000'),
    )
    const certificate = tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes('000000'))
    const certificateVerify = tlsHandshakeMessage(
      TlsHandshakeType.CertificateVerify,
      hexToBytes('04030040'),
    )
    const finished = tlsHandshakeMessage(
      TlsHandshakeType.Finished,
      hexToBytes('000102030405060708090a0b0c0d0e0f'),
    )
    const stream = concatBytes([encryptedExtensions, certificate, certificateVerify, finished])
    const splitOffset = encryptedExtensions.length + 2
    const result = collectQuicTlsHandshakeMessages([
      cryptoFrame(splitOffset, stream.subarray(splitOffset)),
      cryptoFrame(0, stream.subarray(0, splitOffset)),
    ])

    expect(result.endOffset).toBe(stream.length)
    expect(result.messages.map((message) => message.handshake.kind)).toEqual([
      TlsHandshakeKind.EncryptedExtensions,
      TlsHandshakeKind.Certificate,
      TlsHandshakeKind.CertificateVerify,
      TlsHandshakeKind.Finished,
    ])
    expect(messageAt(result, 0).message).toEqual(encryptedExtensions)
    expect(messageAt(result, 1).message).toEqual(certificate)
    expect(messageAt(result, 2).message).toEqual(certificateVerify)
    expect(messageAt(result, 3).message).toEqual(finished)
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

function messageAt(result: QuicTlsHandshakeMessages, index: number): QuicTlsHandshakeMessage {
  const message = result.messages[index]
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

function tlsHandshakeMessage(handshakeType: number, body: Uint8Array): Uint8Array {
  if (!Number.isInteger(handshakeType) || handshakeType < 0 || handshakeType > 0xff) {
    throw new RangeError('TLS handshake type out of range')
  }
  if (body.length > 0xffffff) {
    throw new RangeError('TLS handshake body too large')
  }
  const out = new Uint8Array(4 + body.length)
  out[0] = handshakeType
  out[1] = (body.length >>> 16) & 0xff
  out[2] = (body.length >>> 8) & 0xff
  out[3] = body.length & 0xff
  out.set(body, 4)
  return out
}

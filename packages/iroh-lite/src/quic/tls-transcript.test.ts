import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHello,
  rfc8448ClientServerHelloTranscriptHash,
  rfc8448ServerHello,
} from '../testing/rfc8448-tls'
import type { QuicCryptoFrame } from './frame'
import { TlsHandshakeKind, TlsHandshakeType } from './tls'
import { collectQuicTlsHandshakeMessages } from './tls-crypto-stream'
import { collectTlsHandshakeTranscript, TlsHandshakeTranscriptAccumulator } from './tls-transcript'

describe('TLS handshake transcript from collected QUIC CRYPTO messages', () => {
  test('hashes RFC 8448 ClientHello and ServerHello transcript bytes', () => {
    const clientMessages = collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)])
    const serverMessages = collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)])
    const transcript = collectTlsHandshakeTranscript([clientMessages, serverMessages])

    expect(transcript.messages.map((message) => message.handshake.kind)).toEqual([
      TlsHandshakeKind.ClientHello,
      TlsHandshakeKind.ServerHello,
    ])
    expect(transcript.bytes).toEqual(concatBytes([rfc8448ClientHello, rfc8448ServerHello]))
    expect(bytesToHex(transcript.hash)).toBe(bytesToHex(rfc8448ClientServerHelloTranscriptHash))
  })

  test('extends transcript bytes with opaque encrypted handshakes in order', () => {
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
    const clientMessages = collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)])
    const serverMessages = collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)])
    const encryptedMessages = collectQuicTlsHandshakeMessages([
      cryptoFrame(0, concatBytes([encryptedExtensions, certificate, certificateVerify, finished])),
    ])
    const transcript = collectTlsHandshakeTranscript([
      clientMessages,
      serverMessages,
      encryptedMessages,
    ])

    expect(transcript.messages.map((message) => message.handshake.kind)).toEqual([
      TlsHandshakeKind.ClientHello,
      TlsHandshakeKind.ServerHello,
      TlsHandshakeKind.EncryptedExtensions,
      TlsHandshakeKind.Certificate,
      TlsHandshakeKind.CertificateVerify,
      TlsHandshakeKind.Finished,
    ])
    expect(transcript.bytes).toEqual(
      concatBytes([
        rfc8448ClientHello,
        rfc8448ServerHello,
        encryptedExtensions,
        certificate,
        certificateVerify,
        finished,
      ]),
    )
  })

  test('updates transcript snapshots as message blocks are appended', () => {
    const accumulator = new TlsHandshakeTranscriptAccumulator()
    const clientMessages = collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)])
    const serverMessages = collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)])

    accumulator.append(clientMessages)
    const clientOnly = accumulator.snapshot()
    accumulator.append(serverMessages)
    const clientAndServer = accumulator.snapshot()

    expect(clientOnly.bytes).toEqual(rfc8448ClientHello)
    expect(clientAndServer.bytes).toEqual(concatBytes([rfc8448ClientHello, rfc8448ServerHello]))
    expect(bytesToHex(clientAndServer.hash)).toBe(
      bytesToHex(rfc8448ClientServerHelloTranscriptHash),
    )
  })

  test('keeps transcript snapshots stable after later appends', () => {
    const accumulator = new TlsHandshakeTranscriptAccumulator()
    accumulator.append(collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]))
    const clientOnly = accumulator.snapshot()

    accumulator.append(collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)]))

    expect(clientOnly.bytes).toEqual(rfc8448ClientHello)
    expect(clientOnly.messages).toHaveLength(1)
    expect(clientOnly.messages[0]?.message).toEqual(rfc8448ClientHello)
  })

  test('changes transcript hash when opaque handshake bytes change', () => {
    const encryptedExtensions = tlsHandshakeMessage(
      TlsHandshakeType.EncryptedExtensions,
      hexToBytes('0000'),
    )
    const changedEncryptedExtensions = tlsHandshakeMessage(
      TlsHandshakeType.EncryptedExtensions,
      hexToBytes('0001'),
    )

    const transcript = collectTlsHandshakeTranscript([
      collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]),
      collectQuicTlsHandshakeMessages([cryptoFrame(0, encryptedExtensions)]),
    ])
    const changedTranscript = collectTlsHandshakeTranscript([
      collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]),
      collectQuicTlsHandshakeMessages([cryptoFrame(0, changedEncryptedExtensions)]),
    ])

    expect(bytesToHex(changedTranscript.hash)).not.toBe(bytesToHex(transcript.hash))
  })

  test('includes unknown handshake messages as raw transcript bytes', () => {
    const unknown = tlsHandshakeMessage(0xfe, hexToBytes('aabbcc'))
    const messages = collectQuicTlsHandshakeMessages([cryptoFrame(0, unknown)])
    const transcript = collectTlsHandshakeTranscript([messages])

    expect(transcript.messages.map((message) => message.handshake.kind)).toEqual([
      TlsHandshakeKind.Unknown,
    ])
    expect(transcript.bytes).toEqual(unknown)
  })

  test('keeps browser runtime module free of Node and Bun APIs', async () => {
    const source = await Bun.file(new URL('./tls-transcript.ts', import.meta.url)).text()

    expect(source).not.toContain("from 'node:")
    expect(source).not.toContain('Bun.')
    expect(source).not.toContain('process.')
  })
})

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

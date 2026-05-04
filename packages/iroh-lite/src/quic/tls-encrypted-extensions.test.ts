import { describe, expect, test } from 'bun:test'

import { concatBytes, writeU16BE } from '../bytes'
import { hexToBytes } from '../testing/hex'
import { parseTlsHandshakes, TlsExtensionType, TlsHandshakeKind, TlsHandshakeType } from './tls'
import { parseTlsEncryptedExtensions } from './tls-encrypted-extensions'

describe('TLS 1.3 EncryptedExtensions primitives', () => {
  test('parses encrypted extension list', () => {
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.EncryptedExtensions,
        tlsExtensions([
          {
            type: TlsExtensionType.ApplicationLayerProtocolNegotiation,
            data: hexToBytes('0003026833'),
          },
          {
            type: TlsExtensionType.QuicTransportParameters,
            data: hexToBytes('0000'),
          },
        ]),
      ),
    )

    expect(handshake.kind).toBe(TlsHandshakeKind.EncryptedExtensions)
    expect(parseTlsEncryptedExtensions(handshake)).toEqual({
      extensions: [
        {
          extensionType: TlsExtensionType.ApplicationLayerProtocolNegotiation,
          data: hexToBytes('0003026833'),
          offset: 2,
          endOffset: 11,
        },
        {
          extensionType: TlsExtensionType.QuicTransportParameters,
          data: hexToBytes('0000'),
          offset: 11,
          endOffset: 17,
        },
      ],
    })
  })

  test('rejects non-EncryptedExtensions and malformed bodies', () => {
    expect(() =>
      parseTlsEncryptedExtensions(
        parseSingleHandshake(tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes(''))),
      ),
    ).toThrow('TLS handshake must be EncryptedExtensions')
    expect(() =>
      parseTlsEncryptedExtensions(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.EncryptedExtensions, hexToBytes('0003')),
        ),
      ),
    ).toThrow('not enough bytes for TLS EncryptedExtensions')
    expect(() =>
      parseTlsEncryptedExtensions(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.EncryptedExtensions, hexToBytes('00050010000208')),
        ),
      ),
    ).toThrow('not enough bytes for TLS EncryptedExtensions data')
  })
})

interface ExtensionFixture {
  readonly type: number
  readonly data: Uint8Array
}

function parseSingleHandshake(message: Uint8Array) {
  const result = parseTlsHandshakes(message)
  const handshake = result.handshakes[0]
  if (handshake === undefined) {
    throw new Error('expected TLS handshake')
  }
  return handshake
}

function tlsHandshakeMessage(handshakeType: number, body: Uint8Array): Uint8Array {
  if (!Number.isInteger(handshakeType) || handshakeType < 0 || handshakeType > 0xff) {
    throw new RangeError('TLS handshake type out of range')
  }
  if (body.length > 0xffffff) {
    throw new RangeError('TLS handshake body too large')
  }
  return concatBytes([
    new Uint8Array([
      handshakeType,
      (body.length >>> 16) & 0xff,
      (body.length >>> 8) & 0xff,
      body.length & 0xff,
    ]),
    body,
  ])
}

function tlsExtensions(extensions: readonly ExtensionFixture[]): Uint8Array {
  return tlsU16Vector(concatBytes(extensions.map(tlsExtension)))
}

function tlsExtension(extension: ExtensionFixture): Uint8Array {
  return concatBytes([
    writeU16BE(extension.type),
    writeU16BE(extension.data.length),
    extension.data,
  ])
}

function tlsU16Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) {
    throw new RangeError('TLS u16 vector too large')
  }
  return concatBytes([writeU16BE(bytes.length), bytes])
}

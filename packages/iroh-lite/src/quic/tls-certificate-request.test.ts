import { describe, expect, test } from 'bun:test'

import { concatBytes, writeU16BE } from '../bytes'
import { hexToBytes } from '../testing/hex'
import { parseTlsHandshakes, TlsHandshakeKind, TlsHandshakeType } from './tls'
import { parseTlsCertificateRequest } from './tls-certificate-request'

describe('TLS 1.3 CertificateRequest primitives', () => {
  test('parses request context and extensions', () => {
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.CertificateRequest,
        concatBytes([
          tlsU8Vector(hexToBytes('aabb')),
          tlsExtensions([{ type: 0x000d, data: hexToBytes('0807') }]),
        ]),
      ),
    )

    expect(handshake.kind).toBe(TlsHandshakeKind.CertificateRequest)
    expect(parseTlsCertificateRequest(handshake)).toEqual({
      requestContext: hexToBytes('aabb'),
      extensions: [
        {
          extensionType: 0x000d,
          data: hexToBytes('0807'),
          offset: 5,
          endOffset: 11,
        },
      ],
    })
  })

  test('rejects non-CertificateRequest and malformed bodies', () => {
    expect(() =>
      parseTlsCertificateRequest(
        parseSingleHandshake(tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes(''))),
      ),
    ).toThrow('TLS handshake must be CertificateRequest')
    expect(() =>
      parseTlsCertificateRequest(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.CertificateRequest, hexToBytes('03aa')),
        ),
      ),
    ).toThrow('not enough bytes for TLS CertificateRequest context')
    expect(() =>
      parseTlsCertificateRequest(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.CertificateRequest, hexToBytes('00000300')),
        ),
      ),
    ).toThrow('not enough bytes for TLS CertificateRequest extensions')
    expect(() =>
      parseTlsCertificateRequest(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.CertificateRequest, hexToBytes('000000')),
        ),
      ),
    ).toThrow('TLS CertificateRequest extensions must not be empty')
    expect(() =>
      parseTlsCertificateRequest(
        parseSingleHandshake(
          tlsHandshakeMessage(
            TlsHandshakeType.CertificateRequest,
            concatBytes([tlsU8Vector(hexToBytes('')), hexToBytes('0005000d000208')]),
          ),
        ),
      ),
    ).toThrow('not enough bytes for TLS CertificateRequest extension data')
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

function tlsU8Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xff) {
    throw new RangeError('TLS u8 vector too large')
  }
  return concatBytes([new Uint8Array([bytes.length]), bytes])
}

function tlsU16Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) {
    throw new RangeError('TLS u16 vector too large')
  }
  return concatBytes([writeU16BE(bytes.length), bytes])
}

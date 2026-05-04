import { describe, expect, test } from 'bun:test'

import { concatBytes, writeU16BE } from '../bytes'
import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { parseTlsHandshakes, TlsHandshakeKind, TlsHandshakeType } from './tls'
import {
  ed25519SpkiFromEndpointId,
  endpointIdFromEd25519Spki,
  parseTlsCertificate,
  requireTlsEd25519RawPublicKeyCertificate,
} from './tls-certificate'

describe('TLS 1.3 raw public key Certificate primitives', () => {
  test('parses Certificate request context and entries', () => {
    const certData = hexToBytes('aabbcc')
    const extensions = hexToBytes('00100000')
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.Certificate,
        certificateBody(hexToBytes('01'), [
          {
            data: certData,
            extensions,
          },
        ]),
      ),
    )

    expect(handshake.kind).toBe(TlsHandshakeKind.Certificate)
    expect(parseTlsCertificate(handshake)).toEqual({
      requestContext: hexToBytes('01'),
      entries: [
        {
          data: certData,
          extensions,
          offset: 5,
          endOffset: 17,
        },
      ],
    })
  })

  test('extracts endpoint id from an Ed25519 raw public key certificate', async () => {
    const secretKey = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
    const endpointId = await endpointIdFromSecretKey(secretKey)
    const spki = ed25519SpkiFromEndpointId(endpointId)
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.Certificate,
        certificateBody(hexToBytes(''), [
          {
            data: spki,
            extensions: hexToBytes(''),
          },
        ]),
      ),
    )

    expect(bytesToHex(endpointIdFromEd25519Spki(spki))).toBe(bytesToHex(endpointId))
    expect(bytesToHex(spki)).toBe(
      bytesToHex(concatBytes([hexToBytes('302a300506032b6570032100'), endpointId])),
    )
    expect(bytesToHex(requireTlsEd25519RawPublicKeyCertificate(handshake))).toBe(
      bytesToHex(endpointId),
    )
  })

  test('rejects non-Certificate and malformed Certificate bodies', () => {
    expect(() =>
      parseTlsCertificate(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.EncryptedExtensions, hexToBytes('')),
        ),
      ),
    ).toThrow('TLS handshake must be Certificate')
    expect(() =>
      parseTlsCertificate(
        parseSingleHandshake(tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes('03aa'))),
      ),
    ).toThrow('not enough bytes for TLS Certificate request context')
    expect(() =>
      parseTlsCertificate(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes('00000001')),
        ),
      ),
    ).toThrow('TLS Certificate list length mismatch')
    expect(() =>
      parseTlsCertificate(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes('00000006000004aabbcc')),
        ),
      ),
    ).toThrow('not enough bytes for TLS Certificate data')
    expect(() =>
      parseTlsCertificate(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes('000000050000000000')),
        ),
      ),
    ).toThrow('TLS Certificate data must not be empty')
    expect(() =>
      parseTlsCertificate(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.Certificate, hexToBytes('00000007000001aa000200')),
        ),
      ),
    ).toThrow('not enough bytes for TLS Certificate extensions')
  })

  test('rejects unsupported raw public key certificates', () => {
    const endpointId = hexToBytes(
      '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
    )

    expect(() => endpointIdFromEd25519Spki(hexToBytes('00'))).toThrow(
      'TLS raw public key must be an Ed25519 SubjectPublicKeyInfo',
    )
    expect(() =>
      endpointIdFromEd25519Spki(hexToBytes('302a300506032b6571032100' + '00'.repeat(32))),
    ).toThrow('TLS raw public key must be an Ed25519 SubjectPublicKeyInfo')
    expect(() =>
      requireTlsEd25519RawPublicKeyCertificate(
        parseSingleHandshake(
          tlsHandshakeMessage(
            TlsHandshakeType.Certificate,
            certificateBody(hexToBytes(''), [
              {
                data: ed25519SpkiFromEndpointId(endpointId),
                extensions: hexToBytes(''),
              },
              {
                data: ed25519SpkiFromEndpointId(endpointId),
                extensions: hexToBytes(''),
              },
            ]),
          ),
        ),
      ),
    ).toThrow('TLS Certificate must contain exactly one raw public key')
  })
})

interface CertificateEntryFixture {
  readonly data: Uint8Array
  readonly extensions: Uint8Array
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

function certificateBody(
  requestContext: Uint8Array,
  entries: readonly CertificateEntryFixture[],
): Uint8Array {
  return concatBytes([
    tlsU8Vector(requestContext),
    tlsU24Vector(concatBytes(entries.map(certificateEntry))),
  ])
}

function certificateEntry(entry: CertificateEntryFixture): Uint8Array {
  return concatBytes([
    tlsU24Vector(entry.data),
    writeU16BE(entry.extensions.length),
    entry.extensions,
  ])
}

function tlsU8Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xff) {
    throw new RangeError('TLS u8 vector too large')
  }
  return concatBytes([new Uint8Array([bytes.length]), bytes])
}

function tlsU24Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffffff) {
    throw new RangeError('TLS u24 vector too large')
  }
  return concatBytes([
    new Uint8Array([
      (bytes.length >>> 16) & 0xff,
      (bytes.length >>> 8) & 0xff,
      bytes.length & 0xff,
    ]),
    bytes,
  ])
}

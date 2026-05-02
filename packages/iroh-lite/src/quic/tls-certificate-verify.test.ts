import { describe, expect, test } from 'bun:test'

import { concatBytes, writeU16BE } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientServerHelloTranscriptHash } from '../testing/rfc8448-tls'
import { parseTlsHandshakes, TlsHandshakeKind, TlsHandshakeType } from './tls'
import { ed25519SpkiFromEndpointId } from './tls-certificate'
import {
  buildTls13CertificateVerifyMessage,
  parseTlsCertificateVerify,
  requireTlsEd25519CertificateVerifySignature,
  TlsCertificateVerifyRole,
  TlsSignatureScheme,
  verifyTls13Ed25519CertificateVerifyHandshake,
  verifyTls13Ed25519CertificateVerifyWithCertificate,
  verifyTls13CertificateVerifySignature,
} from './tls-certificate-verify'

describe('TLS 1.3 CertificateVerify primitives', () => {
  test('parses CertificateVerify signature scheme and signature bytes', () => {
    const signature = hexToBytes('01020304')
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.CertificateVerify,
        certificateVerifyBody(TlsSignatureScheme.Ed25519, signature),
      ),
    )

    expect(handshake.kind).toBe(TlsHandshakeKind.CertificateVerify)
    expect(parseTlsCertificateVerify(handshake)).toEqual({
      signatureScheme: TlsSignatureScheme.Ed25519,
      signature,
    })
  })

  test('rejects malformed CertificateVerify handshakes', () => {
    expect(() =>
      parseTlsCertificateVerify(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.EncryptedExtensions, hexToBytes('')),
        ),
      ),
    ).toThrow('TLS handshake must be CertificateVerify')
    expect(() =>
      parseTlsCertificateVerify(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.CertificateVerify, hexToBytes('0807')),
        ),
      ),
    ).toThrow('not enough bytes for TLS CertificateVerify')
    expect(() =>
      parseTlsCertificateVerify(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.CertificateVerify, hexToBytes('0807000201')),
        ),
      ),
    ).toThrow('TLS CertificateVerify signature length mismatch')
  })

  test('requires Ed25519 CertificateVerify signatures', () => {
    expect(
      bytesToHex(
        requireTlsEd25519CertificateVerifySignature(
          parseSingleHandshake(
            tlsHandshakeMessage(
              TlsHandshakeType.CertificateVerify,
              certificateVerifyBody(TlsSignatureScheme.Ed25519, new Uint8Array(64)),
            ),
          ),
        ),
      ),
    ).toBe(bytesToHex(new Uint8Array(64)))
    expect(() =>
      requireTlsEd25519CertificateVerifySignature(
        parseSingleHandshake(
          tlsHandshakeMessage(
            TlsHandshakeType.CertificateVerify,
            certificateVerifyBody(0x0403, new Uint8Array(64)),
          ),
        ),
      ),
    ).toThrow('TLS CertificateVerify signature scheme must be Ed25519')
    expect(() =>
      requireTlsEd25519CertificateVerifySignature(
        parseSingleHandshake(
          tlsHandshakeMessage(
            TlsHandshakeType.CertificateVerify,
            certificateVerifyBody(TlsSignatureScheme.Ed25519, hexToBytes('00')),
          ),
        ),
      ),
    ).toThrow('TLS CertificateVerify signature must be 64 bytes')
  })

  test('builds server signature input bytes', () => {
    const message = buildTls13CertificateVerifyMessage(
      TlsCertificateVerifyRole.Server,
      rfc8448ClientServerHelloTranscriptHash,
    )

    expect(message).toEqual(
      concatBytes([
        new Uint8Array(64).fill(0x20),
        text('TLS 1.3, server CertificateVerify'),
        new Uint8Array([0]),
        rfc8448ClientServerHelloTranscriptHash,
      ]),
    )
  })

  test('builds client signature input bytes', () => {
    const message = buildTls13CertificateVerifyMessage(
      TlsCertificateVerifyRole.Client,
      rfc8448ClientServerHelloTranscriptHash,
    )

    expect(message).toEqual(
      concatBytes([
        new Uint8Array(64).fill(0x20),
        text('TLS 1.3, client CertificateVerify'),
        new Uint8Array([0]),
        rfc8448ClientServerHelloTranscriptHash,
      ]),
    )
  })

  test('requires SHA-256 transcript hashes', () => {
    expect(() =>
      buildTls13CertificateVerifyMessage(TlsCertificateVerifyRole.Server, hexToBytes('00')),
    ).toThrow('TLS transcript hash must be 32 bytes')
  })

  test('changes signature input when transcript hash changes', () => {
    const changedHash = new Uint8Array(rfc8448ClientServerHelloTranscriptHash)
    const firstByte = changedHash[0]
    if (firstByte === undefined) {
      throw new Error('expected transcript hash')
    }
    changedHash.set([firstByte ^ 0xff], 0)

    expect(
      bytesToHex(
        buildTls13CertificateVerifyMessage(
          TlsCertificateVerifyRole.Server,
          rfc8448ClientServerHelloTranscriptHash,
        ),
      ),
    ).not.toBe(
      bytesToHex(buildTls13CertificateVerifyMessage(TlsCertificateVerifyRole.Server, changedHash)),
    )
  })

  test('verifies Ed25519 CertificateVerify signatures over the signed message', async () => {
    const endpointId = hexToBytes(
      '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
    )
    const transcriptHash = hexToBytes(
      '447d442636be06aeec6f3e404c2881af3bc3f2d299d7af466a11d3dadacc6c8a',
    )
    const signature = hexToBytes(
      '2cf50efc76ee3fa1fe5244bb2223f5798d264f4d9b715f7048ebfee3654bbf03604f216e3ae8221de4473a551b2d9f7c3814fce75fe7fc4e163a3923428a490a',
    )

    expect(
      await verifyTls13CertificateVerifySignature(
        TlsCertificateVerifyRole.Server,
        transcriptHash,
        endpointId,
        signature,
      ),
    ).toBe(true)

    expect(
      await verifyTls13CertificateVerifySignature(
        TlsCertificateVerifyRole.Client,
        transcriptHash,
        endpointId,
        signature,
      ),
    ).toBe(false)

    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.CertificateVerify,
        certificateVerifyBody(TlsSignatureScheme.Ed25519, signature),
      ),
    )
    expect(
      await verifyTls13Ed25519CertificateVerifyHandshake(
        TlsCertificateVerifyRole.Server,
        transcriptHash,
        endpointId,
        handshake,
      ),
    ).toBe(true)

    const certificateHandshake = parseSingleHandshake(
      tlsHandshakeMessage(
        TlsHandshakeType.Certificate,
        certificateBody(hexToBytes(''), [
          {
            data: ed25519SpkiFromEndpointId(endpointId),
            extensions: hexToBytes(''),
          },
        ]),
      ),
    )
    expect(
      await verifyTls13Ed25519CertificateVerifyWithCertificate(
        TlsCertificateVerifyRole.Server,
        transcriptHash,
        certificateHandshake,
        handshake,
      ),
    ).toBe(true)
  })
})

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

function certificateVerifyBody(signatureScheme: number, signature: Uint8Array): Uint8Array {
  return concatBytes([writeU16BE(signatureScheme), writeU16BE(signature.length), signature])
}

interface CertificateEntryFixture {
  readonly data: Uint8Array
  readonly extensions: Uint8Array
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

function text(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

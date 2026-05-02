import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientServerHelloTranscriptHash,
} from '../testing/rfc8448-tls'
import { computeTls13FinishedVerifyData } from './tls-key-schedule'
import { parseTlsHandshakes, TlsHandshakeKind, TlsHandshakeType } from './tls'
import { requireTlsFinishedVerifyData, verifyTls13FinishedHandshake } from './tls-finished'

describe('TLS 1.3 Finished handshake primitives', () => {
  test('extracts Finished verify_data from a parsed handshake', () => {
    const verifyData = computeTls13FinishedVerifyData(
      rfc8448ClientHandshakeTrafficSecret,
      rfc8448ClientServerHelloTranscriptHash,
    )
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(TlsHandshakeType.Finished, verifyData),
    )

    expect(handshake.kind).toBe(TlsHandshakeKind.Finished)
    expect(bytesToHex(requireTlsFinishedVerifyData(handshake))).toBe(bytesToHex(verifyData))
  })

  test('rejects non-Finished and wrong-length Finished handshakes', () => {
    expect(() =>
      requireTlsFinishedVerifyData(
        parseSingleHandshake(
          tlsHandshakeMessage(TlsHandshakeType.EncryptedExtensions, hexToBytes('')),
        ),
      ),
    ).toThrow('TLS handshake must be Finished')
    expect(() =>
      requireTlsFinishedVerifyData(
        parseSingleHandshake(tlsHandshakeMessage(TlsHandshakeType.Finished, hexToBytes('00'))),
      ),
    ).toThrow('TLS Finished verify_data must be 32 bytes')
  })

  test('verifies expected Finished data from transcript hash', () => {
    const verifyData = computeTls13FinishedVerifyData(
      rfc8448ClientHandshakeTrafficSecret,
      rfc8448ClientServerHelloTranscriptHash,
    )
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(TlsHandshakeType.Finished, verifyData),
    )

    expect(
      verifyTls13FinishedHandshake(
        rfc8448ClientHandshakeTrafficSecret,
        rfc8448ClientServerHelloTranscriptHash,
        handshake,
      ),
    ).toBe(true)
  })

  test('rejects changed Finished data', () => {
    const verifyData = computeTls13FinishedVerifyData(
      rfc8448ClientHandshakeTrafficSecret,
      rfc8448ClientServerHelloTranscriptHash,
    )
    const changedVerifyData = new Uint8Array(verifyData)
    const firstByte = verifyData[0]
    if (firstByte === undefined) {
      throw new Error('expected Finished verify_data')
    }
    changedVerifyData.set([firstByte ^ 0xff], 0)
    const handshake = parseSingleHandshake(
      tlsHandshakeMessage(TlsHandshakeType.Finished, changedVerifyData),
    )

    expect(
      verifyTls13FinishedHandshake(
        rfc8448ClientHandshakeTrafficSecret,
        rfc8448ClientServerHelloTranscriptHash,
        handshake,
      ),
    ).toBe(false)
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

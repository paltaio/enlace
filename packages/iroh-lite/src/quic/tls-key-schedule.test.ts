import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficIv,
  rfc8448ClientHandshakeTrafficKey,
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientHello,
  rfc8448ClientServerHelloTranscriptHash,
  rfc8448DerivedSecretForHandshake,
  rfc8448EarlySecret,
  rfc8448HandshakeSecret,
  rfc8448ServerHandshakeTrafficIv,
  rfc8448ServerHandshakeTrafficKey,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerHello,
  rfc8448SharedSecret,
} from '../testing/rfc8448-tls'
import {
  deriveTls13Aes128GcmTrafficKeys,
  deriveTls13HandshakeSecrets,
  deriveTls13Secret,
  tls13EmptyTranscriptHash,
  Tls13Transcript,
  tls13TranscriptHash,
} from './tls-key-schedule'

describe('TLS 1.3 SHA-256 transcript hash', () => {
  test('hashes appended handshake messages', () => {
    const transcript = new Tls13Transcript()
    transcript.append(rfc8448ClientHello)
    transcript.append(rfc8448ServerHello)

    expect(bytesToHex(transcript.digest())).toBe(bytesToHex(rfc8448ClientServerHelloTranscriptHash))
    expect(bytesToHex(tls13TranscriptHash([rfc8448ClientHello, rfc8448ServerHello]))).toBe(
      bytesToHex(rfc8448ClientServerHelloTranscriptHash),
    )
  })

  test('hashes empty transcript', () => {
    expect(bytesToHex(tls13EmptyTranscriptHash())).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })
})

describe('TLS 1.3 SHA-256 key schedule', () => {
  test('derives RFC 8448 handshake traffic secrets', () => {
    const secrets = deriveTls13HandshakeSecrets(
      rfc8448SharedSecret,
      rfc8448ClientServerHelloTranscriptHash,
    )

    expect(bytesToHex(secrets.earlySecret)).toBe(bytesToHex(rfc8448EarlySecret))
    expect(bytesToHex(secrets.derivedSecret)).toBe(bytesToHex(rfc8448DerivedSecretForHandshake))
    expect(bytesToHex(secrets.handshakeSecret)).toBe(bytesToHex(rfc8448HandshakeSecret))
    expect(bytesToHex(secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ClientHandshakeTrafficSecret),
    )
    expect(bytesToHex(secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ServerHandshakeTrafficSecret),
    )
  })

  test('derives RFC 8448 AES-128-GCM handshake traffic keys', () => {
    const clientKeys = deriveTls13Aes128GcmTrafficKeys(rfc8448ClientHandshakeTrafficSecret)
    const serverKeys = deriveTls13Aes128GcmTrafficKeys(rfc8448ServerHandshakeTrafficSecret)

    expect(bytesToHex(clientKeys.key)).toBe(bytesToHex(rfc8448ClientHandshakeTrafficKey))
    expect(bytesToHex(clientKeys.iv)).toBe(bytesToHex(rfc8448ClientHandshakeTrafficIv))
    expect(bytesToHex(serverKeys.key)).toBe(bytesToHex(rfc8448ServerHandshakeTrafficKey))
    expect(bytesToHex(serverKeys.iv)).toBe(bytesToHex(rfc8448ServerHandshakeTrafficIv))
  })

  test('rejects wrong transcript hash length', () => {
    expect(() =>
      deriveTls13Secret(rfc8448HandshakeSecret, 'c hs traffic', hexToBytes('00')),
    ).toThrow('TLS transcript hash must be 32 bytes')
  })

  test('rejects invalid shared secrets', () => {
    expect(() => deriveTls13HandshakeSecrets(hexToBytes('00'), tls13EmptyTranscriptHash())).toThrow(
      'TLS X25519 shared secret must be 32 bytes',
    )
    expect(() =>
      deriveTls13HandshakeSecrets(new Uint8Array(32), tls13EmptyTranscriptHash()),
    ).toThrow('TLS X25519 shared secret must not be all zero')
  })

  test('rejects wrong-length traffic secrets', () => {
    expect(() => deriveTls13Aes128GcmTrafficKeys(hexToBytes('00'))).toThrow(
      'TLS traffic secret must be 32 bytes',
    )
  })
})

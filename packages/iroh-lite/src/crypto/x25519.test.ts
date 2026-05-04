import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientPrivateKey,
  rfc8448ClientPublicKey,
  rfc8448ClientServerHelloTranscriptHash,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerPrivateKey,
  rfc8448ServerPublicKey,
  rfc8448SharedSecret,
} from '../testing/rfc8448-tls'
import { deriveTls13HandshakeSecrets } from '../quic/tls-key-schedule'
import {
  deriveX25519PublicKey,
  deriveX25519SharedSecret,
  validateX25519PrivateKey,
  validateX25519PublicKey,
} from './x25519'

describe('X25519 WebCrypto foundation', () => {
  test('derives RFC 8448 public keys from private keys', async () => {
    expect(await deriveX25519PublicKey(rfc8448ClientPrivateKey)).toEqual(rfc8448ClientPublicKey)
    expect(await deriveX25519PublicKey(rfc8448ServerPrivateKey)).toEqual(rfc8448ServerPublicKey)
  })

  test('derives RFC 8448 shared secret from both sides', async () => {
    const clientSecret = await deriveX25519SharedSecret(
      rfc8448ClientPrivateKey,
      rfc8448ServerPublicKey,
    )
    const serverSecret = await deriveX25519SharedSecret(
      rfc8448ServerPrivateKey,
      rfc8448ClientPublicKey,
    )

    expect(bytesToHex(clientSecret)).toBe(bytesToHex(rfc8448SharedSecret))
    expect(bytesToHex(serverSecret)).toBe(bytesToHex(rfc8448SharedSecret))
  })

  test('feeds RFC 8448 shared secret into TLS 1.3 handshake key schedule', async () => {
    const sharedSecret = await deriveX25519SharedSecret(
      rfc8448ClientPrivateKey,
      rfc8448ServerPublicKey,
    )
    const secrets = deriveTls13HandshakeSecrets(
      sharedSecret,
      rfc8448ClientServerHelloTranscriptHash,
    )

    expect(bytesToHex(secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ClientHandshakeTrafficSecret),
    )
    expect(bytesToHex(secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ServerHandshakeTrafficSecret),
    )
  })

  test('rejects invalid key boundaries', async () => {
    expect(() => validateX25519PrivateKey(hexToBytes('00'))).toThrow(
      'X25519 private key must be 32 bytes',
    )
    expect(() => validateX25519PublicKey(hexToBytes('00'))).toThrow(
      'X25519 public key must be 32 bytes',
    )
    await deriveX25519SharedSecret(rfc8448ClientPrivateKey, new Uint8Array(32)).then(
      () => {
        throw new Error('expected all-zero shared secret rejection')
      },
      (error: unknown) => {
        expect(error).toBeInstanceOf(RangeError)
        expect(error).toHaveProperty('message', 'X25519 shared secret must not be all zero')
      },
    )
  })
})

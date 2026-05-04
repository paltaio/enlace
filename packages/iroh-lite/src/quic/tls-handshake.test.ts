import { describe, expect, test } from 'bun:test'

import { concatBytes } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientHello,
  rfc8448ClientPrivateKey,
  rfc8448ClientServerHelloTranscriptHash,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerHello,
  rfc8448ServerPrivateKey,
  rfc8448SharedSecret,
} from '../testing/rfc8448-tls'
import type { QuicCryptoFrame } from './frame'
import {
  parseTlsHandshakes,
  type TlsClientHelloHandshake,
  type TlsServerHelloHandshake,
} from './tls'
import {
  deriveTls13X25519HandshakeSecrets,
  deriveTls13X25519HandshakeSecretsFromQuicCrypto,
  TlsHandshakeRole,
} from './tls-handshake'
import { collectQuicTlsHandshakeMessages } from './tls-crypto-stream'

describe('TLS 1.3 X25519 handshake secret bridge', () => {
  test('derives client-side RFC 8448 handshake secrets from parsed hellos', async () => {
    const result = await deriveTls13X25519HandshakeSecrets({
      role: TlsHandshakeRole.Client,
      privateKey: rfc8448ClientPrivateKey,
      clientHello: parseRfc8448ClientHello(),
      serverHello: parseRfc8448ServerHello(),
      clientHelloMessage: rfc8448ClientHello,
      serverHelloMessage: rfc8448ServerHello,
    })

    expect(bytesToHex(result.sharedSecret)).toBe(bytesToHex(rfc8448SharedSecret))
    expect(bytesToHex(result.transcriptHash)).toBe(
      bytesToHex(rfc8448ClientServerHelloTranscriptHash),
    )
    expect(bytesToHex(result.secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ClientHandshakeTrafficSecret),
    )
    expect(bytesToHex(result.secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ServerHandshakeTrafficSecret),
    )
  })

  test('derives server-side RFC 8448 handshake secrets from parsed hellos', async () => {
    const result = await deriveTls13X25519HandshakeSecrets({
      role: TlsHandshakeRole.Server,
      privateKey: rfc8448ServerPrivateKey,
      clientHello: parseRfc8448ClientHello(),
      serverHello: parseRfc8448ServerHello(),
      clientHelloMessage: rfc8448ClientHello,
      serverHelloMessage: rfc8448ServerHello,
    })

    expect(bytesToHex(result.sharedSecret)).toBe(bytesToHex(rfc8448SharedSecret))
    expect(bytesToHex(result.secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ClientHandshakeTrafficSecret),
    )
    expect(bytesToHex(result.secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ServerHandshakeTrafficSecret),
    )
  })

  test('derives RFC 8448 handshake secrets from QUIC CRYPTO messages', async () => {
    const result = await deriveTls13X25519HandshakeSecretsFromQuicCrypto({
      role: TlsHandshakeRole.Client,
      privateKey: rfc8448ClientPrivateKey,
      clientMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]),
      serverMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)]),
    })

    expect(bytesToHex(result.sharedSecret)).toBe(bytesToHex(rfc8448SharedSecret))
    expect(bytesToHex(result.transcriptHash)).toBe(
      bytesToHex(rfc8448ClientServerHelloTranscriptHash),
    )
    expect(bytesToHex(result.secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ClientHandshakeTrafficSecret),
    )
    expect(bytesToHex(result.secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ServerHandshakeTrafficSecret),
    )
  })

  test('uses ServerHello transcript boundary when server CRYPTO includes later messages', async () => {
    const encryptedExtensions = hexToBytes('080000020000')
    const result = await deriveTls13X25519HandshakeSecretsFromQuicCrypto({
      role: TlsHandshakeRole.Client,
      privateKey: rfc8448ClientPrivateKey,
      clientMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]),
      serverMessages: collectQuicTlsHandshakeMessages([
        cryptoFrame(0, concatBytes([rfc8448ServerHello, encryptedExtensions])),
      ]),
    })

    expect(bytesToHex(result.transcriptHash)).toBe(
      bytesToHex(rfc8448ClientServerHelloTranscriptHash),
    )
    expect(bytesToHex(result.secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ClientHandshakeTrafficSecret),
    )
    expect(bytesToHex(result.secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(rfc8448ServerHandshakeTrafficSecret),
    )
  })

  test('rejects missing QUIC CRYPTO hello messages', async () => {
    await deriveTls13X25519HandshakeSecretsFromQuicCrypto({
      role: TlsHandshakeRole.Client,
      privateKey: rfc8448ClientPrivateKey,
      clientMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)]),
      serverMessages: collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)]),
    }).then(
      () => {
        throw new Error('expected missing ClientHello failure')
      },
      (error: unknown) => {
        expect(error).toBeInstanceOf(RangeError)
        expect(error).toHaveProperty('message', 'missing TLS ClientHello handshake message')
      },
    )
  })

  test('rejects unsupported TLS 1.3 negotiation inputs', async () => {
    const clientHello = parseRfc8448ClientHello()
    const serverHello = parseRfc8448ServerHello()

    await expectDeriveFailure(
      {
        ...clientHello,
        body: {
          ...clientHello.body,
          cipherSuites: [0x1302],
        },
      },
      serverHello,
      'TLS ServerHello cipher suite must be offered by ClientHello',
    )
    await expectDeriveFailure(
      clientHello,
      {
        ...serverHello,
        body: {
          ...serverHello.body,
          cipherSuite: 0x1302,
        },
      },
      'TLS ServerHello must select TLS_AES_128_GCM_SHA256',
    )
  })
})

async function expectDeriveFailure(
  clientHello: TlsClientHelloHandshake,
  serverHello: TlsServerHelloHandshake,
  message: string,
): Promise<void> {
  await deriveTls13X25519HandshakeSecrets({
    role: TlsHandshakeRole.Client,
    privateKey: rfc8448ClientPrivateKey,
    clientHello,
    serverHello,
    clientHelloMessage: rfc8448ClientHello,
    serverHelloMessage: rfc8448ServerHello,
  }).then(
    () => {
      throw new Error('expected TLS handshake derivation failure')
    },
    (error: unknown) => {
      expect(error).toBeInstanceOf(RangeError)
      expect(error).toHaveProperty('message', message)
    },
  )
}

function parseRfc8448ClientHello(): TlsClientHelloHandshake {
  const result = parseTlsHandshakes(rfc8448ClientHello)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== 'client-hello') {
    throw new Error('expected RFC 8448 ClientHello')
  }
  return handshake
}

function parseRfc8448ServerHello(): TlsServerHelloHandshake {
  const result = parseTlsHandshakes(rfc8448ServerHello)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== 'server-hello') {
    throw new Error('expected RFC 8448 ServerHello')
  }
  return handshake
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

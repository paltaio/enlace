import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientHello,
  rfc8448ClientPrivateKey,
  rfc8448ClientPublicKey,
  rfc8448ClientServerHelloTranscriptHash,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerHello,
  rfc8448ServerPrivateKey,
  rfc8448ServerPublicKey,
  rfc8448SharedSecret,
} from '../testing/rfc8448-tls'
import { deriveTls13HandshakeSecrets } from './tls-key-schedule'
import {
  deriveTlsX25519SharedSecret,
  findTlsClientX25519KeyShare,
  tlsX25519KeySharePublicKey,
} from './tls-key-share'
import {
  getTlsExtension,
  parseTlsClientKeyShares,
  parseTlsHandshakes,
  parseTlsServerKeyShare,
  TlsExtensionType,
  TlsNamedGroup,
  type TlsClientHelloHandshake,
  type TlsExtension,
  type TlsServerHelloHandshake,
} from './tls'

describe('TLS X25519 key share bridge', () => {
  test('extracts RFC 8448 X25519 key shares from parsed hellos', () => {
    const clientKeyShare = findTlsClientX25519KeyShare(parseRfc8448ClientKeyShares())
    const serverKeyShare = parseRfc8448ServerKeyShare()

    expect(bytesToHex(tlsX25519KeySharePublicKey(clientKeyShare))).toBe(
      bytesToHex(rfc8448ClientPublicKey),
    )
    expect(bytesToHex(tlsX25519KeySharePublicKey(serverKeyShare))).toBe(
      bytesToHex(rfc8448ServerPublicKey),
    )
  })

  test('derives RFC 8448 shared secret from parsed peer key shares', async () => {
    const clientSecret = await deriveTlsX25519SharedSecret(
      rfc8448ClientPrivateKey,
      parseRfc8448ServerKeyShare(),
    )
    const serverSecret = await deriveTlsX25519SharedSecret(
      rfc8448ServerPrivateKey,
      findTlsClientX25519KeyShare(parseRfc8448ClientKeyShares()),
    )

    expect(bytesToHex(clientSecret)).toBe(bytesToHex(rfc8448SharedSecret))
    expect(bytesToHex(serverSecret)).toBe(bytesToHex(rfc8448SharedSecret))
  })

  test('feeds parsed key-share secret into TLS 1.3 key schedule', async () => {
    const sharedSecret = await deriveTlsX25519SharedSecret(
      rfc8448ClientPrivateKey,
      parseRfc8448ServerKeyShare(),
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

  test('rejects unsupported groups and malformed key shares', async () => {
    const unsupported = {
      group: 0x0017,
      keyExchange: rfc8448ServerPublicKey,
      offset: 0,
      endOffset: 36,
    }
    expect(() => tlsX25519KeySharePublicKey(unsupported)).toThrow(
      'TLS key share group must be X25519',
    )
    expect(() =>
      tlsX25519KeySharePublicKey({
        group: TlsNamedGroup.X25519,
        keyExchange: hexToBytes('00'),
        offset: 0,
        endOffset: 5,
      }),
    ).toThrow('TLS X25519 key share must be 32 bytes')
    expect(() => findTlsClientX25519KeyShare([unsupported])).toThrow(
      'TLS ClientHello must include X25519 key share',
    )
    await deriveTlsX25519SharedSecret(rfc8448ClientPrivateKey, {
      group: TlsNamedGroup.X25519,
      keyExchange: new Uint8Array(32),
      offset: 0,
      endOffset: 36,
    }).then(
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

function parseRfc8448ClientKeyShares() {
  const handshake = parseSingleRfc8448ClientHello()
  return parseTlsClientKeyShares(
    extensionData(handshake.body.extensions, TlsExtensionType.KeyShare),
  )
}

function parseRfc8448ServerKeyShare() {
  const handshake = parseSingleRfc8448ServerHello()
  return parseTlsServerKeyShare(extensionData(handshake.body.extensions, TlsExtensionType.KeyShare))
}

function parseSingleRfc8448ClientHello(): TlsClientHelloHandshake {
  const result = parseTlsHandshakes(rfc8448ClientHello)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== 'client-hello') {
    throw new Error('expected RFC 8448 ClientHello')
  }
  return handshake
}

function parseSingleRfc8448ServerHello(): TlsServerHelloHandshake {
  const result = parseTlsHandshakes(rfc8448ServerHello)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== 'server-hello') {
    throw new Error('expected RFC 8448 ServerHello')
  }
  return handshake
}

function extensionData(extensions: readonly TlsExtension[], extensionType: number): Uint8Array {
  const extension = getTlsExtension(extensions, extensionType)
  if (extension === null) {
    throw new Error(`expected TLS extension 0x${extensionType.toString(16)}`)
  }
  return extension.data
}

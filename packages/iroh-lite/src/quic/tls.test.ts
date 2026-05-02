import { describe, expect, test } from 'bun:test'

import { readU8 } from '../bytes'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
  rfc9001ProtectedServerInitialPacket,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import { parseQuicFrames, type QuicCryptoFrame } from './frame'
import { decryptQuicInitialPacket } from './initial'
import {
  getTlsExtension,
  parseTlsAlpnProtocols,
  parseTlsClientKeyShares,
  parseTlsClientSupportedVersions,
  parseTlsHandshakes,
  parseTlsServerKeyShare,
  parseTlsServerSupportedVersion,
  TLS_VERSION_1_3,
  TlsExtensionType,
  TlsNamedGroup,
  type TlsExtension,
} from './tls'

describe('TLS handshake parsing', () => {
  test('parses ClientHello from RFC 9001 client Initial CRYPTO frame', () => {
    const crypto = initialCryptoData(rfc9001ProtectedClientInitialPacket, 'client')
    const result = parseTlsHandshakes(crypto.data)

    expect(result.endOffset).toBe(crypto.data.length)
    expect(result.handshakes).toHaveLength(1)
    const handshake = result.handshakes[0]
    expect(handshake?.kind).toBe('client-hello')
    if (handshake?.kind !== 'client-hello') {
      throw new Error('expected ClientHello')
    }

    expect(handshake.offset).toBe(0)
    expect(handshake.endOffset).toBe(crypto.data.length)
    expect(handshake.body.legacyVersion).toBe(0x0303)
    expect(bytesToHex(handshake.body.random.subarray(0, 8))).toBe('ebf8fa56f12939b9')
    expect(handshake.body.legacySessionId).toHaveLength(0)
    expect(handshake.body.cipherSuites).toEqual([0x1301, 0x1302])
    expect(bytesToHex(handshake.body.legacyCompressionMethods)).toBe('00')
    expect(extensionData(handshake.body.extensions, TlsExtensionType.ServerName)).toHaveLength(16)
    expect(
      parseTlsAlpnProtocols(
        extensionData(
          handshake.body.extensions,
          TlsExtensionType.ApplicationLayerProtocolNegotiation,
        ),
      ).map(bytesToHex),
    ).toEqual(['616c706e'])
    expect(
      parseTlsClientSupportedVersions(
        extensionData(handshake.body.extensions, TlsExtensionType.SupportedVersions),
      ),
    ).toEqual([TLS_VERSION_1_3])

    const keyShares = parseTlsClientKeyShares(
      extensionData(handshake.body.extensions, TlsExtensionType.KeyShare),
    )
    expect(keyShares).toHaveLength(1)
    expect(keyShares[0]?.group).toBe(TlsNamedGroup.X25519)
    expect(keyShares[0]?.keyExchange).toHaveLength(32)
    expect(
      extensionData(handshake.body.extensions, TlsExtensionType.QuicTransportParameters),
    ).toHaveLength(50)
  })

  test('parses ServerHello from RFC 9001 server Initial CRYPTO frame', () => {
    const crypto = initialCryptoData(rfc9001ProtectedServerInitialPacket, 'server')
    const result = parseTlsHandshakes(crypto.data)

    expect(result.endOffset).toBe(crypto.data.length)
    expect(result.handshakes).toHaveLength(1)
    const handshake = result.handshakes[0]
    expect(handshake?.kind).toBe('server-hello')
    if (handshake?.kind !== 'server-hello') {
      throw new Error('expected ServerHello')
    }

    expect(handshake.offset).toBe(0)
    expect(handshake.endOffset).toBe(crypto.data.length)
    expect(handshake.body.legacyVersion).toBe(0x0303)
    expect(bytesToHex(handshake.body.random.subarray(0, 8))).toBe('eefce7f7b37ba1d1')
    expect(handshake.body.legacySessionIdEcho).toHaveLength(0)
    expect(handshake.body.cipherSuite).toBe(0x1301)
    expect(handshake.body.legacyCompressionMethod).toBe(0)
    expect(
      parseTlsServerSupportedVersion(
        extensionData(handshake.body.extensions, TlsExtensionType.SupportedVersions),
      ),
    ).toBe(TLS_VERSION_1_3)

    const keyShare = parseTlsServerKeyShare(
      extensionData(handshake.body.extensions, TlsExtensionType.KeyShare),
    )
    expect(keyShare.group).toBe(TlsNamedGroup.X25519)
    expect(keyShare.keyExchange).toHaveLength(32)
  })

  test('keeps unknown handshake bodies as raw bytes', () => {
    const result = parseTlsHandshakes(hexToBytes('08000003aabbcc'))

    expect(result.handshakes).toHaveLength(1)
    expect(result.handshakes[0]).toEqual({
      kind: 'unknown',
      handshakeType: 8,
      body: hexToBytes('aabbcc'),
      offset: 0,
      endOffset: 7,
    })
  })

  test('rejects truncated handshake body', () => {
    expect(() => parseTlsHandshakes(hexToBytes('01000005aabbcc'))).toThrow(
      'not enough bytes for TLS handshake body',
    )
  })

  test('rejects trailing bytes in ClientHello body', () => {
    const crypto = initialCryptoData(rfc9001ProtectedClientInitialPacket, 'client')

    expect(() => parseTlsHandshakes(appendHandshakeBodyByte(crypto.data, 0x00))).toThrow(
      'TLS ClientHello contains trailing bytes',
    )
  })

  test('rejects trailing bytes in ServerHello body', () => {
    const crypto = initialCryptoData(rfc9001ProtectedServerInitialPacket, 'server')

    expect(() => parseTlsHandshakes(appendHandshakeBodyByte(crypto.data, 0x00))).toThrow(
      'TLS ServerHello contains trailing bytes',
    )
  })

  test('rejects malformed TLS extension bodies', () => {
    expect(() => parseTlsAlpnProtocols(hexToBytes('000301'))).toThrow(
      'TLS ALPN protocol list length mismatch',
    )
    expect(() => parseTlsClientSupportedVersions(hexToBytes('03030400'))).toThrow(
      'TLS supported versions length must be even',
    )
    expect(() => parseTlsServerSupportedVersion(hexToBytes('030400'))).toThrow(
      'TLS selected version must be 2 bytes',
    )
    expect(() => parseTlsClientKeyShares(hexToBytes('0006001d0020aa'))).toThrow(
      'TLS client key share list length mismatch',
    )
    expect(() => parseTlsServerKeyShare(hexToBytes('001d0001aabb'))).toThrow(
      'TLS server key share length mismatch',
    )
  })
})

function extensionData(extensions: readonly TlsExtension[], extensionType: number): Uint8Array {
  const extension = getTlsExtension(extensions, extensionType)
  if (extension === null) {
    throw new Error(`expected TLS extension 0x${extensionType.toString(16)}`)
  }
  return extension.data
}

function appendHandshakeBodyByte(handshake: Uint8Array, byte: number): Uint8Array {
  const bodyLength =
    readU8(handshake, 1) * 2 ** 16 + readU8(handshake, 2) * 2 ** 8 + readU8(handshake, 3)
  const nextBodyLength = bodyLength + 1
  const out = new Uint8Array(handshake.length + 1)
  out.set(handshake)
  out[1] = (nextBodyLength >>> 16) & 0xff
  out[2] = (nextBodyLength >>> 8) & 0xff
  out[3] = nextBodyLength & 0xff
  out[out.length - 1] = byte
  return out
}

function initialCryptoData(packet: Uint8Array, direction: 'client' | 'server'): QuicCryptoFrame {
  const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
  const directionalKeys = direction === 'client' ? keys.client : keys.server
  const decrypted = decryptQuicInitialPacket(packet, directionalKeys)
  const frames = parseQuicFrames(decrypted.payload)
  const crypto = frames.frames.find((frame) => frame.type === 'crypto')
  if (crypto?.type !== 'crypto') {
    throw new Error('expected CRYPTO frame')
  }
  return crypto
}

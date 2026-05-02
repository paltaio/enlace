import { copyBytes, readU8, readU16BE } from '../bytes'
import { readTlsExtensions, type TlsExtension } from './tls-extension'

export type { TlsExtension } from './tls-extension'

export const TlsHandshakeKind = {
  ClientHello: 'client-hello',
  ServerHello: 'server-hello',
  EncryptedExtensions: 'encrypted-extensions',
  Certificate: 'certificate',
  CertificateRequest: 'certificate-request',
  CertificateVerify: 'certificate-verify',
  Finished: 'finished',
  Unknown: 'unknown',
} as const

export const TlsHandshakeType = {
  ClientHello: 0x01,
  ServerHello: 0x02,
  EncryptedExtensions: 0x08,
  Certificate: 0x0b,
  CertificateRequest: 0x0d,
  CertificateVerify: 0x0f,
  Finished: 0x14,
} as const

export const TlsExtensionType = {
  ServerName: 0x0000,
  ApplicationLayerProtocolNegotiation: 0x0010,
  SupportedVersions: 0x002b,
  KeyShare: 0x0033,
  QuicTransportParameters: 0x0039,
} as const

export const TlsNamedGroup = {
  X25519: 0x001d,
} as const

export const TLS_VERSION_1_3 = 0x0304

export type TlsHandshake =
  | TlsClientHelloHandshake
  | TlsServerHelloHandshake
  | TlsOpaqueHandshake
  | TlsUnknownHandshake

export type TlsOpaqueHandshakeKind =
  | typeof TlsHandshakeKind.EncryptedExtensions
  | typeof TlsHandshakeKind.Certificate
  | typeof TlsHandshakeKind.CertificateRequest
  | typeof TlsHandshakeKind.CertificateVerify
  | typeof TlsHandshakeKind.Finished

export interface TlsClientHello {
  readonly legacyVersion: number
  readonly random: Uint8Array
  readonly legacySessionId: Uint8Array
  readonly cipherSuites: readonly number[]
  readonly legacyCompressionMethods: Uint8Array
  readonly extensions: readonly TlsExtension[]
}

export interface TlsServerHello {
  readonly legacyVersion: number
  readonly random: Uint8Array
  readonly legacySessionIdEcho: Uint8Array
  readonly cipherSuite: number
  readonly legacyCompressionMethod: number
  readonly extensions: readonly TlsExtension[]
}

export interface TlsClientHelloHandshake {
  readonly kind: typeof TlsHandshakeKind.ClientHello
  readonly body: TlsClientHello
  readonly offset: number
  readonly endOffset: number
}

export interface TlsServerHelloHandshake {
  readonly kind: typeof TlsHandshakeKind.ServerHello
  readonly body: TlsServerHello
  readonly offset: number
  readonly endOffset: number
}

export interface TlsOpaqueHandshake {
  readonly kind: TlsOpaqueHandshakeKind
  readonly handshakeType: number
  readonly body: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export interface TlsUnknownHandshake {
  readonly kind: typeof TlsHandshakeKind.Unknown
  readonly handshakeType: number
  readonly body: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export interface TlsHandshakeParseResult {
  readonly handshakes: readonly TlsHandshake[]
  readonly endOffset: number
}

export interface TlsKeyShareEntry {
  readonly group: number
  readonly keyExchange: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export function parseTlsHandshakes(bytes: Uint8Array, offset = 0): TlsHandshakeParseResult {
  validateOffset(bytes, offset)
  const handshakes: TlsHandshake[] = []
  let pos = offset

  while (pos < bytes.length) {
    const handshake = parseTlsHandshake(bytes, pos)
    handshakes.push(handshake)
    pos = handshake.endOffset
  }

  return { handshakes, endOffset: pos }
}

export function getTlsExtension(
  extensions: readonly TlsExtension[],
  extensionType: number,
): TlsExtension | null {
  for (const extension of extensions) {
    if (extension.extensionType === extensionType) {
      return extension
    }
  }
  return null
}

export function parseTlsAlpnProtocols(data: Uint8Array): readonly Uint8Array[] {
  let pos = 0
  const listLength = readU16BE(data, pos)
  pos += 2
  if (data.length - pos !== listLength) {
    throw new RangeError('TLS ALPN protocol list length mismatch')
  }

  const protocols: Uint8Array[] = []
  const endOffset = pos + listLength
  while (pos < endOffset) {
    const protocol = readTlsU8Vector(data, pos, 'TLS ALPN protocol')
    if (protocol.value.length === 0) {
      throw new RangeError('TLS ALPN protocol must not be empty')
    }
    protocols.push(protocol.value)
    pos = protocol.endOffset
  }

  return protocols
}

export function parseTlsClientSupportedVersions(data: Uint8Array): readonly number[] {
  const versions = readTlsU8Vector(data, 0, 'TLS supported versions')
  if (versions.endOffset !== data.length) {
    throw new RangeError('TLS supported versions length mismatch')
  }
  if (versions.value.length % 2 !== 0) {
    throw new RangeError('TLS supported versions length must be even')
  }

  const parsed: number[] = []
  for (let pos = 0; pos < versions.value.length; pos += 2) {
    parsed.push(readU16BE(versions.value, pos))
  }
  return parsed
}

export function parseTlsServerSupportedVersion(data: Uint8Array): number {
  if (data.length !== 2) {
    throw new RangeError('TLS selected version must be 2 bytes')
  }
  return readU16BE(data, 0)
}

export function parseTlsClientKeyShares(data: Uint8Array): readonly TlsKeyShareEntry[] {
  const length = readU16BE(data, 0)
  let pos = 2
  const endOffset = pos + length
  if (data.length !== endOffset) {
    throw new RangeError('TLS client key share list length mismatch')
  }

  const entries: TlsKeyShareEntry[] = []
  while (pos < endOffset) {
    const entry = readTlsKeyShareEntry(data, pos)
    entries.push(entry)
    pos = entry.endOffset
  }
  return entries
}

export function parseTlsServerKeyShare(data: Uint8Array): TlsKeyShareEntry {
  const entry = readTlsKeyShareEntry(data, 0)
  if (entry.endOffset !== data.length) {
    throw new RangeError('TLS server key share length mismatch')
  }
  return entry
}

function parseTlsHandshake(bytes: Uint8Array, offset: number): TlsHandshake {
  if (bytes.length - offset < 4) {
    throw new RangeError('not enough bytes for TLS handshake header')
  }
  const handshakeType = readU8(bytes, offset)
  const bodyLength = readU24BE(bytes, offset + 1)
  const bodyOffset = offset + 4
  const endOffset = bodyOffset + bodyLength
  if (bytes.length < endOffset) {
    throw new RangeError('not enough bytes for TLS handshake body')
  }
  const body = bytes.subarray(bodyOffset, endOffset)

  if (handshakeType === TlsHandshakeType.ClientHello) {
    return {
      kind: TlsHandshakeKind.ClientHello,
      body: parseClientHello(body),
      offset,
      endOffset,
    }
  }
  if (handshakeType === TlsHandshakeType.ServerHello) {
    return {
      kind: TlsHandshakeKind.ServerHello,
      body: parseServerHello(body),
      offset,
      endOffset,
    }
  }

  const opaqueKind = opaqueTlsHandshakeKind(handshakeType)
  if (opaqueKind !== null) {
    return {
      kind: opaqueKind,
      handshakeType,
      body: copyBytes(body),
      offset,
      endOffset,
    }
  }

  return {
    kind: TlsHandshakeKind.Unknown,
    handshakeType,
    body: copyBytes(body),
    offset,
    endOffset,
  }
}

function opaqueTlsHandshakeKind(handshakeType: number): TlsOpaqueHandshakeKind | null {
  switch (handshakeType) {
    case TlsHandshakeType.EncryptedExtensions:
      return TlsHandshakeKind.EncryptedExtensions
    case TlsHandshakeType.Certificate:
      return TlsHandshakeKind.Certificate
    case TlsHandshakeType.CertificateRequest:
      return TlsHandshakeKind.CertificateRequest
    case TlsHandshakeType.CertificateVerify:
      return TlsHandshakeKind.CertificateVerify
    case TlsHandshakeType.Finished:
      return TlsHandshakeKind.Finished
    default:
      return null
  }
}

function readTlsKeyShareEntry(bytes: Uint8Array, offset: number): TlsKeyShareEntry {
  let pos = offset
  const group = readU16BE(bytes, pos)
  pos += 2
  const keyLength = readU16BE(bytes, pos)
  pos += 2
  const keyExchange = readBytes(bytes, pos, keyLength, 'TLS key share')
  pos += keyLength

  return {
    group,
    keyExchange,
    offset,
    endOffset: pos,
  }
}

function parseClientHello(bytes: Uint8Array): TlsClientHello {
  let pos = 0
  const legacyVersion = readU16BE(bytes, pos)
  pos += 2
  const random = readBytes(bytes, pos, 32, 'TLS ClientHello random')
  pos += 32
  const legacySessionId = readTlsU8Vector(bytes, pos, 'TLS ClientHello session id')
  pos = legacySessionId.endOffset
  const cipherSuites = readCipherSuites(bytes, pos)
  pos = cipherSuites.endOffset
  const legacyCompressionMethods = readTlsU8Vector(
    bytes,
    pos,
    'TLS ClientHello compression methods',
  )
  pos = legacyCompressionMethods.endOffset
  const extensions = readTlsExtensions(bytes, pos, 'TLS extensions', 'TLS extension data')
  requireEndOffset(extensions.endOffset, bytes.length, 'TLS ClientHello')

  return {
    legacyVersion,
    random,
    legacySessionId: legacySessionId.value,
    cipherSuites: cipherSuites.value,
    legacyCompressionMethods: legacyCompressionMethods.value,
    extensions: extensions.value,
  }
}

function parseServerHello(bytes: Uint8Array): TlsServerHello {
  let pos = 0
  const legacyVersion = readU16BE(bytes, pos)
  pos += 2
  const random = readBytes(bytes, pos, 32, 'TLS ServerHello random')
  pos += 32
  const legacySessionIdEcho = readTlsU8Vector(bytes, pos, 'TLS ServerHello session id echo')
  pos = legacySessionIdEcho.endOffset
  const cipherSuite = readU16BE(bytes, pos)
  pos += 2
  const legacyCompressionMethod = readU8(bytes, pos)
  pos += 1
  const extensions = readTlsExtensions(bytes, pos, 'TLS extensions', 'TLS extension data')
  requireEndOffset(extensions.endOffset, bytes.length, 'TLS ServerHello')

  return {
    legacyVersion,
    random,
    legacySessionIdEcho: legacySessionIdEcho.value,
    cipherSuite,
    legacyCompressionMethod,
    extensions: extensions.value,
  }
}

function requireEndOffset(offset: number, expected: number, name: string): void {
  if (offset !== expected) {
    throw new RangeError(`${name} contains trailing bytes`)
  }
}

function readCipherSuites(
  bytes: Uint8Array,
  offset: number,
): {
  readonly value: readonly number[]
  readonly endOffset: number
} {
  const length = readU16BE(bytes, offset)
  if (length % 2 !== 0) {
    throw new RangeError('TLS cipher suite vector length must be even')
  }
  let pos = offset + 2
  const endOffset = pos + length
  if (bytes.length < endOffset) {
    throw new RangeError('not enough bytes for TLS cipher suites')
  }
  const cipherSuites: number[] = []
  while (pos < endOffset) {
    cipherSuites.push(readU16BE(bytes, pos))
    pos += 2
  }
  return { value: cipherSuites, endOffset }
}

function readTlsU8Vector(
  bytes: Uint8Array,
  offset: number,
  name: string,
): {
  readonly value: Uint8Array
  readonly endOffset: number
} {
  const length = readU8(bytes, offset)
  const valueOffset = offset + 1
  const endOffset = valueOffset + length
  return {
    value: readBytes(bytes, valueOffset, length, name),
    endOffset,
  }
}

function readBytes(bytes: Uint8Array, offset: number, length: number, name: string): Uint8Array {
  if (bytes.length - offset < length) {
    throw new RangeError(`not enough bytes for ${name}`)
  }
  return copyBytes(bytes.subarray(offset, offset + length))
}

function readU24BE(bytes: Uint8Array, offset: number): number {
  const b0 = readU8(bytes, offset)
  const b1 = readU8(bytes, offset + 1)
  const b2 = readU8(bytes, offset + 2)
  return b0 * 2 ** 16 + (b1 << 8) + b2
}

function validateOffset(bytes: Uint8Array, offset: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > bytes.length) {
    throw new RangeError('TLS handshake offset out of range')
  }
}

import { describe, expect, test } from 'bun:test'

import { concatBytes, writeU16BE } from '../bytes'
import { endpointIdFromSecretKey, sign } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientHello,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerHello,
} from '../testing/rfc8448-tls'
import type { QuicCryptoFrame } from './frame'
import { parseTlsHandshakes, TlsHandshakeKind, TlsHandshakeType } from './tls'
import { ed25519SpkiFromEndpointId } from './tls-certificate'
import {
  buildTls13CertificateVerifyMessage,
  TlsCertificateVerifyRole,
  TlsSignatureScheme,
} from './tls-certificate-verify'
import { collectQuicTlsHandshakeMessages, type QuicTlsHandshakeMessage } from './tls-crypto-stream'
import { computeTls13FinishedVerifyData, tls13TranscriptHash } from './tls-key-schedule'
import {
  verifyTls13ClientEncryptedHandshakeMessages,
  verifyTls13ServerEncryptedHandshakeMessages,
} from './tls-handshake-verify'

describe('TLS encrypted handshake verification bridge', () => {
  test('verifies raw public key CertificateVerify and Finished messages', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: true })
    const result = await verifyTls13ServerEncryptedHandshakeMessages({
      serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
      expectedEndpointId: fixture.endpointId,
      messages: fixture.messages,
    })

    expect(bytesToHex(result.endpointId)).toBe(bytesToHex(fixture.endpointId))
    expect(result.encryptedExtensions.extensions).toEqual([])
    expect(result.certificateRequest?.extensions).toHaveLength(1)
    expect(result.certificate.entries).toHaveLength(1)
    expect(result.certificateVerify.signatureScheme).toBe(TlsSignatureScheme.Ed25519)
    expect(bytesToHex(result.finishedVerifyData)).toBe(bytesToHex(fixture.finishedVerifyData))
    expect(bytesToHex(result.certificateVerifyTranscriptHash)).toBe(
      bytesToHex(fixture.certificateVerifyTranscriptHash),
    )
    expect(bytesToHex(result.finishedTranscriptHash)).toBe(
      bytesToHex(fixture.finishedTranscriptHash),
    )
  })

  test('accepts handshakes without CertificateRequest', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const result = await verifyTls13ServerEncryptedHandshakeMessages({
      serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
      expectedEndpointId: fixture.endpointId,
      messages: fixture.messages,
    })

    expect(result.certificateRequest).toBeNull()
    expect(bytesToHex(result.endpointId)).toBe(bytesToHex(fixture.endpointId))
  })

  test('uses explicit transcript boundaries for CertificateVerify and Finished', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const certificateVerifyIndex = findMessageIndex(
      fixture.messages,
      TlsHandshakeKind.CertificateVerify,
    )
    const finishedIndex = findMessageIndex(fixture.messages, TlsHandshakeKind.Finished)
    const certificateVerifyHash = tls13TranscriptHash(
      fixture.messages.slice(0, certificateVerifyIndex).map((message) => message.message),
    )
    const finishedHash = tls13TranscriptHash(
      fixture.messages.slice(0, finishedIndex).map((message) => message.message),
    )

    expect(bytesToHex(fixture.certificateVerifyTranscriptHash)).toBe(
      bytesToHex(certificateVerifyHash),
    )
    expect(bytesToHex(fixture.finishedTranscriptHash)).toBe(bytesToHex(finishedHash))
    expect(bytesToHex(fixture.certificateVerifyTranscriptHash)).not.toBe(
      bytesToHex(fixture.finishedTranscriptHash),
    )
  })

  test('rejects invalid CertificateVerify signatures', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const changed = replaceMessageBody(
      fixture.messages,
      TlsHandshakeKind.CertificateVerify,
      certificateVerifyBody(TlsSignatureScheme.Ed25519, new Uint8Array(64)),
    )

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: fixture.endpointId,
        messages: changed,
      }),
      'TLS CertificateVerify signature invalid',
    )
  })

  test('rejects invalid Finished verify_data', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const changed = replaceMessageBody(
      fixture.messages,
      TlsHandshakeKind.Finished,
      new Uint8Array(32),
    )

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: fixture.endpointId,
        messages: changed,
      }),
      'TLS Finished verify_data invalid',
    )
  })

  test('rejects missing encrypted handshake messages', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const withoutFinished = fixture.messages.filter(
      (message) => message.handshake.kind !== TlsHandshakeKind.Finished,
    )

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: fixture.endpointId,
        messages: withoutFinished,
      }),
      'missing TLS finished handshake',
    )
  })

  test('rejects encrypted handshakes without hello transcript prefix', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: fixture.endpointId,
        messages: fixture.messages.slice(2),
      }),
      'missing TLS client-hello handshake',
    )
  })

  test('requires SHA-256 handshake traffic secrets', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: hexToBytes('00'),
        expectedEndpointId: fixture.endpointId,
        messages: fixture.messages,
      }),
      'TLS server handshake traffic secret must be 32 bytes',
    )
  })

  test('rejects server raw public keys that do not match expected endpoint id', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const otherEndpointId = await endpointIdFromSecretKey(
      hexToBytes('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'),
    )

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: otherEndpointId,
        messages: fixture.messages,
      }),
      'TLS raw public key does not match expected endpoint id',
    )
  })

  test('rejects non-empty server Certificate contexts', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const changed = replaceMessageBody(
      fixture.messages,
      TlsHandshakeKind.Certificate,
      certificateBody(hexToBytes('01'), [
        {
          data: ed25519SpkiFromEndpointId(fixture.endpointId),
          extensions: hexToBytes(''),
        },
      ]),
    )

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: fixture.endpointId,
        messages: changed,
      }),
      'TLS Certificate request context mismatch',
    )
  })

  test('rejects non-empty main-handshake CertificateRequest contexts', async () => {
    const fixture = await serverEncryptedHandshakeFixture({ certificateRequest: true })
    const changed = replaceMessageBody(
      fixture.messages,
      TlsHandshakeKind.CertificateRequest,
      certificateRequestBody(hexToBytes('01')),
    )

    await expectRejects(
      verifyTls13ServerEncryptedHandshakeMessages({
        serverHandshakeTrafficSecret: rfc8448ServerHandshakeTrafficSecret,
        expectedEndpointId: fixture.endpointId,
        messages: changed,
      }),
      'TLS CertificateRequest context mismatch',
    )
  })

  test('verifies client raw public key CertificateVerify and Finished messages', async () => {
    const fixture = await clientEncryptedHandshakeFixture()
    const result = await verifyTls13ClientEncryptedHandshakeMessages({
      clientHandshakeTrafficSecret: rfc8448ClientHandshakeTrafficSecret,
      messages: fixture.messages,
    })

    expect(bytesToHex(result.endpointId)).toBe(bytesToHex(fixture.endpointId))
    expect(result.certificate.entries).toHaveLength(1)
    expect(result.certificateVerify.signatureScheme).toBe(TlsSignatureScheme.Ed25519)
    expect(bytesToHex(result.finishedVerifyData)).toBe(bytesToHex(fixture.finishedVerifyData))
    expect(bytesToHex(result.certificateVerifyTranscriptHash)).toBe(
      bytesToHex(fixture.certificateVerifyTranscriptHash),
    )
    expect(bytesToHex(result.finishedTranscriptHash)).toBe(
      bytesToHex(fixture.finishedTranscriptHash),
    )
  })

  test('rejects client handshakes without server CertificateRequest', async () => {
    const serverFixture = await serverEncryptedHandshakeFixture({ certificateRequest: false })
    const fixture = await clientEncryptedHandshakeFixtureFromServer(serverFixture)

    await expectRejects(
      verifyTls13ClientEncryptedHandshakeMessages({
        clientHandshakeTrafficSecret: rfc8448ClientHandshakeTrafficSecret,
        messages: fixture.messages,
      }),
      'missing TLS certificate-request handshake',
    )
  })

  test('rejects client Certificate contexts that do not match CertificateRequest', async () => {
    const fixture = await clientEncryptedHandshakeFixture()
    const changed = replaceLastMessageBody(
      fixture.messages,
      TlsHandshakeKind.Certificate,
      certificateBody(hexToBytes('01'), [
        {
          data: ed25519SpkiFromEndpointId(fixture.endpointId),
          extensions: hexToBytes(''),
        },
      ]),
    )

    await expectRejects(
      verifyTls13ClientEncryptedHandshakeMessages({
        clientHandshakeTrafficSecret: rfc8448ClientHandshakeTrafficSecret,
        messages: changed,
      }),
      'TLS Certificate request context mismatch',
    )
  })

  test('rejects invalid client CertificateVerify signatures', async () => {
    const fixture = await clientEncryptedHandshakeFixture()
    const changed = replaceLastMessageBody(
      fixture.messages,
      TlsHandshakeKind.CertificateVerify,
      certificateVerifyBody(TlsSignatureScheme.Ed25519, new Uint8Array(64)),
    )

    await expectRejects(
      verifyTls13ClientEncryptedHandshakeMessages({
        clientHandshakeTrafficSecret: rfc8448ClientHandshakeTrafficSecret,
        messages: changed,
      }),
      'TLS CertificateVerify signature invalid',
    )
  })

  test('rejects invalid client Finished verify_data', async () => {
    const fixture = await clientEncryptedHandshakeFixture()
    const changed = replaceLastMessageBody(
      fixture.messages,
      TlsHandshakeKind.Finished,
      new Uint8Array(32),
    )

    await expectRejects(
      verifyTls13ClientEncryptedHandshakeMessages({
        clientHandshakeTrafficSecret: rfc8448ClientHandshakeTrafficSecret,
        messages: changed,
      }),
      'TLS Finished verify_data invalid',
    )
  })
})

interface EncryptedHandshakeFixture {
  readonly messages: readonly QuicTlsHandshakeMessage[]
  readonly endpointId: Uint8Array
  readonly certificateVerifyTranscriptHash: Uint8Array
  readonly finishedTranscriptHash: Uint8Array
  readonly finishedVerifyData: Uint8Array
}

async function serverEncryptedHandshakeFixture(options: {
  readonly certificateRequest: boolean
}): Promise<EncryptedHandshakeFixture> {
  const secretKey = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
  const endpointId = await endpointIdFromSecretKey(secretKey)
  const encryptedExtensions = tlsHandshakeMessage(
    TlsHandshakeType.EncryptedExtensions,
    writeU16BE(0),
  )
  const certificateRequest = options.certificateRequest
    ? tlsHandshakeMessage(
        TlsHandshakeType.CertificateRequest,
        certificateRequestBody(hexToBytes('')),
      )
    : null
  const certificate = tlsHandshakeMessage(
    TlsHandshakeType.Certificate,
    certificateBody(hexToBytes(''), [
      {
        data: ed25519SpkiFromEndpointId(endpointId),
        extensions: hexToBytes(''),
      },
    ]),
  )
  const beforeCertificateVerify =
    certificateRequest === null
      ? [rfc8448ClientHello, rfc8448ServerHello, encryptedExtensions, certificate]
      : [
          rfc8448ClientHello,
          rfc8448ServerHello,
          encryptedExtensions,
          certificateRequest,
          certificate,
        ]
  const certificateVerifyTranscriptHash = tls13TranscriptHash(beforeCertificateVerify)
  const signature = await sign(
    secretKey,
    buildTls13CertificateVerifyMessage(
      TlsCertificateVerifyRole.Server,
      certificateVerifyTranscriptHash,
    ),
  )
  const certificateVerify = tlsHandshakeMessage(
    TlsHandshakeType.CertificateVerify,
    certificateVerifyBody(TlsSignatureScheme.Ed25519, signature),
  )
  const finishedTranscriptHash = tls13TranscriptHash([
    ...beforeCertificateVerify,
    certificateVerify,
  ])
  const finishedVerifyData = computeTls13FinishedVerifyData(
    rfc8448ServerHandshakeTrafficSecret,
    finishedTranscriptHash,
  )
  const finished = tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)
  const encryptedMessages =
    certificateRequest === null
      ? [encryptedExtensions, certificate, certificateVerify, finished]
      : [encryptedExtensions, certificateRequest, certificate, certificateVerify, finished]

  return {
    messages: [
      ...collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ClientHello)]).messages,
      ...collectQuicTlsHandshakeMessages([cryptoFrame(0, rfc8448ServerHello)]).messages,
      ...collectQuicTlsHandshakeMessages([cryptoFrame(0, concatBytes(encryptedMessages))]).messages,
    ],
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
    finishedVerifyData,
  }
}

async function clientEncryptedHandshakeFixture(): Promise<EncryptedHandshakeFixture> {
  return clientEncryptedHandshakeFixtureFromServer(
    await serverEncryptedHandshakeFixture({ certificateRequest: true }),
  )
}

async function clientEncryptedHandshakeFixtureFromServer(
  serverFixture: EncryptedHandshakeFixture,
): Promise<EncryptedHandshakeFixture> {
  const secretKey = hexToBytes('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
  const endpointId = await endpointIdFromSecretKey(secretKey)
  const certificate = tlsHandshakeMessage(
    TlsHandshakeType.Certificate,
    certificateBody(hexToBytes(''), [
      {
        data: ed25519SpkiFromEndpointId(endpointId),
        extensions: hexToBytes(''),
      },
    ]),
  )
  const beforeCertificateVerify = [
    ...serverFixture.messages.map((message) => message.message),
    certificate,
  ]
  const certificateVerifyTranscriptHash = tls13TranscriptHash(beforeCertificateVerify)
  const signature = await sign(
    secretKey,
    buildTls13CertificateVerifyMessage(
      TlsCertificateVerifyRole.Client,
      certificateVerifyTranscriptHash,
    ),
  )
  const certificateVerify = tlsHandshakeMessage(
    TlsHandshakeType.CertificateVerify,
    certificateVerifyBody(TlsSignatureScheme.Ed25519, signature),
  )
  const finishedTranscriptHash = tls13TranscriptHash([
    ...beforeCertificateVerify,
    certificateVerify,
  ])
  const finishedVerifyData = computeTls13FinishedVerifyData(
    rfc8448ClientHandshakeTrafficSecret,
    finishedTranscriptHash,
  )
  const finished = tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)

  return {
    messages: [
      ...serverFixture.messages,
      ...collectQuicTlsHandshakeMessages([
        cryptoFrame(0, concatBytes([certificate, certificateVerify, finished])),
      ]).messages,
    ],
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
    finishedVerifyData,
  }
}

function replaceMessageBody(
  messages: readonly QuicTlsHandshakeMessage[],
  kind: string,
  body: Uint8Array,
): readonly QuicTlsHandshakeMessage[] {
  return messages.map((message) => {
    if (message.handshake.kind !== kind) {
      return message
    }
    const handshakeType = handshakeTypeForKind(kind)
    const rawMessage = tlsHandshakeMessage(handshakeType, body)
    const handshake = parseSingleHandshake(rawMessage)
    return {
      handshake,
      message: rawMessage,
    }
  })
}

function replaceLastMessageBody(
  messages: readonly QuicTlsHandshakeMessage[],
  kind: string,
  body: Uint8Array,
): readonly QuicTlsHandshakeMessage[] {
  let index = -1
  for (let pos = messages.length - 1; pos >= 0; pos -= 1) {
    if (messages[pos]?.handshake.kind === kind) {
      index = pos
      break
    }
  }
  if (index === -1) {
    throw new Error(`missing ${kind}`)
  }

  const out = messages.slice()
  const handshakeType = handshakeTypeForKind(kind)
  const rawMessage = tlsHandshakeMessage(handshakeType, body)
  out[index] = {
    handshake: parseSingleHandshake(rawMessage),
    message: rawMessage,
  }
  return out
}

function findMessageIndex(messages: readonly QuicTlsHandshakeMessage[], kind: string): number {
  const index = messages.findIndex((message) => message.handshake.kind === kind)
  if (index === -1) {
    throw new Error(`missing ${kind}`)
  }
  return index
}

function parseSingleHandshake(message: Uint8Array) {
  const result = parseTlsHandshakes(message)
  const handshake = result.handshakes[0]
  if (handshake === undefined) {
    throw new Error('expected TLS handshake')
  }
  return handshake
}

async function expectRejects(promise: Promise<unknown>, message: string): Promise<void> {
  try {
    await promise
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(RangeError)
    expect(String(error)).toContain(message)
    return
  }
  throw new Error('expected promise rejection')
}

function handshakeTypeForKind(kind: string): number {
  if (kind === TlsHandshakeKind.Certificate) {
    return TlsHandshakeType.Certificate
  }
  if (kind === TlsHandshakeKind.CertificateRequest) {
    return TlsHandshakeType.CertificateRequest
  }
  if (kind === TlsHandshakeKind.CertificateVerify) {
    return TlsHandshakeType.CertificateVerify
  }
  if (kind === TlsHandshakeKind.Finished) {
    return TlsHandshakeType.Finished
  }
  throw new RangeError('unsupported TLS handshake kind')
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

function certificateRequestBody(requestContext: Uint8Array): Uint8Array {
  return concatBytes([
    tlsU8Vector(requestContext),
    tlsU16Vector(concatBytes([writeU16BE(0x000d), tlsU16Vector(writeU16BE(0x0807))])),
  ])
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

function tlsU16Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) {
    throw new RangeError('TLS u16 vector too large')
  }
  return concatBytes([writeU16BE(bytes.length), bytes])
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

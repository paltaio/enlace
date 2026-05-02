import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ServerHandshakeTrafficSecret,
} from '../testing/rfc8448-tls'
import {
  certificateBody,
  certificateRequestBody,
  certificateVerifyBody,
  clientEncryptedHandshakeFixture,
  clientEncryptedHandshakeFixtureFromServer,
  findMessageIndex,
  replaceLastMessageBody,
  replaceMessageBody,
  serverEncryptedHandshakeFixture,
} from '../testing/tls-handshake-fixtures'
import { TlsExtensionType, TlsHandshakeKind } from './tls'
import { ed25519SpkiFromEndpointId } from './tls-certificate'
import { TlsSignatureScheme } from './tls-certificate-verify'
import { tls13TranscriptHash } from './tls-key-schedule'
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
    expect(
      result.encryptedExtensions.extensions.map((extension) => extension.extensionType),
    ).toEqual([TlsExtensionType.QuicTransportParameters])
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

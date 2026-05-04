import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  replaceLastMessageBody,
  tlsHandshakeStateFixture,
  tlsTestAlpn,
} from '../testing/tls-handshake-fixtures'
import { rfc8448ClientPrivateKey, rfc8448ServerPrivateKey } from '../testing/rfc8448-tls'
import {
  verifyTls13ClientHandshakeState,
  verifyTls13ServerHandshakeState,
} from './tls-handshake-state'
import { TlsHandshakeKind } from './tls'
import type { QuicTlsHandshakeMessage } from './tls-crypto-stream'

describe('TLS 1.3 handshake state bridge', () => {
  test('verifies client-side state with negotiated ALPN and client auth', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: true })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      expectedAlpn: tlsTestAlpn,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.negotiatedAlpn)).toBe(bytesToHex(tlsTestAlpn))
    expect(bytesToHex(state.peerEndpointId)).toBe(bytesToHex(fixture.server.endpointId))
    expect(bytesToHex(state.handshake.transcriptHash)).toBe(
      bytesToHex(fixture.handshake.transcriptHash),
    )
    expect(bytesToHex(state.handshake.secrets.clientHandshakeTrafficSecret)).toBe(
      bytesToHex(fixture.handshake.secrets.clientHandshakeTrafficSecret),
    )
    expect(bytesToHex(state.handshake.secrets.serverHandshakeTrafficSecret)).toBe(
      bytesToHex(fixture.handshake.secrets.serverHandshakeTrafficSecret),
    )
    expect(state.transportParameters.client.initialSourceConnectionId).not.toBeNull()
    expect(state.transportParameters.server.originalDestinationConnectionId).not.toBeNull()
    expect(state.transportParameters.server.initialSourceConnectionId).not.toBeNull()
    expect(state.transportParameters.server.initialMaxData).toBe(65536n)
    expect(state.transportParameters.server.initialMaxStreamDataBidiRemote).toBe(65536n)
    expect(state.client).not.toBeNull()
    expect(bytesToHex(state.transcriptHashes.serverHello)).toBe(
      bytesToHex(fixture.handshake.transcriptHash),
    )
    expect(bytesToHex(state.transcriptHashes.serverCertificateVerify)).toBe(
      bytesToHex(fixture.server.certificateVerifyTranscriptHash),
    )
    expect(bytesToHex(state.transcriptHashes.serverFinished)).toBe(
      bytesToHex(fixture.server.finishedTranscriptHash),
    )
    expect(bytesToHex(requireBytes(state.transcriptHashes.clientCertificateVerify))).toBe(
      bytesToHex(requireFixture(fixture.client).certificateVerifyTranscriptHash),
    )
    expect(bytesToHex(requireBytes(state.transcriptHashes.clientFinished))).toBe(
      bytesToHex(requireFixture(fixture.client).finishedTranscriptHash),
    )
  })

  test('verifies server-side state and client endpoint id when requested', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: true })
    const state = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: fixture.server.endpointId,
      expectedAlpn: tlsTestAlpn,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.negotiatedAlpn)).toBe(bytesToHex(tlsTestAlpn))
    expect(bytesToHex(requireBytes(state.peerEndpointId))).toBe(
      bytesToHex(requireFixture(fixture.client).endpointId),
    )
    expect(state.client).not.toBeNull()
    expect(bytesToHex(state.handshake.sharedSecret)).toBe(
      bytesToHex(fixture.handshake.sharedSecret),
    )
  })

  test('verifies client Finished when no CertificateRequest is present', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    const state = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.negotiatedAlpn)).toBe(bytesToHex(tlsTestAlpn))
    expect(state.client).not.toBeNull()
    expect(state.peerEndpointId).toBeNull()
    expect(state.transcriptHashes.clientCertificateVerify).toBeNull()
    expect(state.transcriptHashes.clientFinished).not.toBeNull()
  })

  test('client-side state also verifies Finished without CertificateRequest', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.negotiatedAlpn)).toBe(bytesToHex(tlsTestAlpn))
    expect(state.client).not.toBeNull()
    expect(state.transcriptHashes.clientCertificateVerify).toBeNull()
    expect(state.transcriptHashes.clientFinished).not.toBeNull()
  })

  test('rejects invalid client Finished without CertificateRequest', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    const changed = replaceLastMessageBody(
      fixture.messages,
      TlsHandshakeKind.Finished,
      new Uint8Array(32),
    )

    await expectRejects(
      verifyTls13ServerHandshakeState({
        x25519PrivateKey: rfc8448ServerPrivateKey,
        localServerEndpointId: fixture.server.endpointId,
        messages: changed,
      }),
      'TLS Finished verify_data invalid',
    )
  })

  test('requires server endpoint id from caller', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    const otherEndpointId = await endpointIdFromSecretKey(
      hexToBytes('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'),
    )

    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: otherEndpointId,
        messages: fixture.messages,
      }),
      'TLS raw public key does not match expected endpoint id',
    )
  })

  test('requires ALPN to be offered and selected', async () => {
    const withoutSelectedAlpn = await tlsHandshakeStateFixture({
      certificateRequest: false,
      selectedAlpn: null,
    })
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: withoutSelectedAlpn.server.endpointId,
        messages: withoutSelectedAlpn.messages,
      }),
      'TLS EncryptedExtensions must select ALPN',
    )

    const notOffered = await tlsHandshakeStateFixture({
      certificateRequest: false,
      selectedAlpn: hexToBytes('6833'),
    })
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: notOffered.server.endpointId,
        messages: notOffered.messages,
      }),
      'TLS selected ALPN must be offered by ClientHello',
    )
  })

  test('requires QUIC transport parameters in encrypted extensions', async () => {
    const fixture = await tlsHandshakeStateFixture({
      certificateRequest: false,
      serverTransportParameters: null,
    })

    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: fixture.server.endpointId,
        messages: fixture.messages,
      }),
      'TLS EncryptedExtensions must include QUIC transport parameters',
    )
  })

  test('requires raw public key certificate type negotiation', async () => {
    const withoutServerOffer = await tlsHandshakeStateFixture({
      certificateRequest: false,
      offerServerRawPublicKey: false,
    })
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: withoutServerOffer.server.endpointId,
        messages: withoutServerOffer.messages,
      }),
      'TLS ClientHello must offer server raw public key certificate type',
    )

    const withoutServerSelection = await tlsHandshakeStateFixture({
      certificateRequest: false,
      selectServerRawPublicKey: false,
    })
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: withoutServerSelection.server.endpointId,
        messages: withoutServerSelection.messages,
      }),
      'TLS EncryptedExtensions must select server raw public key certificate type',
    )

    const withoutClientSelection = await tlsHandshakeStateFixture({
      certificateRequest: true,
      selectClientRawPublicKey: false,
    })
    await expectRejects(
      verifyTls13ServerHandshakeState({
        x25519PrivateKey: rfc8448ServerPrivateKey,
        localServerEndpointId: withoutClientSelection.server.endpointId,
        messages: withoutClientSelection.messages,
      }),
      'TLS EncryptedExtensions must select client raw public key certificate type',
    )
  })

  test('rejects missing ClientHello ALPN and selected ALPN mismatch', async () => {
    const withoutClientAlpn = await tlsHandshakeStateFixture({
      certificateRequest: false,
      offerAlpn: false,
    })
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: withoutClientAlpn.server.endpointId,
        messages: withoutClientAlpn.messages,
      }),
      'TLS ClientHello must offer ALPN',
    )

    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: fixture.server.endpointId,
        expectedAlpn: hexToBytes('6833'),
        messages: fixture.messages,
      }),
      'TLS selected ALPN mismatch',
    )
  })

  test('requires ClientHello then ServerHello at transcript start', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })

    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: fixture.server.endpointId,
        messages: fixture.messages.slice(1),
      }),
      'missing TLS ClientHello handshake message',
    )
    await expectRejects(
      verifyTls13ClientHandshakeState({
        x25519PrivateKey: rfc8448ClientPrivateKey,
        expectedServerEndpointId: fixture.server.endpointId,
        messages: [requireMessage(fixture.messages, 0)],
      }),
      'missing TLS ServerHello handshake message',
    )
  })

  test('uses ServerHello transcript boundary before encrypted messages', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: true })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.transcriptHashes.serverHello)).toBe(
      bytesToHex(fixture.handshake.transcriptHash),
    )
    expect(bytesToHex(state.transcriptHashes.serverHello)).not.toBe(
      bytesToHex(state.transcriptHashes.serverCertificateVerify),
    )
  })
})

function requireBytes(value: Uint8Array | null): Uint8Array {
  if (value === null) {
    throw new Error('expected bytes')
  }
  return value
}

function requireFixture<T>(value: T | null): T {
  if (value === null) {
    throw new Error('expected fixture')
  }
  return value
}

function requireMessage(
  messages: readonly QuicTlsHandshakeMessage[],
  index: number,
): QuicTlsHandshakeMessage {
  const message = messages[index]
  if (message === undefined) {
    throw new Error('expected message')
  }
  return message
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

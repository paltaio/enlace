import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  appendTlsExtensionToClientHello,
  clientEncryptedHandshakeFixtureFromServer,
  serverEncryptedHandshakeFixture,
  tlsAlpnExtensionData,
  tlsTestAlpn,
  type EncryptedHandshakeFixture,
} from '../testing/tls-handshake-fixtures'
import {
  rfc8448ClientHello,
  rfc8448ClientPrivateKey,
  rfc8448ServerHello,
  rfc8448ServerPrivateKey,
} from '../testing/rfc8448-tls'
import {
  parseTlsHandshakes,
  TlsExtensionType,
  TlsHandshakeKind,
  type TlsClientHelloHandshake,
  type TlsServerHelloHandshake,
} from './tls'
import {
  deriveTls13X25519HandshakeSecrets,
  TlsHandshakeRole,
  type Tls13X25519HandshakeSecrets,
} from './tls-handshake'
import {
  verifyTls13ClientHandshakeState,
  verifyTls13ServerHandshakeState,
} from './tls-handshake-state'
import type { QuicTlsHandshakeMessage } from './tls-crypto-stream'

describe('TLS 1.3 handshake state bridge', () => {
  test('verifies client-side state with negotiated ALPN and client auth', async () => {
    const fixture = await handshakeStateFixture({ certificateRequest: true })
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
    const fixture = await handshakeStateFixture({ certificateRequest: true })
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

  test('skips client auth verification when no CertificateRequest is present', async () => {
    const fixture = await handshakeStateFixture({ certificateRequest: false })
    const state = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.negotiatedAlpn)).toBe(bytesToHex(tlsTestAlpn))
    expect(state.client).toBeNull()
    expect(state.peerEndpointId).toBeNull()
    expect(state.transcriptHashes.clientCertificateVerify).toBeNull()
    expect(state.transcriptHashes.clientFinished).toBeNull()
  })

  test('client-side state also skips client auth without CertificateRequest', async () => {
    const fixture = await handshakeStateFixture({ certificateRequest: false })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })

    expect(bytesToHex(state.negotiatedAlpn)).toBe(bytesToHex(tlsTestAlpn))
    expect(state.client).toBeNull()
    expect(state.transcriptHashes.clientCertificateVerify).toBeNull()
    expect(state.transcriptHashes.clientFinished).toBeNull()
  })

  test('requires server endpoint id from caller', async () => {
    const fixture = await handshakeStateFixture({ certificateRequest: false })
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
    const withoutSelectedAlpn = await handshakeStateFixture({
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

    const notOffered = await handshakeStateFixture({
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

  test('rejects missing ClientHello ALPN and selected ALPN mismatch', async () => {
    const withoutClientAlpn = await handshakeStateFixture({
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

    const fixture = await handshakeStateFixture({ certificateRequest: false })
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
    const fixture = await handshakeStateFixture({ certificateRequest: false })

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
    const fixture = await handshakeStateFixture({ certificateRequest: true })
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

interface HandshakeStateFixture {
  readonly handshake: Tls13X25519HandshakeSecrets
  readonly server: EncryptedHandshakeFixture
  readonly client: EncryptedHandshakeFixture | null
  readonly messages: readonly QuicTlsHandshakeMessage[]
}

async function handshakeStateFixture(options: {
  readonly certificateRequest: boolean
  readonly offerAlpn?: boolean
  readonly selectedAlpn?: Uint8Array | null
}): Promise<HandshakeStateFixture> {
  const clientHello =
    options.offerAlpn === false
      ? rfc8448ClientHello
      : appendTlsExtensionToClientHello(rfc8448ClientHello, {
          type: TlsExtensionType.ApplicationLayerProtocolNegotiation,
          data: tlsAlpnExtensionData([tlsTestAlpn]),
        })
  const serverHello = rfc8448ServerHello
  const handshake = await deriveTls13X25519HandshakeSecrets({
    role: TlsHandshakeRole.Client,
    privateKey: rfc8448ClientPrivateKey,
    clientHello: parseClientHello(clientHello),
    serverHello: parseServerHello(serverHello),
    clientHelloMessage: clientHello,
    serverHelloMessage: serverHello,
  })
  const server = await serverEncryptedHandshakeFixture({
    certificateRequest: options.certificateRequest,
    clientHelloMessage: clientHello,
    serverHelloMessage: serverHello,
    serverHandshakeTrafficSecret: handshake.secrets.serverHandshakeTrafficSecret,
    ...(options.selectedAlpn === null
      ? {}
      : {
          selectedAlpn: options.selectedAlpn ?? tlsTestAlpn,
        }),
  })
  const client = options.certificateRequest
    ? await clientEncryptedHandshakeFixtureFromServer(server, {
        clientHandshakeTrafficSecret: handshake.secrets.clientHandshakeTrafficSecret,
      })
    : null

  return {
    handshake,
    server,
    client,
    messages: client?.messages ?? server.messages,
  }
}

function parseClientHello(message: Uint8Array): TlsClientHelloHandshake {
  const result = parseTlsHandshakes(message)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== TlsHandshakeKind.ClientHello) {
    throw new Error('expected ClientHello')
  }
  return handshake
}

function parseServerHello(message: Uint8Array): TlsServerHelloHandshake {
  const result = parseTlsHandshakes(message)
  const handshake = result.handshakes[0]
  if (handshake?.kind !== TlsHandshakeKind.ServerHello) {
    throw new Error('expected ServerHello')
  }
  return handshake
}

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

import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import { tlsHandshakeStateFixture } from '../testing/tls-handshake-fixtures'
import { rfc8448ClientPrivateKey, rfc8448ServerPrivateKey } from '../testing/rfc8448-tls'
import { deriveTls13ApplicationTrafficFromHandshakeState } from './tls-application-traffic'
import { deriveTls13ApplicationTrafficSecrets, tls13TranscriptHash } from './tls-key-schedule'
import {
  verifyTls13ClientHandshakeState,
  verifyTls13ServerHandshakeState,
  type Tls13ServerHandshakeState,
} from './tls-handshake-state'

describe('TLS 1.3 application traffic bridge', () => {
  test('derives application traffic secrets and QUIC 1-RTT keys from verified state', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: true })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })
    const traffic = deriveTls13ApplicationTrafficFromHandshakeState(state)

    expect(bytesToHex(traffic.transcriptHash)).toBe(
      bytesToHex(state.transcriptHashes.serverApplicationTraffic),
    )
    expect(bytesToHex(traffic.transcriptHash)).not.toBe(
      bytesToHex(state.transcriptHashes.serverFinished),
    )
    expect(traffic.secrets.masterSecret).toHaveLength(32)
    expect(traffic.secrets.clientApplicationTrafficSecret).toHaveLength(32)
    expect(traffic.secrets.serverApplicationTrafficSecret).toHaveLength(32)
    expect(traffic.keys.client.packetKey).toHaveLength(16)
    expect(traffic.keys.client.packetIv).toHaveLength(12)
    expect(traffic.keys.client.headerProtectionKey).toHaveLength(16)
    expect(traffic.keys.server.packetKey).toHaveLength(16)
    expect(traffic.keys.server.packetIv).toHaveLength(12)
    expect(traffic.keys.server.headerProtectionKey).toHaveLength(16)
  })

  test('derives the same application traffic from server-side verified state', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: true })
    const clientState = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })
    const serverState = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })
    const clientTraffic = deriveTls13ApplicationTrafficFromHandshakeState(clientState)
    const serverTraffic = deriveTls13ApplicationTrafficFromHandshakeState(serverState)

    expect(bytesToHex(serverTraffic.secrets.clientApplicationTrafficSecret)).toBe(
      bytesToHex(clientTraffic.secrets.clientApplicationTrafficSecret),
    )
    expect(bytesToHex(serverTraffic.secrets.serverApplicationTrafficSecret)).toBe(
      bytesToHex(clientTraffic.secrets.serverApplicationTrafficSecret),
    )
    expect(bytesToHex(serverTraffic.keys.client.packetKey)).toBe(
      bytesToHex(clientTraffic.keys.client.packetKey),
    )
    expect(bytesToHex(serverTraffic.keys.server.packetKey)).toBe(
      bytesToHex(clientTraffic.keys.server.packetKey),
    )
  })

  test('uses transcript through server Finished instead of earlier boundaries', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })
    const traffic = deriveTls13ApplicationTrafficFromHandshakeState(state)
    const expectedTranscriptHash = tls13TranscriptHash(
      fixture.server.messages.map((message) => message.message),
    )
    const serverHelloTraffic = deriveTls13ApplicationTrafficSecrets(
      state.handshake.secrets.handshakeSecret,
      state.transcriptHashes.serverHello,
    )
    const beforeFinishedTraffic = deriveTls13ApplicationTrafficSecrets(
      state.handshake.secrets.handshakeSecret,
      state.transcriptHashes.serverFinished,
    )

    expect(bytesToHex(traffic.transcriptHash)).toBe(bytesToHex(expectedTranscriptHash))
    expect(bytesToHex(traffic.transcriptHash)).not.toBe(
      bytesToHex(state.transcriptHashes.serverFinished),
    )
    expect(bytesToHex(traffic.secrets.clientApplicationTrafficSecret)).not.toBe(
      bytesToHex(serverHelloTraffic.clientApplicationTrafficSecret),
    )
    expect(bytesToHex(traffic.secrets.serverApplicationTrafficSecret)).not.toBe(
      bytesToHex(serverHelloTraffic.serverApplicationTrafficSecret),
    )
    expect(bytesToHex(traffic.secrets.clientApplicationTrafficSecret)).not.toBe(
      bytesToHex(beforeFinishedTraffic.clientApplicationTrafficSecret),
    )
  })

  test('requires verified client Finished when client auth is requested', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: true })
    const state = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })
    const incompleteState: Tls13ServerHandshakeState = {
      ...state,
      client: null,
      peerEndpointId: null,
      transcriptHashes: {
        ...state.transcriptHashes,
        clientCertificateVerify: null,
        clientFinished: null,
      },
    }

    expect(() => deriveTls13ApplicationTrafficFromHandshakeState(incompleteState)).toThrow(
      'TLS client Finished required after CertificateRequest',
    )
  })

  test('rejects wrong-length handshake secret and transcript hash', async () => {
    const fixture = await tlsHandshakeStateFixture({ certificateRequest: false })
    const state = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: fixture.server.endpointId,
      messages: fixture.messages,
    })

    expect(() =>
      deriveTls13ApplicationTrafficSecrets(
        hexToBytes('00'),
        state.transcriptHashes.serverApplicationTraffic,
      ),
    ).toThrow('TLS handshake secret must be 32 bytes')
    expect(() =>
      deriveTls13ApplicationTrafficSecrets(
        state.handshake.secrets.handshakeSecret,
        hexToBytes('00'),
      ),
    ).toThrow('TLS transcript hash must be 32 bytes')
  })
})

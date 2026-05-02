import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import { rfc8448ClientPrivateKey, rfc8448ServerPrivateKey } from '../testing/rfc8448-tls'
import { createQuicConnectionStateFromHandshake } from './connection'
import { encodeQuicCryptoFrame, parseQuicFrames } from './frame'
import {
  buildTls13ClientEncryptedFlight,
  buildTls13ClientHello,
  buildTls13ServerEncryptedFlight,
  buildTls13ServerHello,
} from './tls-handshake-flight'
import {
  verifyTls13ClientHandshakeState,
  verifyTls13ServerHandshakeState,
} from './tls-handshake-state'
import { deriveTls13X25519HandshakeSecrets, TlsHandshakeRole } from './tls-handshake'
import {
  getTlsExtension,
  parseTlsAlpnProtocols,
  parseTlsClientKeyShares,
  TlsExtensionType,
  TlsHandshakeKind,
  type TlsClientHelloHandshake,
  type TlsServerHelloHandshake,
} from './tls'
import { collectQuicTlsHandshakeMessages, type QuicTlsHandshakeMessage } from './tls-crypto-stream'
import {
  encodeQuicTransportParameters,
  parseQuicTransportParameters,
  QuicEndpointRole,
} from './transport-parameters'

const testAlpn = new TextEncoder().encode('/iroh-gossip/1')
const clientConnectionId = hexToBytes('c1c2c3c4')
const serverConnectionId = hexToBytes('d1d2d3d4')
const serverEndpointSecretKey = hexToBytes(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
)
const clientEndpointSecretKey = hexToBytes(
  '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
)

describe('TLS 1.3 handshake flight builders', () => {
  test('builds a ClientHello with QUIC and raw-public-key extensions', async () => {
    const transportParameters = clientTransportParameters()
    const clientHello = await buildTls13ClientHello({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      alpnProtocols: [testAlpn],
      transportParameters,
      random: hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
      legacySessionId: hexToBytes(
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
      ),
    })
    const handshake = requireClientHello(clientHello.message)
    const keyShares = parseTlsClientKeyShares(
      requireExtension(handshake, TlsExtensionType.KeyShare),
    )

    expect(bytesToHex(keyShares[0]?.keyExchange ?? new Uint8Array())).toBe(
      bytesToHex(clientHello.x25519PublicKey),
    )
    expect(bytesToHex(requireExtension(handshake, TlsExtensionType.ClientCertificateType))).toBe(
      '0102',
    )
    expect(bytesToHex(requireExtension(handshake, TlsExtensionType.ServerCertificateType))).toBe(
      '0102',
    )
    expect(
      parseTlsAlpnProtocols(
        requireExtension(handshake, TlsExtensionType.ApplicationLayerProtocolNegotiation),
      ).map(bytesToHex),
    ).toEqual([bytesToHex(testAlpn)])
    expect(
      parseQuicTransportParameters(
        requireExtension(handshake, TlsExtensionType.QuicTransportParameters),
        QuicEndpointRole.Client,
      ).initialSourceConnectionId,
    ).toEqual(clientConnectionId)
  })

  test('carries generated handshakes through CRYPTO frames', async () => {
    const clientHello = await buildTls13ClientHello({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      alpnProtocols: [testAlpn],
      transportParameters: clientTransportParameters(),
    })
    const frames = parseQuicFrames(encodeQuicCryptoFrame(0, clientHello.message.message)).frames
    const cryptoFrame = frames[0]
    if (cryptoFrame === undefined || cryptoFrame.type !== 'crypto') {
      throw new Error('expected CRYPTO frame')
    }
    const collected = collectQuicTlsHandshakeMessages([cryptoFrame])

    expect(collected.messages[0]?.handshake.kind).toBe(TlsHandshakeKind.ClientHello)
    expect(bytesToHex(collected.cryptoStream)).toBe(bytesToHex(clientHello.message.message))
  })

  test('builds verifiable server and client encrypted flights', async () => {
    const clientHello = await buildTls13ClientHello({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      alpnProtocols: [testAlpn],
      transportParameters: clientTransportParameters(),
    })
    const serverHello = await buildTls13ServerHello({
      clientHello: requireClientHello(clientHello.message),
      x25519PrivateKey: rfc8448ServerPrivateKey,
    })
    const handshake = await deriveTls13X25519HandshakeSecrets({
      role: TlsHandshakeRole.Client,
      privateKey: rfc8448ClientPrivateKey,
      clientHello: requireClientHello(clientHello.message),
      serverHello: requireServerHello(serverHello.message),
      clientHelloMessage: clientHello.message.message,
      serverHelloMessage: serverHello.message.message,
    })
    const serverFlight = await buildTls13ServerEncryptedFlight({
      clientHelloMessage: clientHello.message.message,
      serverHelloMessage: serverHello.message.message,
      serverHandshakeTrafficSecret: handshake.secrets.serverHandshakeTrafficSecret,
      endpointSecretKey: serverEndpointSecretKey,
      selectedAlpn: testAlpn,
      transportParameters: serverTransportParameters(),
    })
    const clientPriorMessages = [clientHello.message, serverHello.message, ...serverFlight.messages]
    const clientFlight = await buildTls13ClientEncryptedFlight({
      priorMessages: clientPriorMessages,
      clientHandshakeTrafficSecret: handshake.secrets.clientHandshakeTrafficSecret,
      endpointSecretKey: clientEndpointSecretKey,
    })
    const messages = [...clientPriorMessages, ...clientFlight.messages]
    const serverEndpointId = await endpointIdFromSecretKey(serverEndpointSecretKey)
    const clientState = await verifyTls13ClientHandshakeState({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      expectedServerEndpointId: serverEndpointId,
      expectedAlpn: testAlpn,
      messages,
    })
    const serverState = await verifyTls13ServerHandshakeState({
      x25519PrivateKey: rfc8448ServerPrivateKey,
      localServerEndpointId: serverEndpointId,
      expectedAlpn: testAlpn,
      messages,
    })
    const clientConnection = createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Client,
      handshakeState: clientState,
      localConnectionId: clientConnectionId,
      peerConnectionId: serverConnectionId,
    })
    const serverConnection = createQuicConnectionStateFromHandshake({
      role: QuicEndpointRole.Server,
      handshakeState: serverState,
      localConnectionId: serverConnectionId,
      peerConnectionId: clientConnectionId,
    })
    const sent = clientConnection.sendStream(0, hexToBytes('70696e67'), true)
    const received = serverConnection.receive(sent.packet)

    expect(messages.map((message) => message.handshake.kind)).toEqual([
      TlsHandshakeKind.ClientHello,
      TlsHandshakeKind.ServerHello,
      TlsHandshakeKind.EncryptedExtensions,
      TlsHandshakeKind.CertificateRequest,
      TlsHandshakeKind.Certificate,
      TlsHandshakeKind.CertificateVerify,
      TlsHandshakeKind.Finished,
      TlsHandshakeKind.Certificate,
      TlsHandshakeKind.CertificateVerify,
      TlsHandshakeKind.Finished,
    ])
    expect(bytesToHex(serverFlight.endpointId ?? new Uint8Array())).toBe(
      bytesToHex(serverEndpointId),
    )
    expect(bytesToHex(clientState.negotiatedAlpn)).toBe(bytesToHex(testAlpn))
    expect(received.streamOutputs[0]?.complete).toBe(true)
  })

  test('rejects wrong-length hello random', async () => {
    await buildTls13ClientHello({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      alpnProtocols: [testAlpn],
      transportParameters: clientTransportParameters(),
      random: hexToBytes('00'),
    }).then(
      () => {
        throw new Error('expected ClientHello random validation error')
      },
      (error: unknown) => {
        expect(error).toBeInstanceOf(RangeError)
        expect(errorMessage(error)).toBe('TLS ClientHello random must be 32 bytes')
      },
    )
  })

  test('rejects empty ALPN offers', async () => {
    await buildTls13ClientHello({
      x25519PrivateKey: rfc8448ClientPrivateKey,
      alpnProtocols: [],
      transportParameters: clientTransportParameters(),
    }).then(
      () => {
        throw new Error('expected ALPN validation error')
      },
      (error: unknown) => {
        expect(error).toBeInstanceOf(RangeError)
        expect(errorMessage(error)).toBe('TLS ALPN protocol list must not be empty')
      },
    )
  })
})

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

function clientTransportParameters(): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: 65536n,
    initialMaxStreamDataBidiLocal: 65536n,
    initialMaxStreamDataBidiRemote: 65536n,
    initialMaxStreamDataUni: 65536n,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    initialSourceConnectionId: clientConnectionId,
  })
}

function serverTransportParameters(): Uint8Array {
  return encodeQuicTransportParameters({
    initialMaxData: 65536n,
    initialMaxStreamDataBidiLocal: 65536n,
    initialMaxStreamDataBidiRemote: 65536n,
    initialMaxStreamDataUni: 65536n,
    initialMaxStreamsBidi: 16n,
    initialMaxStreamsUni: 16n,
    originalDestinationConnectionId: clientConnectionId,
    initialSourceConnectionId: serverConnectionId,
  })
}

function requireExtension(handshake: TlsClientHelloHandshake, extensionType: number): Uint8Array {
  const extension = getTlsExtension(handshake.body.extensions, extensionType)
  if (extension === null) {
    throw new Error(`missing TLS extension ${extensionType}`)
  }
  return extension.data
}

function requireClientHello(message: QuicTlsHandshakeMessage): TlsClientHelloHandshake {
  if (message.handshake.kind !== TlsHandshakeKind.ClientHello) {
    throw new Error('expected ClientHello')
  }
  return message.handshake
}

function requireServerHello(message: QuicTlsHandshakeMessage): TlsServerHelloHandshake {
  if (message.handshake.kind !== TlsHandshakeKind.ServerHello) {
    throw new Error('expected ServerHello')
  }
  return message.handshake
}

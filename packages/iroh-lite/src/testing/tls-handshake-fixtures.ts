import { concatBytes, readU8, readU16BE, writeU16BE } from '../bytes'
import { endpointIdFromSecretKey, sign } from '../crypto/ed25519'
import { hexToBytes } from './hex'
import {
  rfc8448ClientPrivateKey,
  rfc8448ClientHandshakeTrafficSecret,
  rfc8448ClientHello,
  rfc8448ServerHandshakeTrafficSecret,
  rfc8448ServerHello,
} from './rfc8448-tls'
import type { QuicCryptoFrame } from '../quic/frame'
import {
  parseTlsHandshakes,
  TlsCertificateType,
  TlsExtensionType,
  TlsHandshakeKind,
  TlsHandshakeType,
  type TlsClientHelloHandshake,
  type TlsHandshake,
  type TlsServerHelloHandshake,
} from '../quic/tls'
import {
  deriveTls13X25519HandshakeSecrets,
  TlsHandshakeRole,
  type Tls13X25519HandshakeSecrets,
} from '../quic/tls-handshake'
import { ed25519SpkiFromEndpointId } from '../quic/tls-certificate'
import {
  buildTls13CertificateVerifyMessage,
  TlsCertificateVerifyRole,
  TlsSignatureScheme,
} from '../quic/tls-certificate-verify'
import {
  collectQuicTlsHandshakeMessages,
  type QuicTlsHandshakeMessage,
} from '../quic/tls-crypto-stream'
import { computeTls13FinishedVerifyData, tls13TranscriptHash } from '../quic/tls-key-schedule'
import { encodeQuicTransportParameters } from '../quic/transport-parameters'

export const tlsTestAlpn = hexToBytes('2f69726f682d676f737369702f31')

export interface EncryptedHandshakeFixture {
  readonly messages: readonly QuicTlsHandshakeMessage[]
  readonly endpointId: Uint8Array
  readonly certificateVerifyTranscriptHash: Uint8Array
  readonly finishedTranscriptHash: Uint8Array
  readonly finishedVerifyData: Uint8Array
}

export interface ServerEncryptedHandshakeFixtureOptions {
  readonly certificateRequest: boolean
  readonly clientHelloMessage?: Uint8Array
  readonly serverHelloMessage?: Uint8Array
  readonly serverHandshakeTrafficSecret?: Uint8Array
  readonly selectedAlpn?: Uint8Array
  readonly serverTransportParameters?: Uint8Array | null
  readonly offerClientRawPublicKey?: boolean
  readonly offerServerRawPublicKey?: boolean
  readonly selectClientRawPublicKey?: boolean
  readonly selectServerRawPublicKey?: boolean
}

export interface ClientEncryptedHandshakeFixtureOptions {
  readonly clientHandshakeTrafficSecret?: Uint8Array
}

export interface TlsHandshakeStateFixture {
  readonly handshake: Tls13X25519HandshakeSecrets
  readonly server: EncryptedHandshakeFixture
  readonly client: EncryptedHandshakeFixture | null
  readonly messages: readonly QuicTlsHandshakeMessage[]
}

export async function serverEncryptedHandshakeFixture(
  options: ServerEncryptedHandshakeFixtureOptions,
): Promise<EncryptedHandshakeFixture> {
  const clientHelloMessage = addRawPublicKeyOffers(
    options.clientHelloMessage ?? rfc8448ClientHello,
    {
      client: options.offerClientRawPublicKey !== false,
      server: options.offerServerRawPublicKey !== false,
    },
  )
  const serverHelloMessage = options.serverHelloMessage ?? rfc8448ServerHello
  const serverHandshakeTrafficSecret =
    options.serverHandshakeTrafficSecret ?? rfc8448ServerHandshakeTrafficSecret
  const secretKey = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
  const endpointId = await endpointIdFromSecretKey(secretKey)
  const encryptedExtensions = tlsHandshakeMessage(
    TlsHandshakeType.EncryptedExtensions,
    encryptedExtensionsBody(
      options.selectedAlpn,
      options.serverTransportParameters,
      options.selectClientRawPublicKey !== false,
      options.selectServerRawPublicKey !== false,
    ),
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
      ? [clientHelloMessage, serverHelloMessage, encryptedExtensions, certificate]
      : [
          clientHelloMessage,
          serverHelloMessage,
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
    serverHandshakeTrafficSecret,
    finishedTranscriptHash,
  )
  const finished = tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)
  const encryptedMessages =
    certificateRequest === null
      ? [encryptedExtensions, certificate, certificateVerify, finished]
      : [encryptedExtensions, certificateRequest, certificate, certificateVerify, finished]

  return {
    messages: [
      ...collectQuicTlsHandshakeMessages([cryptoFrame(0, clientHelloMessage)]).messages,
      ...collectQuicTlsHandshakeMessages([cryptoFrame(0, serverHelloMessage)]).messages,
      ...collectQuicTlsHandshakeMessages([cryptoFrame(0, concatBytes(encryptedMessages))]).messages,
    ],
    endpointId,
    certificateVerifyTranscriptHash,
    finishedTranscriptHash,
    finishedVerifyData,
  }
}

export async function clientEncryptedHandshakeFixture(): Promise<EncryptedHandshakeFixture> {
  return clientEncryptedHandshakeFixtureFromServer(
    await serverEncryptedHandshakeFixture({ certificateRequest: true }),
  )
}

export async function tlsHandshakeStateFixture(options: {
  readonly certificateRequest: boolean
  readonly offerAlpn?: boolean
  readonly selectedAlpn?: Uint8Array | null
  readonly clientTransportParameters?: Uint8Array
  readonly serverTransportParameters?: Uint8Array | null
  readonly offerClientRawPublicKey?: boolean
  readonly offerServerRawPublicKey?: boolean
  readonly selectClientRawPublicKey?: boolean
  readonly selectServerRawPublicKey?: boolean
}): Promise<TlsHandshakeStateFixture> {
  const clientHelloWithTransportParameters = appendTlsExtensionToClientHello(rfc8448ClientHello, {
    type: TlsExtensionType.QuicTransportParameters,
    data:
      options.clientTransportParameters ??
      encodeQuicTransportParameters({
        initialMaxData: 65536n,
        initialMaxStreamDataBidiLocal: 65536n,
        initialMaxStreamDataBidiRemote: 65536n,
        initialMaxStreamDataUni: 65536n,
        initialMaxStreamsBidi: 16n,
        initialMaxStreamsUni: 16n,
        initialSourceConnectionId: hexToBytes('08070605'),
      }),
  })
  const clientHelloWithAlpn =
    options.offerAlpn === false
      ? clientHelloWithTransportParameters
      : appendTlsExtensionToClientHello(clientHelloWithTransportParameters, {
          type: TlsExtensionType.ApplicationLayerProtocolNegotiation,
          data: tlsAlpnExtensionData([tlsTestAlpn]),
        })
  const clientHello = addRawPublicKeyOffers(clientHelloWithAlpn, {
    client: options.offerClientRawPublicKey !== false,
    server: options.offerServerRawPublicKey !== false,
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
    ...(options.serverTransportParameters === undefined
      ? {}
      : {
          serverTransportParameters: options.serverTransportParameters,
        }),
    offerClientRawPublicKey: false,
    offerServerRawPublicKey: false,
    selectClientRawPublicKey: options.selectClientRawPublicKey !== false,
    selectServerRawPublicKey: options.selectServerRawPublicKey !== false,
  })
  const client = options.certificateRequest
    ? await clientEncryptedHandshakeFixtureFromServer(server, {
        clientHandshakeTrafficSecret: handshake.secrets.clientHandshakeTrafficSecret,
      })
    : null

  const messages =
    client?.messages ??
    clientFinishedHandshakeMessages(server.messages, handshake.secrets.clientHandshakeTrafficSecret)

  return {
    handshake,
    server,
    client,
    messages,
  }
}

export async function clientEncryptedHandshakeFixtureFromServer(
  serverFixture: EncryptedHandshakeFixture,
  options: ClientEncryptedHandshakeFixtureOptions = {},
): Promise<EncryptedHandshakeFixture> {
  const clientHandshakeTrafficSecret =
    options.clientHandshakeTrafficSecret ?? rfc8448ClientHandshakeTrafficSecret
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
    clientHandshakeTrafficSecret,
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

function clientFinishedHandshakeMessages(
  priorMessages: readonly QuicTlsHandshakeMessage[],
  clientHandshakeTrafficSecret: Uint8Array,
): readonly QuicTlsHandshakeMessage[] {
  const finishedTranscriptHash = tls13TranscriptHash(
    priorMessages.map((message) => message.message),
  )
  const finishedVerifyData = computeTls13FinishedVerifyData(
    clientHandshakeTrafficSecret,
    finishedTranscriptHash,
  )
  const finished = tlsHandshakeMessage(TlsHandshakeType.Finished, finishedVerifyData)
  return [...priorMessages, ...collectQuicTlsHandshakeMessages([cryptoFrame(0, finished)]).messages]
}

function addRawPublicKeyOffers(
  message: Uint8Array,
  options: {
    readonly client: boolean
    readonly server: boolean
  },
): Uint8Array {
  let out = message
  if (options.client) {
    out = appendTlsExtensionToClientHello(out, {
      type: TlsExtensionType.ClientCertificateType,
      data: tlsCertificateTypeList(TlsCertificateType.RawPublicKey),
    })
  }
  if (options.server) {
    out = appendTlsExtensionToClientHello(out, {
      type: TlsExtensionType.ServerCertificateType,
      data: tlsCertificateTypeList(TlsCertificateType.RawPublicKey),
    })
  }
  return out
}

export function appendTlsExtensionToClientHello(
  message: Uint8Array,
  extension: ExtensionFixture,
): Uint8Array {
  if (readU8(message, 0) !== TlsHandshakeType.ClientHello) {
    throw new RangeError('TLS handshake must be ClientHello')
  }
  const bodyLength = readU24BE(message, 1)
  const bodyOffset = 4
  const bodyEndOffset = bodyOffset + bodyLength
  if (message.length !== bodyEndOffset) {
    throw new RangeError('TLS ClientHello message length mismatch')
  }
  const body = message.subarray(bodyOffset, bodyEndOffset)
  let pos = 0
  pos += 2
  pos += 32
  pos = skipTlsU8Vector(body, pos)
  pos = skipTlsU16Vector(body, pos)
  pos = skipTlsU8Vector(body, pos)

  const extensionsLength = readU16BE(body, pos)
  const extensionsOffset = pos + 2
  const extensionsEndOffset = extensionsOffset + extensionsLength
  if (extensionsEndOffset !== body.length) {
    throw new RangeError('TLS ClientHello extension length mismatch')
  }
  const extensionData = concatBytes([
    body.subarray(extensionsOffset, extensionsEndOffset),
    tlsExtension(extension),
  ])
  return tlsHandshakeMessage(
    TlsHandshakeType.ClientHello,
    concatBytes([body.subarray(0, pos), writeU16BE(extensionData.length), extensionData]),
  )
}

export function tlsAlpnExtensionData(protocols: readonly Uint8Array[]): Uint8Array {
  return tlsU16Vector(concatBytes(protocols.map(tlsU8Vector)))
}

export function replaceMessageBody(
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

export function replaceLastMessageBody(
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

export function findMessageIndex(
  messages: readonly QuicTlsHandshakeMessage[],
  kind: string,
): number {
  const index = messages.findIndex((message) => message.handshake.kind === kind)
  if (index === -1) {
    throw new Error(`missing ${kind}`)
  }
  return index
}

function parseSingleHandshake(message: Uint8Array): TlsHandshake {
  const result = parseTlsHandshakes(message)
  const handshake = result.handshakes[0]
  if (handshake === undefined) {
    throw new Error('expected TLS handshake')
  }
  return handshake
}

function parseClientHello(message: Uint8Array): TlsClientHelloHandshake {
  const handshake = parseSingleHandshake(message)
  if (handshake.kind !== TlsHandshakeKind.ClientHello) {
    throw new Error('expected ClientHello')
  }
  return handshake
}

function parseServerHello(message: Uint8Array): TlsServerHelloHandshake {
  const handshake = parseSingleHandshake(message)
  if (handshake.kind !== TlsHandshakeKind.ServerHello) {
    throw new Error('expected ServerHello')
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

export function certificateVerifyBody(signatureScheme: number, signature: Uint8Array): Uint8Array {
  return concatBytes([writeU16BE(signatureScheme), writeU16BE(signature.length), signature])
}

export function certificateRequestBody(requestContext: Uint8Array): Uint8Array {
  return concatBytes([
    tlsU8Vector(requestContext),
    tlsU16Vector(concatBytes([writeU16BE(0x000d), tlsU16Vector(writeU16BE(0x0807))])),
  ])
}

export interface CertificateEntryFixture {
  readonly data: Uint8Array
  readonly extensions: Uint8Array
}

export function certificateBody(
  requestContext: Uint8Array,
  entries: readonly CertificateEntryFixture[],
): Uint8Array {
  return concatBytes([
    tlsU8Vector(requestContext),
    tlsU24Vector(concatBytes(entries.map(certificateEntry))),
  ])
}

export interface ExtensionFixture {
  readonly type: number
  readonly data: Uint8Array
}

function tlsExtensions(extensions: readonly ExtensionFixture[]): Uint8Array {
  return tlsU16Vector(concatBytes(extensions.map(tlsExtension)))
}

function encryptedExtensionsBody(
  selectedAlpn: Uint8Array | undefined,
  serverTransportParameters: Uint8Array | null | undefined,
  selectClientRawPublicKey: boolean,
  selectServerRawPublicKey: boolean,
): Uint8Array {
  const extensions: ExtensionFixture[] = []
  const transportParameterData =
    serverTransportParameters === undefined
      ? encodeQuicTransportParameters({
          initialMaxData: 65536n,
          initialMaxStreamDataBidiLocal: 65536n,
          initialMaxStreamDataBidiRemote: 65536n,
          initialMaxStreamDataUni: 65536n,
          initialMaxStreamsBidi: 16n,
          initialMaxStreamsUni: 16n,
          originalDestinationConnectionId: hexToBytes('09080706'),
          initialSourceConnectionId: hexToBytes('01020304'),
        })
      : serverTransportParameters
  if (transportParameterData !== null) {
    extensions.push({
      type: TlsExtensionType.QuicTransportParameters,
      data: transportParameterData,
    })
  }
  if (selectedAlpn === undefined) {
    return tlsExtensions(
      addRawPublicKeySelections(extensions, {
        client: selectClientRawPublicKey,
        server: selectServerRawPublicKey,
      }),
    )
  }
  extensions.push({
    type: TlsExtensionType.ApplicationLayerProtocolNegotiation,
    data: tlsAlpnExtensionData([selectedAlpn]),
  })
  return tlsExtensions(
    addRawPublicKeySelections(extensions, {
      client: selectClientRawPublicKey,
      server: selectServerRawPublicKey,
    }),
  )
}

function addRawPublicKeySelections(
  extensions: ExtensionFixture[],
  options: {
    readonly client: boolean
    readonly server: boolean
  },
): ExtensionFixture[] {
  if (options.client) {
    extensions.push({
      type: TlsExtensionType.ClientCertificateType,
      data: new Uint8Array([TlsCertificateType.RawPublicKey]),
    })
  }
  if (options.server) {
    extensions.push({
      type: TlsExtensionType.ServerCertificateType,
      data: new Uint8Array([TlsCertificateType.RawPublicKey]),
    })
  }
  return extensions
}

function certificateEntry(entry: CertificateEntryFixture): Uint8Array {
  return concatBytes([
    tlsU24Vector(entry.data),
    writeU16BE(entry.extensions.length),
    entry.extensions,
  ])
}

function tlsExtension(extension: ExtensionFixture): Uint8Array {
  return concatBytes([
    writeU16BE(extension.type),
    writeU16BE(extension.data.length),
    extension.data,
  ])
}

function tlsU8Vector(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xff) {
    throw new RangeError('TLS u8 vector too large')
  }
  return concatBytes([new Uint8Array([bytes.length]), bytes])
}

function tlsCertificateTypeList(certificateType: number): Uint8Array {
  return tlsU8Vector(new Uint8Array([certificateType]))
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

function skipTlsU8Vector(bytes: Uint8Array, offset: number): number {
  return offset + 1 + readU8(bytes, offset)
}

function skipTlsU16Vector(bytes: Uint8Array, offset: number): number {
  return offset + 2 + readU16BE(bytes, offset)
}

function readU24BE(bytes: Uint8Array, offset: number): number {
  const b0 = readU8(bytes, offset)
  const b1 = readU8(bytes, offset + 1)
  const b2 = readU8(bytes, offset + 2)
  return b0 * 2 ** 16 + (b1 << 8) + b2
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

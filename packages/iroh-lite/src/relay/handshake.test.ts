import { describe, expect, test } from 'bun:test'

import { endpointIdFromSecretKey, verify } from '../crypto/ed25519'
import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  challengeMessageToSign,
  decodeHandshakeFrame,
  encodeClientAuthFrame,
  encodeServerChallengeFrame,
  encodeServerConfirmsAuthFrame,
} from './handshake'

const secretKey = hexToBytes('2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a')
const endpointId = hexToBytes('197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61')
const challenge = hexToBytes('07070707070707070707070707070707')
const challengeMessage = hexToBytes(
  'f767323def67a32a46e288838714814aaae784141c769b9ffe53b64ae417bd21',
)
const challengeSignature = hexToBytes(
  '425fda43adca848e71a65ded8c4fb4f4434ca7f248aa6aec7c547ff96aa0b33bd3245943b407b12a9d8a55522f1bd07fa03180b01793ed572a8068bc49319205',
)

describe('challenge auth', () => {
  test('derives same challenge message as Rust', () => {
    expect(bytesToHex(challengeMessageToSign(challenge))).toBe(bytesToHex(challengeMessage))
  })

  test('derives endpoint id from iroh secret key seed', async () => {
    expect(await endpointIdFromSecretKey(secretKey)).toEqual(endpointId)
  })

  test('encodes server challenge frame', () => {
    const encoded = encodeServerChallengeFrame({ challenge })
    expect(bytesToHex(encoded)).toBe('0007070707070707070707070707070707')
    expect(decodeHandshakeFrame(encoded)).toEqual({
      type: 'server-challenge',
      challenge,
    })
  })

  test('encodes client auth postcard payload', async () => {
    const encoded = await encodeClientAuthFrame(secretKey, { challenge })
    expect(bytesToHex(encoded)).toBe(
      '01197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6140425fda43adca848e71a65ded8c4fb4f4434ca7f248aa6aec7c547ff96aa0b33bd3245943b407b12a9d8a55522f1bd07fa03180b01793ed572a8068bc49319205',
    )
    expect(decodeHandshakeFrame(encoded)).toEqual({
      type: 'client-auth',
      auth: { endpointId, signature: challengeSignature },
    })
  })

  test('verifies Rust challenge signature vector', async () => {
    expect(await verify(endpointId, challengeMessage, challengeSignature)).toBe(true)
  })

  test('encodes empty auth confirmation', () => {
    const encoded = encodeServerConfirmsAuthFrame()
    expect(bytesToHex(encoded)).toBe('02')
    expect(decodeHandshakeFrame(encoded)).toEqual({ type: 'server-confirms-auth' })
  })

  test('decodes denial reason', () => {
    expect(decodeHandshakeFrame(hexToBytes('030e6e6f7420617574686f72697a6564'))).toEqual({
      type: 'server-denies-auth',
      reason: 'not authorized',
    })
  })
})

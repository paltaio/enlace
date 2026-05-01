import * as ed25519 from '@noble/ed25519'

import { copyBytes, requireLength } from '../bytes'

export const SECRET_KEY_LENGTH = 32
export const ENDPOINT_ID_LENGTH = 32
export const SIGNATURE_LENGTH = 64

export function validateSecretKey(secretKey: Uint8Array): Uint8Array {
  requireLength(secretKey, SECRET_KEY_LENGTH, 'secret key')
  return copyBytes(secretKey)
}

export function validateEndpointId(endpointId: Uint8Array): Uint8Array {
  requireLength(endpointId, ENDPOINT_ID_LENGTH, 'endpoint id')
  ed25519.Point.fromBytes(endpointId, false)
  return copyBytes(endpointId)
}

export function randomSecretKey(): Uint8Array {
  return ed25519.utils.randomSecretKey()
}

export async function endpointIdFromSecretKey(secretKey: Uint8Array): Promise<Uint8Array> {
  return ed25519.getPublicKeyAsync(validateSecretKey(secretKey))
}

export async function sign(secretKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return ed25519.signAsync(message, validateSecretKey(secretKey))
}

export async function verify(
  endpointId: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  requireLength(signature, SIGNATURE_LENGTH, 'signature')
  return ed25519.verifyAsync(signature, message, validateEndpointId(endpointId), {
    zip215: false,
  })
}

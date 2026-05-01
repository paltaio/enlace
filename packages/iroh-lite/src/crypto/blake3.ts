import { blake3 } from '@noble/hashes/blake3.js'
import { utf8ToBytes } from '@noble/hashes/utils.js'

export const RELAY_CHALLENGE_DOMAIN = 'iroh-relay handshake v1 challenge signature'

export function deriveRelayChallengeKey(challenge: Uint8Array): Uint8Array {
  return blake3(challenge, {
    context: utf8ToBytes(RELAY_CHALLENGE_DOMAIN),
    dkLen: 32,
  })
}

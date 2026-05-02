import { copyBytes, requireLength } from '../bytes'
import { deriveQuicDirectionalKeys, type QuicDirectionalKeys } from './crypto'
import {
  deriveTls13ApplicationTrafficSecrets,
  TLS13_SHA256_SECRET_LENGTH,
  type Tls13ApplicationTrafficSecrets,
} from './tls-key-schedule'
import type { Tls13ClientHandshakeState, Tls13ServerHandshakeState } from './tls-handshake-state'

export interface QuicOneRttKeys {
  readonly client: QuicDirectionalKeys
  readonly server: QuicDirectionalKeys
}

export interface Tls13ApplicationTraffic {
  readonly transcriptHash: Uint8Array
  readonly secrets: Tls13ApplicationTrafficSecrets
  readonly keys: QuicOneRttKeys
}

export function deriveTls13ApplicationTrafficFromHandshakeState(
  state: Tls13ClientHandshakeState | Tls13ServerHandshakeState,
): Tls13ApplicationTraffic {
  if (state.server.certificateRequest !== null && state.client === null) {
    throw new RangeError('TLS client Finished required after CertificateRequest')
  }
  const transcriptHash = state.transcriptHashes.serverApplicationTraffic
  requireLength(transcriptHash, TLS13_SHA256_SECRET_LENGTH, 'TLS Finished transcript hash')
  const secrets = deriveTls13ApplicationTrafficSecrets(
    state.handshake.secrets.handshakeSecret,
    transcriptHash,
  )

  return {
    transcriptHash: copyBytes(transcriptHash),
    secrets,
    keys: {
      client: deriveQuicDirectionalKeys(secrets.clientApplicationTrafficSecret),
      server: deriveQuicDirectionalKeys(secrets.serverApplicationTrafficSecret),
    },
  }
}

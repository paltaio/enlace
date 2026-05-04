import { copyBytes, readU8, requireLength } from '../bytes'
import { computeTls13FinishedVerifyData, TLS13_SHA256_SECRET_LENGTH } from './tls-key-schedule'
import { TlsHandshakeKind, type TlsHandshake } from './tls'

export function requireTlsFinishedVerifyData(handshake: TlsHandshake): Uint8Array {
  if (handshake.kind !== TlsHandshakeKind.Finished) {
    throw new RangeError('TLS handshake must be Finished')
  }
  requireLength(handshake.body, TLS13_SHA256_SECRET_LENGTH, 'TLS Finished verify_data')
  return copyBytes(handshake.body)
}

export function verifyTls13FinishedHandshake(
  trafficSecret: Uint8Array,
  transcriptHash: Uint8Array,
  handshake: TlsHandshake,
): boolean {
  return equalBytes(
    computeTls13FinishedVerifyData(trafficSecret, transcriptHash),
    requireTlsFinishedVerifyData(handshake),
  )
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }

  let diff = 0
  for (let index = 0; index < left.length; index += 1) {
    diff |= readU8(left, index) ^ readU8(right, index)
  }
  return diff === 0
}

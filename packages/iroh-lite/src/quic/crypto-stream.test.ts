import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import {
  rfc9001DestinationConnectionId,
  rfc9001ProtectedClientInitialPacket,
  rfc9001ProtectedServerInitialPacket,
} from '../testing/rfc9001-quic'
import { deriveQuicInitialKeys } from './crypto'
import { assembleQuicCryptoStream } from './crypto-stream'
import { parseQuicFrames, type QuicCryptoFrame } from './frame'
import { decryptQuicInitialPacket } from './initial'

describe('QUIC CRYPTO stream assembly', () => {
  test('assembles Initial CRYPTO data from RFC 9001 vectors', () => {
    const keys = deriveQuicInitialKeys(rfc9001DestinationConnectionId)
    const clientPacket = decryptQuicInitialPacket(rfc9001ProtectedClientInitialPacket, keys.client)
    const serverPacket = decryptQuicInitialPacket(rfc9001ProtectedServerInitialPacket, keys.server)

    expect(bytesToHex(assembleQuicCryptoStream(cryptoFrames(clientPacket.payload)))).toStartWith(
      '010000ed0303',
    )
    expect(bytesToHex(assembleQuicCryptoStream(cryptoFrames(serverPacket.payload)))).toStartWith(
      '020000560303',
    )
  })

  test('assembles out-of-order fragments', () => {
    const frames = [cryptoFrame(3, hexToBytes('646566')), cryptoFrame(0, hexToBytes('616263'))]

    expect(bytesToHex(assembleQuicCryptoStream(frames))).toBe('616263646566')
  })

  test('accepts duplicate overlapping bytes', () => {
    const frames = [cryptoFrame(0, hexToBytes('616263')), cryptoFrame(1, hexToBytes('6263'))]

    expect(bytesToHex(assembleQuicCryptoStream(frames))).toBe('616263')
  })

  test('rejects gaps and conflicting overlaps', () => {
    expect(() =>
      assembleQuicCryptoStream([
        cryptoFrame(0, hexToBytes('61')),
        cryptoFrame(2, hexToBytes('63')),
      ]),
    ).toThrow('QUIC CRYPTO stream has a gap')

    expect(() =>
      assembleQuicCryptoStream([
        cryptoFrame(0, hexToBytes('6162')),
        cryptoFrame(1, hexToBytes('63')),
      ]),
    ).toThrow('conflicting QUIC CRYPTO stream data')
  })
})

function cryptoFrames(payload: Uint8Array): QuicCryptoFrame[] {
  return parseQuicFrames(payload).frames.filter(
    (frame): frame is QuicCryptoFrame => frame.type === 'crypto',
  )
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

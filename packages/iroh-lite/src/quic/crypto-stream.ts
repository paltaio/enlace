import { copyBytes } from '../bytes'
import type { QuicCryptoFrame } from './frame'

export function assembleQuicCryptoStream(frames: readonly QuicCryptoFrame[]): Uint8Array {
  const sorted = [...frames].sort((left, right) => left.cryptoOffset - right.cryptoOffset)
  let length = 0
  for (const frame of sorted) {
    length = Math.max(length, frame.cryptoOffset + frame.data.length)
  }

  const out = new Uint8Array(length)
  const written = new Uint8Array(length)
  let contiguousLength = 0

  for (const frame of sorted) {
    for (let index = 0; index < frame.data.length; index += 1) {
      const outputIndex = frame.cryptoOffset + index
      const byte = frame.data[index]
      if (byte === undefined) {
        throw new RangeError('not enough bytes for QUIC CRYPTO stream data')
      }
      if (written[outputIndex] === 1 && out[outputIndex] !== byte) {
        throw new RangeError('conflicting QUIC CRYPTO stream data')
      }
      out[outputIndex] = byte
      written[outputIndex] = 1
    }

    while (contiguousLength < written.length && written[contiguousLength] === 1) {
      contiguousLength += 1
    }
    if (frame.cryptoOffset > contiguousLength) {
      throw new RangeError('QUIC CRYPTO stream has a gap')
    }
  }

  if (contiguousLength !== out.length) {
    throw new RangeError('QUIC CRYPTO stream has a gap')
  }
  return copyBytes(out)
}

import { copyBytes } from '../bytes'
import { assembleQuicCryptoStream } from './crypto-stream'
import type { QuicCryptoFrame } from './frame'
import { parseTlsHandshakes, type TlsHandshake } from './tls'

export interface QuicTlsHandshakeMessage {
  readonly handshake: TlsHandshake
  readonly message: Uint8Array
}

export interface QuicTlsHandshakeMessages {
  readonly cryptoStream: Uint8Array
  readonly messages: readonly QuicTlsHandshakeMessage[]
  readonly endOffset: number
}

export function collectQuicTlsHandshakeMessages(
  frames: readonly QuicCryptoFrame[],
): QuicTlsHandshakeMessages {
  const cryptoStream = assembleQuicCryptoStream(frames)
  const parsed = parseTlsHandshakes(cryptoStream)
  const messages = parsed.handshakes.map((handshake) => ({
    handshake,
    message: copyBytes(cryptoStream.subarray(handshake.offset, handshake.endOffset)),
  }))

  return {
    cryptoStream,
    messages,
    endOffset: parsed.endOffset,
  }
}

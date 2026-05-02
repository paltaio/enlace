import { concatBytes, copyBytes, requireLength } from '../bytes'
import type { QuicTlsHandshakeMessage, QuicTlsHandshakeMessages } from './tls-crypto-stream'
import { TLS13_SHA256_SECRET_LENGTH, tls13TranscriptHash } from './tls-key-schedule'

export interface TlsHandshakeTranscript {
  readonly messages: readonly QuicTlsHandshakeMessage[]
  readonly bytes: Uint8Array
  readonly hash: Uint8Array
}

export class TlsHandshakeTranscriptAccumulator {
  readonly #messages: QuicTlsHandshakeMessage[] = []
  readonly #rawMessages: Uint8Array[] = []

  append(block: QuicTlsHandshakeMessages): void {
    for (const message of block.messages) {
      const rawMessage = copyBytes(message.message)
      this.#messages.push({
        handshake: message.handshake,
        message: rawMessage,
      })
      this.#rawMessages.push(rawMessage)
    }
  }

  snapshot(): TlsHandshakeTranscript {
    return buildTlsHandshakeTranscript(this.#messages, this.#rawMessages)
  }
}

export function collectTlsHandshakeTranscript(
  blocks: readonly QuicTlsHandshakeMessages[],
): TlsHandshakeTranscript {
  const transcript = new TlsHandshakeTranscriptAccumulator()

  for (const block of blocks) {
    transcript.append(block)
  }

  return transcript.snapshot()
}

function buildTlsHandshakeTranscript(
  messages: readonly QuicTlsHandshakeMessage[],
  rawMessages: readonly Uint8Array[],
): TlsHandshakeTranscript {
  const hash = tls13TranscriptHash(rawMessages)
  requireLength(hash, TLS13_SHA256_SECRET_LENGTH, 'TLS transcript hash')

  return {
    messages: messages.map((message) => ({
      handshake: message.handshake,
      message: copyBytes(message.message),
    })),
    bytes: concatBytes(rawMessages),
    hash,
  }
}

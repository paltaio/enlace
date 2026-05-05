const Z_BASE_32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'

const DECODE_TABLE = new Map(
  Array.from(Z_BASE_32_ALPHABET, (char, index) => [char, index] as const),
)

export function encodeZ32(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''

  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8

    while (bits >= 5) {
      out += Z_BASE_32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }

  if (bits > 0) {
    out += Z_BASE_32_ALPHABET[(value << (5 - bits)) & 31]
  }

  return out
}

export function decodeZ32(encoded: string): Uint8Array {
  let bits = 0
  let value = 0
  const out: number[] = []

  for (const char of encoded) {
    const decoded = DECODE_TABLE.get(char)
    if (decoded === undefined) {
      throw new TypeError('invalid z-base32 public key encoding')
    }

    value = (value << 5) | decoded
    bits += 5

    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }

  return new Uint8Array(out)
}

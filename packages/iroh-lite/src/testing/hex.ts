export function hexToBytes(hex: string): Uint8Array {
  const compact = hex.replace(/\s+/g, '')
  if (compact.length % 2 !== 0) {
    throw new Error('hex string has odd length')
  }
  const out = new Uint8Array(compact.length / 2)
  for (let index = 0; index < out.length; index += 1) {
    const byte = Number.parseInt(compact.slice(index * 2, index * 2 + 2), 16)
    if (Number.isNaN(byte)) {
      throw new Error('invalid hex string')
    }
    out[index] = byte
  }
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

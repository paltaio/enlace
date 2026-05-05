export function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes)
}

export function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length)
  for (let i = 0; i < length; i += 1) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0)
    if (diff !== 0) {
      return diff
    }
  }
  return left.length - right.length
}

export function bytesToKey(bytes: Uint8Array): string {
  let key = ''
  for (const byte of bytes) {
    key += String.fromCharCode(byte)
  }
  return key
}

export function requireLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`)
  }
}

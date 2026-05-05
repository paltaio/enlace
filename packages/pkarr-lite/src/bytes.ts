export function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes)
}

export function requireLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`)
  }
}

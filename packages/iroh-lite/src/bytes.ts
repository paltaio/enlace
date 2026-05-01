export function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes)
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const len = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(len)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function requireLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`)
  }
}

export function readU8(bytes: Uint8Array, offset: number): number {
  const value = bytes[offset]
  if (value === undefined) {
    throw new RangeError('not enough bytes for u8')
  }
  return value
}

export function readU16BE(bytes: Uint8Array, offset: number): number {
  const hi = bytes[offset]
  const lo = bytes[offset + 1]
  if (hi === undefined || lo === undefined) {
    throw new RangeError('not enough bytes for u16')
  }
  return (hi << 8) | lo
}

export function readU32BE(bytes: Uint8Array, offset: number): number {
  const b0 = bytes[offset]
  const b1 = bytes[offset + 1]
  const b2 = bytes[offset + 2]
  const b3 = bytes[offset + 3]
  if (b0 === undefined || b1 === undefined || b2 === undefined || b3 === undefined) {
    throw new RangeError('not enough bytes for u32')
  }
  return b0 * 2 ** 24 + (b1 << 16) + (b2 << 8) + b3
}

export function writeU16BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError('u16 out of range')
  }
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff])
}

export function writeU32BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError('u32 out of range')
  }
  return new Uint8Array([
    Math.floor(value / 2 ** 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ])
}

export function encodePostcardLen(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError('postcard length out of range')
  }
  const out: number[] = []
  let remaining = value
  while (remaining >= 0x80) {
    out.push((remaining % 0x80) | 0x80)
    remaining = Math.floor(remaining / 0x80)
  }
  out.push(remaining)
  return new Uint8Array(out)
}

export interface PostcardLen {
  readonly value: number
  readonly bytesRead: number
}

export function decodePostcardLen(bytes: Uint8Array, offset = 0): PostcardLen {
  let value = 0
  let shift = 0
  let pos = offset
  while (pos < bytes.length) {
    const byte = readU8(bytes, pos)
    value += (byte & 0x7f) * 2 ** shift
    pos += 1
    if ((byte & 0x80) === 0) {
      return { value, bytesRead: pos - offset }
    }
    shift += 7
    if (shift > 35) {
      throw new RangeError('postcard length too large')
    }
  }
  throw new RangeError('not enough bytes for postcard length')
}

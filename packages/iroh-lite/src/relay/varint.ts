export const MAX_QUIC_VARINT = (1n << 62n) - 1n;

export interface VarIntDecodeResult {
  readonly value: bigint;
  readonly bytesRead: number;
}

export function encodeVarInt(value: number | bigint): Uint8Array {
  const n = typeof value === "bigint" ? value : BigInt(value);
  if (n < 0n || n > MAX_QUIC_VARINT) {
    throw new RangeError("QUIC varint out of range");
  }

  if (n < 2n ** 6n) {
    return new Uint8Array([Number(n)]);
  }
  if (n < 2n ** 14n) {
    const encoded = n | 0x4000n;
    return new Uint8Array([Number((encoded >> 8n) & 0xffn), Number(encoded & 0xffn)]);
  }
  if (n < 2n ** 30n) {
    const encoded = n | 0x80000000n;
    return new Uint8Array([
      Number((encoded >> 24n) & 0xffn),
      Number((encoded >> 16n) & 0xffn),
      Number((encoded >> 8n) & 0xffn),
      Number(encoded & 0xffn),
    ]);
  }

  const encoded = n | 0xc000000000000000n;
  return new Uint8Array([
    Number((encoded >> 56n) & 0xffn),
    Number((encoded >> 48n) & 0xffn),
    Number((encoded >> 40n) & 0xffn),
    Number((encoded >> 32n) & 0xffn),
    Number((encoded >> 24n) & 0xffn),
    Number((encoded >> 16n) & 0xffn),
    Number((encoded >> 8n) & 0xffn),
    Number(encoded & 0xffn),
  ]);
}

export function decodeVarInt(bytes: Uint8Array, offset = 0): VarIntDecodeResult {
  const first = bytes[offset];
  if (first === undefined) {
    throw new RangeError("not enough bytes for QUIC varint");
  }

  const prefix = first >> 6;
  const length = 1 << prefix;
  if (bytes.length - offset < length) {
    throw new RangeError("not enough bytes for QUIC varint");
  }

  let value = BigInt(first & 0x3f);
  for (let index = 1; index < length; index += 1) {
    const byte = bytes[offset + index];
    if (byte === undefined) {
      throw new RangeError("not enough bytes for QUIC varint");
    }
    value = (value << 8n) | BigInt(byte);
  }

  return { value, bytesRead: length };
}

export function decodeVarIntNumber(bytes: Uint8Array, offset = 0): {
  readonly value: number;
  readonly bytesRead: number;
} {
  const decoded = decodeVarInt(bytes, offset);
  if (decoded.value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("QUIC varint exceeds safe integer range");
  }
  return { value: Number(decoded.value), bytesRead: decoded.bytesRead };
}

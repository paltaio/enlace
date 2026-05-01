import { describe, expect, test } from "bun:test";

import { bytesToHex, hexToBytes } from "../testing/hex";
import { decodeVarInt, encodeVarInt } from "./varint";

describe("QUIC varint", () => {
  const vectors: readonly [bigint, string][] = [
    [0n, "00"],
    [13n, "0d"],
    [63n, "3f"],
    [64n, "4040"],
    [16_383n, "7fff"],
    [16_384n, "80004000"],
    [1_073_741_823n, "bfffffff"],
    [1_073_741_824n, "c000000040000000"],
    [(1n << 62n) - 1n, "ffffffffffffffff"],
  ];

  test.each(vectors)("encodes %p", (value, expected) => {
    expect(bytesToHex(encodeVarInt(value))).toBe(expected);
  });

  test.each(vectors)("decodes %p", (value, encoded) => {
    const result = decodeVarInt(hexToBytes(encoded));
    expect(result).toEqual({ value, bytesRead: encoded.length / 2 });
  });
});

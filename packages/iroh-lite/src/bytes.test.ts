import { describe, expect, test } from "bun:test";

import { decodePostcardLen, encodePostcardLen } from "./bytes";
import { bytesToHex } from "./testing/hex";

describe("postcard length", () => {
  test("encodes values beyond 32-bit bitwise range", () => {
    expect(bytesToHex(encodePostcardLen(2 ** 32))).toBe("8080808010");
  });

  test("round trips encoded values", () => {
    const values = [0, 64, 16_384, 2 ** 32] as const;
    for (const value of values) {
      const encoded = encodePostcardLen(value);
      expect(decodePostcardLen(encoded)).toEqual({ value, bytesRead: encoded.length });
    }
  });
});

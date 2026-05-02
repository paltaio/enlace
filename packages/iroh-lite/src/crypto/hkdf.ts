import { expand } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { utf8ToBytes } from '@noble/hashes/utils.js'

import { concatBytes, writeU16BE } from '../bytes'

const TLS13_LABEL_PREFIX = utf8ToBytes('tls13 ')

export function hkdfExpandTls13LabelSha256(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > 0xffff) {
    throw new RangeError('HKDF label length out of range')
  }
  if (context.length > 0xff) {
    throw new RangeError('HKDF label context too long')
  }

  const fullLabel = concatBytes([TLS13_LABEL_PREFIX, utf8ToBytes(label)])
  if (fullLabel.length > 0xff) {
    throw new RangeError('HKDF label too long')
  }

  const hkdfLabel = concatBytes([
    writeU16BE(length),
    new Uint8Array([fullLabel.length]),
    fullLabel,
    new Uint8Array([context.length]),
    context,
  ])
  return expand(sha256, secret, hkdfLabel, length)
}

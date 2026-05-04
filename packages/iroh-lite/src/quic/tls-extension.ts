import { copyBytes, readU16BE } from '../bytes'

export interface TlsExtension {
  readonly extensionType: number
  readonly data: Uint8Array
  readonly offset: number
  readonly endOffset: number
}

export function readTlsExtensions(
  bytes: Uint8Array,
  offset: number,
  vectorName: string,
  dataName: string,
): {
  readonly value: readonly TlsExtension[]
  readonly endOffset: number
} {
  const length = readU16BE(bytes, offset)
  let pos = offset + 2
  const endOffset = pos + length
  if (endOffset > bytes.length) {
    throw new RangeError(`not enough bytes for ${vectorName}`)
  }

  const extensions: TlsExtension[] = []
  while (pos < endOffset) {
    const extensionOffset = pos
    const extensionType = readU16BE(bytes, pos)
    pos += 2
    const dataLength = readU16BE(bytes, pos)
    pos += 2
    const dataEndOffset = pos + dataLength
    if (dataEndOffset > endOffset) {
      throw new RangeError(`not enough bytes for ${dataName}`)
    }
    extensions.push({
      extensionType,
      data: copyBytes(bytes.subarray(pos, dataEndOffset)),
      offset: extensionOffset,
      endOffset: dataEndOffset,
    })
    pos = dataEndOffset
  }

  return {
    value: extensions,
    endOffset,
  }
}

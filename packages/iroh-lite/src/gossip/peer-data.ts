import { concatBytes, copyBytes, decodePostcardLen, encodePostcardLen } from '../bytes'

export interface GossipPeerDataAddrInfo {
  readonly relayUrl: URL | null
  readonly directAddresses: readonly string[]
}

export function encodeGossipPeerDataAddrInfo(info: {
  readonly relayUrl?: URL | string | null
  readonly directAddresses?: readonly string[]
}): Uint8Array {
  const directAddresses = info.directAddresses ?? []
  return concatBytes([
    encodeOptionalRelayUrl(info.relayUrl ?? null),
    encodePostcardLen(directAddresses.length),
    ...directAddresses.map(encodeSocketAddr),
  ])
}

export function decodeGossipPeerDataAddrInfo(peerData: Uint8Array): GossipPeerDataAddrInfo {
  if (peerData.length === 0) {
    return { relayUrl: null, directAddresses: [] }
  }
  const reader = new PostcardReader(peerData)
  const relayUrl = decodeOptionalRelayUrl(reader)
  const directAddressCount = reader.uint()
  const directAddresses: string[] = []
  for (let index = 0; index < directAddressCount; index += 1) {
    directAddresses.push(decodeSocketAddr(reader))
  }
  reader.requireDone()
  return { relayUrl, directAddresses }
}

function encodeOptionalRelayUrl(relayUrl: URL | string | null): Uint8Array {
  if (relayUrl === null) {
    return encodePostcardLen(0)
  }
  return concatBytes([encodePostcardLen(1), encodeString(new URL(relayUrl).toString())])
}

function decodeOptionalRelayUrl(reader: PostcardReader): URL | null {
  const option = reader.uint()
  if (option === 0) {
    return null
  }
  if (option === 1) {
    return new URL(reader.string())
  }
  throw new RangeError(`unsupported gossip relay URL option ${option}`)
}

function decodeSocketAddr(reader: PostcardReader): string {
  const variant = reader.uint()
  if (variant === 0) {
    const octets = reader.fixedBytes(4)
    return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}:${reader.uint()}`
  }
  if (variant === 1) {
    const segments: string[] = []
    const bytes = reader.fixedBytes(16)
    for (let index = 0; index < bytes.length; index += 2) {
      const segment = ((bytes[index] ?? 0) << 8) | (bytes[index + 1] ?? 0)
      segments.push(segment.toString(16))
    }
    return `[${segments.join(':')}]:${reader.uint()}`
  }
  throw new RangeError(`unsupported gossip socket address variant ${variant}`)
}

function encodeSocketAddr(address: string): Uint8Array {
  const ipv4 = /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+):([0-9]+)$/.exec(address)
  if (ipv4 !== null) {
    return concatBytes([
      encodePostcardLen(0),
      new Uint8Array([
        parseIpByte(ipv4[1] ?? ''),
        parseIpByte(ipv4[2] ?? ''),
        parseIpByte(ipv4[3] ?? ''),
        parseIpByte(ipv4[4] ?? ''),
      ]),
      encodePort(ipv4[5] ?? ''),
    ])
  }
  throw new RangeError(`unsupported gossip socket address ${address}`)
}

function parseIpByte(value: string): number {
  const byte = Number(value)
  if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
    throw new RangeError(`invalid IPv4 byte ${value}`)
  }
  return byte
}

function encodePort(value: string): Uint8Array {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new RangeError(`invalid socket port ${value}`)
  }
  return encodePostcardLen(port)
}

function encodeString(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value)
  return concatBytes([encodePostcardLen(bytes.length), bytes])
}

class PostcardReader {
  readonly #bytes: Uint8Array
  #offset = 0

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes
  }

  uint(): number {
    const decoded = decodePostcardLen(this.#bytes, this.#offset)
    this.#offset += decoded.bytesRead
    return decoded.value
  }

  string(): string {
    return new TextDecoder(undefined, { fatal: true }).decode(this.bytes())
  }

  bytes(): Uint8Array {
    const length = this.uint()
    return this.fixedBytes(length)
  }

  fixedBytes(length: number): Uint8Array {
    const endOffset = this.#offset + length
    if (endOffset > this.#bytes.length) {
      throw new RangeError('not enough bytes for postcard bytes')
    }
    const out = copyBytes(this.#bytes.subarray(this.#offset, endOffset))
    this.#offset = endOffset
    return out
  }

  requireDone(): void {
    if (this.#offset !== this.#bytes.length) {
      throw new RangeError('trailing bytes in postcard message')
    }
  }
}

import {
  DEFAULT_MAXIMUM_TTL,
  DEFAULT_MINIMUM_TTL,
  DNS_PACKET_MAX_BYTES,
  PUBLIC_KEY_BYTES,
  RELAY_PAYLOAD_MAX_BYTES,
  SIGNATURE_BYTES,
  SIGNED_PACKET_MAX_BYTES,
  TIMESTAMP_BYTES,
} from './constants'
import { compareBytes } from './bytes'
import {
  type DnsRecord,
  type ServiceBinding,
  encodeDnsResponse,
  findResourceRecords,
  parseDnsResponse,
} from './dns'
import { Keypair, PublicKey } from './keys'

export type TimestampInput = bigint | number | Date

export type DnsRData =
  | Omit<Extract<DnsRecord, { type: 'A' }>, 'name' | 'ttl'>
  | Omit<Extract<DnsRecord, { type: 'AAAA' }>, 'name' | 'ttl'>
  | Omit<Extract<DnsRecord, { type: 'CNAME' }>, 'name' | 'ttl'>
  | Omit<Extract<DnsRecord, { type: 'TXT' }>, 'name' | 'ttl'>
  | Omit<Extract<DnsRecord, { type: 'HTTPS' }>, 'name' | 'ttl'>
  | Omit<Extract<DnsRecord, { type: 'SVCB' }>, 'name' | 'ttl'>

let lastTimestamp = 0n
const SIGNED_PACKET_HEADER_BYTES = PUBLIC_KEY_BYTES + SIGNATURE_BYTES + TIMESTAMP_BYTES
type CreateSignedPacket = (
  publicKey: PublicKey,
  signature: Uint8Array,
  timestamp: bigint,
  encodedPacket: Uint8Array,
  lastSeen: bigint,
) => SignedPacket
let createSignedPacket: CreateSignedPacket = () => {
  throw new Error('SignedPacket factory is not initialized')
}

export class SignedPacketBuilder {
  #records: DnsRecord[] = []
  #timestamp: bigint | null = null

  record(record: DnsRecord): this {
    this.#records.push(cloneRecord(record))
    return this
  }

  rdata(name: string, rdata: DnsRData, ttl: number): this {
    switch (rdata.type) {
      case 'A':
        return this.record({ type: 'A', name, ttl, address: rdata.address })
      case 'AAAA':
        return this.record({ type: 'AAAA', name, ttl, address: rdata.address })
      case 'CNAME':
        return this.record({ type: 'CNAME', name, ttl, cname: rdata.cname })
      case 'TXT':
        return this.record({ type: 'TXT', name, ttl, text: rdata.text })
      case 'HTTPS':
        return this.record({ type: 'HTTPS', name, ttl, binding: rdata.binding })
      case 'SVCB':
        return this.record({ type: 'SVCB', name, ttl, binding: rdata.binding })
      default:
        return assertNever(rdata)
    }
  }

  a(name: string, address: string | Uint8Array, ttl: number): this {
    return this.rdata(name, { type: 'A', address }, ttl)
  }

  aaaa(name: string, address: string | Uint8Array, ttl: number): this {
    return this.rdata(name, { type: 'AAAA', address }, ttl)
  }

  address(name: string, address: string | Uint8Array, ttl: number): this {
    const isIpv6 =
      (typeof address === 'string' && address.includes(':')) ||
      (address instanceof Uint8Array && address.length === 16)
    return isIpv6 ? this.aaaa(name, address, ttl) : this.a(name, address, ttl)
  }

  cname(name: string, cname: string, ttl: number): this {
    return this.rdata(name, { type: 'CNAME', cname }, ttl)
  }

  txt(name: string, text: string | Uint8Array | readonly Uint8Array[], ttl: number): this {
    return this.rdata(name, { type: 'TXT', text }, ttl)
  }

  https(name: string, binding: ServiceBinding, ttl: number): this {
    return this.rdata(name, { type: 'HTTPS', binding }, ttl)
  }

  svcb(name: string, binding: ServiceBinding, ttl: number): this {
    return this.rdata(name, { type: 'SVCB', binding }, ttl)
  }

  timestamp(timestamp: TimestampInput): this {
    this.#timestamp = timestampMicros(timestamp)
    return this
  }

  build(keypair: Keypair): Promise<SignedPacket> {
    return this.sign(keypair)
  }

  async sign(keypair: Keypair): Promise<SignedPacket> {
    const publicKey = keypair.publicKey()
    const encodedPacket = encodeDnsResponse(publicKey.toZ32(), this.#records)
    const timestamp = this.#timestamp ?? nowMicros()
    const signature = await keypair.sign(signableBytes(timestamp, encodedPacket))
    return createSignedPacket(publicKey, signature, timestamp, encodedPacket, nowMicros())
  }
}

export class SignedPacket {
  static readonly MAX_BYTES = SIGNED_PACKET_MAX_BYTES

  static {
    createSignedPacket = (publicKey, signature, timestamp, encodedPacket, lastSeen) =>
      SignedPacket.fromParts(publicKey, signature, timestamp, encodedPacket, lastSeen)
  }

  readonly #publicKey: PublicKey
  readonly #signature: Uint8Array
  readonly #timestamp: bigint
  readonly #encodedPacket: Uint8Array
  readonly #records: DnsRecord[]
  #lastSeen: bigint

  private constructor(
    publicKey: PublicKey,
    signature: Uint8Array,
    timestamp: bigint,
    encodedPacket: Uint8Array,
    records: DnsRecord[],
    lastSeen: bigint,
  ) {
    this.#publicKey = publicKey
    this.#signature = new Uint8Array(signature)
    this.#timestamp = timestamp
    this.#encodedPacket = new Uint8Array(encodedPacket)
    this.#records = records.map(cloneRecord)
    this.#lastSeen = lastSeen
  }

  static builder(): SignedPacketBuilder {
    return new SignedPacketBuilder()
  }

  static async fromRelayPayload(publicKey: PublicKey, payload: Uint8Array): Promise<SignedPacket> {
    if (payload.length > RELAY_PAYLOAD_MAX_BYTES) {
      throw new RangeError(
        `SignedPacket is too large, expected max ${SIGNED_PACKET_MAX_BYTES} bytes but got: ${
          payload.length + PUBLIC_KEY_BYTES
        }`,
      )
    }
    return SignedPacket.fromBytes(concatBytes(publicKey.toBytes(), payload))
  }

  static async fromBytes(bytes: Uint8Array): Promise<SignedPacket> {
    const packet = SignedPacket.parseBytes(bytes, nowMicros())
    const ok = await packet.#publicKey.verify(
      signableBytes(packet.#timestamp, packet.#encodedPacket),
      packet.#signature,
    )
    if (!ok) {
      throw new Error('invalid SignedPacket signature')
    }
    return packet
  }

  static deserialize(bytes: Uint8Array): SignedPacket {
    if (bytes.length < TIMESTAMP_BYTES + SIGNED_PACKET_HEADER_BYTES) {
      throw new RangeError('serialized SignedPacket is too short')
    }

    let lastSeen = readU64(bytes, 0)
    if (lastSeen > nowMicros() + 60_000_000n) {
      lastSeen = 0n
    }

    return SignedPacket.parseBytes(bytes.slice(TIMESTAMP_BYTES), lastSeen)
  }

  asBytes(): Uint8Array {
    return concatBytes(
      this.#publicKey.toBytes(),
      this.#signature,
      writeU64(this.#timestamp),
      this.#encodedPacket,
    )
  }

  toRelayPayload(): Uint8Array {
    return concatBytes(this.#signature, writeU64(this.#timestamp), this.#encodedPacket)
  }

  publicKey(): PublicKey {
    return this.#publicKey
  }

  signature(): Uint8Array {
    return new Uint8Array(this.#signature)
  }

  timestamp(): bigint {
    return this.#timestamp
  }

  encodedPacket(): Uint8Array {
    return new Uint8Array(this.#encodedPacket)
  }

  serialize(): Uint8Array {
    return concatBytes(writeU64(this.#lastSeen), this.asBytes())
  }

  lastSeen(): bigint {
    return this.#lastSeen
  }

  setLastSeen(lastSeen: TimestampInput): void {
    this.#lastSeen = timestampMicros(lastSeen)
  }

  refresh(): void {
    this.#lastSeen = nowMicros()
  }

  moreRecentThan(other: SignedPacket): boolean {
    if (this.#timestamp === other.#timestamp) {
      return compareBytes(this.#encodedPacket, other.#encodedPacket) > 0
    }
    return this.#timestamp > other.#timestamp
  }

  isSameAs(other: SignedPacket): boolean {
    return compareBytes(this.asBytes(), other.asBytes()) === 0
  }

  resourceRecords(name: string): DnsRecord[] {
    return findResourceRecords(this.#records, this.#publicKey.toZ32(), name).map(cloneRecord)
  }

  freshResourceRecords(name: string): DnsRecord[] {
    const elapsed = this.elapsed()
    return this.resourceRecords(name).filter((record) => record.ttl > elapsed)
  }

  allResourceRecords(): DnsRecord[] {
    return this.#records.map(cloneRecord)
  }

  ttl(min = DEFAULT_MINIMUM_TTL, max = DEFAULT_MAXIMUM_TTL): number {
    if (min > max) {
      throw new RangeError('minimum TTL must be less than or equal to maximum TTL')
    }

    const lowest = this.#records.reduce<number | undefined>(
      (current, record) => (current === undefined ? record.ttl : Math.min(current, record.ttl)),
      undefined,
    )
    return clamp(lowest ?? min, min, max)
  }

  expiresIn(min = DEFAULT_MINIMUM_TTL, max = DEFAULT_MAXIMUM_TTL): number {
    return Math.max(0, this.ttl(min, max) - this.elapsed())
  }

  isExpired(min = DEFAULT_MINIMUM_TTL, max = DEFAULT_MAXIMUM_TTL): boolean {
    return this.expiresIn(min, max) === 0
  }

  elapsed(): number {
    const elapsedMicros = nowMicros() - this.#lastSeen
    if (elapsedMicros <= 0n) {
      return 0
    }
    return Number(elapsedMicros / 1_000_000n)
  }

  private static fromParts(
    publicKey: PublicKey,
    signature: Uint8Array,
    timestamp: bigint,
    encodedPacket: Uint8Array,
    lastSeen: bigint,
  ): SignedPacket {
    if (signature.length !== SIGNATURE_BYTES) {
      throw new RangeError(`signature must be ${SIGNATURE_BYTES} bytes`)
    }
    if (encodedPacket.length > DNS_PACKET_MAX_BYTES) {
      throw new RangeError(
        `DNS packet is too large, expected max ${DNS_PACKET_MAX_BYTES} bytes but got: ${encodedPacket.length}`,
      )
    }

    const records = parseDnsResponse(encodedPacket)
    return new SignedPacket(publicKey, signature, timestamp, encodedPacket, records, lastSeen)
  }

  private static parseBytes(bytes: Uint8Array, lastSeen: bigint): SignedPacket {
    if (bytes.length < SIGNED_PACKET_HEADER_BYTES) {
      throw new RangeError(
        `Invalid SignedPacket bytes length, expected at least ${SIGNED_PACKET_HEADER_BYTES} bytes but got: ${bytes.length}`,
      )
    }
    if (bytes.length > SIGNED_PACKET_MAX_BYTES) {
      throw new RangeError(
        `SignedPacket is too large, expected max ${SIGNED_PACKET_MAX_BYTES} bytes but got: ${bytes.length}`,
      )
    }

    return SignedPacket.fromParts(
      PublicKey.fromBytes(bytes.slice(0, PUBLIC_KEY_BYTES)),
      bytes.slice(PUBLIC_KEY_BYTES, PUBLIC_KEY_BYTES + SIGNATURE_BYTES),
      readU64(bytes, PUBLIC_KEY_BYTES + SIGNATURE_BYTES),
      bytes.slice(SIGNED_PACKET_HEADER_BYTES),
      lastSeen,
    )
  }
}

function signableBytes(timestamp: bigint, encodedPacket: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`3:seqi${timestamp}e1:v${encodedPacket.length}:`)
  return concatBytes(prefix, encodedPacket)
}

function timestampMicros(value: TimestampInput): bigint {
  if (value instanceof Date) {
    return BigInt(value.getTime()) * 1_000n
  }
  const timestamp = typeof value === 'bigint' ? value : BigInt(value)
  if (timestamp < 0n || timestamp > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`timestamp out of range: ${value}`)
  }
  return timestamp
}

function nowMicros(): bigint {
  const wallClock = BigInt(Date.now()) * 1_000n
  lastTimestamp = wallClock > lastTimestamp ? wallClock : lastTimestamp + 1n
  return lastTimestamp
}

function readU64(bytes: Uint8Array, offset: number): bigint {
  let value = 0n
  for (let i = 0; i < 8; i += 1) {
    const byte = bytes[offset + i]
    if (byte === undefined) {
      throw new RangeError('timestamp bytes ended early')
    }
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

function writeU64(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8)
  let rest = timestampMicros(value)
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(rest & 0xffn)
    rest >>= 8n
  }
  return bytes
}

function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const out = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

function cloneRecord(record: DnsRecord): DnsRecord {
  switch (record.type) {
    case 'A':
      return { ...record, address: cloneAddress(record.address) }
    case 'AAAA':
      return { ...record, address: cloneAddress(record.address) }
    case 'CNAME':
      return { ...record }
    case 'TXT':
      return { ...record, text: cloneTxt(record.text) }
    case 'HTTPS':
    case 'SVCB':
      return { ...record, binding: cloneBinding(record.binding) }
    default:
      return assertNever(record)
  }
}

function cloneAddress(address: string | Uint8Array): string | Uint8Array {
  return typeof address === 'string' ? address : new Uint8Array(address)
}

function cloneTxt(
  text: string | Uint8Array | readonly Uint8Array[],
): string | Uint8Array | Uint8Array[] {
  if (typeof text === 'string') {
    return text
  }
  if (text instanceof Uint8Array) {
    return new Uint8Array(text)
  }
  return text.map((chunk) => new Uint8Array(chunk))
}

function cloneBinding(binding: ServiceBinding): ServiceBinding {
  return {
    priority: binding.priority,
    target: binding.target,
    params: binding.params.map((param) => {
      switch (param.type) {
        case 'mandatory':
          return { type: 'mandatory', keys: [...param.keys] }
        case 'alpn':
          return { type: 'alpn', ids: param.ids.map(cloneId) }
        case 'no-default-alpn':
          return { type: 'no-default-alpn' }
        case 'port':
          return { type: 'port', port: param.port }
        case 'ipv4hint':
          return { type: 'ipv4hint', addresses: param.addresses.map(cloneAddress) }
        case 'ech':
          return { type: 'ech', data: new Uint8Array(param.data) }
        case 'ipv6hint':
          return { type: 'ipv6hint', addresses: param.addresses.map(cloneAddress) }
        case 'unknown':
          return { type: 'unknown', key: param.key, value: new Uint8Array(param.value) }
        default:
          return assertNever(param)
      }
    }),
  }
}

function cloneId(id: string | Uint8Array): string | Uint8Array {
  return typeof id === 'string' ? id : new Uint8Array(id)
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function assertNever(value: never): never {
  throw new Error(`unsupported variant: ${String(value)}`)
}

import { DNS_PACKET_MAX_BYTES } from './constants'

const CLASS_IN = 1
const HEADER_BYTES = 12
const MAX_LABEL_BYTES = 63
const MAX_NAME_BYTES = 255
const POINTER_MASK = 0xc0
const POINTER_VALUE_MASK = 0x3fff

const TYPE_A = 1
const TYPE_CNAME = 5
const TYPE_TXT = 16
const TYPE_AAAA = 28
const TYPE_SVCB = 64
const TYPE_HTTPS = 65

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

export type DnsRecord =
  | { type: 'A'; name: string; ttl: number; address: string | Uint8Array }
  | { type: 'AAAA'; name: string; ttl: number; address: string | Uint8Array }
  | { type: 'CNAME'; name: string; ttl: number; cname: string }
  | { type: 'TXT'; name: string; ttl: number; text: string | Uint8Array | readonly Uint8Array[] }
  | { type: 'HTTPS'; name: string; ttl: number; binding: ServiceBinding }
  | { type: 'SVCB'; name: string; ttl: number; binding: ServiceBinding }

export interface ServiceBinding {
  priority: number
  target: string
  params: readonly ServiceParam[]
}

export type ServiceParam =
  | { type: 'mandatory'; keys: readonly number[] }
  | { type: 'alpn'; ids: readonly (string | Uint8Array)[] }
  | { type: 'no-default-alpn' }
  | { type: 'port'; port: number }
  | { type: 'ipv4hint'; addresses: readonly (string | Uint8Array)[] }
  | { type: 'ech'; data: Uint8Array }
  | { type: 'ipv6hint'; addresses: readonly (string | Uint8Array)[] }
  | { type: 'unknown'; key: number; value: Uint8Array }

export function normalizeDnsName(origin: string, name: string): string {
  const trimmed = name.endsWith('.') ? name.slice(0, -1) : name
  const parts = trimmed.split('.')
  const last = parts.at(-1) ?? ''

  if (last === origin) {
    return trimmed
  }

  if (last === '@' || last === '') {
    return origin
  }

  return `${trimmed}.${origin}`
}

export function encodeDnsResponse(origin: string, records: readonly DnsRecord[]): Uint8Array {
  const writer = new Writer()
  writer.u16(0)
  writer.u16(0x8000)
  writer.u16(0)
  writer.u16(records.length)
  writer.u16(0)
  writer.u16(0)

  const refs = new Map<string, number>()
  for (const record of records) {
    writeRecord(writer, refs, origin, record)
  }

  const packet = writer.toBytes()
  if (packet.length > DNS_PACKET_MAX_BYTES) {
    throw new RangeError(
      `DNS packet is too large, expected max 1000 bytes but got: ${packet.length}`,
    )
  }
  return packet
}

export function parseDnsResponse(packet: Uint8Array): DnsRecord[] {
  const reader = new Reader(packet)
  reader.u16()
  reader.u16()
  const questions = reader.u16()
  const answers = reader.u16()
  const nameServers = reader.u16()
  const additionalRecords = reader.u16()

  for (let i = 0; i < questions; i += 1) {
    readName(reader)
    reader.skip(4)
  }

  const records: DnsRecord[] = []
  for (let i = 0; i < answers; i += 1) {
    records.push(readRecord(reader))
  }

  for (let i = 0; i < nameServers + additionalRecords; i += 1) {
    skipRecord(reader)
  }

  reader.done()
  return records
}

export function findResourceRecords(
  records: readonly DnsRecord[],
  origin: string,
  name: string,
): DnsRecord[] {
  const normalized = normalizeDnsName(origin, name)

  if (normalized.startsWith('*.')) {
    const suffix = normalized.slice(1)
    return records.filter((record) => {
      if (!record.name.endsWith(suffix)) {
        return false
      }
      const match = record.name.slice(0, -suffix.length)
      return !match.includes('.')
    })
  }

  return records.filter((record) => record.name === normalized)
}

function writeRecord(
  writer: Writer,
  refs: Map<string, number>,
  origin: string,
  record: DnsRecord,
): void {
  writeCompressedName(writer, refs, normalizeDnsName(origin, record.name))
  writer.u16(recordType(record))
  writer.u16(CLASS_IN)
  writer.u32(record.ttl)

  const lengthOffset = writer.length
  writer.u16(0)
  const dataOffset = writer.length

  writeRecordData(writer, refs, record)

  writer.setU16(lengthOffset, writer.length - dataOffset)
}

function writeRecordData(writer: Writer, refs: Map<string, number>, record: DnsRecord): void {
  switch (record.type) {
    case 'A':
      writer.write(ipv4Bytes(record.address))
      return
    case 'AAAA':
      writer.write(ipv6Bytes(record.address))
      return
    case 'CNAME':
      writeCompressedName(writer, refs, record.cname)
      return
    case 'TXT':
      for (const value of txtChunks(record.text)) {
        writer.u8(value.length)
        writer.write(value)
      }
      return
    case 'HTTPS':
    case 'SVCB':
      writeServiceBinding(writer, record.binding)
      return
    default:
      assertNever(record)
  }
}

function readRecord(reader: Reader): DnsRecord {
  const name = readName(reader)
  const type = reader.u16()
  const rrClass = reader.u16()
  const ttl = reader.u32()
  const length = reader.u16()
  const end = reader.offset + length

  if (rrClass !== CLASS_IN) {
    throw new Error(`unsupported DNS class: ${rrClass}`)
  }

  const record = readRecordData(reader, name, ttl, type, end)
  if (reader.offset !== end) {
    throw new Error('invalid DNS record length')
  }
  return record
}

function readRecordData(
  reader: Reader,
  name: string,
  ttl: number,
  type: number,
  end: number,
): DnsRecord {
  switch (type) {
    case TYPE_A:
      return { type: 'A', name, ttl, address: reader.take(4) }
    case TYPE_AAAA:
      return { type: 'AAAA', name, ttl, address: reader.take(16) }
    case TYPE_CNAME:
      return { type: 'CNAME', name, ttl, cname: readName(reader) }
    case TYPE_TXT:
      return { type: 'TXT', name, ttl, text: readTxt(reader, end) }
    case TYPE_HTTPS:
      return { type: 'HTTPS', name, ttl, binding: readServiceBinding(reader, end) }
    case TYPE_SVCB:
      return { type: 'SVCB', name, ttl, binding: readServiceBinding(reader, end) }
    default:
      throw new Error(`unsupported DNS record type: ${type}`)
  }
}

function skipRecord(reader: Reader): void {
  readName(reader)
  reader.skip(8)
  reader.skip(reader.u16())
}

function recordType(record: DnsRecord): number {
  switch (record.type) {
    case 'A':
      return TYPE_A
    case 'AAAA':
      return TYPE_AAAA
    case 'CNAME':
      return TYPE_CNAME
    case 'TXT':
      return TYPE_TXT
    case 'HTTPS':
      return TYPE_HTTPS
    case 'SVCB':
      return TYPE_SVCB
    default:
      return assertNever(record)
  }
}

function writeServiceBinding(writer: Writer, binding: ServiceBinding): void {
  validateServiceBinding(binding)
  writer.u16(binding.priority)
  writeName(writer, binding.target)

  const params = [...binding.params].sort((a, b) => paramKey(a) - paramKey(b))
  let previous = -1

  for (const param of params) {
    const key = paramKey(param)
    if (key === previous) {
      throw new Error(`duplicate SVCB parameter: ${key}`)
    }
    previous = key

    writer.u16(key)
    const lengthOffset = writer.length
    writer.u16(0)
    const valueOffset = writer.length
    writeServiceParam(writer, param)
    writer.setU16(lengthOffset, writer.length - valueOffset)
  }
}

function readServiceBinding(reader: Reader, end: number): ServiceBinding {
  const priority = reader.u16()
  const target = readName(reader)
  const params: ServiceParam[] = []
  let previous = -1

  while (reader.offset < end) {
    const key = reader.u16()
    const length = reader.u16()
    if (key <= previous) {
      throw new Error('SVCB parameters must be sorted by key')
    }
    previous = key
    params.push(readServiceParam(reader, key, reader.offset + length))
  }

  const binding = { priority, target, params }
  validateServiceBinding(binding)
  return binding
}

function validateServiceBinding(binding: ServiceBinding): void {
  const keys = new Set<number>()
  let hasAlpn = false
  let hasNoDefaultAlpn = false
  let mandatory: readonly number[] = []

  for (const param of binding.params) {
    const key = paramKey(param)
    if (keys.has(key)) {
      throw new Error(`duplicate SVCB parameter: ${key}`)
    }
    keys.add(key)

    switch (param.type) {
      case 'mandatory':
        mandatory = param.keys
        validateMandatoryKeys(param.keys, false)
        break
      case 'alpn':
        hasAlpn = true
        requireNonEmpty(param.ids, 'alpn')
        for (const id of param.ids) {
          requireNonEmptyBytes(typeof id === 'string' ? textEncoder.encode(id) : id, 'alpn')
        }
        break
      case 'no-default-alpn':
        hasNoDefaultAlpn = true
        break
      case 'ipv4hint':
        requireNonEmpty(param.addresses, 'ipv4hint')
        break
      case 'ipv6hint':
        requireNonEmpty(param.addresses, 'ipv6hint')
        break
      case 'ech':
      case 'port':
        break
      case 'unknown':
        validateUnknownParam(param)
        break
      default:
        assertNever(param)
    }
  }

  if (hasNoDefaultAlpn && !hasAlpn) {
    throw new Error('no-default-alpn requires alpn')
  }

  for (const key of mandatory) {
    if (!keys.has(key)) {
      throw new Error(`mandatory SVCB parameter is missing: ${key}`)
    }
  }
}

function validateUnknownParam(param: Extract<ServiceParam, { type: 'unknown' }>): void {
  if (param.key <= 6) {
    throw new Error(`unknown SVCB parameter uses known key: ${param.key}`)
  }
}

function validateMandatoryKeys(keys: readonly number[], requireSorted: boolean): void {
  requireNonEmpty(keys, 'mandatory')
  const seen = new Set<number>()
  let previous = -1

  for (const key of keys) {
    assertUnsigned(key, 0xffff)
    if (key === 0) {
      throw new Error('mandatory must not include mandatory')
    }
    if (seen.has(key)) {
      throw new Error(`duplicate mandatory SVCB key: ${key}`)
    }
    if (requireSorted && key <= previous) {
      throw new Error('mandatory SVCB keys must be sorted')
    }
    seen.add(key)
    previous = key
  }
}

function requireNonEmpty(value: readonly unknown[], name: string): void {
  if (value.length === 0) {
    throw new Error(`${name} must not be empty`)
  }
}

function requireNonEmptyBytes(value: Uint8Array, name: string): void {
  if (value.length === 0) {
    throw new Error(`${name} value must not be empty`)
  }
}

function writeServiceParam(writer: Writer, param: ServiceParam): void {
  switch (param.type) {
    case 'mandatory':
      for (const key of [...param.keys].sort((a, b) => a - b)) {
        writer.u16(key)
      }
      return
    case 'alpn':
      for (const id of param.ids) {
        const bytes = typeof id === 'string' ? textEncoder.encode(id) : id
        writer.u8(bytes.length)
        writer.write(bytes)
      }
      return
    case 'no-default-alpn':
      return
    case 'port':
      writer.u16(param.port)
      return
    case 'ipv4hint':
      for (const address of param.addresses) {
        writer.write(ipv4Bytes(address))
      }
      return
    case 'ech':
      writer.u16(param.data.length)
      writer.write(param.data)
      return
    case 'ipv6hint':
      for (const address of param.addresses) {
        writer.write(ipv6Bytes(address))
      }
      return
    case 'unknown':
      writer.write(param.value)
      return
    default:
      assertNever(param)
  }
}

function readServiceParam(reader: Reader, key: number, end: number): ServiceParam {
  const values: number[] = []
  const chunks: Uint8Array[] = []

  switch (key) {
    case 0:
      while (reader.offset < end) {
        values.push(reader.u16())
      }
      validateMandatoryKeys(values, true)
      return { type: 'mandatory', keys: values }
    case 1:
      while (reader.offset < end) {
        chunks.push(reader.take(reader.u8()))
      }
      return { type: 'alpn', ids: chunks }
    case 2:
      reader.expectEnd(end)
      return { type: 'no-default-alpn' }
    case 3: {
      const port = reader.u16()
      reader.expectEnd(end)
      return { type: 'port', port }
    }
    case 4:
      while (reader.offset < end) {
        chunks.push(reader.take(4))
      }
      return { type: 'ipv4hint', addresses: chunks }
    case 5: {
      const length = reader.u16()
      const data = reader.take(length)
      reader.expectEnd(end)
      return { type: 'ech', data }
    }
    case 6:
      while (reader.offset < end) {
        chunks.push(reader.take(16))
      }
      return { type: 'ipv6hint', addresses: chunks }
    default: {
      const value = reader.take(end - reader.offset)
      return { type: 'unknown', key, value }
    }
  }
}

function paramKey(param: ServiceParam): number {
  switch (param.type) {
    case 'mandatory':
      return 0
    case 'alpn':
      return 1
    case 'no-default-alpn':
      return 2
    case 'port':
      return 3
    case 'ipv4hint':
      return 4
    case 'ech':
      return 5
    case 'ipv6hint':
      return 6
    case 'unknown':
      return param.key
    default:
      return assertNever(param)
  }
}

function writeCompressedName(writer: Writer, refs: Map<string, number>, name: string): void {
  const labels = nameLabels(name)

  for (let i = 0; i < labels.length; i += 1) {
    const key = labels.slice(i).map(labelKey).join('\0')
    const offset = refs.get(key)

    if (offset !== undefined) {
      writer.u16((POINTER_MASK << 8) | offset)
      return
    }

    refs.set(key, writer.length)
    const label = labels[i]
    if (label === undefined) {
      throw new Error('invalid DNS name')
    }
    writer.u8(label.length)
    writer.write(label)
  }

  writer.u8(0)
}

function writeName(writer: Writer, name: string): void {
  for (const label of nameLabels(name)) {
    writer.u8(label.length)
    writer.write(label)
  }
  writer.u8(0)
}

function readName(reader: Reader): string {
  const labels: string[] = []
  let cursor = reader.offset
  let consumed = 0
  let followed = false
  let nameLength = 0
  const seenPointers = new Set<number>()

  for (;;) {
    const length = reader.at(cursor)

    if ((length & POINTER_MASK) === POINTER_MASK) {
      const next = reader.at(cursor + 1)
      const pointer = ((length << 8) | next) & POINTER_VALUE_MASK
      if (seenPointers.has(pointer)) {
        throw new Error('invalid DNS compression pointer')
      }
      seenPointers.add(pointer)
      if (!followed) {
        consumed += 2
      }
      cursor = pointer
      followed = true
      continue
    }

    cursor += 1
    if (!followed) {
      consumed += 1
    }

    if (length === 0) {
      break
    }

    if (length > MAX_LABEL_BYTES) {
      throw new Error('invalid DNS label length')
    }

    nameLength += length + 1
    if (nameLength >= MAX_NAME_BYTES) {
      throw new Error('invalid DNS name')
    }

    labels.push(textDecoder.decode(reader.slice(cursor, cursor + length)))
    cursor += length
    if (!followed) {
      consumed += length
    }
  }

  reader.offset += consumed
  return labels.join('.')
}

function nameLabels(name: string): Uint8Array[] {
  const labels = name
    .split('.')
    .filter((label) => label.length > 0)
    .map((label) => textEncoder.encode(label))

  const total = labels.reduce((sum, label) => sum + label.length + 1, 1)
  if (total > MAX_NAME_BYTES) {
    throw new Error('invalid DNS name')
  }

  for (const label of labels) {
    if (label.length > MAX_LABEL_BYTES) {
      throw new Error('invalid DNS label length')
    }
  }

  return labels
}

function labelKey(label: Uint8Array): string {
  return Array.from(label, (byte) => String.fromCharCode(byte)).join('')
}

function txtChunks(text: Extract<DnsRecord, { type: 'TXT' }>['text']): Uint8Array[] {
  if (typeof text === 'string') {
    return splitTxtBytes(textEncoder.encode(text))
  }

  if (text instanceof Uint8Array) {
    return splitTxtBytes(text)
  }

  return text.map((chunk) => new Uint8Array(chunk))
}

function splitTxtBytes(bytes: Uint8Array): Uint8Array[] {
  const chunks: Uint8Array[] = []

  for (let offset = 0; offset < bytes.length; offset += 254) {
    chunks.push(bytes.slice(offset, offset + 254))
  }

  if (chunks.length === 0) {
    chunks.push(new Uint8Array())
  }

  return chunks
}

function readTxt(reader: Reader, end: number): Uint8Array[] {
  const chunks: Uint8Array[] = []
  while (reader.offset < end) {
    chunks.push(reader.take(reader.u8()))
  }
  return chunks
}

function ipv4Bytes(address: string | Uint8Array): Uint8Array {
  if (typeof address !== 'string') {
    if (address.length !== 4) {
      throw new RangeError('IPv4 address must be 4 bytes')
    }
    return address
  }

  const parts = address.split('.').map(parseIpv4Part)
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    throw new Error(`invalid IPv4 address: ${address}`)
  }
  return new Uint8Array(parts)
}

function ipv6Bytes(address: string | Uint8Array): Uint8Array {
  if (typeof address !== 'string') {
    if (address.length !== 16) {
      throw new RangeError('IPv6 address must be 16 bytes')
    }
    return address
  }

  const parts = expandIpv6(address)
  const bytes = new Uint8Array(16)
  parts.forEach((part, index) => {
    bytes[index * 2] = part >> 8
    bytes[index * 2 + 1] = part & 0xff
  })
  return bytes
}

function expandIpv6(address: string): number[] {
  const sections = address.split('::')
  if (sections.length > 2) {
    throw new Error(`invalid IPv6 address: ${address}`)
  }

  const headRaw = sections[0] ?? ''
  const tailRaw = sections.length === 2 ? (sections[1] ?? '') : null
  const head = parseIpv6Parts(headRaw)
  const tail = tailRaw === null ? [] : parseIpv6Parts(tailRaw)
  const missing = 8 - head.length - tail.length

  if (missing < 0 || (tailRaw === null && missing !== 0) || (tailRaw !== null && missing === 0)) {
    throw new Error(`invalid IPv6 address: ${address}`)
  }

  return [...head, ...Array.from({ length: missing }, () => 0), ...tail]
}

function parseIpv4Part(part: string): number {
  if (!/^\d{1,3}$/u.test(part)) {
    throw new Error(`invalid IPv4 segment: ${part}`)
  }
  return Number.parseInt(part, 10)
}

function parseIpv6Parts(raw: string): number[] {
  if (raw.length === 0) {
    return []
  }

  return raw.split(':').map((part) => {
    if (!/^[\da-fA-F]{1,4}$/u.test(part)) {
      throw new Error(`invalid IPv6 segment: ${part}`)
    }
    return Number.parseInt(part, 16)
  })
}

class Writer {
  #bytes: number[] = []

  get length(): number {
    return this.#bytes.length
  }

  u8(value: number): void {
    assertUnsigned(value, 0xff)
    this.#bytes.push(value & 0xff)
  }

  u16(value: number): void {
    assertUnsigned(value, 0xffff)
    this.#bytes.push((value >> 8) & 0xff, value & 0xff)
  }

  u32(value: number): void {
    assertUnsigned(value, 0xffffffff)
    this.#bytes.push(
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    )
  }

  write(value: Uint8Array): void {
    this.#bytes.push(...value)
  }

  setU16(offset: number, value: number): void {
    this.#bytes[offset] = (value >> 8) & 0xff
    this.#bytes[offset + 1] = value & 0xff
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.#bytes)
  }
}

class Reader {
  offset = 0

  constructor(readonly bytes: Uint8Array) {
    if (bytes.length < HEADER_BYTES) {
      throw new Error('DNS packet too short')
    }
  }

  u8(): number {
    const value = this.at(this.offset)
    this.offset += 1
    return value
  }

  u16(): number {
    const value = (this.at(this.offset) << 8) | this.at(this.offset + 1)
    this.offset += 2
    return value
  }

  u32(): number {
    const value =
      this.at(this.offset) * 0x1000000 +
      ((this.at(this.offset + 1) << 16) |
        (this.at(this.offset + 2) << 8) |
        this.at(this.offset + 3))
    this.offset += 4
    return value
  }

  take(length: number): Uint8Array {
    const value = this.slice(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  skip(length: number): void {
    this.slice(this.offset, this.offset + length)
    this.offset += length
  }

  slice(start: number, end: number): Uint8Array {
    if (start < 0 || end > this.bytes.length || start > end) {
      throw new Error('DNS packet ended early')
    }
    return this.bytes.slice(start, end)
  }

  at(offset: number): number {
    const value = this.bytes[offset]
    if (value === undefined) {
      throw new Error('DNS packet ended early')
    }
    return value
  }

  expectEnd(end: number): void {
    if (this.offset !== end) {
      throw new Error('invalid DNS record length')
    }
  }

  done(): void {
    if (this.offset !== this.bytes.length) {
      throw new Error('trailing DNS packet bytes')
    }
  }
}

function assertUnsigned(value: number, max: number): void {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new RangeError(`integer out of range: ${value}`)
  }
}

function assertNever(value: never): never {
  throw new Error(`unsupported variant: ${String(value)}`)
}

export interface NativeVectors {
  key: {
    secret_key_hex: string
    public_key_hex: string
    z32: string
    uri: string
  }
  packet: PacketVector
}

export interface PacketVector {
  timestamp_micros: number
  last_seen_micros: number
  signature_hex: string
  signable_hex: string
  encoded_packet_hex: string
  signed_packet_hex: string
  relay_payload_hex: string
  serialized_hex: string
  ttl_default: number
  ttl_unclamped: number
  records: RecordSummary[]
  lookups: LookupVector[]
}

export interface RecordSummary {
  name: string
  record_type: string
  ttl: number
}

export interface LookupVector {
  name: string
  names: string[]
}

const NATIVE_MANIFEST = Bun.fileURLToPath(new URL('../../native/Cargo.toml', import.meta.url))

export async function nativeVectors(): Promise<NativeVectors> {
  const value: unknown = JSON.parse(await runNative(['vectors']))
  if (!isNativeVectors(value)) {
    throw new Error('native harness returned invalid vectors')
  }
  return value
}

export async function runNative(args: string[], stdin?: string): Promise<string> {
  const proc = Bun.spawn(
    ['cargo', 'run', '--quiet', '--manifest-path', NATIVE_MANIFEST, '--', ...args],
    {
      stdin: stdin === undefined ? undefined : 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )
  if (stdin !== undefined) {
    const stdinWriter = proc.stdin
    if (stdinWriter === undefined) {
      throw new Error('native harness stdin unavailable')
    }
    stdinWriter.write(stdin)
    await stdinWriter.end()
  }
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  if (exitCode !== 0) {
    throw new Error(stderr || `native harness exited with ${exitCode}`)
  }
  return stdout
}

export function isNativeVectors(value: unknown): value is NativeVectors {
  if (!isRecord(value) || !isRecord(value.key) || !isPacketVector(value.packet)) {
    return false
  }
  return (
    typeof value.key.secret_key_hex === 'string' &&
    typeof value.key.public_key_hex === 'string' &&
    typeof value.key.z32 === 'string' &&
    typeof value.key.uri === 'string'
  )
}

export function isPacketVector(value: unknown): value is PacketVector {
  if (!isRecord(value)) {
    return false
  }
  return (
    typeof value.timestamp_micros === 'number' &&
    typeof value.last_seen_micros === 'number' &&
    typeof value.signature_hex === 'string' &&
    typeof value.signable_hex === 'string' &&
    typeof value.encoded_packet_hex === 'string' &&
    typeof value.signed_packet_hex === 'string' &&
    typeof value.relay_payload_hex === 'string' &&
    typeof value.serialized_hex === 'string' &&
    typeof value.ttl_default === 'number' &&
    typeof value.ttl_unclamped === 'number' &&
    isRecordSummaryArray(value.records) &&
    isLookupVectorArray(value.lookups)
  )
}

function isRecordSummaryArray(value: unknown): value is RecordSummary[] {
  return Array.isArray(value) && value.every(isRecordSummary)
}

function isRecordSummary(value: unknown): value is RecordSummary {
  return (
    isRecord(value) &&
    typeof value.name === 'string' &&
    typeof value.record_type === 'string' &&
    typeof value.ttl === 'number'
  )
}

function isLookupVectorArray(value: unknown): value is LookupVector[] {
  return Array.isArray(value) && value.every(isLookupVector)
}

function isLookupVector(value: unknown): value is LookupVector {
  return (
    isRecord(value) &&
    typeof value.name === 'string' &&
    Array.isArray(value.names) &&
    value.names.every((name) => typeof name === 'string')
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

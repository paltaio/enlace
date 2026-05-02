import { bytesToHex, hexToBytes } from './hex'
import { withTimeout } from './local-iroh-relay'

export const nativeIrohEchoAlpn = new TextEncoder().encode('/iroh/echo/1')

export interface NativeIrohEchoServer {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  stop(): Promise<void>
}

export interface NativeIrohEchoClientOptions {
  readonly relayUrl: string
  readonly serverEndpointId: Uint8Array
  readonly payload: Uint8Array
}

export interface NativeIrohEchoClientResult {
  readonly payload: Uint8Array
}

export interface NativeIrohGossipSendOptions {
  readonly relayUrl: string
  readonly serverEndpointId: Uint8Array
}

export interface NativeIrohGossipSendResult {
  readonly topicId: Uint8Array
  readonly payload: Uint8Array
}

export async function startNativeIrohEchoServer(relayUrl: string): Promise<NativeIrohEchoServer> {
  const proc = Bun.spawn(
    ['cargo', 'run', '--quiet', '--manifest-path', nativeIrohEchoManifestPath()],
    {
      env: {
        ...Bun.env,
        CARGO_TARGET_DIR: Bun.env.IROH_NATIVE_ECHO_TARGET_DIR ?? nativeIrohEchoTargetDir(),
        IROH_RELAY_URL: relayUrl,
        RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )
  const reader = proc.stdout.getReader()
  const stderr = streamToText(proc.stderr)

  async function stop(): Promise<void> {
    if (proc.exitCode === null) {
      proc.kill()
      try {
        await withTimeout(proc.exited, 'native iroh echo stop', 2_000)
      } catch {
        proc.kill('SIGKILL')
        await proc.exited
      }
    }
  }

  try {
    const endpointIdHex = await withTimeout(
      readReadyEndpointId(reader, proc, stderr),
      'native iroh echo ready',
      120_000,
    )
    return {
      endpointId: hexToBytes(endpointIdHex),
      endpointIdHex,
      stop,
    }
  } catch (error) {
    await stop()
    throw error
  }
}

export async function runNativeIrohEchoClient(
  options: NativeIrohEchoClientOptions,
): Promise<NativeIrohEchoClientResult> {
  const proc = Bun.spawn(
    ['cargo', 'run', '--quiet', '--manifest-path', nativeIrohEchoManifestPath(), '--', 'client'],
    {
      env: {
        ...Bun.env,
        CARGO_TARGET_DIR: Bun.env.IROH_NATIVE_ECHO_TARGET_DIR ?? nativeIrohEchoTargetDir(),
        IROH_RELAY_URL: options.relayUrl,
        IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
        IROH_ECHO_PAYLOAD_HEX: bytesToHex(options.payload),
        RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )
  const stdout = streamToText(proc.stdout)
  const stderr = streamToText(proc.stderr)
  const exitCode = await waitForProcessExit(proc, 'native iroh echo client', 120_000)
  const output = await stdout
  const errorOutput = await stderr

  if (exitCode !== 0) {
    throw new Error(
      `native iroh echo client exited with code ${exitCode}${processOutput(errorOutput)}`,
    )
  }

  return parseClientResult(output)
}

export async function runNativeIrohGossipSender(
  options: NativeIrohGossipSendOptions,
): Promise<NativeIrohGossipSendResult> {
  const proc = Bun.spawn(
    [
      'cargo',
      'run',
      '--quiet',
      '--manifest-path',
      nativeIrohEchoManifestPath(),
      '--',
      'gossip-send',
    ],
    {
      env: {
        ...Bun.env,
        CARGO_TARGET_DIR: Bun.env.IROH_NATIVE_ECHO_TARGET_DIR ?? nativeIrohEchoTargetDir(),
        IROH_RELAY_URL: options.relayUrl,
        IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
        RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )
  const stdout = streamToText(proc.stdout)
  const stderr = streamToText(proc.stderr)
  const exitCode = await waitForProcessExit(proc, 'native iroh gossip sender', 120_000)
  const output = await stdout
  const errorOutput = await stderr

  if (exitCode !== 0) {
    throw new Error(
      `native iroh gossip sender exited with code ${exitCode}${processOutput(errorOutput)}`,
    )
  }

  return parseGossipSendResult(output)
}

async function readReadyEndpointId(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  proc: ReturnType<typeof Bun.spawn>,
  stderr: Promise<string>,
): Promise<string> {
  const decoder = new TextDecoder()
  let buffered = ''
  while (true) {
    if (proc.exitCode !== null) {
      throw new Error(
        `native iroh echo exited before ready (${proc.exitCode})${await processError(stderr)}`,
      )
    }
    const chunk = await reader.read()
    if (chunk.done === true) {
      throw new Error(`native iroh echo closed stdout before ready${await processError(stderr)}`)
    }
    buffered += decoder.decode(chunk.value, { stream: true })
    const lines = buffered.split('\n')
    buffered = lines.pop() ?? ''
    for (const line of lines) {
      const endpointId = parseReadyEndpointId(line)
      if (endpointId !== null) {
        return endpointId
      }
    }
  }
}

function parseReadyEndpointId(line: string): string | null {
  const prefix = 'IROH_NATIVE_ECHO_READY endpoint_id_hex='
  if (!line.startsWith(prefix)) {
    return null
  }
  const endpointId = line.slice(prefix.length).trim()
  if (!/^[0-9a-f]{64}$/.test(endpointId)) {
    throw new Error(`native iroh echo printed invalid endpoint id: ${endpointId}`)
  }
  return endpointId
}

async function processError(stderr: Promise<string>): Promise<string> {
  const output = (await stderr).trim()
  return processOutput(output)
}

function processOutput(output: string): string {
  const trimmed = output.trim()
  return trimmed.length === 0 ? '' : `\n${trimmed}`
}

async function waitForProcessExit(
  proc: ReturnType<typeof Bun.spawn>,
  label: string,
  timeoutMs: number,
): Promise<number> {
  try {
    return await withTimeout(proc.exited, label, timeoutMs)
  } catch (error) {
    proc.kill()
    try {
      await withTimeout(proc.exited, `${label} stop`, 2_000)
    } catch {
      proc.kill('SIGKILL')
      await proc.exited
    }
    throw error
  }
}

function parseClientResult(output: string): NativeIrohEchoClientResult {
  for (const line of output.split('\n')) {
    const result = parseClientResultLine(line)
    if (result !== null) {
      return result
    }
  }
  throw new Error(`native iroh echo client did not report success${processOutput(output)}`)
}

function parseGossipSendResult(output: string): NativeIrohGossipSendResult {
  for (const line of output.split('\n')) {
    const result = parseGossipSendResultLine(line)
    if (result !== null) {
      return result
    }
  }
  throw new Error(`native iroh gossip sender did not report success${processOutput(output)}`)
}

function parseClientResultLine(line: string): NativeIrohEchoClientResult | null {
  const prefix = 'IROH_NATIVE_ECHO_CLIENT_OK payload_hex='
  if (!line.startsWith(prefix)) {
    return null
  }
  const payloadHex = line.slice(prefix.length).trim()
  if (!/^[0-9a-f]*$/.test(payloadHex) || payloadHex.length % 2 !== 0) {
    throw new Error(`native iroh echo client printed invalid payload hex: ${payloadHex}`)
  }
  return {
    payload: hexToBytes(payloadHex),
  }
}

function parseGossipSendResultLine(line: string): NativeIrohGossipSendResult | null {
  const match =
    /^IROH_NATIVE_GOSSIP_SEND_OK topic_id_hex=([0-9a-f]{64}) payload_hex=([0-9a-f]*)$/.exec(line)
  if (match === null) {
    return null
  }
  const [, topicIdHex, payloadHex] = match
  if (topicIdHex === undefined || payloadHex === undefined || payloadHex.length % 2 !== 0) {
    throw new Error(`native iroh gossip sender printed invalid result: ${line}`)
  }
  return {
    topicId: hexToBytes(topicIdHex),
    payload: hexToBytes(payloadHex),
  }
}

function nativeIrohEchoManifestPath(): string {
  return new URL('../../native/iroh-echo/Cargo.toml', import.meta.url).pathname
}

function streamToText(stream: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(stream).text()
}

function nativeIrohEchoTargetDir(): string {
  return `${temporaryDirectory()}/iroh-lite-native-echo-target`
}

function temporaryDirectory(): string {
  return (Bun.env.TMPDIR ?? '/tmp').replace(/\/$/, '')
}

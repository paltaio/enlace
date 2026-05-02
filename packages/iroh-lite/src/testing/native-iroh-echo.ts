import { hexToBytes } from './hex'
import { withTimeout } from './local-iroh-relay'

export const nativeIrohEchoAlpn = new TextEncoder().encode('/iroh/echo/1')

export interface NativeIrohEchoServer {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  stop(): Promise<void>
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
  return output.length === 0 ? '' : `\n${output}`
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

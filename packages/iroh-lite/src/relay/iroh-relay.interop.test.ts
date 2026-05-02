import { describe, expect, test } from 'bun:test'

import type { RelayWebSocketClient } from './client'
import { connectRelayWebSocket } from './client'
import { endpointIdFromSecretKey, randomSecretKey } from '../crypto/ed25519'

const interopTest = Bun.env.IROH_RELAY_INTEROP === '1' ? test : test.skip
const relayVersion = 'iroh-relay-v2'

interface LocalIrohRelay {
  readonly url: string
  stop(): Promise<void>
}

describe('iroh-relay interop', () => {
  interopTest('authenticates two browser clients and relays raw datagrams', async () => {
    const relay = await startLocalIrohRelay()
    const firstSecretKey = randomSecretKey()
    const secondSecretKey = randomSecretKey()
    const firstEndpointId = await endpointIdFromSecretKey(firstSecretKey)
    const secondEndpointId = await endpointIdFromSecretKey(secondSecretKey)
    const firstPayload = new TextEncoder().encode('from browser client one')
    const secondPayload = new TextEncoder().encode('from browser client two')

    let firstClient: RelayWebSocketClient | null = null
    let secondClient: RelayWebSocketClient | null = null
    try {
      firstClient = await withTimeout(
        connectRelayWebSocket({ url: relay.url, secretKey: firstSecretKey }),
        'first relay client connect',
      )
      secondClient = await withTimeout(
        connectRelayWebSocket({ url: relay.url, secretKey: secondSecretKey }),
        'second relay client connect',
      )

      expect(firstClient.protocol).toBe(relayVersion)
      expect(secondClient.protocol).toBe(relayVersion)
      expect(firstClient.endpointId).toEqual(firstEndpointId)
      expect(secondClient.endpointId).toEqual(secondEndpointId)

      const firstToSecond = receiveNextDatagrams(secondClient)
      firstClient.sendDatagrams({
        endpointId: secondEndpointId,
        ecn: null,
        contents: firstPayload,
      })
      await expect(withTimeout(firstToSecond, 'first datagram relay')).resolves.toEqual({
        endpointId: firstEndpointId,
        ecn: null,
        contents: firstPayload,
      })

      const secondToFirst = receiveNextDatagrams(firstClient)
      secondClient.sendDatagrams({
        endpointId: firstEndpointId,
        ecn: 3,
        segmentSize: 8,
        contents: secondPayload,
      })
      await expect(withTimeout(secondToFirst, 'second datagram relay')).resolves.toEqual({
        endpointId: secondEndpointId,
        ecn: 3,
        segmentSize: 8,
        contents: secondPayload,
      })
    } finally {
      firstClient?.close()
      secondClient?.close()
      await relay.stop()
    }
  })
})

async function receiveNextDatagrams(client: RelayWebSocketClient) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const frame = await client.receive()
    if (frame === null) {
      throw new Error('relay websocket closed before datagrams')
    }
    if (frame.type === 'datagrams') {
      return frame.datagrams
    }
  }
  throw new Error('relay did not deliver datagrams')
}

async function startLocalIrohRelay(): Promise<LocalIrohRelay> {
  const manifestPath = await findIrohRelayManifest()
  const port = reserveLocalPort()
  const configPath = `${temporaryDirectory()}/iroh-relay-${crypto.randomUUID()}.toml`
  await Bun.write(
    configPath,
    [
      'enable_metrics = false',
      'enable_quic_addr_discovery = false',
      `http_bind_addr = "127.0.0.1:${port}"`,
      '',
    ].join('\n'),
  )

  const proc = Bun.spawn(
    [
      'cargo',
      'run',
      '--quiet',
      '--manifest-path',
      manifestPath,
      '--features',
      'server',
      '--bin',
      'iroh-relay',
      '--',
      '--dev',
      '--config-path',
      configPath,
    ],
    {
      env: {
        ...Bun.env,
        RUST_LOG: Bun.env.RUST_LOG ?? 'iroh_relay=info',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )
  const stdout = Bun.readableStreamToText(proc.stdout)
  const stderr = Bun.readableStreamToText(proc.stderr)
  const url = `http://127.0.0.1:${port}`

  async function stop(): Promise<void> {
    if (proc.exitCode === null) {
      proc.kill()
      try {
        await withTimeout(proc.exited, 'iroh-relay stop', 2_000)
      } catch {
        proc.kill('SIGKILL')
        await proc.exited
      }
    }
    await Bun.file(configPath)
      .delete()
      .catch(() => undefined)
  }

  try {
    await waitForRelay(url, proc, stdout, stderr)
  } catch (error) {
    await stop()
    throw error
  }

  return { url, stop }
}

async function waitForRelay(
  url: string,
  proc: ReturnType<typeof Bun.spawn>,
  stdout: Promise<string>,
  stderr: Promise<string>,
): Promise<void> {
  const deadline = Date.now() + 120_000
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error(
        `iroh-relay exited before ready (${proc.exitCode})${await processOutput(stdout, stderr)}`,
      )
    }
    try {
      const response = await fetch(`${url}/healthz`)
      if (response.ok) {
        return
      }
    } catch {
      await sleep(100)
    }
  }
  throw new Error(`iroh-relay did not become ready at ${url}`)
}

async function findIrohRelayManifest(): Promise<string> {
  if (Bun.env.IROH_RELAY_MANIFEST !== undefined) {
    return Bun.env.IROH_RELAY_MANIFEST
  }
  const home = Bun.env.HOME
  if (home === undefined) {
    throw new Error('HOME is required to find local iroh-relay crate')
  }

  const proc = Bun.spawn(
    [
      'sh',
      '-lc',
      'set -- "$HOME"/.cargo/registry/src/*/iroh-relay-0.98.0/Cargo.toml; [ -f "$1" ] && printf "%s" "$1"',
    ],
    { env: Bun.env, stdout: 'pipe', stderr: 'pipe' },
  )
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    Bun.readableStreamToText(proc.stdout),
    Bun.readableStreamToText(proc.stderr),
  ])
  if (exitCode !== 0 || stdout.length === 0) {
    throw new Error(`local iroh-relay crate not found${formatProcessOutput(stdout, stderr)}`)
  }
  return stdout
}

function reserveLocalPort(): number {
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch() {
      return new Response('ok')
    },
  })
  const port = Number(new URL(server.url).port)
  void server.stop(true)
  return port
}

function temporaryDirectory(): string {
  return (Bun.env.TMPDIR ?? '/tmp').replace(/\/$/, '')
}

async function withTimeout<T>(promise: Promise<T>, label: string, timeoutMs = 10_000): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | null = null
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`${label} timed out`))
    }, timeoutMs)
  })
  try {
    return await Promise.race([promise, timeout])
  } finally {
    if (timeoutId !== null) {
      clearTimeout(timeoutId)
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function processOutput(stdout: Promise<string>, stderr: Promise<string>): Promise<string> {
  const [out, err] = await Promise.all([stdout, stderr])
  return formatProcessOutput(out, err)
}

function formatProcessOutput(stdout: string, stderr: string): string {
  const output = [stdout.trim(), stderr.trim()].filter((value) => value.length > 0).join('\n')
  return output.length === 0 ? '' : `\n${output}`
}

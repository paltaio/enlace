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

export interface NativeIrohGossipClientSendOptions {
  readonly relayUrl: string
  readonly serverEndpointId: Uint8Array
  readonly topicId: Uint8Array
  readonly payload: Uint8Array
}

export interface NativeIrohGossipClientRecvOptions {
  readonly relayUrl: string
  readonly serverEndpointId: Uint8Array
  readonly topicId: Uint8Array
  readonly expectedPayload?: Uint8Array
}

export interface NativeIrohGossipClientSendResult {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
  readonly payload: Uint8Array
}

export interface NativeIrohGossipClientRecvResult {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
  readonly deliveredFrom: Uint8Array
  readonly payload: Uint8Array
}

export interface NativeIrohGossipClientSender extends NativeIrohGossipClientSendResult {
  stop(): Promise<void>
}

export interface NativeIrohGossipClientReceiver {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
  received(): Promise<NativeIrohGossipClientRecvResult>
  stop(): Promise<void>
}

export interface NativeIrohGossipServer {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
  broadcast(payload: Uint8Array): Promise<void>
  nextEvent(): Promise<NativeIrohGossipEvent>
  stop(): Promise<void>
}

export type NativeIrohGossipEvent =
  | { readonly type: 'neighbor-up'; readonly peer: Uint8Array }
  | { readonly type: 'neighbor-down'; readonly peer: Uint8Array }
  | {
      readonly type: 'message'
      readonly deliveredFrom: Uint8Array
      readonly payload: Uint8Array
    }
  | { readonly type: 'lagged' }

export async function startNativeIrohEchoServer(relayUrl: string): Promise<NativeIrohEchoServer> {
  const proc = Bun.spawn(nativeIrohEchoCommand(), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: relayUrl,
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
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
  const proc = Bun.spawn(nativeIrohEchoCommand('client'), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: options.relayUrl,
      IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
      IROH_ECHO_PAYLOAD_HEX: bytesToHex(options.payload),
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
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
  const proc = Bun.spawn(nativeIrohEchoCommand('gossip-send'), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: options.relayUrl,
      IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
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

export async function runNativeIrohGossipClientSend(
  options: NativeIrohGossipClientSendOptions,
): Promise<NativeIrohGossipClientSendResult> {
  const proc = Bun.spawn(nativeIrohEchoCommand('gossip-client-send'), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: options.relayUrl,
      IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
      IROH_GOSSIP_TOPIC_ID_HEX: bytesToHex(options.topicId),
      IROH_GOSSIP_PAYLOAD_HEX: bytesToHex(options.payload),
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const stdout = streamToText(proc.stdout)
  const stderr = streamToText(proc.stderr)
  const exitCode = await waitForProcessExit(proc, 'native iroh gossip client send', 120_000)
  const output = await stdout
  const errorOutput = await stderr

  if (exitCode !== 0) {
    throw new Error(
      `native iroh gossip client send exited with code ${exitCode}${processOutput(errorOutput)}`,
    )
  }

  return parseGossipClientSendResult(output)
}

export async function startNativeIrohGossipClientSender(
  options: NativeIrohGossipClientSendOptions,
): Promise<NativeIrohGossipClientSender> {
  const proc = Bun.spawn(nativeIrohEchoCommand('gossip-client-send'), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: options.relayUrl,
      IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
      IROH_GOSSIP_TOPIC_ID_HEX: bytesToHex(options.topicId),
      IROH_GOSSIP_PAYLOAD_HEX: bytesToHex(options.payload),
      IROH_GOSSIP_STAY_OPEN: '1',
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const lines = new ProcessLineReader(proc.stdout.getReader())
  const stderr = streamToText(proc.stderr)

  async function stop(): Promise<void> {
    await closeProcessStdin(proc)
    await waitForStopOrKill(proc, 'native iroh gossip client sender stop')
  }

  try {
    const result = await withTimeout(
      readGossipClientSendStarted(lines, proc, stderr),
      'native iroh gossip client sender ready',
      120_000,
    )
    return { ...result, payload: new Uint8Array(options.payload), stop }
  } catch (error) {
    await stop()
    throw error
  }
}

export async function startNativeIrohGossipClientReceiver(
  options: NativeIrohGossipClientRecvOptions,
): Promise<NativeIrohGossipClientReceiver> {
  const proc = Bun.spawn(nativeIrohEchoCommand('gossip-client-recv'), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: options.relayUrl,
      IROH_SERVER_ENDPOINT_ID_HEX: bytesToHex(options.serverEndpointId),
      IROH_GOSSIP_TOPIC_ID_HEX: bytesToHex(options.topicId),
      ...(options.expectedPayload === undefined
        ? {}
        : { IROH_GOSSIP_EXPECT_PAYLOAD_HEX: bytesToHex(options.expectedPayload) }),
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const lines = new ProcessLineReader(proc.stdout.getReader())
  const stderr = streamToText(proc.stderr)

  async function stop(): Promise<void> {
    await stopProcess(proc, 'native iroh gossip client receiver stop')
  }

  try {
    const ready = await withTimeout(
      readGossipClientRecvReady(lines, proc, stderr),
      'native iroh gossip client receiver ready',
      120_000,
    )
    return {
      ...ready,
      received: () => readGossipClientRecvResult(lines, proc, stderr),
      stop,
    }
  } catch (error) {
    await stop()
    throw error
  }
}

export async function startNativeIrohGossipServer(
  relayUrl: string,
  topicId: Uint8Array,
): Promise<NativeIrohGossipServer> {
  const proc = Bun.spawn(nativeIrohEchoCommand('gossip-server'), {
    env: {
      ...Bun.env,
      IROH_RELAY_URL: relayUrl,
      IROH_GOSSIP_TOPIC_ID_HEX: bytesToHex(topicId),
      IROH_GOSSIP_STDIN_COMMANDS: '1',
      RUST_LOG: Bun.env.RUST_LOG ?? 'iroh=info,iroh_relay=info',
    },
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const lines = new ProcessLineReader(proc.stdout.getReader())
  const stderr = streamToText(proc.stderr)

  async function stop(): Promise<void> {
    await stopProcess(proc, 'native iroh gossip server stop')
  }

  try {
    const ready = await withTimeout(
      readGossipServerReady(lines, proc, stderr),
      'native iroh gossip server ready',
      120_000,
    )
    return {
      ...ready,
      broadcast: (payload) => writeGossipServerBroadcast(proc, lines, stderr, payload),
      nextEvent: () => readGossipEvent(lines, proc, stderr),
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

async function readGossipServerReady(
  lines: ProcessLineReader,
  proc: ReturnType<typeof Bun.spawn>,
  stderr: Promise<string>,
): Promise<{
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
}> {
  while (true) {
    const line = await lines.readLine(proc, stderr, 'native iroh gossip server')
    const ready = parseGossipServerReadyLine(line)
    if (ready !== null) {
      return ready
    }
  }
}

async function readGossipEvent(
  lines: ProcessLineReader,
  proc: ReturnType<typeof Bun.spawn>,
  stderr: Promise<string>,
): Promise<NativeIrohGossipEvent> {
  while (true) {
    const line = await lines.readLine(proc, stderr, 'native iroh gossip server')
    const event = parseGossipEventLine(line)
    if (event !== null) {
      return event
    }
  }
}

async function readGossipClientSendStarted(
  lines: ProcessLineReader,
  proc: ReturnType<typeof Bun.spawn>,
  stderr: Promise<string>,
): Promise<Pick<NativeIrohGossipClientSendResult, 'endpointId' | 'endpointIdHex' | 'topicId'>> {
  while (true) {
    const line = await lines.readLine(proc, stderr, 'native iroh gossip client sender')
    const result = parseGossipClientSendStartedLine(line)
    if (result !== null) {
      return result
    }
  }
}

async function readGossipClientRecvReady(
  lines: ProcessLineReader,
  proc: ReturnType<typeof Bun.spawn>,
  stderr: Promise<string>,
): Promise<{
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
}> {
  while (true) {
    const line = await lines.readLine(proc, stderr, 'native iroh gossip client receiver')
    const ready = parseGossipClientRecvReadyLine(line)
    if (ready !== null) {
      return ready
    }
  }
}

async function readGossipClientRecvResult(
  lines: ProcessLineReader,
  proc: ReturnType<typeof Bun.spawn>,
  stderr: Promise<string>,
): Promise<NativeIrohGossipClientRecvResult> {
  while (true) {
    const line = await lines.readLine(proc, stderr, 'native iroh gossip client receiver')
    const result = parseGossipClientRecvResultLine(line)
    if (result !== null) {
      return result
    }
  }
}

async function writeGossipServerBroadcast(
  proc: ReturnType<typeof Bun.spawn>,
  lines: ProcessLineReader,
  stderr: Promise<string>,
  payload: Uint8Array,
): Promise<void> {
  await writeProcessStdin(proc, `broadcast ${bytesToHex(payload)}\n`)
  while (true) {
    const line = await lines.readLine(proc, stderr, 'native iroh gossip server broadcast')
    const broadcastPayload = parseGossipServerBroadcastLine(line)
    if (broadcastPayload !== null) {
      if (!bytesEqual(broadcastPayload, payload)) {
        throw new Error('native iroh gossip server broadcasted unexpected payload')
      }
      return
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

function parseGossipServerReadyLine(line: string): {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
} | null {
  const match =
    /^IROH_NATIVE_GOSSIP_SERVER_READY endpoint_id_hex=([0-9a-f]{64}) topic_id_hex=([0-9a-f]{64})$/.exec(
      line,
    )
  if (match === null) {
    return null
  }
  const [, endpointIdHex, topicIdHex] = match
  if (endpointIdHex === undefined || topicIdHex === undefined) {
    throw new Error(`native iroh gossip server printed invalid ready line: ${line}`)
  }
  return {
    endpointId: hexToBytes(endpointIdHex),
    endpointIdHex,
    topicId: hexToBytes(topicIdHex),
  }
}

function parseGossipEventLine(line: string): NativeIrohGossipEvent | null {
  const neighbor =
    /^IROH_NATIVE_GOSSIP_EVENT type=neighbor-(up|down) peer_hex=([0-9a-f]{64})$/.exec(line)
  if (neighbor !== null) {
    const [, direction, peerHex] = neighbor
    if (direction !== 'up' && direction !== 'down') {
      throw new Error(`native iroh gossip server printed invalid neighbor event: ${line}`)
    }
    if (peerHex === undefined) {
      throw new Error(`native iroh gossip server printed invalid neighbor event: ${line}`)
    }
    return { type: direction === 'up' ? 'neighbor-up' : 'neighbor-down', peer: hexToBytes(peerHex) }
  }
  const message =
    /^IROH_NATIVE_GOSSIP_EVENT type=message from_endpoint_id_hex=([0-9a-f]{64}) payload_hex=([0-9a-f]*)$/.exec(
      line,
    )
  if (message !== null) {
    const [, deliveredFromHex, payloadHex] = message
    if (deliveredFromHex === undefined || payloadHex === undefined || payloadHex.length % 2 !== 0) {
      throw new Error(`native iroh gossip server printed invalid message event: ${line}`)
    }
    return {
      type: 'message',
      deliveredFrom: hexToBytes(deliveredFromHex),
      payload: hexToBytes(payloadHex),
    }
  }
  if (line === 'IROH_NATIVE_GOSSIP_EVENT type=lagged') {
    return { type: 'lagged' }
  }
  return null
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

async function stopProcess(proc: ReturnType<typeof Bun.spawn>, label: string): Promise<void> {
  if (proc.exitCode !== null) {
    return
  }
  proc.kill()
  await waitForStopOrKill(proc, label)
}

async function waitForStopOrKill(proc: ReturnType<typeof Bun.spawn>, label: string): Promise<void> {
  if (proc.exitCode !== null) {
    return
  }
  try {
    await withTimeout(proc.exited, label, 2_000)
  } catch {
    proc.kill()
    try {
      await withTimeout(proc.exited, `${label} after terminate`, 2_000)
      return
    } catch {
      proc.kill('SIGKILL')
      await proc.exited
    }
  }
}

async function closeProcessStdin(proc: ReturnType<typeof Bun.spawn>): Promise<void> {
  const stdin = proc.stdin
  if (typeof stdin !== 'object' || stdin === null) {
    return
  }
  if ('getWriter' in stdin && typeof stdin.getWriter === 'function') {
    const writer = stdin.getWriter()
    try {
      await writer.close()
    } finally {
      writer.releaseLock()
    }
    return
  }
  try {
    stdin.end()
  } catch {
    if (proc.exitCode === null) {
      proc.kill()
    }
  }
}

async function writeProcessStdin(proc: ReturnType<typeof Bun.spawn>, text: string): Promise<void> {
  const stdin = proc.stdin
  if (typeof stdin !== 'object' || stdin === null) {
    throw new Error('native process stdin is not writable')
  }
  if ('getWriter' in stdin && typeof stdin.getWriter === 'function') {
    const writer = stdin.getWriter()
    try {
      await writer.write(new TextEncoder().encode(text))
    } finally {
      writer.releaseLock()
    }
    return
  }
  if ('write' in stdin && typeof stdin.write === 'function') {
    await Promise.resolve(stdin.write(text))
    return
  }
  throw new Error('native process stdin is not writable')
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false
    }
  }
  return true
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

function parseGossipClientSendResult(output: string): NativeIrohGossipClientSendResult {
  for (const line of output.split('\n')) {
    const result = parseGossipClientSendResultLine(line)
    if (result !== null) {
      return result
    }
  }
  throw new Error(`native iroh gossip client send did not report success${processOutput(output)}`)
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

function parseGossipClientSendResultLine(line: string): NativeIrohGossipClientSendResult | null {
  const match =
    /^IROH_NATIVE_GOSSIP_CLIENT_SEND_OK endpoint_id_hex=([0-9a-f]{64}) topic_id_hex=([0-9a-f]{64}) payload_hex=([0-9a-f]*)$/.exec(
      line,
    )
  if (match === null) {
    return null
  }
  const [, endpointIdHex, topicIdHex, payloadHex] = match
  if (
    endpointIdHex === undefined ||
    topicIdHex === undefined ||
    payloadHex === undefined ||
    payloadHex.length % 2 !== 0
  ) {
    throw new Error(`native iroh gossip client send printed invalid result: ${line}`)
  }
  return {
    endpointId: hexToBytes(endpointIdHex),
    endpointIdHex,
    topicId: hexToBytes(topicIdHex),
    payload: hexToBytes(payloadHex),
  }
}

function parseGossipClientSendStartedLine(
  line: string,
): Pick<NativeIrohGossipClientSendResult, 'endpointId' | 'endpointIdHex' | 'topicId'> | null {
  const match =
    /^IROH_NATIVE_GOSSIP_CLIENT_SEND_STARTED endpoint_id_hex=([0-9a-f]{64}) topic_id_hex=([0-9a-f]{64})$/.exec(
      line,
    )
  if (match === null) {
    return null
  }
  const [, endpointIdHex, topicIdHex] = match
  if (endpointIdHex === undefined || topicIdHex === undefined) {
    throw new Error(`native iroh gossip client send printed invalid started line: ${line}`)
  }
  return {
    endpointId: hexToBytes(endpointIdHex),
    endpointIdHex,
    topicId: hexToBytes(topicIdHex),
  }
}

function parseGossipClientRecvReadyLine(line: string): {
  readonly endpointId: Uint8Array
  readonly endpointIdHex: string
  readonly topicId: Uint8Array
} | null {
  const match =
    /^IROH_NATIVE_GOSSIP_CLIENT_RECV_READY endpoint_id_hex=([0-9a-f]{64}) topic_id_hex=([0-9a-f]{64})$/.exec(
      line,
    )
  if (match === null) {
    return null
  }
  const [, endpointIdHex, topicIdHex] = match
  if (endpointIdHex === undefined || topicIdHex === undefined) {
    throw new Error(`native iroh gossip client recv printed invalid ready line: ${line}`)
  }
  return {
    endpointId: hexToBytes(endpointIdHex),
    endpointIdHex,
    topicId: hexToBytes(topicIdHex),
  }
}

function parseGossipClientRecvResultLine(line: string): NativeIrohGossipClientRecvResult | null {
  const match =
    /^IROH_NATIVE_GOSSIP_CLIENT_RECV_OK endpoint_id_hex=([0-9a-f]{64}) topic_id_hex=([0-9a-f]{64}) from_endpoint_id_hex=([0-9a-f]{64}) payload_hex=([0-9a-f]*)$/.exec(
      line,
    )
  if (match === null) {
    return null
  }
  const [, endpointIdHex, topicIdHex, deliveredFromHex, payloadHex] = match
  if (
    endpointIdHex === undefined ||
    topicIdHex === undefined ||
    deliveredFromHex === undefined ||
    payloadHex === undefined ||
    payloadHex.length % 2 !== 0
  ) {
    throw new Error(`native iroh gossip client recv printed invalid result: ${line}`)
  }
  return {
    endpointId: hexToBytes(endpointIdHex),
    endpointIdHex,
    topicId: hexToBytes(topicIdHex),
    deliveredFrom: hexToBytes(deliveredFromHex),
    payload: hexToBytes(payloadHex),
  }
}

function parseGossipServerBroadcastLine(line: string): Uint8Array | null {
  const match = /^IROH_NATIVE_GOSSIP_SERVER_BROADCAST_OK payload_hex=([0-9a-f]*)$/.exec(line)
  if (match === null) {
    return null
  }
  const [, payloadHex] = match
  if (payloadHex === undefined || payloadHex.length % 2 !== 0) {
    throw new Error(`native iroh gossip server printed invalid broadcast result: ${line}`)
  }
  return hexToBytes(payloadHex)
}

function nativeIrohEchoCommand(mode?: string): string[] {
  const command = [nativeIrohEchoBinaryPath()]
  if (mode !== undefined) {
    command.push(mode)
  }
  return command
}

function streamToText(stream: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(stream).text()
}

function nativeIrohEchoBinaryPath(): string {
  return (
    Bun.env.IROH_NATIVE_ECHO_BIN ??
    new URL('../../native/iroh-echo/target/debug/iroh-lite-native-echo', import.meta.url).pathname
  )
}

class ProcessLineReader {
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>
  readonly #decoder = new TextDecoder()
  #buffered = ''

  constructor(reader: ReadableStreamDefaultReader<Uint8Array>) {
    this.#reader = reader
  }

  async readLine(
    proc: ReturnType<typeof Bun.spawn>,
    stderr: Promise<string>,
    label: string,
  ): Promise<string> {
    while (true) {
      const line = this.#nextBufferedLine()
      if (line !== null) {
        return line
      }
      if (proc.exitCode !== null) {
        throw new Error(
          `${label} exited before expected output (${proc.exitCode})${await processError(stderr)}`,
        )
      }
      const chunk = await this.#reader.read()
      if (chunk.done === true) {
        throw new Error(
          `${label} closed stdout before expected output${await processError(stderr)}`,
        )
      }
      this.#buffered += this.#decoder.decode(chunk.value, { stream: true })
    }
  }

  #nextBufferedLine(): string | null {
    const newline = this.#buffered.indexOf('\n')
    if (newline === -1) {
      return null
    }
    const line = this.#buffered.slice(0, newline)
    this.#buffered = this.#buffered.slice(newline + 1)
    return line
  }
}

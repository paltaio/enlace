/** @jsxImportSource preact */
import { render } from 'preact'
import { useCallback, useEffect, useRef, useState } from 'preact/hooks'

import { n0DefaultRelayUrls, randomSecretKey } from '../../../packages/iroh-lite/src/index'

import { createChatBackend, type ChatBackend, type ChatMessage } from './backend'
import './styles.css'

declare module 'preact' {
  namespace JSX {
    interface IntrinsicElements {
      'iconify-icon': JSX.HTMLAttributes<HTMLElement> & {
        icon: string
        width?: string | number
        height?: string | number
        inline?: boolean | ''
        noobserver?: boolean | ''
        rotate?: string | number
        flip?: 'horizontal' | 'vertical' | 'horizontal,vertical'
      }
    }
  }
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const params = new URLSearchParams(globalThis.location.search)
const tabId = globalThis.crypto.randomUUID()
const channelName = `enlace-chat:${param('room', 'default')}`
const secretKeyStorageKey = `${channelName}:secret-key`
const peerInvitesStorageKey = `${channelName}:peer-invites`
const activeViewCapacity = 16
const peerDialRetryMs = 1_500
const peerDialTimeoutMs = 2_000

const browserState: BrowserChatState = {
  ready: false,
  paired: false,
  inviteLink: null,
  received: [],
  sent: [],
  errors: [],
}

declare global {
  interface Window {
    readonly enlaceChatState?: BrowserChatState
  }
}

interface BrowserChatState {
  ready: boolean
  paired: boolean
  inviteLink: string | null
  received: string[]
  sent: string[]
  errors: string[]
}

interface AppState extends BrowserChatState {
  readonly backend: string
  readonly status: string
}

interface Runtime {
  readonly backend: ChatBackend
  readonly signal: BroadcastChannel
  readonly peers: Set<string>
  readonly dialingPeers: Set<string>
  readonly pendingPeerJoins: Set<string>
  readonly seenMessageIds: Set<string>
  readonly appendMessage: (message: ChatMessageView) => void
  readonly update: (state: Partial<AppState>) => void
  announceInterval: ReturnType<typeof globalThis.setInterval> | null
  localInviteHex: string | null
}

interface ChatMessageView {
  readonly id: string
  readonly text: string
  readonly local: boolean
}

interface InviteSignal {
  readonly type: 'invite'
  readonly tabId: string
  readonly invite: string
}

type WireMessage = WireChatMessage | WireInviteMessage

interface WireChatMessage {
  readonly type: 'chat'
  readonly id: string | null
  readonly text: string
}

interface WireInviteMessage {
  readonly type: 'invite'
  readonly tabId: string
  readonly invite: string
}

type Theme = 'light' | 'dark'

const themeStorageKey = 'enlace-chat:theme'

function readInitialTheme(): Theme {
  if (typeof document === 'undefined') {
    return 'light'
  }
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}

function App() {
  const runtimeRef = useRef<Runtime | null>(null)
  const bottomRef = useRef<HTMLDivElement | null>(null)
  const [state, setState] = useState<AppState>({
    ...browserState,
    backend: 'iroh-lite',
    status: 'Connecting',
  })
  const [messages, setMessages] = useState<ChatMessageView[]>([])
  const [draft, setDraft] = useState('')
  const [theme, setTheme] = useState<Theme>(readInitialTheme)
  const [confirmReset, setConfirmReset] = useState(false)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages.length])

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      globalThis.localStorage.setItem(themeStorageKey, theme)
    } catch {
      /* storage unavailable */
    }
  }, [theme])

  const toggleTheme = useCallback(() => {
    setTheme((current) => (current === 'dark' ? 'light' : 'dark'))
  }, [])

  const update = useCallback((nextState: Partial<AppState>) => {
    Object.assign(browserState, nextState)
    setState((current) => ({ ...current, ...nextState }))
  }, [])

  const appendMessage = useCallback((message: ChatMessageView) => {
    setMessages((current) => current.concat(message))
  }, [])

  useEffect(() => {
    Object.defineProperty(window, 'enlaceChatState', { configurable: true, value: browserState })

    let runtime: Runtime | null = null
    let retry: ReturnType<typeof globalThis.setInterval> | null = null

    async function start(): Promise<void> {
      const backend = await openBackend()
      const signal = new BroadcastChannel(channelName)
      runtime = {
        backend,
        signal,
        peers: new Set(),
        dialingPeers: new Set(),
        pendingPeerJoins: new Set(),
        seenMessageIds: new Set(),
        appendMessage,
        update,
        announceInterval: null,
        localInviteHex: null,
      }
      runtimeRef.current = runtime
      update({ backend: backend.kind, ready: true, status: 'Waiting for peer' })
      runMessageLoop(runtime)
      wirePairing(runtime)
      retry = globalThis.setInterval(() => {
        const currentRuntime = runtime
        if (currentRuntime !== null && currentRuntime.localInviteHex !== null) {
          void restorePeerInvites(currentRuntime, currentRuntime.localInviteHex)
        }
      }, peerDialRetryMs)
    }

    function close(): void {
      if (retry !== null) {
        globalThis.clearInterval(retry)
      }
      if (runtime?.announceInterval !== null && runtime?.announceInterval !== undefined) {
        globalThis.clearInterval(runtime.announceInterval)
      }
      runtime?.backend.close()
      runtime?.signal.close()
      runtimeRef.current = null
    }

    globalThis.addEventListener('pagehide', close)
    void start().catch((error: unknown) => {
      recordError(error, update)
    })

    return () => {
      globalThis.removeEventListener('pagehide', close)
      close()
    }
  }, [appendMessage, update])

  const send = useCallback(
    (text: string) => {
      const runtime = runtimeRef.current
      if (runtime === null) {
        return
      }
      sendText(runtime, text)
    },
    [runtimeRef],
  )

  const dotClass = !state.ready
    ? 'bg-amber-400'
    : state.paired
      ? 'bg-emerald-500'
      : 'bg-zinc-300 dark:bg-zinc-600'

  return (
    <main className="grid h-dvh grid-rows-[auto_1fr_auto] bg-zinc-50 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
      <header className="sticky top-0 z-10 flex items-center justify-between gap-4 border-b border-zinc-200/70 bg-white/80 px-5 py-3 backdrop-blur dark:border-zinc-800/70 dark:bg-zinc-900/70">
        <div className="flex min-w-0 items-center gap-3">
          <span
            className={`relative inline-flex size-2 shrink-0 rounded-full ${dotClass}`}
            aria-hidden="true"
          >
            {state.paired ? (
              <span className="absolute inset-0 animate-ping rounded-full bg-emerald-400 opacity-60" />
            ) : null}
          </span>
          <div className="flex min-w-0 flex-col leading-tight">
            <span className="text-sm font-medium tracking-tight">Enlace Chat</span>
            <span className="truncate text-xs text-zinc-500 dark:text-zinc-400">
              {state.status}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <span className="hidden rounded-full border border-zinc-200 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-zinc-500 sm:inline dark:border-zinc-800 dark:text-zinc-400">
            {state.backend}
          </span>
          <button
            type="button"
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
            onClick={toggleTheme}
            className="inline-flex size-9 items-center justify-center rounded-full text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
          >
            <iconify-icon
              icon={theme === 'dark' ? 'mdi:weather-sunny' : 'mdi:weather-night'}
              width="18"
              height="18"
            />
          </button>
          <button
            type="button"
            title="Copy invite link"
            aria-label="Copy invite link"
            disabled={state.inviteLink === null}
            onClick={() => {
              void copyInvite(state.inviteLink, update)
            }}
            className="inline-flex size-9 items-center justify-center rounded-full text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100 dark:disabled:hover:bg-transparent dark:disabled:hover:text-zinc-400"
          >
            <iconify-icon icon="mdi:link-variant" width="18" height="18" />
          </button>
          <button
            type="button"
            title="Reset identity"
            aria-label="Reset identity"
            onClick={() => {
              setConfirmReset(true)
            }}
            className="inline-flex size-9 items-center justify-center rounded-full text-zinc-600 transition hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
          >
            <iconify-icon icon="mdi:refresh" width="18" height="18" />
          </button>
        </div>
      </header>

      <section className="overflow-y-auto" aria-live="polite">
        <div className="mx-auto flex max-w-2xl flex-col gap-1.5 px-5 py-6">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center gap-3 pt-24 text-center text-zinc-400 dark:text-zinc-600">
              <iconify-icon icon="mdi:message-text-outline" width="28" height="28" />
              <p className="text-sm">Send a message to begin.</p>
            </div>
          ) : (
            messages.map((message) => (
              <div
                key={message.id}
                className={`max-w-[80%] rounded-2xl px-3.5 py-2 text-[15px] leading-relaxed [overflow-wrap:anywhere] ${
                  message.local
                    ? 'self-end bg-zinc-900 text-zinc-50 dark:bg-zinc-100 dark:text-zinc-900'
                    : 'self-start border border-zinc-200 bg-white text-zinc-900 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100'
                }`}
              >
                {message.text}
              </div>
            ))
          )}
          <div ref={bottomRef} className="h-px" />
        </div>
      </section>

      <form
        className="border-t border-zinc-200/70 bg-white/80 px-5 py-3 backdrop-blur dark:border-zinc-800/70 dark:bg-zinc-900/70"
        onSubmit={(event) => {
          event.preventDefault()
          const text = draft.trim()
          if (text.length === 0) {
            return
          }
          send(text)
          setDraft('')
        }}
      >
        <div className="mx-auto flex max-w-2xl items-center gap-2">
          <input
            className="h-11 flex-1 rounded-full border border-zinc-200 bg-white px-4 text-[15px] text-zinc-900 placeholder-zinc-400 outline-none transition focus:border-zinc-400 focus:ring-2 focus:ring-zinc-100 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder-zinc-500 dark:focus:border-zinc-600 dark:focus:ring-zinc-800"
            autoComplete="off"
            placeholder="Message"
            value={draft}
            onInput={(event) => {
              setDraft(event.currentTarget.value)
            }}
          />
          <button
            type="submit"
            aria-label="Send"
            title="Send"
            disabled={!state.ready || draft.trim().length === 0}
            className="inline-flex size-11 shrink-0 items-center justify-center rounded-full bg-zinc-900 text-white transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:bg-zinc-300 disabled:hover:bg-zinc-300 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white dark:disabled:bg-zinc-700 dark:disabled:text-zinc-500 dark:disabled:hover:bg-zinc-700"
          >
            <iconify-icon icon="mdi:arrow-up" width="20" height="20" />
          </button>
        </div>
      </form>

      {confirmReset ? (
        <ResetConfirm
          onCancel={() => {
            setConfirmReset(false)
          }}
          onConfirm={() => {
            setConfirmReset(false)
            resetIdentity()
          }}
        />
      ) : null}
    </main>
  )
}

interface ResetConfirmProps {
  readonly onCancel: () => void
  readonly onConfirm: () => void
}

function ResetConfirm({ onCancel, onConfirm }: ResetConfirmProps) {
  useEffect(() => {
    function onKey(event: KeyboardEvent): void {
      if (event.key === 'Escape') {
        onCancel()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
    }
  }, [onCancel])

  return (
    <div
      className="fixed inset-0 z-20 flex items-center justify-center bg-zinc-950/40 px-4 backdrop-blur-sm dark:bg-zinc-950/70"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reset-confirm-title"
      onClick={onCancel}
    >
      <div
        className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-5 shadow-xl dark:border-zinc-800 dark:bg-zinc-900"
        onClick={(event) => {
          event.stopPropagation()
        }}
      >
        <div className="flex items-start gap-3">
          <span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400">
            <iconify-icon icon="mdi:alert-outline" width="20" height="20" />
          </span>
          <div className="min-w-0">
            <h2
              id="reset-confirm-title"
              className="text-sm font-semibold text-zinc-900 dark:text-zinc-100"
            >
              Reset identity?
            </h2>
            <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
              Your secret key and known peers for this room will be discarded. The page will reload.
            </p>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="h-9 rounded-full border border-zinc-200 bg-white px-4 text-sm font-medium text-zinc-700 transition hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            autoFocus
            className="h-9 rounded-full bg-red-600 px-4 text-sm font-medium text-white transition hover:bg-red-500 dark:bg-red-500 dark:hover:bg-red-400"
          >
            Reset
          </button>
        </div>
      </div>
    </div>
  )
}

async function openBackend(): Promise<ChatBackend> {
  const seed = await seedBytes(param('room', 'default'))
  const channel = param('channel', 'chat')
  return await createChatBackend({
    kind: 'iroh-lite',
    seed,
    channel,
    activeViewCapacity,
    relayUrls: relayUrlInputs(),
    secretKey: sessionSecretKey(),
  })
}

function relayUrlInputs(): readonly string[] {
  const relayUrls = params.getAll('relay').filter((relayUrl) => relayUrl.length > 0)
  if (relayUrls.length > 0) {
    return relayUrls
  }
  return n0DefaultRelayUrls
}

function wirePairing(runtime: Runtime): void {
  if (runtime.backend.localInvite === null) {
    runtime.update({ status: 'Backend has no invite' })
    return
  }
  const invite = bytesToHex(runtime.backend.localInvite)
  runtime.localInviteHex = invite
  runtime.update({ inviteLink: inviteLink(invite) })
  runtime.signal.addEventListener('message', (event) => {
    void handleSignal(runtime, event.data)
  })
  void handleInviteParam(runtime, invite)
  void restorePeerInvites(runtime, invite)
  announceInvite(runtime.signal, invite)
  runtime.announceInterval = globalThis.setInterval(() => {
    announceInvite(runtime.signal, invite)
  }, 1_000)
}

async function handleSignal(runtime: Runtime, value: unknown): Promise<void> {
  try {
    const invite = inviteSignal(value)
    await addPeerInvite(runtime, invite.tabId, invite.invite)
  } catch (error) {
    recordError(error, runtime.update)
  }
}

function runMessageLoop(runtime: Runtime): void {
  void (async () => {
    try {
      for await (const message of runtime.backend.messages()) {
        void handleWireMessage(runtime, message)
      }
    } catch (error) {
      recordError(error, runtime.update)
    }
  })()
}

async function handleWireMessage(runtime: Runtime, message: ChatMessage): Promise<void> {
  const wire = parseWireMessage(message)
  if (wire.type === 'invite') {
    await addPeerInvite(runtime, wire.tabId, wire.invite, false)
    return
  }
  if (wire.id !== null && runtime.seenMessageIds.has(wire.id)) {
    return
  }
  if (wire.id !== null) {
    runtime.seenMessageIds.add(wire.id)
  }
  runtime.appendMessage({
    id: wire.id ?? globalThis.crypto.randomUUID(),
    text: wire.text,
    local: false,
  })
  browserState.received.push(wire.text)
  runtime.update({ paired: true, received: browserState.received, status: 'Connected' })
}

function parseWireMessage(message: ChatMessage): WireMessage {
  const text = messageText(message)
  try {
    const value: unknown = JSON.parse(text)
    if (isObject(value)) {
      const type = objectString(value, 'type')
      if (type === 'invite') {
        return {
          type,
          tabId: objectString(value, 'tabId'),
          invite: objectString(value, 'invite'),
        }
      }
      if (type === 'chat') {
        return {
          type,
          id: objectOptionalString(value, 'id'),
          text: objectString(value, 'text'),
        }
      }
    }
  } catch {
    return { type: 'chat', id: null, text }
  }
  return { type: 'chat', id: null, text }
}

function sendAutoMessage(runtime: Runtime): void {
  const text = params.get('auto')
  if (text === null || browserState.sent.includes(text)) {
    return
  }
  sendText(runtime, text)
}

function sendText(runtime: Runtime, text: string): void {
  const id = globalThis.crypto.randomUUID()
  runtime.backend.send(encodeWireMessage({ type: 'chat', id, text }))
  browserState.sent.push(text)
  runtime.update({ sent: browserState.sent })
  runtime.appendMessage({ id, text, local: true })
}

function announceInvite(signal: BroadcastChannel, invite: string): void {
  signal.postMessage({
    type: 'invite',
    tabId,
    invite,
  } satisfies InviteSignal)
}

async function copyInvite(
  link: string | null,
  update: (state: Partial<AppState>) => void,
): Promise<void> {
  if (link === null) {
    return
  }
  await globalThis.navigator.clipboard.writeText(link)
  update({ status: 'Invite link copied' })
}

function inviteLink(invite: string): string {
  const url = new URL(globalThis.location.href)
  url.searchParams.set('invite', invite)
  url.searchParams.delete('auto')
  return url.toString()
}

async function handleInviteParam(runtime: Runtime, localInvite: string): Promise<void> {
  const invite = params.get('invite')
  if (invite === null || invite === localInvite) {
    return
  }
  await addPeerInvite(runtime, `url:${invite}`, invite)
}

async function addPeerInvite(
  runtime: Runtime,
  peerKey: string,
  invite: string,
  sendReply = true,
): Promise<void> {
  if (peerKey === tabId || runtime.peers.has(peerKey) || runtime.dialingPeers.has(peerKey)) {
    return
  }
  rememberPeerInvite(peerKey, invite, runtime.localInviteHex)
  runtime.dialingPeers.add(peerKey)
  let dial: Promise<void>
  try {
    dial = Promise.resolve(runtime.backend.addPeer(hexToBytes(invite)))
  } catch (error) {
    runtime.dialingPeers.delete(peerKey)
    recordError(error, runtime.update)
    return
  }
  if (!runtime.pendingPeerJoins.has(peerKey)) {
    runtime.pendingPeerJoins.add(peerKey)
    void dial.then(
      () => {
        completePeerInvite(runtime, peerKey, sendReply)
      },
      (error: unknown) => {
        runtime.pendingPeerJoins.delete(peerKey)
        runtime.dialingPeers.delete(peerKey)
        recordError(error, runtime.update)
      },
    )
  }
  globalThis.setTimeout(() => {
    if (!runtime.peers.has(peerKey)) {
      runtime.dialingPeers.delete(peerKey)
    }
  }, peerDialTimeoutMs)
}

function completePeerInvite(runtime: Runtime, peerKey: string, sendReply: boolean): void {
  runtime.pendingPeerJoins.delete(peerKey)
  runtime.dialingPeers.delete(peerKey)
  if (runtime.peers.has(peerKey)) {
    return
  }
  runtime.peers.add(peerKey)
  runtime.update({ paired: true, status: 'Connected' })
  if (sendReply && runtime.localInviteHex !== null) {
    runtime.backend.send(
      encodeWireMessage({ type: 'invite', tabId, invite: runtime.localInviteHex }),
    )
  }
  sendAutoMessage(runtime)
}

function encodeWireMessage(message: WireMessage): Uint8Array {
  return encoder.encode(JSON.stringify(message))
}

async function restorePeerInvites(runtime: Runtime, localInvite: string): Promise<void> {
  for (const peer of storedPeerInvites()) {
    if (peer.invite !== localInvite) {
      void addPeerInvite(runtime, peer.key, peer.invite, false)
    }
  }
}

function rememberPeerInvite(key: string, invite: string, localInvite: string | null): void {
  if (invite === localInvite) {
    return
  }
  const peersToStore = storedPeerInvites().filter(
    (peer) => peer.key !== key && peer.invite !== invite,
  )
  peersToStore.unshift({ key, invite })
  globalThis.sessionStorage.setItem(
    peerInvitesStorageKey,
    JSON.stringify(peersToStore.slice(0, 16)),
  )
}

function storedPeerInvites(): StoredPeerInvite[] {
  const value = globalThis.sessionStorage.getItem(peerInvitesStorageKey)
  if (value === null) {
    return []
  }
  const decoded: unknown = JSON.parse(value)
  if (!Array.isArray(decoded)) {
    return []
  }
  return decoded.filter((entry) => isStoredPeerInvite(entry))
}

function isStoredPeerInvite(value: unknown): value is StoredPeerInvite {
  if (!isObject(value)) {
    return false
  }
  try {
    return objectString(value, 'key').length > 0 && objectString(value, 'invite').length > 0
  } catch {
    return false
  }
}

interface StoredPeerInvite {
  readonly key: string
  readonly invite: string
}

async function seedBytes(room: string): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(room)))
}

function messageText(message: ChatMessage): string {
  return decoder.decode(message.payload)
}

function inviteSignal(value: unknown): InviteSignal {
  if (!isObject(value)) {
    throw new TypeError('signal must be an object')
  }
  const type = objectString(value, 'type')
  const signalTabId = objectString(value, 'tabId')
  const invite = objectString(value, 'invite')
  if (type !== 'invite') {
    throw new TypeError('signal type is unsupported')
  }
  return { type, tabId: signalTabId, invite }
}

function objectString(value: object, key: string): string {
  const prop = Object.getOwnPropertyDescriptor(value, key)?.value
  if (typeof prop !== 'string') {
    throw new TypeError(`field ${key} must be a string`)
  }
  return prop
}

function objectOptionalString(value: object, key: string): string | null {
  const prop = Object.getOwnPropertyDescriptor(value, key)?.value
  if (prop === undefined) {
    return null
  }
  if (typeof prop !== 'string') {
    throw new TypeError(`field ${key} must be a string`)
  }
  return prop
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) {
    throw new TypeError('hex string must contain complete lowercase bytes')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function sessionSecretKey(): Uint8Array {
  const stored = globalThis.sessionStorage.getItem(secretKeyStorageKey)
  if (stored !== null) {
    return hexToBytes(stored)
  }
  const secretKey = randomSecretKey()
  globalThis.sessionStorage.setItem(secretKeyStorageKey, bytesToHex(secretKey))
  return secretKey
}

function resetIdentity(): void {
  globalThis.sessionStorage.removeItem(secretKeyStorageKey)
  globalThis.sessionStorage.removeItem(peerInvitesStorageKey)
  globalThis.location.reload()
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

function recordError(error: unknown, update: (state: Partial<AppState>) => void): void {
  const message = errorMessage(error)
  browserState.errors.push(message)
  update({ errors: browserState.errors, status: message })
}

function param(name: string, fallback: string): string {
  const value = params.get(name)
  if (value === null || value.length === 0) {
    return fallback
  }
  return value
}

const root = document.getElementById('root')
if (root === null) {
  throw new Error('missing root element')
}

render(<App />, root)

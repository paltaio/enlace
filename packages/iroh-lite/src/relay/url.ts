export const RELAY_PATH = '/relay'

export type RelayUrlInput = string | URL

export function normalizeRelayUrl(input: RelayUrlInput): URL {
  const url = new URL(input)
  assertRelayUrlProtocol(url)
  url.pathname = '/'
  url.search = ''
  url.hash = ''
  return url
}

export function normalizeRelayUrls(inputs: Iterable<RelayUrlInput>): URL[] {
  return Array.from(inputs, normalizeRelayUrl)
}

export function relayUrlToWebSocketUrl(input: RelayUrlInput): URL {
  const url = normalizeRelayUrl(input)
  if (url.protocol === 'https:') {
    url.protocol = 'wss:'
  } else if (url.protocol === 'http:') {
    url.protocol = 'ws:'
  }
  url.pathname = RELAY_PATH
  return url
}

export const relayHttpUrlToWebSocketUrl = relayUrlToWebSocketUrl

function assertRelayUrlProtocol(url: URL): void {
  if (
    url.protocol !== 'http:' &&
    url.protocol !== 'https:' &&
    url.protocol !== 'ws:' &&
    url.protocol !== 'wss:'
  ) {
    throw new TypeError('relay URL must use http, https, ws, or wss')
  }
}

import { describe, expect, test } from 'bun:test'

import {
  normalizeRelayUrl,
  normalizeRelayUrls,
  relayHttpUrlToWebSocketUrl,
  relayUrlToWebSocketUrl,
} from './url'

describe('relay URL', () => {
  test('normalizes relay base URLs', () => {
    expect(normalizeRelayUrl('https://relay.example.com/ping?x=1#probe').toString()).toBe(
      'https://relay.example.com/',
    )
    expect(normalizeRelayUrl(new URL('ws://127.0.0.1:3340/relay')).toString()).toBe(
      'ws://127.0.0.1:3340/',
    )
  })

  test('normalizes relay URL lists without changing order', () => {
    expect(
      normalizeRelayUrls([
        'https://first.example.com/ping',
        new URL('http://second.example.com/relay?x=1'),
      ]).map((url) => url.toString()),
    ).toEqual(['https://first.example.com/', 'http://second.example.com/'])
  })

  test('converts relay URLs to WebSocket /relay URLs', () => {
    expect(relayUrlToWebSocketUrl('https://relay.example.com/ping?x=1').toString()).toBe(
      'wss://relay.example.com/relay',
    )
    expect(relayUrlToWebSocketUrl('http://127.0.0.1:3340').toString()).toBe(
      'ws://127.0.0.1:3340/relay',
    )
    expect(relayUrlToWebSocketUrl('wss://relay.example.com/relay').toString()).toBe(
      'wss://relay.example.com/relay',
    )
  })

  test('keeps previous relay URL helper name as alias', () => {
    expect(relayHttpUrlToWebSocketUrl).toBe(relayUrlToWebSocketUrl)
  })

  test('rejects unsupported relay URL schemes', () => {
    expect(() => normalizeRelayUrl('ftp://relay.example.com')).toThrow(
      'relay URL must use http, https, ws, or wss',
    )
  })
})

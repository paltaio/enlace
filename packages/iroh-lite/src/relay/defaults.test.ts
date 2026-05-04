import { describe, expect, test } from 'bun:test'

import {
  n0AsiaPacificRelayUrl,
  n0DefaultRelayUrls,
  n0EuropeRelayUrl,
  n0NaEastRelayUrl,
  n0NaWestRelayUrl,
} from '@paltaio/iroh-lite/relay/defaults'

describe('n0 relay defaults', () => {
  test('exports the public n0 relay URLs in endpoint selection order', () => {
    expect(n0DefaultRelayUrls).toEqual([
      n0NaEastRelayUrl,
      n0NaWestRelayUrl,
      n0EuropeRelayUrl,
      n0AsiaPacificRelayUrl,
    ])
  })
})

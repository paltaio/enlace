import { describe, expect, test } from 'bun:test'

import { bytesToHex, hexToBytes } from '../testing/hex'
import { decodeGossipPeerDataAddrInfo, encodeGossipPeerDataAddrInfo } from './peer-data'

const vector = {
  emptyPeerDataHex: '',
  emptyAddrInfoHex: '0000',
  relayUrl: 'https://relay.example.com/',
  relayPeerDataHex: '011a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f00',
  directPeerDataHex: '0001007f000001b960',
}

describe('gossip peer data', () => {
  test('decodes empty native peer data as empty address info', () => {
    expect(decodeGossipPeerDataAddrInfo(hexToBytes(vector.emptyPeerDataHex))).toEqual({
      relayUrl: null,
      directAddresses: [],
    })
  })

  test('decodes native empty address info', () => {
    expect(decodeGossipPeerDataAddrInfo(hexToBytes(vector.emptyAddrInfoHex))).toEqual({
      relayUrl: null,
      directAddresses: [],
    })
  })

  test('encodes native empty address info', () => {
    expect(bytesToHex(encodeGossipPeerDataAddrInfo({ relayUrl: null }))).toBe(
      vector.emptyAddrInfoHex,
    )
  })

  test('decodes native relay-only address info', () => {
    expect(decodeGossipPeerDataAddrInfo(hexToBytes(vector.relayPeerDataHex))).toEqual({
      relayUrl: new URL(vector.relayUrl),
      directAddresses: [],
    })
  })

  test('encodes native relay-only address info', () => {
    expect(bytesToHex(encodeGossipPeerDataAddrInfo({ relayUrl: vector.relayUrl }))).toBe(
      vector.relayPeerDataHex,
    )
  })

  test('decodes native direct address info', () => {
    expect(decodeGossipPeerDataAddrInfo(hexToBytes(vector.directPeerDataHex))).toEqual({
      relayUrl: null,
      directAddresses: ['127.0.0.1:12345'],
    })
  })

  test('encodes native direct address info', () => {
    expect(
      bytesToHex(
        encodeGossipPeerDataAddrInfo({
          relayUrl: null,
          directAddresses: ['127.0.0.1:12345'],
        }),
      ),
    ).toBe(vector.directPeerDataHex)
  })
})

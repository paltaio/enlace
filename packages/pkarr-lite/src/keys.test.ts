import { describe, expect, test } from 'bun:test'

import { Keypair, PublicKey } from '@paltaio/pkarr-lite'
import { PublicKey as SubpathPublicKey } from '@paltaio/pkarr-lite/keys'

const MESSAGE = new TextEncoder().encode('pkarr-lite key vector')

const PUBLIC_KEY_HEX = '01b467a3b7913ab27a04a8edf2f3fb074cfe0ecf4babe108d67be3853b0f26c5'
const PUBLIC_KEY_Z32 = 'yg4gxe7z1r7mr6orids9fh95y7gxhdsxjqi6nngsxxtakqaxr5no'
const PUBLIC_KEY_URI = `pk:${PUBLIC_KEY_Z32}`

const PARSE_INPUTS = [
  PUBLIC_KEY_Z32,
  PUBLIC_KEY_URI,
  `${PUBLIC_KEY_URI}/foo`,
  `${PUBLIC_KEY_URI}?foo=bar`,
  `${PUBLIC_KEY_URI}#foo`,
  `${PUBLIC_KEY_URI}.`,
  `https://${PUBLIC_KEY_Z32}///foo/bar`,
  `https://${PUBLIC_KEY_Z32}?foo=bar`,
  `https://${PUBLIC_KEY_Z32}#foo`,
  `https://foo.bar.${PUBLIC_KEY_Z32}#foo`,
  `https://foo.${PUBLIC_KEY_Z32}.`,
  `https://foo@${PUBLIC_KEY_Z32}#foo`,
  `https://${PUBLIC_KEY_Z32}:8888`,
  `https://foo@bar.${PUBLIC_KEY_Z32}.:8888?q=v&a=b#foo`,
  `https://o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy.${PUBLIC_KEY_Z32}`,
] as const

const KEY_VECTORS = [
  {
    secret: '0000000000000000000000000000000000000000000000000000000000000000',
    publicKey: '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29',
    z32: '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo',
    uri: 'pk:8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo',
    signature:
      '1bc8a481df6f13376463a856b0038e51d5037a6708269e7a40efdaa5790fb48f8213e1401efe9a8e3f1bff18ffa8b8547c874c47e06f640e7a3312db34244f09',
  },
  {
    secret: '0101010101010101010101010101010101010101010101010101010101010101',
    publicKey: '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
    z32: 'tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy',
    uri: 'pk:tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy',
    signature:
      '78e8bbccb7d1b995063feedab7f733688149bb192d62c05dc750031d5b89c1fdebfb420352ff215bd2f38cae27ec6ba4449aa8a147f45af49c0a351fb5901701',
  },
  {
    secret: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    publicKey: '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8',
    z32: 'yqooxx9u3aemh8mo5wcqq16yufu6jitouq1o4za751dger1igghy',
    uri: 'pk:yqooxx9u3aemh8mo5wcqq16yufu6jitouq1o4za751dger1igghy',
    signature:
      '399ff3d1a7a53e0a2239a9c3cdca9d63cf1428ce37228aba7b5c51bee0490e3661ae07ede1796646fc1e728fbdb4ae6758d5d97230832437c2ee3216c8a7fc02',
  },
] as const

describe('PublicKey', () => {
  test('exports from root and keys subpath', () => {
    expect(SubpathPublicKey).toBe(PublicKey)
  })

  test('parses Rust URI forms', () => {
    for (const input of PARSE_INPUTS) {
      const publicKey = PublicKey.parse(input)
      expect(bytesToHex(publicKey.toBytes())).toBe(PUBLIC_KEY_HEX)
      expect(publicKey.toZ32()).toBe(PUBLIC_KEY_Z32)
      expect(publicKey.toUriString()).toBe(PUBLIC_KEY_URI)
    }
  })

  test('rejects invalid public keys', () => {
    expect(() => PublicKey.fromBytes(new Uint8Array(31))).toThrow(RangeError)
    expect(() => PublicKey.parse(PUBLIC_KEY_Z32.toUpperCase())).toThrow()
    expect(() => PublicKey.parse(`https://${PUBLIC_KEY_Z32.toUpperCase()}`)).toThrow()
    expect(() =>
      PublicKey.fromZ32('c1bkg8tfsyy8wcedtmw4fwhdmm7bbzhgg3z58tf43m5ow8w9mbus'),
    ).toThrow()
  })
})

describe('Keypair', () => {
  test('matches Rust secret key vectors', async () => {
    for (const vector of KEY_VECTORS) {
      const keypair = await Keypair.fromSecretKey(hexToBytes(vector.secret))
      const publicKey = keypair.publicKey()
      const signature = await keypair.sign(MESSAGE)

      expect(bytesToHex(keypair.secretKey())).toBe(vector.secret)
      expect(bytesToHex(publicKey.toBytes())).toBe(vector.publicKey)
      expect(keypair.toZ32()).toBe(vector.z32)
      expect(keypair.toUriString()).toBe(vector.uri)
      expect(bytesToHex(signature)).toBe(vector.signature)
      expect(await keypair.verify(MESSAGE, signature)).toBe(true)
      expect(await publicKey.verify(MESSAGE, signature)).toBe(true)
    }
  })

  test('generates random browser-safe keypairs', async () => {
    const keypair = await Keypair.random()
    const signature = await keypair.sign(MESSAGE)

    expect(keypair.secretKey()).toHaveLength(32)
    expect(keypair.publicKey().toBytes()).toHaveLength(32)
    expect(keypair.toZ32()).toHaveLength(52)
    expect(keypair.toUriString()).toBe(`pk:${keypair.toZ32()}`)
    expect(await keypair.verify(MESSAGE, signature)).toBe(true)
  })
})

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

import { Point, getPublicKeyAsync, signAsync, utils, verifyAsync } from '@noble/ed25519'

import { PUBLIC_KEY_BYTES, SIGNATURE_BYTES } from './constants'
import { copyBytes, requireLength } from './bytes'
import { decodeZ32, encodeZ32 } from './z32'

export class PublicKey {
  readonly #bytes: Uint8Array

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes
  }

  static fromBytes(bytes: Uint8Array): PublicKey {
    requireLength(bytes, PUBLIC_KEY_BYTES, 'public key')
    Point.fromBytes(bytes, false)
    return new PublicKey(copyBytes(bytes))
  }

  static fromZ32(encoded: string): PublicKey {
    return PublicKey.fromBytes(decodeZ32(encoded))
  }

  static parse(input: string): PublicKey {
    return PublicKey.fromZ32(extractPublicKeyText(input))
  }

  static fromUriString(input: string): PublicKey {
    return PublicKey.parse(input)
  }

  toBytes(): Uint8Array {
    return copyBytes(this.#bytes)
  }

  toZ32(): string {
    return encodeZ32(this.#bytes)
  }

  toUriString(): string {
    return `pk:${this.toZ32()}`
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    requireLength(signature, SIGNATURE_BYTES, 'signature')
    return verifyAsync(signature, message, this.#bytes, {
      zip215: false,
    })
  }
}

export class Keypair {
  readonly #secretKey: Uint8Array
  readonly #publicKey: PublicKey

  private constructor(secretKey: Uint8Array, publicKey: PublicKey) {
    this.#secretKey = secretKey
    this.#publicKey = publicKey
  }

  static async random(): Promise<Keypair> {
    return Keypair.fromSecretKey(utils.randomSecretKey())
  }

  static async fromSecretKey(secretKey: Uint8Array): Promise<Keypair> {
    requireLength(secretKey, PUBLIC_KEY_BYTES, 'secret key')
    const secretKeyBytes = copyBytes(secretKey)
    const publicKey = PublicKey.fromBytes(await getPublicKeyAsync(secretKeyBytes))
    return new Keypair(secretKeyBytes, publicKey)
  }

  secretKey(): Uint8Array {
    return copyBytes(this.#secretKey)
  }

  publicKey(): PublicKey {
    return this.#publicKey
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return signAsync(message, this.#secretKey)
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return this.#publicKey.verify(message, signature)
  }

  toZ32(): string {
    return this.#publicKey.toZ32()
  }

  toUriString(): string {
    return this.#publicKey.toUriString()
  }
}

function extractPublicKeyText(input: string): string {
  if (input.startsWith('pk:')) {
    return rightmostDomainLabel(stripNonUrlDecorations(input.slice('pk:'.length)))
  }

  const hostOrInput = stripNonUrlDecorations(stripScheme(input))
  return rightmostDomainLabel(hostOrInput)
}

function stripScheme(input: string): string {
  return /^[A-Za-z][A-Za-z\d+.-]*:/u.test(input) ? (input.split(':', 2)[1] ?? input) : input
}

function stripNonUrlDecorations(input: string): string {
  const authority = input.startsWith('//') ? input.slice(2) : input
  const withoutUser = authority.split('@').at(-1) ?? authority
  return withoutUser.split(/[/?#:]/u, 1)[0] ?? withoutUser
}

function rightmostDomainLabel(input: string): string {
  const withoutTrailingDot = input.replace(/\.+$/u, '')
  return withoutTrailingDot.split('.').at(-1) ?? withoutTrailingDot
}

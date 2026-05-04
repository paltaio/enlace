import { hexToBytes } from './hex'

export const rfc8448ClientHello = hexToBytes(`
  010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2
  ef6283024dece7000006130113031302010000910000000b0009000006736572
  766572ff01000100000a00140012001d00170018001901000101010201030104
  00230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c0
  6e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e04030503
  0603020308040805080604010501060102010402050206020202002d00020101
  001c00024001
`)

export const rfc8448ServerHello = hexToBytes(`
  020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155
  772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb
  f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304
`)

export const rfc8448SharedSecret = hexToBytes(
  '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d',
)

export const rfc8448ClientPrivateKey = hexToBytes(
  '49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005',
)

export const rfc8448ClientPublicKey = hexToBytes(
  '99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c',
)

export const rfc8448ServerPrivateKey = hexToBytes(
  'b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e',
)

export const rfc8448ServerPublicKey = hexToBytes(
  'c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f',
)

export const rfc8448EarlySecret = hexToBytes(
  '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a',
)

export const rfc8448DerivedSecretForHandshake = hexToBytes(
  '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba',
)

export const rfc8448ClientServerHelloTranscriptHash = hexToBytes(
  '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8',
)

export const rfc8448HandshakeSecret = hexToBytes(
  '1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac',
)

export const rfc8448ClientHandshakeTrafficSecret = hexToBytes(
  'b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21',
)

export const rfc8448ServerHandshakeTrafficSecret = hexToBytes(
  'b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38',
)

export const rfc8448ClientHandshakeTrafficKey = hexToBytes('dbfaa693d1762c5b666af5d950258d01')

export const rfc8448ClientHandshakeTrafficIv = hexToBytes('5bd3c71b836e0b76bb73265f')

export const rfc8448ServerHandshakeTrafficKey = hexToBytes('3fce516009c21727d0f2e4e86ee403bc')

export const rfc8448ServerHandshakeTrafficIv = hexToBytes('5d313eb2671276ee13000b30')

export const rfc8448ClientHandshakeFinishedKey = hexToBytes(
  'b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4',
)

export const rfc8448ServerHandshakeFinishedKey = hexToBytes(
  '008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8',
)

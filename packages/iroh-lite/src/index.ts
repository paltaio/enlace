export { RELAY_CHALLENGE_DOMAIN, deriveRelayChallengeKey } from './crypto/blake3'
export {
  ENDPOINT_ID_LENGTH,
  SECRET_KEY_LENGTH,
  SIGNATURE_LENGTH,
  endpointIdFromSecretKey,
  randomSecretKey,
  sign,
  validateEndpointId,
  validateSecretKey,
  verify,
} from './crypto/ed25519'
export { RelayAuthDeniedError, RelayWebSocketClient, connectRelayWebSocket } from './relay/client'
export type {
  ConnectRelayWebSocketOptions,
  RelayBrowserWebSocket,
  RelayProtocolVersion,
  RelayWebSocketConstructor,
  RelayWebSocketReceiveFrame,
} from './relay/client'
export {
  FrameType,
  MAX_FRAME_SIZE,
  MAX_PACKET_SIZE,
  RelayStatus,
  decodeClientToRelayFrame,
  decodeRelayToClientFrame,
  encodeClientToRelayFrame,
  encodeRelayToClientFrame,
} from './relay/frames'
export type {
  ClientRelayFrame,
  Datagrams,
  EcnCodepoint,
  FrameTypeValue,
  RelayFrame,
  RelayFrameProtocolVersion,
  RelayStatusValue,
} from './relay/frames'
export {
  CLIENT_AUTH_HEADER,
  RELAY_PATH,
  RELAY_SUBPROTOCOLS,
  SERVER_CHALLENGE_LENGTH,
  challengeMessageToSign,
  createClientAuth,
  decodeHandshakeFrame,
  encodeClientAuth,
  encodeClientAuthFrame,
  encodeServerChallengeFrame,
  encodeServerConfirmsAuthFrame,
  relayHttpUrlToWebSocketUrl,
} from './relay/handshake'
export type { ClientAuth, HandshakeFrame, ServerChallenge } from './relay/handshake'
export { MAX_QUIC_VARINT, decodeVarInt, decodeVarIntNumber, encodeVarInt } from './relay/varint'
export type { VarIntDecodeResult } from './relay/varint'

import {
  concatBytes,
  copyBytes,
  decodePostcardLen,
  encodePostcardLen,
  requireLength,
} from "../bytes";
import {
  ENDPOINT_ID_LENGTH,
  SIGNATURE_LENGTH,
  endpointIdFromSecretKey,
  sign,
  validateEndpointId,
} from "../crypto/ed25519";
import { deriveRelayChallengeKey } from "../crypto/blake3";
import { FrameType } from "./frames";
import { decodeVarIntNumber, encodeVarInt } from "./varint";

export const RELAY_PATH = "/relay";
export const RELAY_SUBPROTOCOLS = ["iroh-relay-v2", "iroh-relay-v1"] as const;
export const CLIENT_AUTH_HEADER = "x-iroh-relay-client-auth-v1";
export const SERVER_CHALLENGE_LENGTH = 16;

export interface ServerChallenge {
  readonly challenge: Uint8Array;
}

export interface ClientAuth {
  readonly endpointId: Uint8Array;
  readonly signature: Uint8Array;
}

export type HandshakeFrame =
  | { readonly type: "server-challenge"; readonly challenge: Uint8Array }
  | { readonly type: "server-confirms-auth" }
  | { readonly type: "server-denies-auth"; readonly reason: string }
  | { readonly type: "client-auth"; readonly auth: ClientAuth };

export function relayHttpUrlToWebSocketUrl(input: string | URL): URL {
  const url = new URL(input);
  if (url.protocol === "https:") {
    url.protocol = "wss:";
  } else if (url.protocol === "http:") {
    url.protocol = "ws:";
  } else if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new TypeError("relay URL must use http, https, ws, or wss");
  }
  url.pathname = RELAY_PATH;
  url.search = "";
  url.hash = "";
  return url;
}

export function challengeMessageToSign(challenge: Uint8Array): Uint8Array {
  requireLength(challenge, SERVER_CHALLENGE_LENGTH, "server challenge");
  return deriveRelayChallengeKey(challenge);
}

export async function createClientAuth(
  secretKey: Uint8Array,
  challenge: ServerChallenge,
): Promise<ClientAuth> {
  const message = challengeMessageToSign(challenge.challenge);
  return {
    endpointId: await endpointIdFromSecretKey(secretKey),
    signature: await sign(secretKey, message),
  };
}

export async function encodeClientAuthFrame(
  secretKey: Uint8Array,
  challenge: ServerChallenge,
): Promise<Uint8Array> {
  return encodeClientAuth(await createClientAuth(secretKey, challenge));
}

export function encodeClientAuth(auth: ClientAuth): Uint8Array {
  const endpointId = validateEndpointId(auth.endpointId);
  requireLength(auth.signature, SIGNATURE_LENGTH, "signature");
  return concatBytes([
    encodeVarInt(FrameType.ClientAuth),
    endpointId,
    encodePostcardLen(SIGNATURE_LENGTH),
    auth.signature,
  ]);
}

export function encodeServerChallengeFrame(challenge: ServerChallenge): Uint8Array {
  requireLength(challenge.challenge, SERVER_CHALLENGE_LENGTH, "server challenge");
  return concatBytes([encodeVarInt(FrameType.ServerChallenge), challenge.challenge]);
}

export function encodeServerConfirmsAuthFrame(): Uint8Array {
  return encodeVarInt(FrameType.ServerConfirmsAuth);
}

export function decodeHandshakeFrame(bytes: Uint8Array): HandshakeFrame {
  const decoded = decodeVarIntNumber(bytes);
  const payload = bytes.subarray(decoded.bytesRead);

  switch (decoded.value) {
    case FrameType.ServerChallenge:
      requireLength(payload, SERVER_CHALLENGE_LENGTH, "server challenge payload");
      return { type: "server-challenge", challenge: copyBytes(payload) };
    case FrameType.ClientAuth:
      return { type: "client-auth", auth: decodeClientAuthPayload(payload) };
    case FrameType.ServerConfirmsAuth:
      requireLength(payload, 0, "server confirms auth payload");
      return { type: "server-confirms-auth" };
    case FrameType.ServerDeniesAuth:
      return { type: "server-denies-auth", reason: decodeServerDeniesAuthReason(payload) };
    default:
      throw new RangeError(`invalid handshake frame tag ${decoded.value}`);
  }
}

function decodeClientAuthPayload(payload: Uint8Array): ClientAuth {
  if (payload.length < ENDPOINT_ID_LENGTH + 1 + SIGNATURE_LENGTH) {
    throw new RangeError("invalid client auth payload");
  }
  const endpointId = validateEndpointId(payload.subarray(0, ENDPOINT_ID_LENGTH));
  const signatureLen = decodePostcardLen(payload, ENDPOINT_ID_LENGTH);
  if (signatureLen.value !== SIGNATURE_LENGTH) {
    throw new RangeError("invalid client auth signature length");
  }
  const signatureStart = ENDPOINT_ID_LENGTH + signatureLen.bytesRead;
  const signatureEnd = signatureStart + SIGNATURE_LENGTH;
  if (payload.length !== signatureEnd) {
    throw new RangeError("invalid client auth payload length");
  }
  return {
    endpointId,
    signature: copyBytes(payload.subarray(signatureStart, signatureEnd)),
  };
}

function decodeServerDeniesAuthReason(payload: Uint8Array): string {
  const reasonLen = decodePostcardLen(payload);
  const start = reasonLen.bytesRead;
  const end = start + reasonLen.value;
  if (payload.length !== end) {
    throw new RangeError("invalid server denial payload length");
  }
  return new TextDecoder().decode(payload.subarray(start, end));
}

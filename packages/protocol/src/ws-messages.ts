// packages/protocol/src/ws-messages.ts
//
// WebSocket wire-format message types per design.md §6.2 / Requirement 12.
//
// All frames are msgpack-encoded; the discriminator field `t` selects the
// branch for both ClientToServer and ServerToClient. Serialization /
// deserialization lives in `codec.ts` (added in task 3.2).
//
// See note in envelopes.ts on enum representation: we use plain `enum` so
// the discriminator literals survive `verbatimModuleSyntax: true` while
// preserving the exact integer values mandated by design.md §6.2.

import type { CiphertextEnvelope } from './envelopes.js';

/** Client → Server message discriminator. */
export enum C2S {
  HELLO = 1, // initial auth handshake (JWT in header, this is sequence start)
  SEND_ENVELOPE = 2,
  ENVELOPE_RECEIVED = 3, // transport-level ack (got the bytes, not "delivered to user")
  PRESENCE_PING = 4,
  SUBSCRIBE_ROOM = 5,
  UNSUBSCRIBE_ROOM = 6,
}

/** Server → Client message discriminator. */
export enum S2C {
  HELLO_OK = 101,
  ENVELOPE = 102, // inbound envelope for this device
  ENVELOPE_QUEUED = 103, // server confirms persistence of an outbound envelope
  ROOM_POST = 104, // broadcast room post (public, plaintext + signature)
  ERROR = 199,
}

/** Discriminated union of every Client → Server WSS frame. */
export type ClientToServer =
  | { t: C2S.HELLO; deviceId: string; protoVersion: 1 }
  | { t: C2S.SEND_ENVELOPE; clientNonce: string; envelope: CiphertextEnvelope }
  | { t: C2S.ENVELOPE_RECEIVED; envelopeId: bigint }
  | { t: C2S.PRESENCE_PING }
  | { t: C2S.SUBSCRIBE_ROOM; slug: string }
  | { t: C2S.UNSUBSCRIBE_ROOM; slug: string };

/** Discriminated union of every Server → Client WSS frame. */
export type ServerToClient =
  | { t: S2C.HELLO_OK; serverTimeMs: number; queuedCount: number }
  | { t: S2C.ENVELOPE; envelope: CiphertextEnvelope }
  | { t: S2C.ENVELOPE_QUEUED; clientNonce: string; envelopeId: bigint; serverTimeMs: number }
  | { t: S2C.ROOM_POST; post: BroadcastPost }
  | { t: S2C.ERROR; code: ErrorCode; message: string };

/** Public broadcast room post (plaintext body + Ed25519 author signature).
 *  Carried inside `ServerToClient { t: ROOM_POST }`. */
export interface BroadcastPost {
  readonly id: bigint;
  readonly roomId: string;
  readonly authorUserId: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array; // for signature verification
  readonly body: string;
  readonly authorSignature: Uint8Array;
  readonly createdAt: number;
}

/** Error codes carried inside `ServerToClient { t: ERROR }`. */
export enum ErrorCode {
  AUTH_REQUIRED = 1,
  RATE_LIMITED = 2,
  INVALID_PAYLOAD = 3,
  RECIPIENT_UNKNOWN = 4,
  INTERNAL = 99,
}

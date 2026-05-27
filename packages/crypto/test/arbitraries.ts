// packages/crypto/test/arbitraries.ts
//
// Shared `fast-check` arbitraries (generators) for the property-based test
// suite. Per design.md §16.2 we expose:
//
//   - arbCurve25519KeyPair  — fresh X25519 keypair (real curve math)
//   - arbPlaintext(min,max) — random Uint8Array bytes
//   - arbSession            — pair of identities for an X3DH session pair
//   - arbEnvelope           — well-formed CiphertextEnvelope with arbitrary
//                             ciphertext bytes (server-visible shape)
//   - arbClientToServer     — discriminated-union ClientToServer WS frame
//   - arbServerToClient     — discriminated-union ServerToClient WS frame
//   - arbWSMessage          — union of arbClientToServer | arbServerToClient
//
// Phase-3 placeholder note: `arbSession` here returns the two keypairs
// Alice and Bob would feed into `establishSession` (task 4.2). The "pair
// of stores with completed X3DH" form referenced by design.md §16.2 lands
// in task 4.10 once `packages/crypto/src/session.ts` exists; properties
// P1, P3–P7 will then build on top of this arbitrary by running the keys
// through real X3DH. Until then this arbitrary is the input bundle.
//
// `arbEnvelope` produces a well-typed `CiphertextEnvelope` whose
// `ciphertext` is arbitrary bytes — NOT a real libsignal serialization.
// That's by design for codec / routing properties (P10–P18); the
// libsignal-generated form is constructed inside `arbSession`-driven
// properties in task 4.10+.

import * as fc from 'fast-check';
import { x25519 } from '@noble/curves/ed25519';

import {
  C2S,
  type ClientToServer,
  EnvelopeRouterType,
  type CiphertextEnvelope,
  ErrorCode,
  S2C,
  type ServerToClient,
} from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------

/** Curve25519 (X25519) keypair: a fresh 32-byte private scalar plus its
 *  derived 32-byte public point. */
export interface Curve25519KeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/**
 * Fresh X25519 keypair. Generates a uniformly random 32-byte private
 * scalar and derives the public key via `@noble/curves`.
 *
 * NB: `@noble/curves` clamps the scalar internally per RFC 7748 — we do
 * not pre-clamp here so the arbitrary covers the full input space the
 * library actually accepts.
 */
export const arbCurve25519KeyPair: fc.Arbitrary<Curve25519KeyPair> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map((priv) => ({
    privateKey: priv,
    publicKey: x25519.getPublicKey(priv),
  }));

/**
 * Arbitrary plaintext Uint8Array of length in [min, max].
 *
 * Used by P1 (E2EE round-trip text, lengths 1..16384) and P2
 * (attachments, lengths 1..25 MiB). We accept the bounds as parameters
 * so callers don't pull an entire 25 MiB sample on every iteration of a
 * smaller-scope property.
 */
export function arbPlaintext(min: number, max: number): fc.Arbitrary<Uint8Array> {
  if (!Number.isInteger(min) || !Number.isInteger(max) || min < 0 || max < min) {
    throw new RangeError(
      `arbPlaintext requires 0 <= min <= max integers, got min=${min}, max=${max}`,
    );
  }
  return fc.uint8Array({ minLength: min, maxLength: max });
}

/**
 * X3DH-shaped session input: the pair of identity keypairs Alice and Bob
 * would each generate before establishing a session.
 *
 * Phase-3 placeholder per the file header: this arbitrary becomes "two
 * SignalProtocolStores with completed X3DH" in task 4.10. Property tests
 * authored before then can already use this arbitrary by running the
 * keys through `establishSession` (added in task 4.2).
 */
export interface SessionPair {
  readonly aliceKp: Curve25519KeyPair;
  readonly bobKp: Curve25519KeyPair;
}

export const arbSession: fc.Arbitrary<SessionPair> = fc.record({
  aliceKp: arbCurve25519KeyPair,
  bobKp: arbCurve25519KeyPair,
});

// ---------------------------------------------------------------------------
// Wire-format arbitraries (server-visible)
// ---------------------------------------------------------------------------

// Bound `ciphertext` to a server-acceptable size: the WS gateway rejects
// any frame larger than 1 MiB (Requirement 12.7), and the codec/routing
// properties only need byte-level arbitrariness, not stress-size buffers.
const MAX_CIPHERTEXT_BYTES = 65536; // 64 KiB — comfortably below the 1 MiB cap

/**
 * Well-formed `CiphertextEnvelope` with arbitrary ciphertext bytes.
 *
 * Per design.md §16.2 / Requirement 12 / Requirement 21.10:
 *   - All three device IDs are UUIDs.
 *   - `type` is one of the three `EnvelopeRouterType` discriminants.
 *   - `ciphertext` is opaque bytes (1..64 KiB) — the libsignal-generated
 *     ciphertext form is produced inside `arbSession`-driven properties.
 *   - `id` and `createdAt` are server-assigned and omitted on the
 *     client→server path, so we leave them off here. (Tests that need
 *     server-shaped envelopes can `.map` to attach them.)
 */
export const arbEnvelope: fc.Arbitrary<CiphertextEnvelope> = fc.record({
  sessionId: fc.uuid(),
  senderDeviceId: fc.uuid(),
  recipientDeviceId: fc.uuid(),
  type: fc.constantFrom(
    EnvelopeRouterType.MESSAGE,
    EnvelopeRouterType.ACK,
    EnvelopeRouterType.CALL,
  ),
  ciphertext: fc.uint8Array({ minLength: 1, maxLength: MAX_CIPHERTEXT_BYTES }),
});

// ---------------------------------------------------------------------------
// WebSocket message arbitraries
// ---------------------------------------------------------------------------

/** Slug pattern accepted by `SUBSCRIBE_ROOM` / `UNSUBSCRIBE_ROOM`
 *  (design.md §6.2 / Requirement 10.2: 3..64 lowercase `[a-z0-9-]`). */
const slugArb = fc.stringMatching(/^[a-z0-9-]{3,64}$/);

/** Discriminated-union generator for `ClientToServer` WSS frames.
 *  Mirrors `packages/protocol/src/ws-messages.ts`. */
export const arbClientToServer: fc.Arbitrary<ClientToServer> = fc.oneof(
  fc.record({
    t: fc.constant(C2S.HELLO),
    deviceId: fc.uuid(),
    protoVersion: fc.constant(1 as const),
  }),
  fc.record({
    t: fc.constant(C2S.SEND_ENVELOPE),
    clientNonce: fc.string({ minLength: 1, maxLength: 64 }),
    envelope: arbEnvelope,
  }),
  fc.record({
    t: fc.constant(C2S.ENVELOPE_RECEIVED),
    envelopeId: fc.bigInt(),
  }),
  fc.record({ t: fc.constant(C2S.PRESENCE_PING) }),
  fc.record({ t: fc.constant(C2S.SUBSCRIBE_ROOM), slug: slugArb }),
  fc.record({ t: fc.constant(C2S.UNSUBSCRIBE_ROOM), slug: slugArb }),
);

/** Discriminated-union generator for `ServerToClient` WSS frames.
 *  Mirrors `packages/protocol/src/ws-messages.ts`. */
export const arbServerToClient: fc.Arbitrary<ServerToClient> = fc.oneof(
  fc.record({
    t: fc.constant(S2C.HELLO_OK),
    serverTimeMs: fc.integer({ min: 0 }),
    queuedCount: fc.integer({ min: 0, max: 10000 }),
  }),
  fc.record({
    t: fc.constant(S2C.ENVELOPE),
    envelope: arbEnvelope,
  }),
  fc.record({
    t: fc.constant(S2C.ENVELOPE_QUEUED),
    clientNonce: fc.string({ minLength: 1, maxLength: 64 }),
    envelopeId: fc.bigInt(),
    serverTimeMs: fc.integer({ min: 0 }),
  }),
  fc.record({
    t: fc.constant(S2C.ERROR),
    code: fc.constantFrom(
      ErrorCode.AUTH_REQUIRED,
      ErrorCode.RATE_LIMITED,
      ErrorCode.INVALID_PAYLOAD,
      ErrorCode.RECIPIENT_UNKNOWN,
      ErrorCode.INTERNAL,
    ),
    message: fc.string({ maxLength: 256 }),
  }),
  // Note: ROOM_POST omitted here — the BroadcastPost arbitrary depends
  // on Ed25519 signing material that lands with task 4.8 / Phase 6
  // (broadcast). It will be added as `arbRoomPost` then and unioned in
  // here. Until then arbWSMessage / arbServerToClient cover the
  // codec / error / queueing surface.
);

/** Discriminated-union generator for any WSS frame in either direction.
 *  Per design.md §16.2: `arbWSMessage` covers both `ClientToServer` and
 *  `ServerToClient`. */
export const arbWSMessage: fc.Arbitrary<ClientToServer | ServerToClient> =
  fc.oneof(arbClientToServer, arbServerToClient);

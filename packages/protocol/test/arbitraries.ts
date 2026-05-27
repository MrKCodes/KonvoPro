// packages/protocol/test/arbitraries.ts
//
// Local `fast-check` arbitraries for the `@konvo/protocol` test suite.
//
// These mirror the wire-format generators that live in
// `packages/crypto/test/arbitraries.ts` (`arbEnvelope`,
// `arbClientToServer`, `arbServerToClient`). We intentionally inline a
// copy here rather than importing across packages: the crypto package's
// test directory is not part of its publishable surface, and the
// protocol package must remain self-contained.
//
// Used by the codec round-trip property test (P10, task 3.9 — see
// `codec.property.test.ts`). Bounds match the crypto-side arbitraries
// so any divergence between the two test surfaces stays mechanical:
//   - `ciphertext` ≤ 64 KiB (well under the 1 MiB `MAX_FRAME_BYTES`)
//   - `slug` matches the room-slug regex from design.md §6.2
//     / Requirement 10.2
//   - `envelopeId` is constrained to non-negative int64 (server-
//     assigned monotonic ids; matches the `useBigInt64: true` wire
//     encoding documented in `src/codec.ts`)

import * as fc from 'fast-check';

import {
  C2S,
  type CiphertextEnvelope,
  type ClientToServer,
  EnvelopeRouterType,
  ErrorCode,
  S2C,
  type ServerToClient,
} from '../src/index.js';

// 64 KiB — comfortably below the 1 MiB `MAX_FRAME_BYTES` cap so the
// round-trip property is never gated by the size guard.
const MAX_CIPHERTEXT_BYTES = 65536;

// Non-negative int64 ceiling — server-assigned envelope ids are
// monotonic positive integers, and the wire encoding is msgpack int64
// via `useBigInt64: true` (see `src/codec.ts`).
const MAX_INT64 = 2n ** 63n - 1n;

/** Well-formed `CiphertextEnvelope` with arbitrary opaque ciphertext.
 *
 *  Server-assigned `id` and `createdAt` are omitted — they only appear on
 *  the S→C path and the codec accepts envelopes without them. */
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

/** Slug pattern accepted by `SUBSCRIBE_ROOM` / `UNSUBSCRIBE_ROOM`
 *  (design.md §6.2 / Requirement 10.2: 3..64 lowercase `[a-z0-9-]`). */
const slugArb = fc.stringMatching(/^[a-z0-9-]{3,64}$/);

/** Discriminated-union generator for `ClientToServer` WSS frames.
 *  Mirrors `src/ws-messages.ts`. */
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
    envelopeId: fc.bigInt({ min: 0n, max: MAX_INT64 }),
  }),
  fc.record({ t: fc.constant(C2S.PRESENCE_PING) }),
  fc.record({ t: fc.constant(C2S.SUBSCRIBE_ROOM), slug: slugArb }),
  fc.record({ t: fc.constant(C2S.UNSUBSCRIBE_ROOM), slug: slugArb }),
);

/** Discriminated-union generator for `ServerToClient` WSS frames.
 *  Mirrors `src/ws-messages.ts`.
 *
 *  Note: `ROOM_POST` is omitted — its `BroadcastPost` payload depends on
 *  Ed25519 signing material introduced in Phase 6 (broadcast rooms),
 *  matching the omission in `packages/crypto/test/arbitraries.ts`. */
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
    envelopeId: fc.bigInt({ min: 0n, max: MAX_INT64 }),
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
);

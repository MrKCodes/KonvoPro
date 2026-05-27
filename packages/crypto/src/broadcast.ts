// packages/crypto/src/broadcast.ts
//
// Implements task 7.1: broadcast post signing/verification, per
// design.md §8.4 and requirements.md §10.4, 10.8, 10.9.
//
// What this module owns:
//   - the canonical byte encoding of a broadcast post for signing
//     (`canonicalBroadcastMessage`),
//   - Ed25519 signing of a post with the author's identity Ed25519
//     private key (`signBroadcastPost`),
//   - non-throwing Ed25519 verification of a post against a candidate
//     author Ed25519 public key (`verifyBroadcastPost`).
//
// What this module does NOT own:
//   - persistence of posts (server-side: design.md §9 broadcast routes;
//     client-side: task 4.x roomPosts table per design.md §11),
//   - rate limiting / `createdAtMs` clock skew check (server route),
//   - rendering "verified author" / "unverified" badges (UI in
//     `apps/web/src/features/broadcast/`).
//
// Phase-1 placeholder: dual-key identity
// --------------------------------------
// Per `identity.ts` and `prekeys.ts`, the Konvo identity is currently
// represented as a parallel Curve25519 + Ed25519 keypair. The Ed25519
// sub-key is what we actually sign with here. When libsignal lands
// (task 4.x), the Ed25519 key collapses back into the single libsignal
// identity key via XEdDSA, and `signBroadcastPost` becomes a thin call
// into libsignal's signing API. The wire shape stays the same: the
// signature is 64 bytes of Ed25519 over the canonical message.
//
// Endianness note
// ---------------
// design.md §13.7 sketches a verification flow that uses big-endian
// `u64BE(createdAtMs)`. The implementation contract for task 7.1 fixes
// the canonical encoding as **little-endian** `u64-le(createdAtMs)`,
// matching the broader Konvo wire-format stance (msgpack int64s + LE
// integer fields). Sender and verifier must agree byte-for-byte on the
// canonical message; this file is the single source of truth.

import { ed25519 } from '@noble/curves/ed25519';

import { type IdentityPrivateKey } from './identity.js';

/**
 * Canonical message bytes signed/verified by `signBroadcastPost` /
 * `verifyBroadcastPost`:
 *
 *   utf8(body) || utf8(roomId) || u64-le(createdAtMs)
 *
 * The encoding is:
 *   - `body` and `roomId` UTF-8 encoded (no length prefix; the trailing
 *     8-byte `createdAtMs` is fixed-width so the boundary between
 *     `roomId` and `createdAtMs` is unambiguous given a fixed `body` and
 *     `roomId` pair),
 *   - `createdAtMs` written as an unsigned 64-bit little-endian integer
 *     using a `BigUint64Array` view of an 8-byte `ArrayBuffer`. We must
 *     use 64 bits (not 32) because JavaScript `Date.now()` exceeds
 *     2^32 ms (~49.7 days since epoch).
 *
 * This encoding is stable: calling `canonicalBroadcastMessage` with the
 * same arguments always yields byte-equal output, and the bytes match
 * what `verifyBroadcastPost` rebuilds on the recipient side.
 *
 * Requirements 10.4, 10.8, 10.9.
 */
export function canonicalBroadcastMessage(
  body: string,
  roomId: string,
  createdAtMs: number,
): Uint8Array {
  const encoder = new TextEncoder();
  const bodyBytes = encoder.encode(body);
  const roomIdBytes = encoder.encode(roomId);

  // 8-byte little-endian u64. `BigUint64Array` writes platform-native
  // endianness, but every runtime Konvo targets (Node 20, all evergreen
  // browsers) is little-endian, and we explicitly assert that via
  // `DataView.setBigUint64(..., true)` instead so the encoding is
  // independent of host endianness. Keeping the asserted-LE path makes
  // this safe to lift verbatim into a hypothetical big-endian runtime.
  const createdAtBytes = new Uint8Array(8);
  new DataView(createdAtBytes.buffer).setBigUint64(
    0,
    BigInt(createdAtMs),
    /* littleEndian */ true,
  );

  const out = new Uint8Array(
    bodyBytes.length + roomIdBytes.length + createdAtBytes.length,
  );
  out.set(bodyBytes, 0);
  out.set(roomIdBytes, bodyBytes.length);
  out.set(createdAtBytes, bodyBytes.length + roomIdBytes.length);
  return out;
}

/**
 * Sign a broadcast post with the author's identity Ed25519 private key
 * (Phase-1 sub-key; see file header).
 *
 * Returns 64 bytes of Ed25519 signature per RFC 8032 over the canonical
 * message produced by `canonicalBroadcastMessage(body, roomId, createdAtMs)`.
 *
 * The `IdentityPrivateKey.bytes()` accessor returns a fresh defensive
 * copy of the raw seed; we scrub that copy in a `finally` so it does
 * not linger in JS memory after signing returns.
 *
 * Requirement 10.4.
 */
export function signBroadcastPost(
  body: string,
  roomId: string,
  createdAtMs: number,
  identityEdPriv: IdentityPrivateKey,
): Uint8Array {
  const message = canonicalBroadcastMessage(body, roomId, createdAtMs);
  const sk = identityEdPriv.bytes();
  try {
    return ed25519.sign(message, sk);
  } finally {
    // Best-effort scrub of the transient seed copy. The
    // `IdentityPrivateKey` always returns a fresh copy so this only
    // zeros our local view, not the cached private state.
    sk.fill(0);
  }
}

/**
 * Verify a broadcast post signature against a candidate author Ed25519
 * public key.
 *
 * Returns `true` iff `signature` is a valid Ed25519 signature of
 * `canonicalBroadcastMessage(body, roomId, createdAtMs)` by
 * `authorIdentityEdPub`.
 *
 * Returns `false` (never throws) on any failure mode:
 *   - malformed/short signature,
 *   - malformed/short public key,
 *   - signature does not verify,
 *   - any underlying noble-curves throw (e.g. invalid point encoding).
 *
 * Requirements 10.8, 10.9.
 */
export function verifyBroadcastPost(
  body: string,
  roomId: string,
  createdAtMs: number,
  signature: Uint8Array,
  authorIdentityEdPub: Uint8Array,
): boolean {
  try {
    const message = canonicalBroadcastMessage(body, roomId, createdAtMs);
    return ed25519.verify(signature, message, authorIdentityEdPub);
  } catch {
    // requirement 10.9: any tampering / malformed input → false, not throw.
    return false;
  }
}

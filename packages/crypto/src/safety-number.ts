// packages/crypto/src/safety-number.ts
//
// Implements task 4.8 (data-layer half): Safety_Number computation per
// design.md §8.1 / §13.4, requirements 8.3, 8.4, 8.5, 8.6.
//
// What this module owns:
//   - the canonical 5200-iteration SHA-512 fingerprint of an `(identityPub,
//     userId)` pair (`fingerprintFor`),
//   - the 30-byte → 30-decimal-digit encoder (`encodeDigits`) that yields
//     6 groups of 5 digits per fingerprint (12 groups of 5 across both
//     parties = 60 digits total),
//   - the symmetric `computeSafetyNumber` entry point that produces the
//     same digits + QR payload regardless of which side calls it
//     (Signal-style canonical ordering of the two parties' user IDs).
//
// What this module does NOT own:
//   - persistence of TOFU bookkeeping (`remoteIdentities` table — see
//     `apps/web/src/db/repositories/remote-identities.ts`),
//   - re-verify banner state / accept/reject UI (UI tasks land later in
//     phase 4 follow-ups),
//   - QR-code rendering. The exported `qrPayload` is the raw 60-byte
//     concatenation of the two parties' fingerprints; the UI is
//     responsible for base64-encoding and QR rendering per requirement
//     8.6 / task 9.5.
//
// Algorithm — design.md §13.4 verbatim
// ------------------------------------
// 1. Canonical ordering: the smaller `userId` (string compare) is treated
//    as party A, the larger as party B. This makes the computation
//    symmetric: swapping the input pairs produces the same digit string.
//    Requirement 8.4 (P8: determinism + symmetry).
//
// 2. For each side, derive a 30-byte fingerprint by iterating SHA-512
//    5200 times:
//        state₀ = utf8(userId) || identityPub
//        stateₖ = SHA-512(stateₖ₋₁ || identityPub)        for k in 1..5200
//        fp     = stateₖ.slice(0, 30)                     // 30 bytes
//
//    The iteration count and "always re-mix `identityPub`" structure
//    match Signal's `NumericFingerprintGenerator`. The 5200 iterations
//    serve as a poor-man's KDF: any single-bit change in either
//    `identityPub` propagates through every iteration. Requirement 8.5
//    (P9: single-bit sensitivity).
//
// 3. Each 30-byte fingerprint encodes to 30 decimal digits via 6 groups
//    of 5 bytes each: `readBigUInt40BE(chunk) % 100000` zero-padded to
//    5 digits. Concatenating both sides yields exactly 60 digits.
//
// 4. The returned `digits` is grouped 12 × 5 separated by single ASCII
//    spaces (requirement 8.3 / 15.2: "60-digit ... formatted in 12
//    groups of 5"). The returned `qrPayload` is the raw 60-byte
//    concatenation of the two fingerprints in canonical order;
//    requirement 8.6 specifies a base64 QR payload, but this module
//    keeps the bytes untouched so the UI owns the choice of base64
//    flavor (standard vs. URL-safe).
//
// Cost note
// ---------
// 5200 iterations of SHA-512 over a ~96-byte buffer runs in ~5 ms in
// Node 20 / `@noble/hashes`. We compute two fingerprints per call =
// ~10 ms per `computeSafetyNumber`. Property tests at the default 100
// iterations (see `packages/crypto/test/setup.ts`) therefore add ~1 s
// to the suite — well within budget.

import { sha512 } from '@noble/hashes/sha2';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Signal's numeric fingerprint iteration count. 5200 SHA-512 rounds per
 * fingerprint side. Hard-coded — changing this value invalidates every
 * previously-rendered safety number, and requirement 8.3 explicitly
 * binds the number.
 */
const SAFETY_NUMBER_ITERATIONS = 5200;

/** Bytes retained from the final SHA-512 state per side. 30 bytes → 30
 * decimal digits via the 5-byte / 5-digit chunking scheme. */
const FINGERPRINT_BYTES_PER_SIDE = 30;

/** Identity public keys are 32-byte Curve25519 points. Validated up
 * front so a malformed bundle can't silently produce a degenerate
 * fingerprint. */
const IDENTITY_PUB_LENGTH = 32;

/** Number of 5-byte chunks per fingerprint (30 / 5 = 6). Each chunk
 * yields exactly 5 decimal digits. */
const CHUNKS_PER_FINGERPRINT = 6;

/** Decimal digits per chunk (1e5 = 100000 modulus). */
const DIGITS_PER_CHUNK = 5;

/** Total digits in a complete safety number: 6 chunks × 5 digits × 2
 * sides = 60. Used in invariant assertions and group-by-5 formatting. */
const TOTAL_DIGITS = 60;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Result of {@link computeSafetyNumber}.
 *
 * - `digits`: 60 decimal digits formatted as 12 groups of 5 separated
 *   by single ASCII spaces (e.g. `"12345 67890 ..."`). Stable across
 *   calls with the same inputs and symmetric across the two parties.
 *   Requirements 8.3, 8.4.
 * - `qrPayload`: 60 raw bytes (`fpA || fpB` in canonical order). The UI
 *   base64-encodes this for QR rendering per requirement 8.6.
 */
export interface SafetyNumber {
  readonly digits: string;
  readonly qrPayload: Uint8Array;
}

/**
 * Compute the symmetric Safety_Number between two device identities.
 *
 * Inputs:
 *   - `localIdentityPub` / `remoteIdentityPub`: 32-byte Curve25519
 *     identity public keys. The function does NOT see private bytes —
 *     safety numbers are derived solely from public material.
 *   - `localUserId` / `remoteUserId`: stable user identifiers (UUID
 *     strings per design.md §8.1). Used both as canonicalization key
 *     and as fingerprint seed material so that two users sharing an
 *     identity public key (theoretically impossible, but defended
 *     against here) still produce distinct safety numbers.
 *
 * Postconditions per design.md §13.4 / requirement 8:
 *   - The result is deterministic: same inputs → same `digits` and
 *     byte-equal `qrPayload`.
 *   - The result is symmetric: swapping (`localIdentityPub`,
 *     `localUserId`) with (`remoteIdentityPub`, `remoteUserId`)
 *     produces identical output. Requirement 8.4 (P8).
 *   - The result is sensitive: any single-bit mutation of either
 *     `identityPub` (or any change to either `userId`) yields a
 *     different `digits`. Requirement 8.5 (P9).
 *
 * Async signature is preserved from design.md even though `@noble/
 * hashes`' SHA-512 is synchronous, so the public contract continues to
 * match the §8.1 declaration (and a future swap to WebCrypto's
 * `crypto.subtle.digest` — also async — is a body-only change).
 */
export async function computeSafetyNumber(
  localIdentityPub: Uint8Array,
  localUserId: string,
  remoteIdentityPub: Uint8Array,
  remoteUserId: string,
): Promise<SafetyNumber> {
  if (localIdentityPub.length !== IDENTITY_PUB_LENGTH) {
    throw new Error(
      `localIdentityPub must be ${IDENTITY_PUB_LENGTH} bytes, got ${localIdentityPub.length}`,
    );
  }
  if (remoteIdentityPub.length !== IDENTITY_PUB_LENGTH) {
    throw new Error(
      `remoteIdentityPub must be ${IDENTITY_PUB_LENGTH} bytes, got ${remoteIdentityPub.length}`,
    );
  }

  // Canonical ordering — design.md §13.4. The lexicographically smaller
  // `userId` becomes party A. JavaScript's `<` on strings is a
  // lexicographic comparison over UTF-16 code units which is stable
  // and matches what both peers will compute given identical inputs.
  //
  // Tie note: if `localUserId === remoteUserId` (a self-conversation),
  // the branch is a no-op — both sides produce the same fingerprint
  // already. We don't reject the case; safety numbers between a user
  // and themselves are a legitimate (if unusual) computation.
  const [aId, aPub, bId, bPub] =
    localUserId < remoteUserId
      ? [localUserId, localIdentityPub, remoteUserId, remoteIdentityPub]
      : [remoteUserId, remoteIdentityPub, localUserId, localIdentityPub];

  const aFp = fingerprintFor(aId, aPub);
  const bFp = fingerprintFor(bId, bPub);

  // 30 + 30 = 60 decimal digits. We assert this to catch accidental
  // breakage of the chunking constants.
  const rawDigits = encodeDigits(aFp) + encodeDigits(bFp);
  if (rawDigits.length !== TOTAL_DIGITS) {
    throw new Error(
      `safety-number invariant: expected ${TOTAL_DIGITS} digits, got ${rawDigits.length}`,
    );
  }

  return {
    digits: groupBy5(rawDigits),
    qrPayload: concatBytes(aFp, bFp),
  };
}

// ---------------------------------------------------------------------------
// Internal helpers — exported for testability of property tests P8 / P9
// without making them part of the package's public surface. The leading
// underscore is the conventional "package-internal" marker.
// ---------------------------------------------------------------------------

/**
 * Iterated SHA-512 fingerprint per design.md §13.4.
 *
 * Loop invariant (after iteration k, k ∈ [1, 5200]):
 *   `state` is exactly `SHA-512^k(utf8(userId) || identityPub, identityPub)`,
 * where `SHA-512^k(initial, mix)` is shorthand for "apply
 * `state ← SHA-512(state || mix)` k times starting from `initial`".
 *
 * After 5200 iterations, the first 30 bytes form the per-side
 * fingerprint. The trailing 34 bytes are discarded — keeping only 30
 * bytes (240 bits) is enough collision resistance for the safety-
 * number use case (the user is comparing 60 visible digits, not
 * defending against birthday attacks on the whole hash).
 */
function fingerprintFor(userId: string, identityPub: Uint8Array): Uint8Array {
  const userIdBytes = new TextEncoder().encode(userId);

  // state₀ = utf8(userId) || identityPub
  let state = concatBytes(userIdBytes, identityPub);

  // stateₖ = SHA-512(stateₖ₋₁ || identityPub) for k in 1..5200
  for (let i = 0; i < SAFETY_NUMBER_ITERATIONS; i += 1) {
    state = sha512(concatBytes(state, identityPub));
  }

  // Keep only the leading 30 bytes — design.md §13.4.
  return state.slice(0, FINGERPRINT_BYTES_PER_SIDE);
}

/**
 * Big-endian 40-bit unsigned read of a 5-byte chunk.
 *
 * Returns a `bigint` because `2^40 > Number.MAX_SAFE_INTEGER` is false
 * (`2^40 = 1.099e12 < 2^53`), but using `bigint` makes the modulus
 * arithmetic in `encodeDigits` explicit and matches design.md §13.4's
 * `readBigUInt40BE` reference name.
 */
function readBigUInt40BE(chunk: Uint8Array): bigint {
  if (chunk.length !== 5) {
    // Defensive: `encodeDigits` always slices a 5-byte view, but a
    // misuse from a future caller would silently corrupt the digits.
    throw new Error(
      `readBigUInt40BE expects exactly 5 bytes, got ${chunk.length}`,
    );
  }
  let v = 0n;
  for (let i = 0; i < chunk.length; i += 1) {
    v = (v << 8n) | BigInt(chunk[i]!);
  }
  return v;
}

/**
 * Encode a 30-byte fingerprint as 30 decimal digits (no spaces).
 *
 * Six 5-byte chunks; each chunk reads as a big-endian u40, takes
 * mod 100000, and zero-pads to 5 digits. Output length is exactly
 * `CHUNKS_PER_FINGERPRINT * DIGITS_PER_CHUNK = 30`.
 *
 * Modulo 10^5 introduces a small bias (2^40 / 10^5 ≈ 10995116 with a
 * remainder of 27776) but that bias is well below user-visible
 * indistinguishability thresholds (the next-digit probability differs
 * by ≈ 2.5×10⁻⁶). Signal's reference implementation makes the same
 * tradeoff.
 */
function encodeDigits(fp: Uint8Array): string {
  if (fp.length !== FINGERPRINT_BYTES_PER_SIDE) {
    throw new Error(
      `encodeDigits expects exactly ${FINGERPRINT_BYTES_PER_SIDE} bytes, got ${fp.length}`,
    );
  }
  let out = '';
  for (let i = 0; i < CHUNKS_PER_FINGERPRINT; i += 1) {
    const chunk = fp.subarray(i * 5, i * 5 + 5);
    const v = readBigUInt40BE(chunk) % 100000n;
    out += v.toString().padStart(DIGITS_PER_CHUNK, '0');
  }
  return out;
}

/**
 * Format a 60-digit string as 12 groups of 5 separated by single ASCII
 * spaces. Requirements 8.3, 15.2.
 */
function groupBy5(digits: string): string {
  if (digits.length !== TOTAL_DIGITS) {
    throw new Error(
      `groupBy5 expects exactly ${TOTAL_DIGITS} digits, got ${digits.length}`,
    );
  }
  const groups: string[] = [];
  for (let i = 0; i < digits.length; i += DIGITS_PER_CHUNK) {
    groups.push(digits.slice(i, i + DIGITS_PER_CHUNK));
  }
  return groups.join(' ');
}

/**
 * Concatenate two byte buffers into a fresh `Uint8Array`. Inlined
 * here (rather than imported from `session.ts`) to keep this module
 * self-contained — `concatBytes` is a one-liner and a future merge
 * with libsignal will likely drop both copies.
 */
function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

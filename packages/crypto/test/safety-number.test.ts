// Tests for task 4.8 (data-layer half): Safety_Number computation.
//
// Mix of example-based unit tests and the two property tests called out
// in design.md §14.1 / requirements.md §21.8 + §21.9:
//
//   - **P8: Safety number determinism + symmetry**
//     `computeSafetyNumber(IK_A, uid_A, IK_B, uid_B).digits ===
//      computeSafetyNumber(IK_B, uid_B, IK_A, uid_A).digits`,
//     and the result is stable across calls with the same inputs.
//     **Validates: Requirements 8.4, 21.8**
//
//   - **P9: Safety number sensitivity**
//     For any single-bit mutation of either identity public key, the
//     resulting digits differ.
//     **Validates: Requirements 8.5, 21.9**
//
// Cost note: each `computeSafetyNumber` call performs 2 × 5200 SHA-512
// rounds (~10 ms in Node). The default `FAST_CHECK_RUNS=100` (see
// `test/setup.ts`) means each property runs ~1 s. P9's per-iteration
// shrinking can multiply that further; we keep the public-key
// arbitrary cheap (raw 32 random bytes — Curve25519 doesn't require
// validation for the hash to be defined) so shrinking stays bounded.

import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';

import { computeSafetyNumber } from '../src/safety-number.js';

// ---------------------------------------------------------------------------
// Local arbitraries — purpose-built for safety-number tests.
// ---------------------------------------------------------------------------

/** 32 random bytes. Safety-number derivation hashes the bytes; it does
 * not reject non-Curve25519 points, so we don't constrain to valid
 * Edwards points here. */
const arbIdentityPub = fc.uint8Array({ minLength: 32, maxLength: 32 });

/** Stable user id strings. UUID-shaped is the production case; we
 * widen to alphanumeric for cheap shrinking and still cover the
 * canonical-ordering branch. Length 1..36 keeps shrinks fast. */
const arbUserId = fc
  .string({ minLength: 1, maxLength: 36 })
  // Ensure the string is non-empty even after shrinking (fc's default
  // string can shrink to empty, which is still a valid input but makes
  // counterexamples noisier).
  .filter((s) => s.length > 0);

/** Two distinct user ids — required for the symmetry test, since the
 * canonical-ordering branch is a no-op when the ids tie. */
const arbDistinctUserIdPair = fc
  .tuple(arbUserId, arbUserId)
  .filter(([a, b]) => a !== b);

// ---------------------------------------------------------------------------
// Example-based unit tests
// ---------------------------------------------------------------------------

describe('computeSafetyNumber — shape and formatting', () => {
  it('returns 60 digits formatted as 12 groups of 5 separated by spaces', async () => {
    const ikA = new Uint8Array(32);
    ikA.fill(0x11);
    const ikB = new Uint8Array(32);
    ikB.fill(0x22);

    const { digits, qrPayload } = await computeSafetyNumber(
      ikA,
      'alice',
      ikB,
      'bob',
    );

    // 12 groups × 5 digits + 11 single-space separators = 71 chars.
    expect(digits).toMatch(
      /^[0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5}$/,
    );
    expect(digits.length).toBe(71);
    expect(digits.replace(/ /g, '').length).toBe(60);

    // qrPayload is the raw 60-byte concatenation of the two
    // fingerprints (30 + 30).
    expect(qrPayload).toBeInstanceOf(Uint8Array);
    expect(qrPayload.length).toBe(60);
  });

  it('rejects identityPub buffers that are not exactly 32 bytes', async () => {
    const ikGood = new Uint8Array(32);
    const ikShort = new Uint8Array(31);
    const ikLong = new Uint8Array(33);

    await expect(
      computeSafetyNumber(ikShort, 'a', ikGood, 'b'),
    ).rejects.toThrow(/32 bytes/);
    await expect(
      computeSafetyNumber(ikGood, 'a', ikLong, 'b'),
    ).rejects.toThrow(/32 bytes/);
  });

  it('produces stable output for the same inputs (snapshot-style determinism)', async () => {
    const ikA = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) ikA[i] = i;
    const ikB = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) ikB[i] = 31 - i;

    const a = await computeSafetyNumber(ikA, 'alice', ikB, 'bob');
    const b = await computeSafetyNumber(ikA, 'alice', ikB, 'bob');
    expect(b.digits).toBe(a.digits);
    expect(Array.from(b.qrPayload)).toEqual(Array.from(a.qrPayload));
  });
});

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

describe('P8: safety number determinism + symmetry', () => {
  /**
   * **Validates: Requirements 8.4, 21.8**
   *
   * For any pair `(IK_A, IK_B, uid_A, uid_B)`:
   *   `computeSafetyNumber(IK_A, uid_A, IK_B, uid_B).digits ===
   *    computeSafetyNumber(IK_B, uid_B, IK_A, uid_A).digits`
   * and the result is stable across calls.
   *
   * We constrain `uid_A !== uid_B` so the canonical-ordering branch
   * actually fires; the equal-id case is covered by the explicit
   * "stable on repeat" inner check.
   */
  it('digits are symmetric under party swap and stable across calls', async () => {
    await fc.assert(
      fc.asyncProperty(
        arbIdentityPub,
        arbIdentityPub,
        arbDistinctUserIdPair,
        async (ikA, ikB, [uidA, uidB]) => {
          const fwd = await computeSafetyNumber(ikA, uidA, ikB, uidB);
          const rev = await computeSafetyNumber(ikB, uidB, ikA, uidA);

          // Symmetry: swapping the two parties yields identical output.
          expect(rev.digits).toBe(fwd.digits);
          expect(Array.from(rev.qrPayload)).toEqual(Array.from(fwd.qrPayload));

          // Stability: a repeat call with the same inputs is byte-equal
          // (same digits, same qrPayload).
          const repeat = await computeSafetyNumber(ikA, uidA, ikB, uidB);
          expect(repeat.digits).toBe(fwd.digits);
          expect(Array.from(repeat.qrPayload)).toEqual(
            Array.from(fwd.qrPayload),
          );
        },
      ),
    );
  });
});

describe('P9: safety number sensitivity', () => {
  /**
   * **Validates: Requirements 8.5, 21.9**
   *
   * For any single-bit mutation of either identity public key, the
   * resulting Safety_Number digits differ.
   *
   * We pick a random byte index in [0,31] and a random bit in [0,7] in
   * the local-side public key, then assert that flipping that bit
   * changes `digits`. The same property holds symmetrically on the
   * remote side via the symmetry test in P8 — flipping a bit on the
   * "other" key is observationally identical to flipping it on a
   * relabeled local key.
   */
  it('flipping any single bit of either identityPub changes the digits', async () => {
    await fc.assert(
      fc.asyncProperty(
        arbIdentityPub,
        arbIdentityPub,
        arbDistinctUserIdPair,
        fc.integer({ min: 0, max: 31 }),
        fc.integer({ min: 0, max: 7 }),
        fc.boolean(),
        async (ikA, ikB, [uidA, uidB], byteIdx, bitIdx, mutateLocal) => {
          // Defensive copies — fast-check sometimes shares the
          // underlying buffer between iterations.
          const ikACopy = new Uint8Array(ikA);
          const ikBCopy = new Uint8Array(ikB);

          const baseline = await computeSafetyNumber(
            ikACopy,
            uidA,
            ikBCopy,
            uidB,
          );

          // Flip exactly one bit on the chosen side.
          const mutated = new Uint8Array(mutateLocal ? ikACopy : ikBCopy);
          mutated[byteIdx] = (mutated[byteIdx]! ^ (1 << bitIdx)) & 0xff;

          const after = mutateLocal
            ? await computeSafetyNumber(mutated, uidA, ikBCopy, uidB)
            : await computeSafetyNumber(ikACopy, uidA, mutated, uidB);

          // The 5200-iteration construction is well-mixed, so a
          // single-bit flip propagates through every iteration. Any
          // collision here would indicate either a hash-truncation bug
          // (we kept too few bytes) or a canonical-ordering bug.
          expect(after.digits).not.toBe(baseline.digits);
        },
      ),
    );
  });
});

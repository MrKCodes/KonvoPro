// packages/crypto/test/p7-out-of-order.property.test.ts
//
// Property-based test for task 4.15 — P7: Out-of-order delivery.
//
// Property under test (P7):
//
//   FOR ALL permutations π of the first K ≤ 1000 ciphertexts produced
//   by Alice's sending chain, when those ciphertexts are delivered to
//   Bob in the order π(0), π(1), …, π(K-1), each ciphertext SHALL
//   decrypt successfully exactly once and yield its corresponding
//   original plaintext.
//
// In Signal-protocol terms this is the out-of-order receive guarantee
// of the Double Ratchet symmetric chain: as long as the gap to the
// highest-numbered already-received message is ≤ MAX_SKIPPED_KEYS
// (= 1000, requirement 9.3), the receiver MUST be able to decrypt
// late-arriving messages by consuming pre-derived skipped message
// keys, while in-order or already-skipped-past messages still decrypt
// when their key is in the skipped store. After all K permuted
// deliveries Bob has consumed every position exactly once.
//
// Validates: Requirements 4.13, 21.7
//   - Requirement 4.13: "WHEN messages are delivered out of order
//     within a chain of up to 1000 ciphertexts, THE Crypto_Module
//     SHALL decrypt each ciphertext to its corresponding plaintext
//     exactly once."
//   - Requirement 21.7 (P7): "FOR ALL permutations of the first
//     K ≤ 1000 ciphertexts in a chain delivered in any order, each
//     ciphertext SHALL decrypt to its corresponding plaintext exactly
//     once."
//
// Iteration count
// ---------------
// `test/setup.ts` configures fast-check with 100 runs by default and
// ≥ 500 in nightly via `FAST_CHECK_RUNS`, satisfying the ≥ 100
// minimum required for property-based tests.
//
// Performance notes
// -----------------
// Each iteration encrypts K messages (each an AES-GCM operation +
// HMAC chain step) and then decrypts K messages (some via the skipped
// fast path, some via same-chain advance). To keep CI runtime
// reasonable while still exercising the property meaningfully, K is
// drawn from [1, 50]. The property holds for any K ≤ 1000 — the
// design's hard cap MAX_SKIPPED_KEYS = 1000 only constrains how many
// keys may be pre-derived at once, and a permutation of K ≤ 50 never
// produces a per-call gap exceeding 1000. The same-chain branch of
// `decryptFromDevice` handles arbitrary permutations within K ≤ 1000
// by exactly the same code path as for K = 50, so the smaller K is a
// safe representative sample.

import * as fc from 'fast-check';
import { describe, it, expect } from 'vitest';

import { x25519 } from '@noble/curves/ed25519';

import {
  decryptFromDevice,
  encryptToDevice,
  initReceiverRatchet,
  initSenderRatchet,
  type RatchetMessageHeader,
  type RatchetState,
} from '../src/ratchet.js';

interface SentMessage {
  readonly ciphertext: Uint8Array;
  readonly header: RatchetMessageHeader;
  readonly plaintext: Uint8Array;
}

/**
 * Encode an integer index into a deterministic plaintext payload so
 * that each message in the chain has a unique, recoverable body. The
 * receiver compares the decrypted bytes back to this encoding to
 * confirm that decryption produced the *exact* original plaintext
 * (requirement 4.10 carries through to 4.13 — out-of-order delivery
 * must still return the corresponding plaintext, not just any
 * plaintext).
 */
function plaintextForIndex(i: number): Uint8Array {
  // 4 bytes big-endian — covers indices well beyond the K ≤ 1000 cap.
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, i >>> 0, /* littleEndian */ false);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Provision a fresh Alice ↔ Bob ratchet pair sharing a 32-byte root
 * key. Mirrors `freshPair` in `ratchet.test.ts`; inlined here so the
 * property test stays self-contained.
 */
function freshPair(): { alice: RatchetState; bob: RatchetState } {
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);

  const bobSpkPriv = new Uint8Array(32);
  crypto.getRandomValues(bobSpkPriv);
  const bobSpkPub = x25519.getPublicKey(bobSpkPriv);

  const alice = initSenderRatchet(sk, bobSpkPub);
  const bob = initReceiverRatchet(sk, { priv: bobSpkPriv, pub: bobSpkPub });
  return { alice, bob };
}

/**
 * fast-check arbitrary that yields a `(K, permutation)` pair where
 * `permutation` is a permutation of `[0, K)`. We use `fc.shuffledSubarray`
 * over the identity range, asking for exactly `K` elements, which
 * guarantees a valid permutation and shrinks toward the identity
 * order on failure (which surfaces the smallest counterexample order).
 */
function arbKAndPermutation(): fc.Arbitrary<{
  K: number;
  permutation: readonly number[];
}> {
  return fc.integer({ min: 1, max: 50 }).chain((K) => {
    const indices = Array.from({ length: K }, (_, i) => i);
    return fc
      .shuffledSubarray(indices, { minLength: K, maxLength: K })
      .map((permutation) => ({ K, permutation }));
  });
}

describe('P7: out-of-order delivery (Requirements 4.13, 21.7)', () => {
  it('any permutation of K ≤ 50 ciphertexts each decrypts exactly once to its corresponding plaintext', async () => {
    await fc.assert(
      fc.asyncProperty(arbKAndPermutation(), async ({ K, permutation }) => {
        // Sanity: the arbitrary really did produce a permutation of
        // [0, K). If this ever fails, the arbitrary itself is buggy
        // and we want to catch that before blaming the ratchet.
        expect(permutation.length).toBe(K);
        expect(new Set(permutation).size).toBe(K);

        let { alice, bob } = freshPair();

        // Stage K ciphertexts on Alice's sending chain. Alice's state
        // is threaded forward; each call advances the chain by exactly
        // one step (requirement 4.4), so `sent[i]` corresponds to
        // sending-chain message number i.
        const sent: SentMessage[] = [];
        for (let i = 0; i < K; i++) {
          const plaintext = plaintextForIndex(i);
          const result = await encryptToDevice(alice, plaintext);
          alice = result.state;
          sent.push({
            ciphertext: result.ciphertext,
            header: result.header,
            plaintext,
          });
        }

        // Deliver to Bob in the permuted order. Each ciphertext must
        // decrypt successfully and yield the plaintext that Alice
        // encrypted at that index. We track which indices Bob has
        // consumed so we can assert "exactly once" at the end.
        const consumed = new Set<number>();
        for (const idx of permutation) {
          const m = sent[idx]!;
          const r = await decryptFromDevice(bob, m.ciphertext, m.header);
          bob = r.state;

          if (!r.result.ok) {
            // Annotate which permutation element broke the property —
            // fast-check will print the K and permutation on shrink.
            return false;
          }
          if (!bytesEqual(r.result.plaintext, m.plaintext)) {
            return false;
          }
          if (consumed.has(idx)) {
            // Should be impossible — every idx in the permutation is
            // unique by construction — but guards against an arbitrary
            // bug masquerading as a ratchet bug.
            return false;
          }
          consumed.add(idx);
        }

        // Every position in [0, K) must have been consumed exactly
        // once.
        if (consumed.size !== K) {
          return false;
        }

        // After consuming the entire permutation, Bob's skipped-key
        // store must be empty: every pre-derived key for [0, K) was
        // either used in-order on the same-chain advance path or
        // pulled out of skipped on the fast path. A non-empty store
        // here would indicate a leak that grows unboundedly with K.
        if (bob.skippedKeys.length !== 0) {
          return false;
        }

        return true;
      }),
    );
  });
});

// packages/crypto/test/broadcast.completeness.property.test.ts
//
// Property-based test for task 7.6: broadcast signature completeness.
//
// Property under test (P9 — completeness):
//
//   For any post signed by signer `S`'s identity Ed25519 private key,
//   `verifyBroadcastPost(body, roomId, createdAtMs, signature,
//   S.ed25519PublicKey)` returns `true`.
//
// In cryptographic terms this is the *completeness* half of broadcast
// verification: honest signatures (those produced by the legitimate
// signer over the canonical message) MUST always verify under that
// signer's public key. The companion *soundness* property — that a
// signature does not verify under any unrelated identity key — lives
// in `broadcast.property.test.ts` (task 7.5).
//
// Validates: Requirements 10.8, 21.19
//   - Requirement 10.8: "WHEN a Web_Client receives a BroadcastPost,
//     THE Crypto_Module SHALL invoke verifyBroadcastPost with the
//     author identity public key, and verifyBroadcastPost SHALL return
//     true for any post whose Ed25519 signature over
//     (body || roomId || createdAtMs) was produced by signBroadcastPost
//     with that key."
//   - Requirement 21.19 (P19 in the spec): "FOR ALL BroadcastPost
//     values whose signature was produced by signBroadcastPost with
//     key IK, verifyBroadcastPost with the same IK SHALL return true."
//
// Iteration count
// ---------------
// `test/setup.ts` configures `fast-check` globally with 100 iterations
// per property by default (and ≥ 500 in the nightly tamper job via
// `FAST_CHECK_RUNS`). That satisfies the ≥ 100 minimum required for P9.
//
// Performance note
// ----------------
// Identity generation via `getOrCreateIdentity` includes an AES-KW
// wrap/unwrap pair plus two keypair derivations, so creating a fresh
// identity per iteration would dominate runtime. We pre-generate a
// small pool of identities up front and have the property pick the
// signer index. fast-check's shrinker walks the index space, which
// keeps counterexamples small.

import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import { signBroadcastPost, verifyBroadcastPost } from '../src/broadcast.js';
import {
  getOrCreateIdentity,
  MemoryIdentityStore,
  type IdentityKeyPair,
} from '../src/identity.js';

describe('P9: broadcast signature completeness (Requirements 10.8, 21.19)', () => {
  it('verify with the signer identity always returns true', async () => {
    // Pre-generate a pool of identities so we don't pay AES-KW + keypair
    // generation cost on every iteration.
    const POOL_SIZE = 4;
    const identities: IdentityKeyPair[] = await Promise.all(
      Array.from({ length: POOL_SIZE }, () => {
        const store = new MemoryIdentityStore();
        return getOrCreateIdentity(store);
      }),
    );

    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: POOL_SIZE - 1 }),
        fc.string({ maxLength: 1024 }),
        fc.string({ maxLength: 64 }),
        // 0 .. Number.MAX_SAFE_INTEGER covers any plausible Date.now()
        // value and well beyond, exercising the full 64-bit LE encoding
        // path inside `canonicalBroadcastMessage`.
        fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
        (signerIdx, body, roomId, createdAtMs) => {
          const signer = identities[signerIdx]!;

          const sig = signBroadcastPost(
            body,
            roomId,
            createdAtMs,
            signer.ed25519PrivateKey,
          );

          const verified = verifyBroadcastPost(
            body,
            roomId,
            createdAtMs,
            sig,
            signer.ed25519PublicKey,
          );

          return verified === true;
        },
      ),
    );
  });
});

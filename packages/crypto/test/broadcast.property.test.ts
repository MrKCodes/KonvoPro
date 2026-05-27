// packages/crypto/test/broadcast.property.test.ts
//
// Property-based tests for task 7.5: broadcast signature soundness.
//
// Property under test (orchestrator-specified P8 wording):
//
//   For any post `{body, roomId, createdAtMs, signature}` and any
//   candidate verification public key `K`, if
//   `verifyBroadcastPost(body, roomId, createdAtMs, signature, K)`
//   returns `true`, then `K` matches the signer's identity Ed25519
//   public key with overwhelming probability.
//
// Equivalently, the soundness direction we exercise here:
//
//   For any post signed by signer `S` with private key `IK_S`, calling
//   `verifyBroadcastPost(..., signer_signature, K_other)` for any
//   candidate public key `K_other` distinct from `S.ed25519PublicKey`
//   MUST return `false`.
//
// This is the cryptographic-soundness half of broadcast verification:
// an attacker cannot make a forged-attribution signature verify under
// an unrelated identity. The companion round-trip ("verify with the
// same identity returns true") is exercised by the example tests in
// `broadcast.test.ts`.
//
// Validates: Requirements 10.8, 21.19
//   - Requirement 10.8 / requirements.md §21.19 (P19 in the spec):
//     `verifyBroadcastPost` is sound with respect to the signer's
//     identity key — verification only passes for the actual signer.
//
// Iteration count
// ---------------
// `test/setup.ts` configures `fast-check` globally with 100 iterations
// per property by default (and ≥ 500 in the nightly tamper job via
// `FAST_CHECK_RUNS`). That satisfies the ≥ 100 minimum for P8.
//
// Performance note
// ----------------
// Ed25519 keypair generation via `getOrCreateIdentity` includes an
// AES-KW wrap/unwrap pair, so generating a fresh identity per iteration
// would dominate runtime. We pre-generate a small pool of identities up
// front and have the property pick signer / verifier indices into the
// pool. fast-check's shrinker walks the index space, which keeps
// counterexamples small.

import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import { signBroadcastPost, verifyBroadcastPost } from '../src/broadcast.js';
import {
  getOrCreateIdentity,
  MemoryIdentityStore,
  type IdentityKeyPair,
} from '../src/identity.js';

describe('P8: broadcast signature soundness (Requirements 10.8, 21.19)', () => {
  it('verify with a different identity public key returns false', async () => {
    // Pre-generate a pool of identities so we don't pay AES-KW + Ed25519
    // keypair generation cost on every iteration.
    const POOL_SIZE = 4;
    const identities: IdentityKeyPair[] = await Promise.all(
      Array.from({ length: POOL_SIZE }, () => {
        const store = new MemoryIdentityStore();
        return getOrCreateIdentity(store);
      }),
    );

    await fc.assert(
      fc.property(
        fc.integer({ min: 0, max: POOL_SIZE - 1 }),
        fc.integer({ min: 0, max: POOL_SIZE - 1 }),
        fc.string({ maxLength: 1024 }),
        fc.string({ maxLength: 64 }),
        // 0 .. Number.MAX_SAFE_INTEGER covers any plausible Date.now()
        // value and well beyond, exercising the full 64-bit LE encoding
        // path inside `canonicalBroadcastMessage`.
        fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
        (signerIdx, verifierIdx, body, roomId, createdAtMs) => {
          // Trivial collision: when signer === verifier the property
          // would be vacuously violated (the post verifies under its
          // own key, which is the round-trip case from
          // `broadcast.test.ts`, not the soundness claim). Skip those
          // iterations rather than special-casing them.
          fc.pre(signerIdx !== verifierIdx);

          const signer = identities[signerIdx]!;
          const verifier = identities[verifierIdx]!;

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
            verifier.ed25519PublicKey,
          );

          return verified === false;
        },
      ),
    );
  });
});

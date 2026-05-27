// packages/crypto/test/p6-idempotent-decryption.property.test.ts
//
// Property-based test for task 4.14: P6 — idempotent decryption.
//
// Property under test (orchestrator-specified P6 wording):
//
//   For all ciphertexts `c`, repeating `decryptFromDevice(c)` up to 100
//   times succeeds exactly once and returns
//   `DecryptError { kind: 'duplicate' }` thereafter; ratchet state
//   advances exactly once across all repeats.
//
// Validates: Requirements 4.12, 21.6
//   - Requirement 4.12: "WHEN the same Ciphertext_Envelope is decrypted
//     more than once, THE Crypto_Module SHALL succeed exactly once and
//     return `DecryptError { kind: 'duplicate' }` on subsequent attempts,
//     advancing ratchet state exactly once."
//   - Requirement 21.6: "FOR ALL ciphertexts `c`, repeating
//     `decryptFromDevice` up to 100 times SHALL succeed exactly once and
//     return `{ kind: 'duplicate' }` thereafter, advancing ratchet state
//     exactly once across all repeats."
//
// Strategy
// --------
//   1. Build an Alice / Bob ratchet pair sharing a 32-byte root key
//      (the same shape `session.ts` produces from X3DH).
//   2. Encrypt one message Alice → Bob.
//   3. Pick K ∈ [1, 100] via fast-check and call `decryptFromDevice`
//      K times against Bob, threading the returned state forward.
//   4. Assert exactly one call returned `{ ok: true }`, the remaining
//      K-1 returned `DecryptError { kind: 'duplicate' }`, and zero
//      returned `invalid_message` / `message_lost`.
//   5. Assert Bob's `receivingMessageNumber` advanced exactly once: it
//      ends at 1 (the first message was `messageNumber = 0`, so a
//      single advance yields counter = 1; further duplicates leave it
//      untouched per `decryptSameChain`'s duplicate path).
//
// Iteration count
// ---------------
// `test/setup.ts` configures fast-check globally with 100 iterations
// per property by default (≥ 500 in the nightly job via
// `FAST_CHECK_RUNS`). That satisfies the ≥ 100 minimum for P6.

import { x25519 } from '@noble/curves/ed25519';
import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  decryptFromDevice,
  encryptToDevice,
  initReceiverRatchet,
  initSenderRatchet,
} from '../src/ratchet.js';

describe('P6: idempotent decryption (Requirements 4.12, 21.6)', () => {
  it('K repeats yield exactly one ok and K-1 duplicates; ratchet advances once', async () => {
    // Pre-generate the shared X3DH-derived inputs once: a 32-byte root
    // key and Bob's signed-prekey keypair. Each fast-check iteration
    // re-initializes Alice and Bob from these inputs, so the per-
    // iteration ratchet states are independent. Generating these once
    // up front keeps the property fast (X25519 keygen would otherwise
    // dominate).
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    const bobSpkPriv = new Uint8Array(32);
    crypto.getRandomValues(bobSpkPriv);
    const bobSpkPub = x25519.getPublicKey(bobSpkPriv);

    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 100 }), async (K) => {
        // Fresh ratchet pair per iteration. `initSenderRatchet`
        // generates a fresh sending DH keypair internally, so Alice's
        // outbound `header.dhPub` differs from Bob's stored
        // `receivingDhPub` (= null) — the first inbound triggers the
        // DH-ratchet branch in `decryptFromDevice`.
        const alice = initSenderRatchet(sk, bobSpkPub);
        let bob = initReceiverRatchet(sk, {
          priv: bobSpkPriv,
          pub: bobSpkPub,
        });

        // One encrypted message, replayed K times against Bob.
        const sent = await encryptToDevice(alice, new Uint8Array([1, 2, 3]));

        let okCount = 0;
        let duplicateCount = 0;
        let invalidCount = 0;
        for (let i = 0; i < K; i++) {
          const r = await decryptFromDevice(bob, sent.ciphertext, sent.header);
          bob = r.state;
          if (r.result.ok) {
            okCount += 1;
          } else if (r.result.error.kind === 'duplicate') {
            duplicateCount += 1;
          } else {
            // `invalid_message` or `message_lost` — both forbidden
            // for an idempotent replay of a well-formed ciphertext.
            invalidCount += 1;
          }
        }

        // Property: exactly one success, K-1 duplicates, no other
        // errors, and Bob's receiving counter advanced exactly once
        // (header.messageNumber = 0 → counter = 1 after the single
        // advance; duplicates leave it at 1).
        return (
          okCount === 1 &&
          duplicateCount === K - 1 &&
          invalidCount === 0 &&
          bob.receivingMessageNumber === 1
        );
      }),
    );
  });
});

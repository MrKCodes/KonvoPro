// packages/crypto/test/p3-tamper-rejection.property.test.ts
//
// Property-based test for task 4.11: tamper rejection (P3).
//
// Property under test (P3 — tamper rejection):
//
//   For every valid ciphertext `c` produced by `encryptToDevice` and
//   any single-byte mutation `c'` (a single-bit flip at any byte
//   index), `decryptFromDevice(c')` returns
//   `{ ok: false, error: { kind: 'invalid_message' } }`. No plaintext
//   leaks to the returned object, and the receiver's ratchet state
//   does NOT advance past the tamper attempt — `receivingMessageNumber`
//   is unchanged.
//
// Validates: Requirements 4.11, 21.3
//   - Requirement 4.11: tamper rejection — single-byte mutation of
//     any ciphertext returns DecryptError(invalid_message) with no
//     plaintext leak.
//   - Requirement 21.3 (P3 in the spec): for all valid ciphertexts
//     and any single-byte mutation, decryptFromDevice returns
//     `{ ok: false, error: { kind: 'invalid_message' } }`; no
//     plaintext leaks to returned objects, thrown values, logs,
//     metrics, persisted records, or callback arguments.
//
// Iteration count
// ---------------
// `test/setup.ts` configures `fast-check` globally with 100 iterations
// per property by default (and ≥ 500 in the nightly tamper job via
// `FAST_CHECK_RUNS`). That satisfies the ≥ 100 minimum required for
// P3, with a higher bar on the nightly tamper job per design.md
// §16.2.
//
// Performance note
// ----------------
// Initializing a fresh ratchet pair and producing a fresh ciphertext
// per iteration would dominate runtime (X25519 keygen + DH + HKDF +
// AES-GCM). The property under test only varies the *mutation* —
// which byte to flip and which bit within that byte. We therefore
// pre-stage one ratchet pair and one ciphertext outside the property,
// then have fast-check explore the (byteIdx, bitIdx) space. This
// matches the strategy used in `broadcast.property.test.ts` and
// `broadcast.completeness.property.test.ts` (pre-computed pool, index
// arbitraries inside the property).

import { x25519 } from '@noble/curves/ed25519';
import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  decryptFromDevice,
  encryptToDevice,
  initReceiverRatchet,
  initSenderRatchet,
  type RatchetState,
} from '../src/ratchet.js';

/**
 * Provision a fresh Alice ↔ Bob ratchet pair sharing a 32-byte root
 * key (which production derives from X3DH). For this property test
 * the SK is just random bytes — what matters is that both sides
 * start from the same SK and Alice initializes against Bob's SPK
 * pubkey, so a clean encrypt → decrypt round-trip succeeds before
 * we introduce the tamper.
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

describe('P3: tamper rejection (Requirements 4.11, 21.3)', () => {
  it('any single-bit flip in the ciphertext returns invalid_message and does not advance receiver state', async () => {
    // Pre-stage one ratchet pair and one ciphertext. The property
    // under test ranges over the *mutation* (byte index × bit
    // index), not the input session — a fresh pair per iteration
    // would multiply runtime by ≥ 100 with no gain in coverage of
    // the P3 invariant.
    const { alice, bob } = freshPair();
    const plaintext = new TextEncoder().encode(
      'plaintext that must never leak',
    );
    const sent = await encryptToDevice(alice, plaintext);
    const ciphertext = sent.ciphertext;
    const header = sent.header;

    // Snapshot Bob's pre-tamper state for the "no advance" assertion.
    // Bob has not yet decrypted anything, so receivingMessageNumber
    // is 0 and skippedKeys is empty. The property holds for any
    // pre-tamper state; we capture the full counter set so the
    // assertion is robust if the test is later re-staged with Bob
    // already mid-conversation.
    const bobReceivingMessageNumberBefore = bob.receivingMessageNumber;
    const bobSkippedKeysCountBefore = bob.skippedKeys.length;
    const bobReceivingDhPubBefore = bob.receivingDhPub;
    const bobReceivingChainKeyBefore = bob.receivingChainKey;

    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: ciphertext.length - 1 }),
        fc.integer({ min: 0, max: 7 }),
        async (byteIdx, bitIdx) => {
          // Mutate exactly one bit of the ciphertext: XOR a 1-bit
          // mask into byte `byteIdx`. This is the canonical
          // "single-byte mutation" of req 4.11 — flipping any bit
          // changes that byte's value, so it covers the full
          // single-byte mutation space (any new byte value is
          // reachable from the original via some sequence of
          // bit flips, but P3 only requires that *each* single-bit
          // perturbation is rejected).
          const tampered = new Uint8Array(ciphertext);
          // The non-null assertion is safe: byteIdx is bounded to
          // [0, ciphertext.length - 1] by the arbitrary above.
          tampered[byteIdx] = (tampered[byteIdx]! ^ (1 << bitIdx)) & 0xff;

          const recv = await decryptFromDevice(bob, tampered, header);

          // Primary assertion: invalid_message and no plaintext.
          if (recv.result.ok !== false) {
            return false;
          }
          if (recv.result.error.kind !== 'invalid_message') {
            return false;
          }

          // No-advance assertion: Bob's returned state has the
          // same receiving counter as before. This is the
          // "ratchet state unchanged on tamper" half of req 4.11.
          if (
            recv.state.receivingMessageNumber !==
            bobReceivingMessageNumberBefore
          ) {
            return false;
          }
          if (recv.state.skippedKeys.length !== bobSkippedKeysCountBefore) {
            return false;
          }
          // On a first-ever-inbound failure, the DH ratchet must
          // NOT have been committed. Bob still has no observed
          // peer dhPub and no receiving chain key.
          if (recv.state.receivingDhPub !== bobReceivingDhPubBefore) {
            return false;
          }
          if (recv.state.receivingChainKey !== bobReceivingChainKeyBefore) {
            return false;
          }
          return true;
        },
      ),
    );

    // Sanity check post-property: the *un-tampered* original still
    // decrypts under Bob, proving the pre-staged ciphertext was
    // genuinely valid and the property's rejections were caused by
    // the bit flip, not by some pre-existing error in the test
    // setup. This also confirms Bob's state was never mutated by
    // the tamper attempts (decrypt of the original advances state
    // exactly once, from 0 to 1).
    const cleanRecv = await decryptFromDevice(bob, ciphertext, header);
    expect(cleanRecv.result.ok).toBe(true);
    if (cleanRecv.result.ok) {
      expect(Array.from(cleanRecv.result.plaintext)).toEqual(
        Array.from(plaintext),
      );
    }
    expect(cleanRecv.state.receivingMessageNumber).toBe(
      bobReceivingMessageNumberBefore + 1,
    );
  });
});

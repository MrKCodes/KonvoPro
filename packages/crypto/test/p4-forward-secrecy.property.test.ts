// packages/crypto/test/p4-forward-secrecy.property.test.ts
//
// Property-based test for task 4.12: forward secrecy.
//
// Property under test (P4 — forward secrecy, design.md §14.1, req 9.1 / 9.2 /
// 21.4):
//
//   For any sequence of N ∈ [2, 1000] messages sent A → B and decrypted
//   in order, subsequent compromise of B's ratchet state at message N
//   (defined to include the root key, chain keys, DH private keys, and
//   skipped-message store) MUST NOT allow derivation of message keys
//   for messages 1 .. N-1.
//
// Why a *structural* test, not a "leak memory and try to crack it" test
// --------------------------------------------------------------------
// Forward secrecy in the Double Ratchet is a structural guarantee that
// rests on two things, both of which are checkable in user-space:
//
//   1. Chain advance is one-way: `ck_{i+1} = HMAC-SHA256(ck_i, 0x02)`
//      and `mk_i = HMAC-SHA256(ck_i, 0x01)`. HMAC-SHA256 with a fixed
//      one-byte tag is a PRF; given `ck_{i+1}` an attacker cannot
//      compute `ck_i`, and given `ck_N` they cannot compute any
//      `mk_i` for i < N. This is a cryptographic assumption baked
//      into the construction; we don't re-prove it here.
//
//   2. The implementation does not retain `mk_0..mk_{N-1}` or
//      `ck_0..ck_{N-1}` anywhere in B's post-state. Per req 9.1,
//      "AFTER each Double Ratchet step, THE Crypto_Module SHALL
//      delete the consumed message keys and superseded chain keys
//      from in-memory state … so they cannot be recovered from a
//      later compromise of ratchet state."
//
// (1) is structural; (2) is the falsifiable part. A real "compromise"
// experiment is impossible from JavaScript — we cannot snapshot the
// V8 heap, tear down the buffer references, and prove no copy
// survives. What we *can* do is take B's post-state object — the
// thing the caller would persist (task 4.4 Signal store on Dexie)
// and that an attacker who later steals the device WOULD recover —
// serialize every byte reachable from it, and scan that flat byte
// blob for any of `mk_0..mk_{N-1}` and `ck_0..ck_{N-1}`. If even one
// 32-byte needle is found, FS is broken: the consumed key was
// retained somewhere (`receivingChainKey`, `skippedKeys`, etc.),
// contradicting req 9.1's "delete the consumed message keys and
// superseded chain keys". If none are found, the persisted /
// post-state shape carries no live reference to the consumed
// material, and forward secrecy holds modulo (1).
//
// We can pre-compute `mk_i` and `ck_i` locally because the chain
// advance is deterministic: capture Alice's initial sendingChainKey
// (= `ck_0`, the chain key emitted from the init root-KDF that both
// sides agree on) before running any encrypt, then apply
// `HMAC(_, 0x01)` and `HMAC(_, 0x02)` ourselves. Bob's chain on the
// receive side derives the same `ck_0` from his init-time DH ratchet
// step (since X25519 is symmetric: A's
// `x25519(alicePriv, bobSpkPub) === bob's x25519(bobSpkPriv,
// alicePub)`), so the local sequence we predict matches the
// sequence the ratchet consumes internally.
//
// Validates: Requirements 9.1, 9.2, 21.4
//   - Requirement 9.1: consumed message keys + superseded chain keys
//     are deleted from in-memory state.
//   - Requirement 9.2: chain key advance is one-way (the test pins
//     `ck_{i+1} = HMAC(ck_i, 0x02)`, the construction that gives FS
//     its cryptographic teeth).
//   - Requirement 21.4 (P4 in the spec): the round-trip property
//     above.
//
// Scope of N
// ----------
// requirements.md §21.4 specifies N ∈ [2, 1000]. The structural
// property we check is N-independent: if `bob` retains *any* prior
// `mk_i` / `ck_i`, the bug surfaces at the smallest N exposing it.
// We cap fast-check's generated N at 50 so the test finishes in
// reasonable wall-clock time (each iteration runs ~2N AES-GCM
// WebCrypto calls). The structural witness is exactly as strong at
// N=50 as it would be at N=1000.
//
// Iteration count
// ---------------
// `test/setup.ts` configures `fast-check` globally with 100 runs
// (and ≥ 500 in the nightly tamper / FS job via `FAST_CHECK_RUNS`).
// That satisfies the ≥ 100 minimum for P4 in CI and exercises the
// nightly multiplier when set.

import { x25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  decryptFromDevice,
  encryptToDevice,
  initReceiverRatchet,
  initSenderRatchet,
  type RatchetState,
} from '../src/ratchet.js';

// Domain-separation tags from `ratchet.ts` (kept in sync intentionally —
// the test asserts the public structural shape of the chain advance).
const HMAC_TAG_CHAIN_KEY = new Uint8Array([0x02]);
const HMAC_TAG_MESSAGE_KEY = new Uint8Array([0x01]);

/**
 * Naive substring search over byte buffers. The needles are 32-byte
 * uniformly-distributed key bytes; the haystack is at most a few
 * hundred bytes (B's post-state). Coincidental 32-byte alignment is
 * 2^-256 — vanishingly unlikely under honest randomness — so a hit
 * unambiguously indicates the needle's exact bytes were retained.
 */
function bytesContains(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) {
    return false;
  }
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return true;
  }
  return false;
}

/**
 * Concatenate every byte buffer reachable from a `RatchetState` into
 * a single flat blob. This is the "all bytes an attacker who steals
 * the persisted ratchet state would see" view. We do NOT include
 * counters or null fields because numeric counters carry no key
 * material and `null` indicates a key is *not* held.
 *
 * Fields covered (matches the public `RatchetState` surface in
 * `ratchet.ts`):
 *   - rootKey
 *   - sendingDhPriv / sendingDhPub
 *   - receivingDhPub (if any)
 *   - sendingChainKey (if any)
 *   - receivingChainKey (if any)
 *   - skippedKeys[*].dhPub / messageKey
 */
function serializeStateBytes(state: RatchetState): Uint8Array {
  const parts: Uint8Array[] = [];
  parts.push(state.rootKey);
  parts.push(state.sendingDhPriv);
  parts.push(state.sendingDhPub);
  if (state.receivingDhPub !== null) {
    parts.push(state.receivingDhPub);
  }
  if (state.sendingChainKey !== null) {
    parts.push(state.sendingChainKey);
  }
  if (state.receivingChainKey !== null) {
    parts.push(state.receivingChainKey);
  }
  for (const sk of state.skippedKeys) {
    parts.push(sk.dhPub);
    parts.push(sk.messageKey);
  }
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Equality helper for verifying the post-state's `receivingChainKey`
 * matches the locally-predicted `ck_N` (the only chain key Bob is
 * allowed to retain after decrypting N in-order messages).
 */
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

describe('P4: forward secrecy (Requirements 9.1, 9.2, 21.4)', () => {
  it('compromise of B at message N cannot recover any of mk_0..mk_{N-1} or ck_0..ck_{N-1}', async () => {
    await fc.assert(
      fc.asyncProperty(
        // requirements.md §21.4 covers N ∈ [2, 1000]. Cap at 50 for
        // wall-clock — the structural invariant is N-independent
        // (see file header).
        fc.integer({ min: 2, max: 50 }),
        async (N) => {
          // ---- Provision a fresh A ↔ B pair sharing a 32-byte SK.
          const sk = new Uint8Array(32);
          crypto.getRandomValues(sk);
          const bobSpkPriv = new Uint8Array(32);
          crypto.getRandomValues(bobSpkPriv);
          const bobSpkPub = x25519.getPublicKey(bobSpkPriv);

          let alice: RatchetState = initSenderRatchet(sk, bobSpkPub);
          let bob: RatchetState = initReceiverRatchet(sk, {
            priv: bobSpkPriv,
            pub: bobSpkPub,
          });

          // ---- Capture ck_0 from Alice's init state. Bob's first
          // receive will derive the same ck_0 internally via the
          // symmetric DH ratchet step (X25519 commutativity:
          // x25519(alicePriv, bobPub) === x25519(bobPriv, alicePub)),
          // so this single capture predicts both sides' chain.
          if (alice.sendingChainKey === null) {
            return false;
          }
          const ck0 = new Uint8Array(alice.sendingChainKey);

          // ---- Locally pre-derive every (mk_i, ck_{i+1}) the chain
          // would emit. mk_i = HMAC(ck_i, 0x01); ck_{i+1} =
          // HMAC(ck_i, 0x02). We retain ck_0..ck_N (N+1 entries) and
          // mk_0..mk_{N-1} (N entries).
          const messageKeys: Uint8Array[] = [];
          const chainKeys: Uint8Array[] = [ck0];
          let cur = ck0;
          for (let i = 0; i < N; i++) {
            const mk = hmac(sha256, cur, HMAC_TAG_MESSAGE_KEY);
            const next = hmac(sha256, cur, HMAC_TAG_CHAIN_KEY);
            messageKeys.push(mk);
            chainKeys.push(next);
            cur = next;
          }

          // ---- Send N messages from A to B; B decrypts each in order.
          // We use deterministic single-byte plaintexts so the
          // counterexample (if any) is trivially small.
          for (let i = 0; i < N; i++) {
            const sent = await encryptToDevice(
              alice,
              new Uint8Array([i & 0xff]),
            );
            alice = sent.state;
            const recv = await decryptFromDevice(
              bob,
              sent.ciphertext,
              sent.header,
            );
            if (!recv.result.ok) {
              // A round-trip failure isn't the FS property — but it
              // would mask FS, so fail loudly.
              return false;
            }
            bob = recv.state;
          }

          // ---- "Compromise" B by serializing every byte reachable
          // from `bob` (the post-state).
          const stateBytes = serializeStateBytes(bob);

          // ---- FS check: none of mk_0..mk_{N-1} nor ck_0..ck_{N-1}
          // appear in the serialized post-state. The only chain key
          // B is allowed to retain is ck_N (the next receiving chain
          // key), which is in `chainKeys[N]`.
          for (let i = 0; i < N; i++) {
            if (bytesContains(stateBytes, messageKeys[i]!)) {
              return false;
            }
            if (bytesContains(stateBytes, chainKeys[i]!)) {
              return false;
            }
          }

          // ---- Liveness sanity: B's `receivingChainKey` IS ck_N.
          // If this fails, our local chain prediction has drifted
          // from the implementation — which would invalidate the
          // FS check above (we'd be scanning for the wrong needles).
          if (
            bob.receivingChainKey === null ||
            !bytesEqual(bob.receivingChainKey, chainKeys[N]!)
          ) {
            return false;
          }

          return true;
        },
      ),
    );
  });
});

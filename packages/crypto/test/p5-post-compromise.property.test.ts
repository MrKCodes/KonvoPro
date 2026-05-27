// packages/crypto/test/p5-post-compromise.property.test.ts
//
// Property-based test for task 4.13: post-compromise security (P5).
//
// Property under test (P5 — post-compromise security, design.md §14.1,
// req 9.2 / 21.5):
//
//   For all pairs (A, B), after each peer has performed at least one
//   DH ratchet step following compromise of an old sending chain key,
//   an attacker holding the old chain key MUST NOT decrypt new
//   messages.
//
// Why a *structural* test, not a "leak memory and try to crack it" test
// --------------------------------------------------------------------
// Post-compromise security in the Double Ratchet rests on a single
// structural fact: every DH ratchet step mixes a *fresh* X25519 shared
// secret into the root KDF before deriving the next chain key
// (`ratchet.ts::rootKdf`, `dhRatchetReceiveStep`). The freshness comes
// from the receiver generating a new DH ratchet keypair on every
// inbound chain transition (`ratchet.ts::generateRatchetKeypair`
// inside `decryptNewChain`). An attacker who recorded only the old
// chain keys / old root key — but did NOT record the new DH private
// — has no way to compute the new DH output, so the new root key
// (and therefore every subsequent chain key) is independent of what
// they hold.
//
// As with P4, a real "compromise" experiment is impossible from
// JavaScript — we cannot reset V8's heap, hand the attacker exactly
// the old state bytes, and prove no live reference to the new keys
// leaks. What we *can* do is the structural witness: stash the
// receiver's pre-ratchet state object, run a DH ratchet step (Bob
// replies → Alice receives Bob's reply → Alice's next send is on a
// new sending chain), then attempt to decrypt the post-ratchet
// ciphertext using the stashed pre-ratchet state. The Double
// Ratchet's correctness implies that:
//
//   - The post-ratchet ciphertext was authenticated under a message
//     key derived from a chain key that was *only* derived through a
//     root KDF call that consumed the new DH output.
//   - The pre-ratchet state holds neither the new DH private nor
//     any chain key derived past the ratchet step. Trial-decrypting
//     under it must therefore fail AES-GCM tag verification, which
//     `decryptFromDevice` surfaces as `invalid_message` (or
//     `message_lost` if the chain index gap exceeds 1000 — but
//     never `ok: true`).
//
// And the post-state structural witness:
//
//   - Bob's post-ratchet root key, sending chain key, and receiving
//     chain key are all DIFFERENT from their pre-ratchet bytes.
//     Anything else would mean the DH output was either zeroed out
//     (broken X25519) or not mixed in (broken root KDF), both of
//     which directly violate req 9.2.
//
// The two checks together pin both halves of P5: structural
// freshness of the new chain (the `bob.rootKey` / chainKey diff)
// AND functional inability of the old chain key to decrypt the new
// message (the trial-decrypt failure).
//
// Pre-ratchet state, precisely
// ----------------------------
// In our setup the "old sending chain key" is Alice's first sending
// chain key (`ck0`), produced by `initSenderRatchet` from the
// initial root KDF over `(SK, x25519(aliceSpkInitDh, bobSpkPub))`.
// Bob's symmetric peer of that chain — what Bob would derive on
// his first inbound — is the same `ck0` (X25519 commutativity). To
// "compromise" that old chain in user-space, we capture Bob's full
// `RatchetState` object *immediately after `initReceiverRatchet`*,
// before any inbound receive triggers his DH ratchet step. That
// state holds:
//   - rootKey = SK (initial)
//   - sendingDhPriv/Pub = bobSpkPriv/Pub (the pre-ratchet pair)
//   - receivingChainKey = null (Bob has no chain key yet)
//   - sendingChainKey = null
//
// After Alice → Bob → Alice → Bob → … message exchanges with at
// least one Bob-reply (which DH-ratchets both peers per
// `decryptFromDevice`'s new-chain branch), Alice's next send is on
// a fresh sending chain seeded by a new DH output that the
// pre-ratchet Bob state does not hold. Feeding that new ciphertext
// into the *captured* pre-ratchet state must fail.
//
// Validates: Requirements 9.2, 21.5
//   - Requirement 9.2: chain key advance after a DH ratchet step is
//     bound to a fresh DH output combined with the existing root
//     key.
//   - Requirement 21.5 (P5 in the spec): pre-ratchet chain-key
//     attacker cannot decrypt post-ratchet messages.
//
// Iteration count
// ---------------
// `test/setup.ts` configures `fast-check` globally with 100 runs
// (and ≥ 500 in the nightly tamper / FS job via `FAST_CHECK_RUNS`).
// That satisfies the ≥ 100 minimum required for P5.
//
// Scope of N
// ----------
// We parameterize over N ∈ [1, 5], the number of Alice → Bob
// messages before Bob's reply triggers the DH ratchet. The
// invariant is N-independent — the freshness of the post-ratchet
// chain depends on the DH ratchet step itself, not on how many
// pre-ratchet messages preceded it. Capping at 5 keeps wall-clock
// reasonable while still exercising the same-chain advance path
// before the DH transition.

import { x25519 } from '@noble/curves/ed25519';
import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  decryptFromDevice,
  encryptToDevice,
  initReceiverRatchet,
  initSenderRatchet,
  type RatchetState,
} from '../src/ratchet.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Provision a fresh Alice ↔ Bob ratchet pair sharing a 32-byte SK
 * (production derives this from X3DH; here we stub it with random
 * bytes — what matters is that both sides start from the same SK
 * and Alice initializes against Bob's SPK pubkey).
 */
function freshPair(): {
  alice: RatchetState;
  bob: RatchetState;
} {
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
 * Deep-copy every byte buffer reachable from a `RatchetState` so
 * later mutations of the live state cannot retroactively change the
 * captured snapshot. This is the "what the attacker stole at the
 * moment of compromise" view — it must be a stable, independent
 * copy.
 *
 * `RatchetState` declares its byte fields `readonly`, but TypeScript
 * `readonly` is purely a structural fiction; the actual `Uint8Array`
 * instances share backing memory with the live state until we copy
 * them. We therefore allocate new buffers for every byte field and
 * for every entry in `skippedKeys`.
 */
function snapshotState(s: RatchetState): RatchetState {
  return {
    rootKey: new Uint8Array(s.rootKey),
    sendingDhPriv: new Uint8Array(s.sendingDhPriv),
    sendingDhPub: new Uint8Array(s.sendingDhPub),
    receivingDhPub:
      s.receivingDhPub === null ? null : new Uint8Array(s.receivingDhPub),
    sendingChainKey:
      s.sendingChainKey === null ? null : new Uint8Array(s.sendingChainKey),
    receivingChainKey:
      s.receivingChainKey === null ? null : new Uint8Array(s.receivingChainKey),
    sendingMessageNumber: s.sendingMessageNumber,
    receivingMessageNumber: s.receivingMessageNumber,
    previousSendingChainLength: s.previousSendingChainLength,
    skippedKeys: s.skippedKeys.map((k) => ({
      dhPub: new Uint8Array(k.dhPub),
      messageNumber: k.messageNumber,
      messageKey: new Uint8Array(k.messageKey),
    })),
  };
}

/** Length-checked bytewise equality for 32-byte chain / root keys. */
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

// ---------------------------------------------------------------------------
// Property
// ---------------------------------------------------------------------------

describe('P5: post-compromise security (Requirements 9.2, 21.5)', () => {
  it(
    'after a DH ratchet step, an attacker holding the pre-ratchet chain ' +
      'state cannot decrypt the new post-ratchet message, and the new ' +
      'root + chain keys differ from their pre-ratchet bytes',
    async () => {
      await fc.assert(
        fc.asyncProperty(
          // N = how many Alice → Bob messages precede Bob's reply.
          // The invariant is N-independent (see file header), but we
          // sweep a small range to exercise the same-chain advance
          // path before the DH ratchet transition.
          fc.integer({ min: 1, max: 5 }),
          async (N) => {
            // ---- Provision a fresh Alice ↔ Bob ratchet pair.
            let { alice, bob } = freshPair();

            // ---- "Compromise" point: snapshot Bob's full state at
            // init time. This is the state holding the pre-ratchet
            // sending DH priv (= bobSpkPriv) and the initial root
            // key (= SK). It does NOT yet hold the fresh DH priv
            // that Bob will generate when he replies, nor the
            // post-ratchet root / chain keys derived from that
            // fresh DH output.
            const bobPreRatchet = snapshotState(bob);

            // ---- Send N Alice → Bob messages on Alice's initial
            // sending chain (the chain seeded by ck0, the chain
            // key derived from the init DH output). All of these
            // travel under the same `sendingDhPub` — no DH ratchet
            // on Alice's side yet.
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
                // Round-trip should always succeed for in-order
                // delivery on the initial chain. A failure here
                // would mask the P5 invariant.
                return false;
              }
              bob = recv.state;
            }

            // ---- Bob replies — his first send DH-ratchets him.
            // Bob's `encryptToDevice` requires a sendingChainKey;
            // he acquired one when he first decrypted Alice's m0
            // above (the new-chain branch of `decryptFromDevice`
            // generates a fresh DH keypair on Bob's side and runs
            // the sending DH ratchet step → req 9.2).
            const bobReply = await encryptToDevice(
              bob,
              new Uint8Array([0xaa]),
            );
            bob = bobReply.state;

            // ---- Alice receives Bob's reply — this DH-ratchets
            // Alice. After this, Alice's `sendingDhPub` is fresh
            // (her receive path generated a new keypair) and her
            // `sendingChainKey` is seeded by a root KDF call that
            // mixed in the new DH output `x25519(aliceFreshPriv,
            // bobReply.header.dhPub)`.
            const aliceRecv = await decryptFromDevice(
              alice,
              bobReply.ciphertext,
              bobReply.header,
            );
            if (!aliceRecv.result.ok) {
              return false;
            }
            alice = aliceRecv.state;

            // ---- Alice sends a NEW post-ratchet message under her
            // fresh sending DH key + fresh sending chain key. This
            // is "the new message" the P5 attacker shouldn't be
            // able to decrypt.
            const postRatchet = await encryptToDevice(
              alice,
              new Uint8Array([0x55]),
            );
            alice = postRatchet.state;

            // ---- Structural witness #1: Bob's post-ratchet state
            // bytes must differ from the pre-ratchet snapshot for
            // root key, sending chain key (Bob's), and receiving
            // chain key (Bob's). Anything else means the DH output
            // wasn't mixed in (or was zero), directly violating
            // req 9.2.
            //
            // Pre-ratchet `bob.receivingChainKey` was null and
            // `bob.sendingChainKey` was null; post-ratchet both
            // are non-null. We assert non-null AND-different-from-
            // any-pre-ratchet-bytes-we-might-have-held. Since
            // null !== Uint8Array, "different" is automatic for
            // these two; what we explicitly want to confirm is
            // simply that they ARE non-null (chain freshness
            // produced live key material) AND that the root key
            // changed.
            if (bob.rootKey === null) {
              return false;
            }
            if (bytesEqual(bob.rootKey, bobPreRatchet.rootKey)) {
              // Pre-ratchet rootKey was SK (initial); post-ratchet
              // it has been advanced through TWO root-KDF calls
              // (one for the receive DH ratchet step on Bob's
              // first inbound, one for the send DH ratchet step
              // when Bob's first send fired). If equal, the root
              // KDF didn't advance — req 9.2 is broken.
              return false;
            }
            if (
              bob.sendingChainKey === null ||
              bob.receivingChainKey === null
            ) {
              // After Alice → Bob (× N) and Bob → Alice (× 1), Bob
              // has both a receiving chain (from Alice's first
              // header) and a sending chain (his own DH ratchet
              // step). Either being null means the ratchet step
              // didn't seed them.
              return false;
            }

            // ---- Structural witness #2: Bob's post-ratchet
            // sendingDhPriv differs from the pre-ratchet one.
            // The pre-ratchet sendingDhPriv was bobSpkPriv (the
            // initial keypair). After Bob's first inbound, the
            // new-chain branch of `decryptFromDevice` generated a
            // fresh keypair via `generateRatchetKeypair()` and
            // installed it. If equal, no fresh DH was generated
            // — req 9.2 is broken.
            if (bytesEqual(bob.sendingDhPriv, bobPreRatchet.sendingDhPriv)) {
              return false;
            }

            // ---- Structural witness #3 (the P5 functional
            // check): the captured pre-ratchet Bob state CANNOT
            // decrypt the new post-ratchet ciphertext.
            //
            // The pre-ratchet state holds `sendingDhPriv =
            // bobSpkPriv`. The post-ratchet ciphertext travels
            // under Alice's fresh `sendingDhPub` (call it
            // alicePub'). When `decryptFromDevice` sees that
            // header.dhPub doesn't match the pre-ratchet
            // `receivingDhPub` (which is null on the snapshot), it
            // takes the new-chain branch and computes
            // `x25519(bobSpkPriv, alicePub')` for the receive DH
            // ratchet step. But Alice's post-ratchet sending
            // chain was seeded by `x25519(aliceFreshPriv,
            // bobReply.header.dhPub)` (where bobReply.header.dhPub
            // = bob's FRESH DH pub, not bobSpkPub). The pre-
            // ratchet state has no path to compute that DH output
            // because it doesn't hold bob's fresh DH priv. The
            // root KDF therefore produces a chain key that is
            // unrelated to the one Alice used; the AES-GCM tag
            // check fails → invalid_message.
            const attackResult = await decryptFromDevice(
              bobPreRatchet,
              postRatchet.ciphertext,
              postRatchet.header,
            );
            if (attackResult.result.ok) {
              // The attacker decrypted the post-ratchet message
              // using only pre-ratchet state. P5 is violated.
              return false;
            }
            // We accept either `invalid_message` (the typical
            // outcome — AES-GCM tag fails) or `message_lost`
            // (could occur if the message-number geometry between
            // pre- and post-ratchet pushes the new-chain skip
            // count over the cap; not the typical case here, but
            // structurally equivalent — neither yields plaintext).
            const errKind = attackResult.result.error.kind;
            if (errKind !== 'invalid_message' && errKind !== 'message_lost') {
              return false;
            }

            // ---- Liveness sanity: the LIVE post-ratchet Bob
            // state DOES decrypt the new message. If it doesn't,
            // either the test setup is wrong or the ratchet is
            // broken in a way that would mask P5 (any failure
            // path that prevents decryption looks superficially
            // like P5 holding). This check ensures we're rejecting
            // for the right reason — old-state failure, not
            // total-system failure.
            const liveRecv = await decryptFromDevice(
              bob,
              postRatchet.ciphertext,
              postRatchet.header,
            );
            if (!liveRecv.result.ok) {
              return false;
            }
            if (liveRecv.result.plaintext.length !== 1) {
              return false;
            }
            if (liveRecv.result.plaintext[0] !== 0x55) {
              return false;
            }

            return true;
          },
        ),
      );
    },
  );
});

// packages/crypto/test/p1-e2ee-roundtrip.property.test.ts
//
// Property-based test for task 4.10: P1 — E2EE round-trip (text).
//
// Property under test (orchestrator-specified P1 wording):
//
//   For any plaintext `m` of length 1..16384 bytes and any X3DH-
//   initialized Double Ratchet session pair `(A, B)`,
//   `decrypt_B(encrypt_A→B(m)) === m` byte-for-byte.
//
// This is the soundness half of the E2EE pipeline: every plaintext
// Alice encrypts to Bob through the (X3DH + Double Ratchet) stack
// must decrypt on Bob's side to the exact same bytes. The companion
// tamper / forward-secrecy / out-of-order properties land in tasks
// 4.11–4.13.
//
// Validates: Requirements 4.10, 21.1
//   - Requirement 4.10 (Crypto_Module Double Ratchet): "advances the
//     ratchet by exactly one message key per encrypt and decrypt; the
//     resulting plaintext on the recipient is byte-identical to the
//     sender's input".
//   - Requirement 21.1 (P1 in requirements.md): the round-trip
//     property as stated above.
//
// Phase-3 placeholder note
// ------------------------
// design.md §13 hands the Double Ratchet off to libsignal's
// `SessionCipher`. libsignal isn't on disk yet (it lands in a later
// 4.x task). Until then the session is constructed via
// `packages/crypto/src/session.ts` (`establishSession` /
// `acceptSession` — task 4.2, real X3DH on `@noble/curves`) and the
// ratchet via `packages/crypto/src/ratchet.ts` (`initSenderRatchet`
// / `initReceiverRatchet` + `encryptToDevice` / `decryptFromDevice`
// — task 4.3, hand-rolled Double Ratchet on `@noble/curves` +
// `@noble/hashes` + WebCrypto AES-GCM). The property's contract
// (round-trip equality) is preserved across the libsignal swap.
//
// Iteration count
// ---------------
// `test/setup.ts` configures `fast-check` globally with 100
// iterations per property by default (and ≥ 500 in the nightly job
// via `FAST_CHECK_RUNS`). That satisfies the ≥ 100 minimum for P1.
//
// Performance / fixture-reuse note
// --------------------------------
// Generating a fresh identity pair + prekey bundle + running X3DH
// per iteration would dominate runtime (Argon2-shape AES-KW wrap,
// Ed25519 signing, four ECDH multiplications, HKDF). We pay that
// cost ONCE at the top of the test and then run all 100 iterations
// against the same `(A, B)` Double Ratchet, advancing the sending
// chain by one message per iteration. fast-check's shrinker walks
// the plaintext space; a counter-example shrinks to a small byte
// array regardless of how far the chain has advanced.
//
// Using a single session pair is sound for P1 because the property
// is per-message: the round-trip equality must hold for every
// individual `(state, m)` pair, regardless of how the chain has
// advanced. In effect the test exercises 100 sequential round-trips
// on one chain, which strictly stresses the ratchet harder than 100
// independent chain-position-zero round-trips would.

import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  MemoryIdentityStore,
  getOrCreateIdentity,
} from '../src/identity.js';
import {
  generateInitialBundle,
  unwrapStoredPrekeyPrivate,
  type OneTimePreKeyRecord,
  type PreKeyStore,
  type SignedPreKeyRecord,
} from '../src/prekeys.js';
import {
  acceptSession,
  establishSession,
  type RemotePreKeyBundle,
} from '../src/session.js';
import {
  decryptFromDevice,
  encryptToDevice,
  initReceiverRatchet,
  initSenderRatchet,
  type RatchetState,
} from '../src/ratchet.js';

// ---------------------------------------------------------------------------
// Fixture: in-memory PreKeyStore (mirrors the one in
// `packages/crypto/test/session.test.ts` so the X3DH path sees the
// real persistence shape).
// ---------------------------------------------------------------------------
class MemoryPreKeyStore implements PreKeyStore {
  signed: SignedPreKeyRecord[] = [];
  opks: OneTimePreKeyRecord[] = [];

  async listUnusedOneTimePreKeyCount(): Promise<number> {
    return this.opks.filter((r) => !r.used).length;
  }

  async getNextSignedPreKeyId(): Promise<number> {
    return this.signed.reduce((m, r) => Math.max(m, r.keyId), 0) + 1;
  }

  async getNextOneTimePreKeyId(): Promise<number> {
    return this.opks.reduce((m, r) => Math.max(m, r.keyId), 0) + 1;
  }

  async saveSignedPreKey(record: SignedPreKeyRecord): Promise<void> {
    this.signed.push(record);
  }

  async saveOneTimePreKey(record: OneTimePreKeyRecord): Promise<void> {
    this.opks.push(record);
  }

  async getCurrentSignedPreKey(): Promise<SignedPreKeyRecord | null> {
    if (this.signed.length === 0) {
      return null;
    }
    let newest = this.signed[0]!;
    for (const r of this.signed) {
      if (r.keyId > newest.keyId) {
        newest = r;
      }
    }
    return newest;
  }
}

describe('P1: E2EE round-trip (text) — Requirements 4.10, 21.1', () => {
  it('decrypt_B(encrypt_A→B(m)) === m for plaintexts of length 1..16384', async () => {
    // -----------------------------------------------------------------
    // Pre-generate Alice & Bob identities + Bob's prekey bundle, then
    // run real X3DH end-to-end so both sides hold the same root key.
    // -----------------------------------------------------------------
    const aliceIdStore = new MemoryIdentityStore();
    const alice = await getOrCreateIdentity(aliceIdStore);

    const bobIdStore = new MemoryIdentityStore();
    const bob = await getOrCreateIdentity(bobIdStore);
    const bobKek = await bobIdStore.getOrCreateAesKwKey();
    const bobPreKeyStore = new MemoryPreKeyStore();
    const bobBundle = await generateInitialBundle(bob, bobPreKeyStore, bobKek);

    // Shape Bob's wire-form bundle exactly as the API_Gateway would
    // return it on `GET /users/:handle/prekey-bundle`.
    const opk0 = bobBundle.oneTimePreKeys[0]!;
    const remoteBundle: RemotePreKeyBundle = {
      recipientDeviceId: 'bob-device-1',
      identityPub: bobBundle.identityPub,
      identityEdPub: bobBundle.identityEdPub,
      registrationId: bobBundle.registrationId,
      signedPreKey: bobBundle.signedPreKey,
      oneTimePreKey: { keyId: opk0.keyId, publicKey: opk0.publicKey },
    };

    // Alice's side of X3DH.
    const aliceX3dh = establishSession(alice, remoteBundle);

    // Bob's side of X3DH: unwrap the SPK + OPK private bytes from his
    // own store, run acceptSession, derive the matching root key.
    const spkRow = bobPreKeyStore.signed.find(
      (r) => r.keyId === aliceX3dh.sessionInit.signedPreKeyId,
    )!;
    const spkPriv = await unwrapStoredPrekeyPrivate(
      spkRow.wrappedPrivateKey,
      bobKek,
    );
    const opkRow = bobPreKeyStore.opks.find(
      (r) => r.keyId === aliceX3dh.sessionInit.oneTimePreKeyId,
    )!;
    const opkPriv = await unwrapStoredPrekeyPrivate(
      opkRow.wrappedPrivateKey,
      bobKek,
    );
    const bobX3dh = acceptSession(bob, spkPriv, opkPriv, aliceX3dh.sessionInit);

    // -----------------------------------------------------------------
    // Initialize the Double Ratchet on both sides from the X3DH SK.
    //
    // Alice's sender ratchet seeds against Bob's signed-prekey public
    // (the same SPK she DH'd against in X3DH); Bob's receiver ratchet
    // is seeded with the matching SPK keypair so the first inbound
    // message under Alice's *new* sending DH pubkey triggers a clean
    // DH ratchet step on Bob's side. This is exactly the boundary
    // design.md §13.1 → §13.2 specifies.
    // -----------------------------------------------------------------
    const bobSpkPub = bobBundle.signedPreKey.publicKey;
    let aliceRatchet: RatchetState = initSenderRatchet(
      aliceX3dh.rootKey,
      bobSpkPub,
    );
    let bobRatchet: RatchetState = initReceiverRatchet(bobX3dh.rootKey, {
      priv: spkPriv,
      pub: bobSpkPub,
    });

    // initReceiverRatchet copied the SPK private bytes; we no longer
    // need our local copy. Same for the OPK private bytes — X3DH has
    // already consumed them.
    spkPriv.fill(0);
    opkPriv.fill(0);

    // -----------------------------------------------------------------
    // P1: for every plaintext in [1..16384] bytes, encrypt on Alice's
    // side and decrypt on Bob's side yields the same bytes. We thread
    // the (mutable) ratchet state across iterations so the chain
    // genuinely advances message-by-message.
    // -----------------------------------------------------------------
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 16384 }),
        async (m) => {
          const sent = await encryptToDevice(aliceRatchet, m);
          aliceRatchet = sent.state;

          const recv = await decryptFromDevice(
            bobRatchet,
            sent.ciphertext,
            sent.header,
          );
          bobRatchet = recv.state;

          if (!recv.result.ok) {
            return false;
          }
          if (recv.result.plaintext.length !== m.length) {
            return false;
          }
          for (let i = 0; i < m.length; i++) {
            if (recv.result.plaintext[i] !== m[i]) {
              return false;
            }
          }
          return true;
        },
      ),
    );
  });
});

// Tests for task 4.2: Crypto_Module X3DH session establishment.
//
// The tests exercise the producer (`session.ts`) end-to-end against
// in-memory identity / prekey stores so the cryptographic agreement is
// validated against the actual @noble/curves + @noble/hashes
// primitives — no mocks, no fakes.
//
// Coverage:
//   - Alice (`establishSession`) and Bob (`acceptSession`) derive the
//     SAME 32-byte root key when fed a well-formed bundle with an OPK
//     (full 4-DH X3DH).
//   - Same agreement holds in degraded mode when the bundle has no
//     OPK (3-DH X3DH per requirement 3.6).
//   - Tampering the signed-prekey signature → `establishSession`
//     throws `InvalidSignedPreKeyError` and produces no value
//     (requirement 4.2).
//   - Tampering the bundle's `identityEdPub` (so the otherwise-valid
//     signature won't verify against the wrong key) → same refusal.

import { describe, expect, it } from 'vitest';

import {
  MemoryIdentityStore,
  getOrCreateIdentity,
  type IdentityKeyPair,
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
  InvalidSignedPreKeyError,
  type RemotePreKeyBundle,
} from '../src/session.js';

// ---------------------------------------------------------------------------
// Fixture: in-memory PreKeyStore (kept in sync with prekeys.test.ts).
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

// ---------------------------------------------------------------------------
// Fixture: provision a peer "Bob" who has enrolled — fresh identity,
// fresh prekey bundle persisted in an in-memory store, and the
// `RemotePreKeyBundle` shape Alice would receive over the wire.
// ---------------------------------------------------------------------------
interface ProvisionedPeer {
  identity: IdentityKeyPair;
  preKeyStore: MemoryPreKeyStore;
  kek: CryptoKey;
  bundle: RemotePreKeyBundle;
}

async function provisionPeer(
  recipientDeviceId = 'bob-device-1',
): Promise<ProvisionedPeer> {
  const idStore = new MemoryIdentityStore();
  const identity = await getOrCreateIdentity(idStore);
  const kek = await idStore.getOrCreateAesKwKey();

  const preKeyStore = new MemoryPreKeyStore();
  const upload = await generateInitialBundle(identity, preKeyStore, kek);

  // Construct a `RemotePreKeyBundle` exactly as the API_Gateway would
  // shape it on `GET /users/:handle/prekey-bundle?deviceId=...`.
  // Pick the first OPK from the upload as the "consumed" one.
  const opk0 = upload.oneTimePreKeys[0]!;
  const bundle: RemotePreKeyBundle = {
    recipientDeviceId,
    identityPub: upload.identityPub,
    identityEdPub: upload.identityEdPub,
    registrationId: upload.registrationId,
    signedPreKey: upload.signedPreKey,
    oneTimePreKey: { keyId: opk0.keyId, publicKey: opk0.publicKey },
  };

  return { identity, preKeyStore, kek, bundle };
}

/**
 * Look up Bob's signed-prekey + one-time prekey private bytes from the
 * in-memory store given the keyIds Alice's `SessionInit` referenced.
 * The caller takes ownership of the returned buffers and must scrub
 * them after `acceptSession` returns.
 */
async function bobUnwrapForAccept(
  bob: ProvisionedPeer,
  signedPreKeyId: number,
  oneTimePreKeyId: number | null,
): Promise<{ spkPriv: Uint8Array; opkPriv: Uint8Array | null }> {
  const spkRow = bob.preKeyStore.signed.find((r) => r.keyId === signedPreKeyId);
  if (spkRow === undefined) {
    throw new Error(`spk keyId ${signedPreKeyId} not found in store`);
  }
  const spkPriv = await unwrapStoredPrekeyPrivate(
    spkRow.wrappedPrivateKey,
    bob.kek,
  );

  let opkPriv: Uint8Array | null = null;
  if (oneTimePreKeyId !== null) {
    const opkRow = bob.preKeyStore.opks.find(
      (r) => r.keyId === oneTimePreKeyId,
    );
    if (opkRow === undefined) {
      throw new Error(`opk keyId ${oneTimePreKeyId} not found in store`);
    }
    opkPriv = await unwrapStoredPrekeyPrivate(opkRow.wrappedPrivateKey, bob.kek);
  }

  return { spkPriv, opkPriv };
}

async function freshAlice(): Promise<IdentityKeyPair> {
  return getOrCreateIdentity(new MemoryIdentityStore());
}

// ---------------------------------------------------------------------------

describe('establishSession + acceptSession (X3DH agreement, requirement 4.1)', () => {
  it('Alice and Bob derive the same 32-byte root key with an OPK (4-DH)', async () => {
    const alice = await freshAlice();
    const bob = await provisionPeer();

    const aliceResult = establishSession(alice, bob.bundle);

    expect(aliceResult.rootKey.length).toBe(32);
    expect(aliceResult.sessionInit.oneTimePreKeyId).not.toBeNull();
    expect(aliceResult.sessionInit.signedPreKeyId).toBe(
      bob.bundle.signedPreKey.keyId,
    );
    expect(Array.from(aliceResult.sessionInit.aliceIdentityPub)).toEqual(
      Array.from(alice.publicKey),
    );

    const { spkPriv, opkPriv } = await bobUnwrapForAccept(
      bob,
      aliceResult.sessionInit.signedPreKeyId,
      aliceResult.sessionInit.oneTimePreKeyId,
    );
    try {
      const bobResult = acceptSession(
        bob.identity,
        spkPriv,
        opkPriv,
        aliceResult.sessionInit,
      );
      expect(bobResult.rootKey.length).toBe(32);
      expect(Array.from(bobResult.rootKey)).toEqual(
        Array.from(aliceResult.rootKey),
      );
    } finally {
      spkPriv.fill(0);
      opkPriv?.fill(0);
    }
  });

  it('agrees in degraded 3-DH mode when the bundle has no OPK (requirement 3.6)', async () => {
    const alice = await freshAlice();
    const bob = await provisionPeer();

    // Drop the OPK from the bundle to simulate the API_Gateway running
    // out of unused one-time prekeys.
    const degradedBundle: RemotePreKeyBundle = {
      ...bob.bundle,
      oneTimePreKey: null,
    };

    const aliceResult = establishSession(alice, degradedBundle);

    expect(aliceResult.rootKey.length).toBe(32);
    expect(aliceResult.sessionInit.oneTimePreKeyId).toBeNull();

    const { spkPriv } = await bobUnwrapForAccept(
      bob,
      aliceResult.sessionInit.signedPreKeyId,
      null,
    );
    try {
      const bobResult = acceptSession(
        bob.identity,
        spkPriv,
        null,
        aliceResult.sessionInit,
      );
      expect(Array.from(bobResult.rootKey)).toEqual(
        Array.from(aliceResult.rootKey),
      );
    } finally {
      spkPriv.fill(0);
    }
  });

  it('two independent establishSession calls produce different ephemeral keys + root keys', async () => {
    // Forward secrecy structural property: each session-init draws a
    // fresh ephemeral, so two sessions to the same peer with the same
    // identity keys yield distinct root keys. (Full P3 forward-secrecy
    // PBT lands in task 4.10.)
    const alice = await freshAlice();
    const bob = await provisionPeer();

    const a1 = establishSession(alice, bob.bundle);
    const a2 = establishSession(alice, bob.bundle);

    expect(Array.from(a1.sessionInit.ephemeralPub)).not.toEqual(
      Array.from(a2.sessionInit.ephemeralPub),
    );
    expect(Array.from(a1.rootKey)).not.toEqual(Array.from(a2.rootKey));
  });
});

describe('establishSession refuses on invalid signed-prekey signature (requirement 4.2)', () => {
  it('throws InvalidSignedPreKeyError when the signature is tampered', async () => {
    const alice = await freshAlice();
    const bob = await provisionPeer();

    const tamperedSig = new Uint8Array(bob.bundle.signedPreKey.signature);
    tamperedSig[0] = (tamperedSig[0]! ^ 0x01) & 0xff;

    const tamperedBundle: RemotePreKeyBundle = {
      ...bob.bundle,
      signedPreKey: { ...bob.bundle.signedPreKey, signature: tamperedSig },
    };

    expect(() => establishSession(alice, tamperedBundle)).toThrow(
      InvalidSignedPreKeyError,
    );
  });

  it("throws InvalidSignedPreKeyError when the bundle's identityEdPub is wrong", async () => {
    // Substitute a *different* peer's Ed25519 identity public key into
    // an otherwise-valid bundle. The signature was produced by the
    // original peer's signing key, so it cannot verify against the
    // substituted public key.
    const alice = await freshAlice();
    const bob = await provisionPeer();
    const eve = await provisionPeer('eve-device-1');

    const tamperedBundle: RemotePreKeyBundle = {
      ...bob.bundle,
      identityEdPub: eve.bundle.identityEdPub,
    };

    expect(() => establishSession(alice, tamperedBundle)).toThrow(
      InvalidSignedPreKeyError,
    );
  });

  it('refusal is total: no rootKey, no sessionInit returned', async () => {
    const alice = await freshAlice();
    const bob = await provisionPeer();

    // Flip every byte of the signature so even a wildly improbable
    // collision-with-zero-flip can't slip through.
    const trashSig = new Uint8Array(bob.bundle.signedPreKey.signature.length);
    for (let i = 0; i < trashSig.length; i++) {
      trashSig[i] = bob.bundle.signedPreKey.signature[i]! ^ 0xff;
    }
    const tamperedBundle: RemotePreKeyBundle = {
      ...bob.bundle,
      signedPreKey: { ...bob.bundle.signedPreKey, signature: trashSig },
    };

    let captured: unknown;
    try {
      establishSession(alice, tamperedBundle);
    } catch (e) {
      captured = e;
    }
    expect(captured).toBeInstanceOf(InvalidSignedPreKeyError);
    // The function returned nothing (it threw); there is no
    // partial-state to assert against because the module is purely
    // functional. This test documents that contract.
  });
});

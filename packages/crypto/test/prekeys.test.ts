// Tests for task 2.8: Crypto_Module prekey generation, replenishment,
// and rotation.
//
// The tests exercise the producer (`prekeys.ts`) against an in-memory
// `PreKeyStore` so the cryptographic logic is decoupled from Dexie /
// IndexedDB. The Dexie wiring is tested separately in
// `apps/web/test/db-identity.test.ts` plus the prekey-store tests that
// land alongside task 2.9's repository.

import { ed25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';

import {
  MemoryIdentityStore,
  getOrCreateIdentity,
  type IdentityKeyPair,
} from '../src/identity.js';
import {
  ONE_TIME_PREKEY_TARGET,
  ONE_TIME_PREKEY_THRESHOLD,
  SIGNED_PREKEY_MAX_AGE_MS,
  generateInitialBundle,
  type OneTimePreKeyRecord,
  type PreKeyStore,
  replenishOneTimePreKeys,
  rotateSignedPreKey,
  shouldRotateSignedPreKey,
  type SignedPreKeyRecord,
  verifySignedPreKeySignature,
} from '../src/prekeys.js';

// ---------------------------------------------------------------------------
// Fixture: in-memory PreKeyStore.
//
// Mirrors the production Dexie-backed `DexiePreKeyStore` semantics but
// keeps everything in arrays. KeyId allocators are monotonic and start at
// 1 (libsignal treats 0 as a sentinel in some flows).
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

async function freshIdentity(): Promise<{
  identity: IdentityKeyPair;
  kek: CryptoKey;
}> {
  const idStore = new MemoryIdentityStore();
  const identity = await getOrCreateIdentity(idStore);
  const kek = await idStore.getOrCreateAesKwKey();
  return { identity, kek };
}

// ---------------------------------------------------------------------------

describe('generateInitialBundle', () => {
  it('returns 1 signed prekey + 100 OPKs (requirement 3.1)', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const bundle = await generateInitialBundle(identity, store, kek);

    expect(bundle.oneTimePreKeys.length).toBe(ONE_TIME_PREKEY_TARGET);
    expect(store.signed.length).toBe(1);
    expect(store.opks.length).toBe(ONE_TIME_PREKEY_TARGET);
    expect(await store.listUnusedOneTimePreKeyCount()).toBe(
      ONE_TIME_PREKEY_TARGET,
    );
  });

  it('signed prekey signature is 64 bytes and verifies via Ed25519 (requirement 3.2)', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const bundle = await generateInitialBundle(identity, store, kek);
    const spk = bundle.signedPreKey;

    expect(spk.signature.length).toBe(64);
    expect(spk.publicKey.length).toBe(32);

    // Direct verify using @noble/curves to avoid relying on the helper.
    const ok = ed25519.verify(
      spk.signature,
      spk.publicKey,
      identity.ed25519PublicKey,
    );
    expect(ok).toBe(true);

    // And via the package helper.
    expect(verifySignedPreKeySignature(spk, bundle.identityEdPub)).toBe(true);
  });

  it('uploads identityPub, identityEdPub, and registrationId from identity', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const bundle = await generateInitialBundle(identity, store, kek);

    expect(Array.from(bundle.identityPub)).toEqual(
      Array.from(identity.publicKey),
    );
    expect(Array.from(bundle.identityEdPub)).toEqual(
      Array.from(identity.ed25519PublicKey),
    );
    expect(bundle.registrationId).toBe(identity.registrationId);
  });

  it('produces 100 OPKs with strictly increasing, unique keyIds', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const bundle = await generateInitialBundle(identity, store, kek);
    const ids = bundle.oneTimePreKeys.map((k) => k.keyId);

    expect(new Set(ids).size).toBe(ids.length);
    for (let i = 1; i < ids.length; i++) {
      expect(ids[i]!).toBeGreaterThan(ids[i - 1]!);
    }
  });

  it('throws when called twice on a non-empty store', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    await generateInitialBundle(identity, store, kek);

    await expect(generateInitialBundle(identity, store, kek)).rejects.toThrow(
      /not empty/i,
    );
  });

  it('persists OPKs as wrapped private bytes (40 bytes via AES-KW), never raw', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const bundle = await generateInitialBundle(identity, store, kek);

    // AES-KW ciphertext is `inputLength + 8` bytes (RFC 3394) → 32 → 40.
    for (const row of store.opks) {
      expect(row.wrappedPrivateKey.length).toBe(40);
      expect(row.publicKey.length).toBe(32);
      expect(row.used).toBe(false);
    }
    expect(store.signed[0]!.wrappedPrivateKey.length).toBe(40);

    // The uploaded bundle never carries private bytes.
    for (let i = 0; i < bundle.oneTimePreKeys.length; i++) {
      const dto = bundle.oneTimePreKeys[i]!;
      expect(dto.publicKey.length).toBe(32);
      // The DTO has no `wrappedPrivateKey` field — nothing to assert
      // beyond the public-only shape, which TS already enforces.
    }
  });
});

describe('replenishOneTimePreKeys (requirement 3.3)', () => {
  it('is a no-op when count >= threshold', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    await generateInitialBundle(identity, store, kek);
    expect(await store.listUnusedOneTimePreKeyCount()).toBe(
      ONE_TIME_PREKEY_TARGET,
    );

    const minted = await replenishOneTimePreKeys(identity, store, kek);
    expect(minted.length).toBe(0);
    expect(await store.listUnusedOneTimePreKeyCount()).toBe(
      ONE_TIME_PREKEY_TARGET,
    );
  });

  it('mints exactly (target − count) when count < threshold', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    await generateInitialBundle(identity, store, kek);

    // Mark all but 15 as used → triggers replenishment.
    const keepUnused = 15;
    for (let i = 0; i < ONE_TIME_PREKEY_TARGET - keepUnused; i++) {
      const r = store.opks[i]!;
      store.opks[i] = { ...r, used: true };
    }
    expect(await store.listUnusedOneTimePreKeyCount()).toBe(keepUnused);

    const minted = await replenishOneTimePreKeys(identity, store, kek);

    expect(minted.length).toBe(ONE_TIME_PREKEY_TARGET - keepUnused);
    expect(await store.listUnusedOneTimePreKeyCount()).toBe(
      ONE_TIME_PREKEY_TARGET,
    );

    // New keys must use fresh keyIds (strictly greater than every prior).
    const priorMaxId = ONE_TIME_PREKEY_TARGET; // initial allocator gave 1..100
    for (const k of minted) {
      expect(k.keyId).toBeGreaterThan(priorMaxId);
    }
    expect(new Set(minted.map((k) => k.keyId)).size).toBe(minted.length);
  });

  it('uses ONE_TIME_PREKEY_THRESHOLD = 20 and ONE_TIME_PREKEY_TARGET = 100 by default', () => {
    // Sanity-check the defaults match the requirement.
    expect(ONE_TIME_PREKEY_THRESHOLD).toBe(20);
    expect(ONE_TIME_PREKEY_TARGET).toBe(100);
  });

  it('rejects target < threshold', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    await expect(
      replenishOneTimePreKeys(identity, store, kek, 50, 10),
    ).rejects.toThrow();
  });
});

describe('rotateSignedPreKey (requirement 3.7)', () => {
  it('produces a new signed prekey with a different keyId and a valid signature', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const initial = await generateInitialBundle(identity, store, kek);
    const before = initial.signedPreKey;

    const after = await rotateSignedPreKey(identity, store, kek);

    expect(after.keyId).not.toBe(before.keyId);
    expect(after.keyId).toBeGreaterThan(before.keyId);
    expect(after.signature.length).toBe(64);
    expect(
      ed25519.verify(after.signature, after.publicKey, identity.ed25519PublicKey),
    ).toBe(true);

    // Both signed prekeys persist; `getCurrentSignedPreKey` returns the
    // newer one.
    expect(store.signed.length).toBe(2);
    const current = await store.getCurrentSignedPreKey();
    expect(current).not.toBeNull();
    expect(current!.keyId).toBe(after.keyId);
  });

  it('does not mint additional OPKs', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    await generateInitialBundle(identity, store, kek);
    const before = store.opks.length;

    await rotateSignedPreKey(identity, store, kek);
    expect(store.opks.length).toBe(before);
  });
});

describe('shouldRotateSignedPreKey (requirement 3.7)', () => {
  it('false at age 1 day, true at age 7 days', () => {
    const now = 1_000_000_000_000;
    const oneDay = 24 * 60 * 60 * 1000;

    expect(shouldRotateSignedPreKey({ createdAt: now - oneDay }, now)).toBe(
      false,
    );
    expect(
      shouldRotateSignedPreKey({ createdAt: now - 7 * oneDay }, now),
    ).toBe(true);
  });

  it('true exactly at SIGNED_PREKEY_MAX_AGE_MS, false one ms before', () => {
    const now = 2_000_000_000_000;
    expect(
      shouldRotateSignedPreKey(
        { createdAt: now - SIGNED_PREKEY_MAX_AGE_MS },
        now,
      ),
    ).toBe(true);
    expect(
      shouldRotateSignedPreKey(
        { createdAt: now - SIGNED_PREKEY_MAX_AGE_MS + 1 },
        now,
      ),
    ).toBe(false);
  });
});

describe('verifySignedPreKeySignature (requirement 3.2)', () => {
  it('rejects a tampered signature', async () => {
    const { identity, kek } = await freshIdentity();
    const store = new MemoryPreKeyStore();
    const bundle = await generateInitialBundle(identity, store, kek);

    const tampered = new Uint8Array(bundle.signedPreKey.signature);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff;

    expect(
      verifySignedPreKeySignature(
        { ...bundle.signedPreKey, signature: tampered },
        bundle.identityEdPub,
      ),
    ).toBe(false);
  });

  it('rejects when verifier holds a different identity Ed25519 key', async () => {
    const { identity: a, kek: aKek } = await freshIdentity();
    const { identity: b } = await freshIdentity();
    const store = new MemoryPreKeyStore();

    const bundle = await generateInitialBundle(a, store, aKek);
    expect(
      verifySignedPreKeySignature(bundle.signedPreKey, b.ed25519PublicKey),
    ).toBe(false);
  });
});

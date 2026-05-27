// Tests for task 2.9: Dexie identity repository.
//
// Scope (per task brief):
//   - `saveWrappedIdentity` then `loadWrappedIdentity` returns the same
//     data (round-trip).
//   - `getOrCreateAesKwKey` returns the same key on repeat calls
//     (idempotent KEK).
//
// Tests run under jsdom + fake-indexeddb (see `test/setup.ts`), so they
// exercise the real Dexie and structured-clone code paths without
// needing a browser.

import { afterEach, describe, expect, it } from 'vitest';

import { DexieIdentityStore } from '../src/db/repositories/identity.js';
import { KonvoDb } from '../src/db/schema.js';

// Each test gets a fresh DB name to avoid cross-test bleed under
// fake-indexeddb (which keeps the in-memory store global to the
// process). We also explicitly close + delete the DB after each test
// to free schema versions.
let activeDb: KonvoDb | null = null;
function freshDb(): KonvoDb {
  const name = `konvo-test-${Math.random().toString(36).slice(2)}`;
  activeDb = new KonvoDb(name);
  return activeDb;
}

afterEach(async () => {
  if (activeDb !== null) {
    activeDb.close();
    await activeDb.delete();
    activeDb = null;
  }
});

describe('DexieIdentityStore', () => {
  it('returns null before anything is saved', async () => {
    const store = new DexieIdentityStore(freshDb());
    expect(await store.loadWrappedIdentity()).toBeNull();
  });

  it('round-trips saveWrappedIdentity → loadWrappedIdentity', async () => {
    const store = new DexieIdentityStore(freshDb());

    const publicKey = new Uint8Array(32);
    publicKey.fill(0xab);
    const wrappedPrivateKey = new Uint8Array(40); // AES-KW of 32 bytes = 40
    wrappedPrivateKey.fill(0xcd);
    const ed25519PublicKey = new Uint8Array(32);
    ed25519PublicKey.fill(0xef);
    const wrappedEd25519PrivateKey = new Uint8Array(40);
    wrappedEd25519PrivateKey.fill(0x12);
    const registrationId = 4242;

    await store.saveWrappedIdentity({
      publicKey,
      wrappedPrivateKey,
      ed25519PublicKey,
      wrappedEd25519PrivateKey,
      registrationId,
    });

    const loaded = await store.loadWrappedIdentity();
    if (loaded === null) {
      throw new Error('expected wrapped identity to be persisted');
    }
    expect(loaded.registrationId).toBe(registrationId);
    expect(Array.from(loaded.publicKey)).toEqual(Array.from(publicKey));
    expect(Array.from(loaded.wrappedPrivateKey)).toEqual(
      Array.from(wrappedPrivateKey),
    );
    expect(Array.from(loaded.ed25519PublicKey)).toEqual(
      Array.from(ed25519PublicKey),
    );
    expect(Array.from(loaded.wrappedEd25519PrivateKey)).toEqual(
      Array.from(wrappedEd25519PrivateKey),
    );
  });

  it('saveWrappedIdentity is idempotent (last write wins)', async () => {
    const store = new DexieIdentityStore(freshDb());

    await store.saveWrappedIdentity({
      publicKey: new Uint8Array(32).fill(0x11),
      wrappedPrivateKey: new Uint8Array(40).fill(0x22),
      ed25519PublicKey: new Uint8Array(32).fill(0x55),
      wrappedEd25519PrivateKey: new Uint8Array(40).fill(0x66),
      registrationId: 1,
    });
    await store.saveWrappedIdentity({
      publicKey: new Uint8Array(32).fill(0x33),
      wrappedPrivateKey: new Uint8Array(40).fill(0x44),
      ed25519PublicKey: new Uint8Array(32).fill(0x77),
      wrappedEd25519PrivateKey: new Uint8Array(40).fill(0x88),
      registrationId: 9999,
    });

    const loaded = await store.loadWrappedIdentity();
    if (loaded === null) {
      throw new Error('expected wrapped identity to be persisted');
    }
    expect(loaded.registrationId).toBe(9999);
    expect(loaded.publicKey[0]).toBe(0x33);
    expect(loaded.ed25519PublicKey[0]).toBe(0x77);
  });

  it('getOrCreateAesKwKey returns the same key on repeat calls', async () => {
    const store = new DexieIdentityStore(freshDb());

    const k1 = await store.getOrCreateAesKwKey();
    const k2 = await store.getOrCreateAesKwKey();

    // The KEK is non-extractable, so we can't compare bytes. We rely on
    // the structured-clone identity preserved by IndexedDB: the second
    // call returns the persisted CryptoKey. As a behavioural check, both
    // keys MUST refuse `exportKey('raw', ...)`.
    expect(k1.algorithm.name).toBe('AES-KW');
    expect(k2.algorithm.name).toBe('AES-KW');
    expect(k1.extractable).toBe(false);
    expect(k2.extractable).toBe(false);
    expect(k1.usages.sort()).toEqual(['unwrapKey', 'wrapKey']);
    expect(k2.usages.sort()).toEqual(['unwrapKey', 'wrapKey']);

    // Functional equivalence: wrap a probe key with k1, unwrap with k2.
    // If k1 and k2 are the same persisted KEK (as required) the wrap →
    // unwrap round-trips; if they were independently generated the
    // unwrap would fail with an OperationError.
    const probe = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      /* extractable */ true,
      ['sign'],
    );
    const wrapped = await crypto.subtle.wrapKey('raw', probe, k1, 'AES-KW');
    const unwrapped = await crypto.subtle.unwrapKey(
      'raw',
      wrapped,
      k2,
      'AES-KW',
      { name: 'HMAC', hash: 'SHA-256' },
      /* extractable */ true,
      ['sign'],
    );
    expect(unwrapped.algorithm.name).toBe('HMAC');
  });
});

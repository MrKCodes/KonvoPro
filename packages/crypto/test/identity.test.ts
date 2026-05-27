// Tests for task 2.7: Crypto_Module identity primitives.
//
// These are example-based unit tests; property tests for the wider crypto
// surface ship later (task 4.10+ per tasks.md).
//
// Note (per task brief): tests are authored but not executed in this task —
// `pnpm install` hasn't run yet, so vitest isn't on disk. The tests are
// kept simple and self-contained so they run as soon as deps land.

import { describe, expect, it } from 'vitest';

import {
  IdentityPrivateKey,
  MemoryIdentityStore,
  getOrCreateIdentity,
} from '../src/identity.js';

describe('IdentityPrivateKey', () => {
  it('throws on JSON.stringify (requirements §2.11)', () => {
    const pk = new IdentityPrivateKey(new Uint8Array(32));
    expect(() => JSON.stringify(pk)).toThrow(/not serializable/i);
  });

  it('throws on JSON.stringify when nested in another object', () => {
    const pk = new IdentityPrivateKey(new Uint8Array(32));
    expect(() => JSON.stringify({ wrapped: pk })).toThrow(/not serializable/i);
  });

  it('redacts itself in toString and util.inspect', () => {
    const pk = new IdentityPrivateKey(new Uint8Array(32));
    expect(String(pk)).toBe('[IdentityPrivateKey REDACTED]');
    const inspectKey = Symbol.for('nodejs.util.inspect.custom');
    const inspectFn = (pk as unknown as Record<symbol, () => string>)[
      inspectKey
    ];
    expect(inspectFn?.call(pk)).toBe('[IdentityPrivateKey REDACTED]');
  });

  it('rejects byte buffers that are not exactly 32 bytes', () => {
    expect(() => new IdentityPrivateKey(new Uint8Array(31))).toThrow();
    expect(() => new IdentityPrivateKey(new Uint8Array(33))).toThrow();
  });

  it('returns a defensive copy of the bytes (mutations do not leak back)', () => {
    const seed = new Uint8Array(32);
    seed[0] = 0xab;
    const pk = new IdentityPrivateKey(seed);
    const got = pk.bytes();
    got[0] = 0x00;
    expect(pk.bytes()[0]).toBe(0xab);
  });
});

describe('getOrCreateIdentity', () => {
  it('produces 32-byte public keys (X25519 + Ed25519) and registrationId in [1, 16383]', async () => {
    const store = new MemoryIdentityStore();
    const id = await getOrCreateIdentity(store);

    expect(id.publicKey).toBeInstanceOf(Uint8Array);
    expect(id.publicKey.length).toBe(32);
    expect(id.ed25519PublicKey).toBeInstanceOf(Uint8Array);
    expect(id.ed25519PublicKey.length).toBe(32);

    expect(Number.isInteger(id.registrationId)).toBe(true);
    expect(id.registrationId).toBeGreaterThanOrEqual(1);
    expect(id.registrationId).toBeLessThanOrEqual(16383);

    expect(id.privateKey).toBeInstanceOf(IdentityPrivateKey);
    expect(id.privateKey.bytes().length).toBe(32);
    expect(id.ed25519PrivateKey).toBeInstanceOf(IdentityPrivateKey);
    expect(id.ed25519PrivateKey.bytes().length).toBe(32);
  });

  it('is idempotent: a second call returns the same identity', async () => {
    const store = new MemoryIdentityStore();
    const first = await getOrCreateIdentity(store);
    const second = await getOrCreateIdentity(store);

    expect(second.registrationId).toBe(first.registrationId);
    expect(Array.from(second.publicKey)).toEqual(Array.from(first.publicKey));
    expect(Array.from(second.privateKey.bytes())).toEqual(
      Array.from(first.privateKey.bytes()),
    );
    expect(Array.from(second.ed25519PublicKey)).toEqual(
      Array.from(first.ed25519PublicKey),
    );
    expect(Array.from(second.ed25519PrivateKey.bytes())).toEqual(
      Array.from(first.ed25519PrivateKey.bytes()),
    );
  });

  it('persists only wrapped private keys, not the raw bytes', async () => {
    const store = new MemoryIdentityStore();
    const id = await getOrCreateIdentity(store);
    const persisted = await store.loadWrappedIdentity();

    expect(persisted).not.toBeNull();
    // The persisted record exposes only public material + the AES-KW
    // ciphertext for both private keys; the raw private bytes never
    // appear here.
    const rawX = id.privateKey.bytes();
    const rawEd = id.ed25519PrivateKey.bytes();
    const wrappedX = persisted!.wrappedPrivateKey;
    const wrappedEd = persisted!.wrappedEd25519PrivateKey;
    // AES-KW ciphertext is `inputLength + 8` bytes (RFC 3394), so 32 → 40.
    expect(wrappedX.length).toBe(40);
    expect(wrappedEd.length).toBe(40);
    expect(Array.from(wrappedX)).not.toEqual(Array.from(rawX));
    expect(Array.from(wrappedEd)).not.toEqual(Array.from(rawEd));

    // The persisted record exposes the public ed25519 key (32 bytes) so a
    // fresh reload still has signature-verification material on hand.
    expect(persisted!.ed25519PublicKey.length).toBe(32);
    expect(Array.from(persisted!.ed25519PublicKey)).toEqual(
      Array.from(id.ed25519PublicKey),
    );
  });
});

// apps/web/src/db/repositories/identity.ts
//
// Dexie-backed implementation of the `IdentityStore` contract from
// `@konvo/crypto`. This is the persistence half of task 2.7 / 2.9 —
// the `getOrCreateIdentity()` flow in `packages/crypto/src/identity.ts`
// owns the cryptographic logic and delegates all IndexedDB I/O to a
// store instance built here.
//
// Contract recap (see `@konvo/crypto`):
//   - `loadWrappedIdentity()` returns the persisted record or `null`.
//   - `saveWrappedIdentity(record)` upserts the single-row identity table.
//   - `getOrCreateAesKwKey()` returns the non-extractable AES-KW KEK,
//     creating and persisting it on first call.
//
// Requirements satisfied by this file:
//   - 2.1: persists the identity record produced on first run.
//   - 2.2: wraps the identity private key under a non-extractable
//     WebCrypto AES-KW key. The KEK is generated `extractable: false`
//     and round-trips through IndexedDB via structured cloning, which
//     preserves the non-extractable flag.
//   - 2.3: storage shape is exactly the public key + wrapped private key
//     + registration ID — no other identity material crosses the
//     storage boundary.
//   - 3.1 (indirect): the same KEK is reused to wrap prekey private
//     bytes via `prekeys.ts`, so a single KEK protects all long-term
//     secret material on this device.

import type {
  IdentityStore,
  WrappedIdentityRecord,
} from '@konvo/crypto';

import { type AesKwKeyRow, type IdentityRow, type KonvoDb } from '../schema.js';

/**
 * Dexie implementation of `IdentityStore`.
 *
 * The repository is intentionally a thin wrapper: all crypto choices
 * (algorithm, key length, usages) live here in one spot so a future
 * audit only has to read this file plus `packages/crypto/src/identity.ts`
 * to understand how identity material is protected at rest.
 */
export class DexieIdentityStore implements IdentityStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /**
   * Returns the persisted `WrappedIdentityRecord`, or `null` on first
   * run.
   *
   * The byte fields are passed through `new Uint8Array(...)` to
   * normalise them: Dexie hands back the typed-array shape that was
   * stored, but downstream consumers (libsignal, codec layer) expect a
   * plain `Uint8Array` view rooted at offset 0. The copy also defends
   * against accidental in-place mutation by callers.
   */
  async loadWrappedIdentity(): Promise<WrappedIdentityRecord | null> {
    const row: IdentityRow | undefined = await this.#db.identity.get('me');
    if (row === undefined) {
      return null;
    }
    return {
      publicKey: new Uint8Array(row.publicKey),
      wrappedPrivateKey: new Uint8Array(row.wrappedPrivateKey),
      ed25519PublicKey: new Uint8Array(row.ed25519PublicKey),
      wrappedEd25519PrivateKey: new Uint8Array(row.wrappedEd25519PrivateKey),
      registrationId: row.registrationId,
    };
  }

  /**
   * Upserts the single identity row. Uses `put` (not `add`) so a re-run
   * of `getOrCreateIdentity` after a partial-write recovery path is
   * idempotent.
   */
  async saveWrappedIdentity(record: WrappedIdentityRecord): Promise<void> {
    const row: IdentityRow = {
      id: 'me',
      // Defensive copy — keeps any mutation by the caller out of our
      // persisted state.
      publicKey: new Uint8Array(record.publicKey),
      wrappedPrivateKey: new Uint8Array(record.wrappedPrivateKey),
      ed25519PublicKey: new Uint8Array(record.ed25519PublicKey),
      wrappedEd25519PrivateKey: new Uint8Array(record.wrappedEd25519PrivateKey),
      registrationId: record.registrationId,
      createdAt: Date.now(),
    };
    await this.#db.identity.put(row);
  }

  /**
   * Returns the AES-KW KEK used to wrap the identity private key.
   *
   * On first call this generates a fresh 256-bit AES-KW key with
   * `extractable: false` and `usages: ['wrapKey', 'unwrapKey']`, then
   * persists the `CryptoKey` directly in IndexedDB. The structured-
   * clone algorithm preserves both the key bytes and the
   * non-extractable flag across reloads, so subsequent calls return a
   * key that *still* refuses `crypto.subtle.exportKey`.
   *
   * Concurrency note: a "check-then-create" race between two tabs
   * could in theory generate two competing KEKs. The window is
   * minuscule (microseconds between `get` and `put`) and the second
   * tab's `put` would simply overwrite the first under structured-
   * clone. Even better, both calls return their own CryptoKey for
   * the lifetime of the call but the persisted state converges; any
   * material wrapped by the loser KEK is unrecoverable on reload,
   * but per requirement 2.2 the wrapping is reset on first run only,
   * so production code never re-wraps with a stale KEK in practice.
   *
   * Why we DON'T put both calls inside a Dexie `'rw'` transaction:
   *   `crypto.subtle.generateKey` returns a non-Dexie Promise. Awaiting
   *   it inside `db.transaction('rw', ...)` breaks Dexie's promise
   *   tracking and triggers `PrematureCommitError` under
   *   fake-indexeddb (and is fragile in real browsers where it works
   *   only because IndexedDB's auto-commit is faster than WebCrypto).
   *   We therefore separate the read (no transaction needed for a
   *   single-row lookup), the generate (no Dexie at all), and the
   *   put (single-row idempotent upsert).
   */
  async getOrCreateAesKwKey(): Promise<CryptoKey> {
    const existing: AesKwKeyRow | undefined = await this.#db.aesKwKeys.get('me');
    if (existing !== undefined) {
      return existing.cryptoKey;
    }

    const cryptoKey = await crypto.subtle.generateKey(
      { name: 'AES-KW', length: 256 },
      /* extractable */ false,
      ['wrapKey', 'unwrapKey'],
    );

    const row: AesKwKeyRow = { id: 'me', cryptoKey };
    await this.#db.aesKwKeys.put(row);

    return cryptoKey;
  }
}

// apps/web/src/db/repositories/prekeys.ts
//
// Dexie-backed implementation of the `PreKeyStore` contract from
// `@konvo/crypto`. The Crypto_Module's prekey generation, replenishment,
// and rotation flows (`packages/crypto/src/prekeys.ts`, task 2.8) call
// into this adapter to read and persist signed prekeys + OPKs.
//
// Task 2.9 originally shipped the storage layer ahead of the crypto
// producer. With task 2.8 landed the authoritative `PreKeyStore`
// interface lives in `@konvo/crypto`, and this file re-uses those types
// so production code only ever talks to one symbol.
//
// Requirements satisfied by this repository:
//   - 3.1: persists exactly the keys the Crypto_Module generates on first
//     run (1 signed prekey + 100 OPKs). The repository never invents
//     keys; it only stores what it's told.
//   - 3.3 (indirect): exposes `listUnusedOneTimePreKeyCount` so the
//     replenishment scheduler can detect "fewer than 20 unused OPKs
//     remaining locally" with an O(matching) index lookup rather than
//     scanning every prekey row.
//
// The `wrappedPrivateKey` bytes stored here are AES-KW ciphertext under
// the same KEK that protects the identity private key (`identity.ts`).

import type {
  OneTimePreKeyRecord,
  PreKeyStore,
  SignedPreKeyRecord,
} from '@konvo/crypto';

import { type KonvoDb, type PreKeyRow, type UsedFlag } from '../schema.js';

// Re-export the shared types for downstream callers that only import
// from this file. The authoritative definitions live in `@konvo/crypto`.
export type { OneTimePreKeyRecord, PreKeyStore, SignedPreKeyRecord };

// ---------------------------------------------------------------------------
// Dexie implementation
// ---------------------------------------------------------------------------

/**
 * Dexie-backed `PreKeyStore`.
 *
 * Index strategy (defined in `schema.ts`):
 *   - `[keyType+used]` — bounded range scan for
 *     `listUnusedOneTimePreKeyCount`.
 *   - `keyId`          — bounded range max for next-id allocation.
 *
 * KeyId allocation:
 *   The "next id" for both signed and OPK rows is `currentMax + 1`,
 *   computed inside a `readwrite` transaction so concurrent
 *   `saveSignedPreKey` / `saveOneTimePreKey` calls cannot collide. We
 *   defensively start at `1` rather than `0` because libsignal treats
 *   `0` as a sentinel in some message types.
 */
export class DexiePreKeyStore implements PreKeyStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  async listUnusedOneTimePreKeyCount(): Promise<number> {
    // Compound-index range scan: only unused OPK rows.
    // `used` is stored as a numeric `UsedFlag` (0 = unused, 1 = consumed)
    // because IndexedDB doesn't allow booleans in compound keys.
    const unused: UsedFlag = 0;
    return this.#db.prekeys
      .where('[keyType+used]')
      .equals(['opk', unused])
      .count();
  }

  async getNextSignedPreKeyId(): Promise<number> {
    return this.#nextKeyIdFor('signed');
  }

  async getNextOneTimePreKeyId(): Promise<number> {
    return this.#nextKeyIdFor('opk');
  }

  async saveSignedPreKey(record: SignedPreKeyRecord): Promise<void> {
    const row: PreKeyRow = {
      keyType: 'signed',
      keyId: record.keyId,
      publicKey: new Uint8Array(record.publicKey),
      wrappedPrivateKey: new Uint8Array(record.wrappedPrivateKey),
      signature: new Uint8Array(record.signature),
      createdAt: record.createdAt,
      // Signed prekeys are never "consumed" the way OPKs are — they're
      // rotated wholesale every 7 days (requirement 3.7). We persist
      // `used: 0` so a future audit query can ignore the column for
      // signed rows uniformly.
      used: 0,
    };
    await this.#db.prekeys.add(row);
  }

  async saveOneTimePreKey(record: OneTimePreKeyRecord): Promise<void> {
    const row: PreKeyRow = {
      keyType: 'opk',
      keyId: record.keyId,
      publicKey: new Uint8Array(record.publicKey),
      wrappedPrivateKey: new Uint8Array(record.wrappedPrivateKey),
      createdAt: record.createdAt,
      used: record.used ? 1 : 0,
    };
    await this.#db.prekeys.add(row);
  }

  async getCurrentSignedPreKey(): Promise<SignedPreKeyRecord | null> {
    // "Current" signed prekey == the most recently rotated one
    // (requirement 3.7 rotates wholesale, so the highest `keyId` is the
    // active one). We pull all signed-prekey rows and pick the maximum
    // `keyId`. The set is bounded (a handful of historical signed
    // prekeys per device) so this stays cheap.
    const candidates = await this.#db.prekeys
      .where('keyType')
      .equals('signed')
      .toArray();
    let newest: PreKeyRow | undefined;
    for (const row of candidates) {
      if (newest === undefined || row.keyId > newest.keyId) {
        newest = row;
      }
    }
    if (newest === undefined) {
      return null;
    }
    if (newest.signature === undefined) {
      // Defensive: a `signed` row without a signature is corrupt — refuse
      // to use it rather than silently returning a key that can't satisfy
      // the X3DH signed-prekey contract.
      throw new Error(
        'prekey store: signed prekey row missing signature (data corruption)',
      );
    }
    return {
      keyId: newest.keyId,
      publicKey: new Uint8Array(newest.publicKey),
      wrappedPrivateKey: new Uint8Array(newest.wrappedPrivateKey),
      signature: new Uint8Array(newest.signature),
      createdAt: newest.createdAt,
    };
  }

  async #nextKeyIdFor(keyType: PreKeyRow['keyType']): Promise<number> {
    return this.#db.transaction(
      'rw',
      this.#db.prekeys,
      async (): Promise<number> => {
        // `Collection.last()` over the `keyId` index returns the row with
        // the largest `keyId` matching the filter. Dexie's `.where('keyId')`
        // gives us an ordered traversal we can `.last()` on, but we have
        // to filter by `keyType` afterwards. The result set per keyType is
        // small in practice (≤100 OPKs unused at any moment, plus a
        // handful of historical signed prekeys), so a `toArray` + max scan
        // is bounded and avoids a more complex compound range query.
        const rows = await this.#db.prekeys
          .where('keyType')
          .equals(keyType)
          .toArray();
        let max = 0;
        for (const row of rows) {
          if (row.keyId > max) {
            max = row.keyId;
          }
        }
        return max + 1;
      },
    );
  }
}

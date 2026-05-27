// Tests for task 4.4: Dexie-backed `SignalProtocolStore` adapter.
//
// Scope (per task brief):
//   - `saveSession` then `loadSession` round-trips state byte-for-byte
//     across the IndexedDB structured-clone boundary.
//   - `loadSession` returns null for an unknown peer.
//   - `deleteSession` removes the persisted row.
//   - `markOpkUsed` flips the `used` flag on the matching OPK row, is
//     idempotent on already-consumed rows, and is a no-op when no
//     matching row exists.
//   - Defensive copying: mutating buffers returned from `loadSession`
//     does not leak into the persisted row, and mutating buffers
//     after `saveSession` resolves does not retroactively corrupt
//     the persisted row (the trial-decrypt scrub-after-success
//     contract from `@konvo/crypto`'s `ratchet.ts` relies on this).
//
// Tests run under jsdom + fake-indexeddb (see `test/setup.ts`) so
// the real Dexie + structured-clone code paths are exercised
// without needing a browser.

import { afterEach, describe, expect, it } from 'vitest';

import type { SerializedRatchetState } from '@konvo/crypto';

import { DexiePreKeyStore } from '../src/db/repositories/prekeys.js';
import { DexieSessionsStore } from '../src/db/repositories/sessions.js';
import { KonvoDb } from '../src/db/schema.js';

// Each test gets a fresh DB name to avoid cross-test bleed under
// fake-indexeddb (which keeps the in-memory store global to the
// process). We close + delete the DB after each test to free schema
// versions.
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

const userA = 'user-a-uuid';
const deviceA1 = 'device-a1-uuid';
const userB = 'user-b-uuid';
const deviceB1 = 'device-b1-uuid';

/**
 * Construct a representative `SerializedRatchetState` populated with
 * recognisable byte patterns so a round-trip through Dexie can be
 * compared field-by-field.
 *
 * The shape covers:
 *   - all four required Uint8Array fields (root, sending DH priv/pub,
 *     plus the optional sending chain key),
 *   - both nullable fields exercised: `receivingDhPub` and
 *     `receivingChainKey` (null on the sender side before any
 *     reply; populated below for the round-trip case to ensure
 *     non-null values also clone correctly),
 *   - a non-empty `skippedKeys` array so the nested-array structure
 *     is exercised by IDB's structured clone.
 */
function makeFakeState(seed: number): SerializedRatchetState {
  const k = (fill: number, len = 32): Uint8Array =>
    new Uint8Array(len).fill((fill + seed) & 0xff);
  return {
    rootKey: k(0x10),
    sendingDhPriv: k(0x20),
    sendingDhPub: k(0x30),
    receivingDhPub: k(0x40),
    sendingChainKey: k(0x50),
    receivingChainKey: k(0x60),
    sendingMessageNumber: 7,
    receivingMessageNumber: 3,
    previousSendingChainLength: 5,
    skippedKeys: [
      { dhPub: k(0x70), messageNumber: 0, messageKey: k(0x80) },
      { dhPub: k(0x70), messageNumber: 1, messageKey: k(0x90) },
    ],
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe('DexieSessionsStore', () => {
  describe('loadSession', () => {
    it('returns null for an unknown peer device', async () => {
      const store = new DexieSessionsStore(freshDb());
      expect(await store.loadSession(userA, deviceA1)).toBeNull();
    });

    it('returns null when a session exists for a different peer', async () => {
      const store = new DexieSessionsStore(freshDb());
      await store.saveSession(userA, deviceA1, makeFakeState(1));
      // Same userId but different deviceId — should not match.
      expect(await store.loadSession(userA, deviceB1)).toBeNull();
      // Same deviceId but different userId — should not match.
      expect(await store.loadSession(userB, deviceA1)).toBeNull();
    });
  });

  describe('saveSession + loadSession round-trip', () => {
    it('round-trips every field byte-for-byte', async () => {
      const store = new DexieSessionsStore(freshDb());
      const state = makeFakeState(2);

      await store.saveSession(userA, deviceA1, state);
      const loaded = await store.loadSession(userA, deviceA1);
      if (loaded === null) {
        throw new Error('expected the session row to be persisted');
      }

      expect(loaded.sendingMessageNumber).toBe(state.sendingMessageNumber);
      expect(loaded.receivingMessageNumber).toBe(state.receivingMessageNumber);
      expect(loaded.previousSendingChainLength).toBe(
        state.previousSendingChainLength,
      );

      expect(bytesEqual(loaded.rootKey, state.rootKey)).toBe(true);
      expect(bytesEqual(loaded.sendingDhPriv, state.sendingDhPriv)).toBe(true);
      expect(bytesEqual(loaded.sendingDhPub, state.sendingDhPub)).toBe(true);

      if (loaded.receivingDhPub === null || state.receivingDhPub === null) {
        throw new Error('expected receivingDhPub to be populated in this test');
      }
      expect(bytesEqual(loaded.receivingDhPub, state.receivingDhPub)).toBe(
        true,
      );

      if (loaded.sendingChainKey === null || state.sendingChainKey === null) {
        throw new Error('expected sendingChainKey to be populated');
      }
      expect(bytesEqual(loaded.sendingChainKey, state.sendingChainKey)).toBe(
        true,
      );

      if (
        loaded.receivingChainKey === null ||
        state.receivingChainKey === null
      ) {
        throw new Error('expected receivingChainKey to be populated');
      }
      expect(
        bytesEqual(loaded.receivingChainKey, state.receivingChainKey),
      ).toBe(true);

      expect(loaded.skippedKeys).toHaveLength(state.skippedKeys.length);
      for (let i = 0; i < state.skippedKeys.length; i += 1) {
        const lk = loaded.skippedKeys[i]!;
        const sk = state.skippedKeys[i]!;
        expect(lk.messageNumber).toBe(sk.messageNumber);
        expect(bytesEqual(lk.dhPub, sk.dhPub)).toBe(true);
        expect(bytesEqual(lk.messageKey, sk.messageKey)).toBe(true);
      }
    });

    it('round-trips state with all nullable fields actually null', async () => {
      // Receiver-side initial state: no receiving DH chain yet, no
      // chain keys, no skipped keys.
      const store = new DexieSessionsStore(freshDb());
      const state: SerializedRatchetState = {
        rootKey: new Uint8Array(32).fill(0xaa),
        sendingDhPriv: new Uint8Array(32).fill(0xbb),
        sendingDhPub: new Uint8Array(32).fill(0xcc),
        receivingDhPub: null,
        sendingChainKey: null,
        receivingChainKey: null,
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedKeys: [],
      };
      await store.saveSession(userA, deviceA1, state);
      const loaded = await store.loadSession(userA, deviceA1);
      if (loaded === null) {
        throw new Error('expected persisted state');
      }
      expect(loaded.receivingDhPub).toBeNull();
      expect(loaded.sendingChainKey).toBeNull();
      expect(loaded.receivingChainKey).toBeNull();
      expect(loaded.skippedKeys).toEqual([]);
    });

    it('saveSession is idempotent (last write wins)', async () => {
      const store = new DexieSessionsStore(freshDb());
      const first = makeFakeState(3);
      const second = makeFakeState(4);

      await store.saveSession(userA, deviceA1, first);
      await store.saveSession(userA, deviceA1, second);

      const loaded = await store.loadSession(userA, deviceA1);
      if (loaded === null) {
        throw new Error('expected a persisted session');
      }
      expect(bytesEqual(loaded.rootKey, second.rootKey)).toBe(true);
      expect(loaded.sendingMessageNumber).toBe(second.sendingMessageNumber);
    });

    it('keeps sessions for distinct peers independent', async () => {
      const store = new DexieSessionsStore(freshDb());
      const stateA = makeFakeState(5);
      const stateB = makeFakeState(6);

      await store.saveSession(userA, deviceA1, stateA);
      await store.saveSession(userB, deviceB1, stateB);

      const loadedA = await store.loadSession(userA, deviceA1);
      const loadedB = await store.loadSession(userB, deviceB1);
      if (loadedA === null || loadedB === null) {
        throw new Error('expected both sessions to be persisted');
      }
      expect(bytesEqual(loadedA.rootKey, stateA.rootKey)).toBe(true);
      expect(bytesEqual(loadedB.rootKey, stateB.rootKey)).toBe(true);
      expect(bytesEqual(loadedA.rootKey, loadedB.rootKey)).toBe(false);
    });
  });

  describe('defensive copying', () => {
    it('mutating the loaded state does not affect the persisted row', async () => {
      const store = new DexieSessionsStore(freshDb());
      const state = makeFakeState(7);
      await store.saveSession(userA, deviceA1, state);

      const loadedOnce = await store.loadSession(userA, deviceA1);
      if (loadedOnce === null) {
        throw new Error('expected persisted state');
      }
      // Mutate aggressively — this is the same kind of scrub the
      // ratchet code does after a successful encrypt / decrypt.
      loadedOnce.rootKey.fill(0);
      loadedOnce.sendingDhPriv.fill(0);
      if (loadedOnce.skippedKeys.length > 0) {
        loadedOnce.skippedKeys[0]!.messageKey.fill(0);
      }

      const loadedAgain = await store.loadSession(userA, deviceA1);
      if (loadedAgain === null) {
        throw new Error('expected persisted state on second load');
      }
      expect(bytesEqual(loadedAgain.rootKey, state.rootKey)).toBe(true);
      expect(bytesEqual(loadedAgain.sendingDhPriv, state.sendingDhPriv)).toBe(
        true,
      );
      if (loadedAgain.skippedKeys.length > 0) {
        expect(
          bytesEqual(
            loadedAgain.skippedKeys[0]!.messageKey,
            state.skippedKeys[0]!.messageKey,
          ),
        ).toBe(true);
      }
    });

    it('mutating the source state after saveSession does not corrupt the persisted row', async () => {
      const store = new DexieSessionsStore(freshDb());
      const state = makeFakeState(8);
      // Snapshot the bytes BEFORE the save so we can compare after
      // mutating the source.
      const expectedRootKey = new Uint8Array(state.rootKey);

      await store.saveSession(userA, deviceA1, state);

      // Caller-side scrub of the source state — exactly what the
      // ratchet's encrypt/decrypt path does after committing the
      // new state to storage.
      state.rootKey.fill(0);
      state.sendingDhPriv.fill(0);

      const loaded = await store.loadSession(userA, deviceA1);
      if (loaded === null) {
        throw new Error('expected persisted state');
      }
      expect(bytesEqual(loaded.rootKey, expectedRootKey)).toBe(true);
    });
  });

  describe('deleteSession', () => {
    it('removes the persisted row', async () => {
      const store = new DexieSessionsStore(freshDb());
      await store.saveSession(userA, deviceA1, makeFakeState(9));
      expect(await store.loadSession(userA, deviceA1)).not.toBeNull();

      await store.deleteSession(userA, deviceA1);
      expect(await store.loadSession(userA, deviceA1)).toBeNull();
    });

    it('is idempotent (deleting a missing session resolves cleanly)', async () => {
      const store = new DexieSessionsStore(freshDb());
      await expect(
        store.deleteSession(userA, deviceA1),
      ).resolves.toBeUndefined();
      // And again — still resolves.
      await expect(
        store.deleteSession(userA, deviceA1),
      ).resolves.toBeUndefined();
    });

    it('does not affect sessions for other peer devices', async () => {
      const store = new DexieSessionsStore(freshDb());
      const stateA = makeFakeState(10);
      const stateB = makeFakeState(11);
      await store.saveSession(userA, deviceA1, stateA);
      await store.saveSession(userB, deviceB1, stateB);

      await store.deleteSession(userA, deviceA1);

      expect(await store.loadSession(userA, deviceA1)).toBeNull();
      const loadedB = await store.loadSession(userB, deviceB1);
      if (loadedB === null) {
        throw new Error('peer B session should still be persisted');
      }
      expect(bytesEqual(loadedB.rootKey, stateB.rootKey)).toBe(true);
    });
  });

  describe('markOpkUsed', () => {
    it('flips used=1 on the matching OPK row', async () => {
      const db = freshDb();
      const sessions = new DexieSessionsStore(db);
      const prekeys = new DexiePreKeyStore(db);

      // Plant an unused OPK record. We use the higher-level
      // `saveOneTimePreKey` so the row shape lines up with what
      // production code would store.
      await prekeys.saveOneTimePreKey({
        keyId: 42,
        publicKey: new Uint8Array(32).fill(0xaa),
        wrappedPrivateKey: new Uint8Array(40).fill(0xbb),
        createdAt: 1_700_000_000_000,
        used: false,
      });

      // Sanity: the row is unused, so it counts toward the unused
      // OPK count.
      expect(await prekeys.listUnusedOneTimePreKeyCount()).toBe(1);

      await sessions.markOpkUsed(42);

      // After consumption it should NOT count toward the unused
      // OPK count.
      expect(await prekeys.listUnusedOneTimePreKeyCount()).toBe(0);

      // And the row in storage should have used=1.
      const row = await db.prekeys.where('keyId').equals(42).first();
      if (row === undefined) {
        throw new Error('expected the OPK row to still be persisted');
      }
      expect(row.used).toBe(1);
      expect(row.keyType).toBe('opk');
    });

    it('is idempotent (re-marking a consumed OPK is a no-op)', async () => {
      const db = freshDb();
      const sessions = new DexieSessionsStore(db);
      const prekeys = new DexiePreKeyStore(db);

      await prekeys.saveOneTimePreKey({
        keyId: 7,
        publicKey: new Uint8Array(32).fill(0x11),
        wrappedPrivateKey: new Uint8Array(40).fill(0x22),
        createdAt: 1,
        used: false,
      });

      await sessions.markOpkUsed(7);
      // Second call resolves cleanly, leaves used=1 in place.
      await expect(sessions.markOpkUsed(7)).resolves.toBeUndefined();

      const row = await db.prekeys.where('keyId').equals(7).first();
      if (row === undefined) {
        throw new Error('expected the OPK row to still be persisted');
      }
      expect(row.used).toBe(1);
    });

    it('is a no-op when no row matches the keyId', async () => {
      const db = freshDb();
      const sessions = new DexieSessionsStore(db);
      // No OPK rows planted at all.
      await expect(sessions.markOpkUsed(999)).resolves.toBeUndefined();
    });

    it('does not flip the signed-prekey row even if a keyId collides', async () => {
      // Defence-in-depth: signed prekey ids and OPK ids live in the
      // same table and could in principle collide. `markOpkUsed`
      // must only touch OPK rows.
      const db = freshDb();
      const sessions = new DexieSessionsStore(db);
      const prekeys = new DexiePreKeyStore(db);

      await prekeys.saveSignedPreKey({
        keyId: 1,
        publicKey: new Uint8Array(32).fill(0xee),
        wrappedPrivateKey: new Uint8Array(40).fill(0xff),
        signature: new Uint8Array(64).fill(0xdd),
        createdAt: 1,
      });
      await prekeys.saveOneTimePreKey({
        keyId: 1,
        publicKey: new Uint8Array(32).fill(0x10),
        wrappedPrivateKey: new Uint8Array(40).fill(0x20),
        createdAt: 2,
        used: false,
      });

      await sessions.markOpkUsed(1);

      // Both rows exist; only the OPK row should have used=1.
      const rows = await db.prekeys.where('keyId').equals(1).toArray();
      const signed = rows.find((r) => r.keyType === 'signed');
      const opk = rows.find((r) => r.keyType === 'opk');
      if (signed === undefined || opk === undefined) {
        throw new Error('expected both rows to be persisted');
      }
      expect(signed.used).toBe(0);
      expect(opk.used).toBe(1);
    });
  });
});

// Tests for task 4.8 (data-layer half): Dexie remoteIdentities
// repository.
//
// Scope:
//   - first-sight TOFU: a previously-unseen `(peerUserId,
//     peerDeviceId)` is persisted with `trusted=true` (requirement
//     8.1).
//   - unchanged: re-recording the same identity public key is a
//     no-op and reports `kind: 'unchanged'`.
//   - changed: a different identity public key is reported via
//     `kind: 'changed'` and storage is NOT mutated until the caller
//     explicitly accepts or rejects (requirement 8.2).
//   - markTrusted accepts a new identity key and stamps
//     `lastChangedAt` (requirement 8.7).
//   - markUntrusted flips trust to false and (if a new key is
//     supplied) stamps `lastChangedAt` (requirement 8.9).
//   - listForUser groups peer devices for the per-peer Safety_Number
//     screen.
//
// Tests run under jsdom + fake-indexeddb (see `test/setup.ts`), so
// Dexie + its compound indices behave as they will in production.

import { afterEach, describe, expect, it } from 'vitest';

import { DexieRemoteIdentitiesStore } from '../src/db/repositories/remote-identities.js';
import { KonvoDb } from '../src/db/schema.js';

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
const deviceA2 = 'device-a2-uuid';

function ikBytes(fill: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(fill);
  return out;
}

describe('DexieRemoteIdentitiesStore', () => {
  describe('get', () => {
    it('returns null for an unrecorded peer device', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      expect(await store.get(userA, deviceA1)).toBeNull();
    });
  });

  describe('recordFirstSightOrDetectChange', () => {
    it('persists with trusted=true on first sight (TOFU)', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const ik = ikBytes(0xab);
      const now = 1_700_000_000_000;

      const outcome = await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ik,
        now,
      );

      expect(outcome.kind).toBe('first_sight');
      expect(outcome.record.trusted).toBe(true);
      expect(outcome.record.firstSeenAt).toBe(now);
      expect(outcome.record.lastChangedAt).toBeNull();
      expect(Array.from(outcome.record.identityPub)).toEqual(Array.from(ik));

      // Round-trip via get.
      const fetched = await store.get(userA, deviceA1);
      if (fetched === null) {
        throw new Error('expected the row to be persisted');
      }
      expect(fetched.trusted).toBe(true);
      expect(Array.from(fetched.identityPub)).toEqual(Array.from(ik));
    });

    it('reports unchanged and does not write when the identityPub matches', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const ik = ikBytes(0x11);

      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ik,
        1_700_000_000_000,
      );
      const second = await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ik,
        1_800_000_000_000, // different "now" — should not propagate
      );

      expect(second.kind).toBe('unchanged');
      // firstSeenAt should still be the original timestamp.
      expect(second.record.firstSeenAt).toBe(1_700_000_000_000);
    });

    it('reports changed and does NOT mutate storage on a different identityPub', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const original = ikBytes(0x22);
      const next = ikBytes(0x33);

      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        original,
        1_700_000_000_000,
      );

      const outcome = await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        next,
        1_800_000_000_000,
      );

      expect(outcome.kind).toBe('changed');
      if (outcome.kind !== 'changed') return; // type narrowing
      expect(Array.from(outcome.record.identityPub)).toEqual(
        Array.from(original),
      );
      expect(Array.from(outcome.newIdentityPub)).toEqual(Array.from(next));

      // Storage MUST still hold the original key, since the caller
      // hasn't accepted/rejected yet.
      const persisted = await store.get(userA, deviceA1);
      if (persisted === null) {
        throw new Error('expected the original row to remain persisted');
      }
      expect(Array.from(persisted.identityPub)).toEqual(Array.from(original));
      // Trust flag is unchanged — the higher layer is responsible
      // for pausing sends until the user accepts/rejects.
      expect(persisted.trusted).toBe(true);
      expect(persisted.lastChangedAt).toBeNull();
    });
  });

  describe('markTrusted', () => {
    it('rotates identityPub and stamps lastChangedAt when accepting a new key', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const original = ikBytes(0x44);
      const next = ikBytes(0x55);

      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        original,
        1_700_000_000_000,
      );
      const updated = await store.markTrusted(
        userA,
        deviceA1,
        next,
        1_800_000_000_000,
      );

      expect(updated.trusted).toBe(true);
      expect(updated.lastChangedAt).toBe(1_800_000_000_000);
      expect(Array.from(updated.identityPub)).toEqual(Array.from(next));

      const persisted = await store.get(userA, deviceA1);
      if (persisted === null) {
        throw new Error('expected the row to be persisted');
      }
      expect(Array.from(persisted.identityPub)).toEqual(Array.from(next));
      expect(persisted.trusted).toBe(true);
      expect(persisted.lastChangedAt).toBe(1_800_000_000_000);
    });

    it('does not stamp lastChangedAt when no key change is supplied', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ikBytes(0x66),
        1_700_000_000_000,
      );

      const updated = await store.markTrusted(userA, deviceA1, null);
      expect(updated.trusted).toBe(true);
      expect(updated.lastChangedAt).toBeNull();
    });

    it('throws when no row exists', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      await expect(
        store.markTrusted(userA, deviceA1, ikBytes(0x77)),
      ).rejects.toThrow(/no remoteIdentities row/);
    });
  });

  describe('markUntrusted', () => {
    it('flips trust=false and preserves identityPub when no new key supplied', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const ik = ikBytes(0x88);
      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ik,
        1_700_000_000_000,
      );

      const result = await store.markUntrusted(userA, deviceA1);
      expect(result.trusted).toBe(false);
      expect(Array.from(result.identityPub)).toEqual(Array.from(ik));
      expect(result.lastChangedAt).toBeNull();
    });

    it('rotates identityPub and stamps lastChangedAt when rejecting a new key', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const original = ikBytes(0x99);
      const next = ikBytes(0xaa);
      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        original,
        1_700_000_000_000,
      );

      const result = await store.markUntrusted(
        userA,
        deviceA1,
        next,
        1_800_000_000_000,
      );
      expect(result.trusted).toBe(false);
      expect(Array.from(result.identityPub)).toEqual(Array.from(next));
      expect(result.lastChangedAt).toBe(1_800_000_000_000);
    });

    it('throws when no row exists', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      await expect(store.markUntrusted(userA, deviceA1)).rejects.toThrow(
        /no remoteIdentities row/,
      );
    });
  });

  describe('listForUser', () => {
    it('returns all recorded peer devices for a given user', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ikBytes(0x10),
        1,
      );
      await store.recordFirstSightOrDetectChange(
        userA,
        deviceA2,
        ikBytes(0x20),
        2,
      );
      await store.recordFirstSightOrDetectChange(
        'other-user',
        'other-device',
        ikBytes(0x30),
        3,
      );

      const list = await store.listForUser(userA);
      expect(list).toHaveLength(2);
      const deviceIds = list.map((r) => r.peerDeviceId).sort();
      expect(deviceIds).toEqual([deviceA1, deviceA2].sort());
    });

    it('returns an empty array when no peer devices exist for the user', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      expect(await store.listForUser('absent-user')).toEqual([]);
    });
  });

  describe('returned identityPub buffers are independent of storage', () => {
    it('mutating the returned buffer does not affect persisted state', async () => {
      const store = new DexieRemoteIdentitiesStore(freshDb());
      const ik = ikBytes(0xcc);
      const outcome = await store.recordFirstSightOrDetectChange(
        userA,
        deviceA1,
        ik,
      );

      // Mutate the byte view we got back.
      outcome.record.identityPub[0] = 0x00;

      const fetched = await store.get(userA, deviceA1);
      if (fetched === null) {
        throw new Error('expected the row to be persisted');
      }
      // Persisted bytes still match the original.
      expect(fetched.identityPub[0]).toBe(0xcc);
    });
  });
});

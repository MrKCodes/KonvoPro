// apps/web/test/opk-replenishment.test.ts
//
// Tests for task 4.6 — OPK replenishment + signed-prekey rotation
// background tasks.
//
// Scope:
//   - When fewer than 20 unused OPKs remain locally, the scheduler
//     mints fresh keys to bring the count back to 100 and uploads
//     them via `POST /devices/:id/prekeys` (Requirements 3.3, 3.4).
//   - When at least 20 unused OPKs remain, no upload happens
//     (Requirement 3.3 — the threshold gates the work).
//   - Signed-prekey rotation fires once per app start when the
//     current signed prekey is older than 7 days (Requirement 3.7),
//     uploading the new prekey via the dedicated route.
//   - The localStorage timestamp short-circuits subsequent rotation
//     checks within the same window.
//   - The periodic timer (`setInterval`) re-runs the OPK check at
//     the configured cadence and the stop callback halts further
//     ticks.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  generateInitialBundle,
  getOrCreateIdentity,
} from '@konvo/crypto';

import { db } from '../src/db/schema.js';
import { DexieIdentityStore } from '../src/db/repositories/identity.js';
import { DexiePreKeyStore } from '../src/db/repositories/prekeys.js';
import { AuthApiClient } from '../src/features/auth/api.js';
import {
  LAST_ROTATED_STORAGE_KEY,
  checkAndReplenishOpks,
  checkAndRotateSignedPreKey,
  readLastRotatedAt,
  startOpkReplenishment,
  startSignedPreKeyRotation,
} from '../src/features/auth/opkReplenishment.js';
import {
  __resetAuthStoreForTests,
  authActions,
} from '../src/features/auth/store.js';

interface RecordedRequest {
  url: string;
  method: string;
  body: unknown;
}

function makeRecorder(
  responder: (req: RecordedRequest) => Response = () =>
    new Response(JSON.stringify({ count: 0 }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
): { fetch: typeof fetch; calls: RecordedRequest[] } {
  const calls: RecordedRequest[] = [];
  const fetchImpl = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    let parsed: unknown = null;
    if (init?.body !== undefined && init.body !== null) {
      try {
        parsed = JSON.parse(String(init.body));
      } catch {
        parsed = init.body;
      }
    }
    const req: RecordedRequest = {
      url: String(input),
      method: init?.method ?? 'GET',
      body: parsed,
    };
    calls.push(req);
    return responder(req);
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

async function seedInitialBundle(): Promise<void> {
  // Use the real crypto module against the real Dexie repositories so
  // the test exercises the same persistence path the production
  // scheduler hits. `generateInitialBundle` produces 1 signed prekey
  // + 100 OPKs.
  const identityStore = new DexieIdentityStore(db);
  const preKeyStore = new DexiePreKeyStore(db);
  const identity = await getOrCreateIdentity(identityStore);
  const kek = await identityStore.getOrCreateAesKwKey();
  await generateInitialBundle(identity, preKeyStore, kek);
}

/** Wait for real-timer-driven async work (Dexie transactions, fetch
 *  promises) to settle. Microtask draining alone isn't enough because
 *  Dexie's batching uses `setTimeout(0)` under the hood. */
async function flushMacrotasks(ms = 100): Promise<void> {
  await new Promise<void>((r) => setTimeout(r, ms));
}

beforeEach(async () => {
  __resetAuthStoreForTests();
  authActions.setAuth({
    accessToken: 'tok',
    user: { id: 'u1', handle: 'alice' },
  });
  if (typeof localStorage !== 'undefined') localStorage.clear();
  await db.identity.clear();
  await db.prekeys.clear();
  await db.aesKwKeys.clear();
});

afterEach(async () => {
  vi.useRealTimers();
  __resetAuthStoreForTests();
  await db.identity.clear();
  await db.prekeys.clear();
  await db.aesKwKeys.clear();
  if (typeof localStorage !== 'undefined') localStorage.clear();
});

describe('checkAndReplenishOpks', () => {
  it('uploads minted OPKs when unused count drops below the threshold', async () => {
    await seedInitialBundle();
    // Mark 85 of the 100 OPKs as consumed so 15 unused remain (below
    // the 20-key threshold).
    const opks = await db.prekeys
      .where('keyType')
      .equals('opk')
      .toArray();
    expect(opks.length).toBe(100);
    const toConsume = opks
      .sort((a, b) => a.keyId - b.keyId)
      .slice(0, 85)
      .map((row) => row.id!)
      .filter((id): id is number => typeof id === 'number');
    await db.prekeys
      .where('id')
      .anyOf(toConsume)
      .modify({ used: 1 as 0 | 1 });

    const { fetch: fetchImpl, calls } = makeRecorder();
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });

    const minted = await checkAndReplenishOpks({
      deviceId: 'dev-1',
      api,
      database: db,
    });

    expect(minted).toBe(85); // target 100 - currentCount 15
    // One upload to /devices/:id/prekeys.
    expect(calls.length).toBe(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain('/devices/dev-1/prekeys');
    const body = calls[0]?.body as { oneTimePreKeys: Array<{ keyId: number; publicKey: string }> };
    expect(body.oneTimePreKeys).toHaveLength(85);
    // Wire format: each public key is 32 bytes encoded as base64.
    for (const opk of body.oneTimePreKeys) {
      expect(atob(opk.publicKey).length).toBe(32);
    }

    // After replenishment the unused-OPK count is back at the target.
    const unusedAfter = await new DexiePreKeyStore(db).listUnusedOneTimePreKeyCount();
    expect(unusedAfter).toBe(100);
  });

  it('is a no-op when unused count is at or above the threshold', async () => {
    await seedInitialBundle();
    // Consume 79 OPKs → 21 unused remain (above 20). No upload should
    // happen.
    const opks = await db.prekeys.where('keyType').equals('opk').toArray();
    const toConsume = opks
      .sort((a, b) => a.keyId - b.keyId)
      .slice(0, 79)
      .map((row) => row.id!)
      .filter((id): id is number => typeof id === 'number');
    await db.prekeys
      .where('id')
      .anyOf(toConsume)
      .modify({ used: 1 as 0 | 1 });

    const { fetch: fetchImpl, calls } = makeRecorder();
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });

    const minted = await checkAndReplenishOpks({
      deviceId: 'dev-1',
      api,
      database: db,
    });

    expect(minted).toBe(0);
    expect(calls).toHaveLength(0);
  });
});

describe('startOpkReplenishment lifecycle', () => {
  it('runs an immediate check on start and registers a periodic timer', async () => {
    await seedInitialBundle();
    // Drain to 5 unused so the immediate tick replenishes.
    const opks = await db.prekeys.where('keyType').equals('opk').toArray();
    const toConsume = opks
      .sort((a, b) => a.keyId - b.keyId)
      .slice(0, 95)
      .map((row) => row.id!)
      .filter((id): id is number => typeof id === 'number');
    await db.prekeys
      .where('id')
      .anyOf(toConsume)
      .modify({ used: 1 as 0 | 1 });

    // Spy on the real setInterval/clearInterval. We can't `vi.useFakeTimers`
    // here because fake-indexeddb's internal `setTimeout(0)` calls would
    // hang Dexie's async work — but spying on `setInterval` lets us
    // assert the scheduler registered the right cadence and that
    // `stop()` cleans up.
    const setIntervalSpy = vi.spyOn(globalThis, 'setInterval');
    const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval');

    const { fetch: fetchImpl, calls } = makeRecorder();
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });

    const stop = startOpkReplenishment({
      deviceId: 'dev-1',
      api,
      database: db,
      pollIntervalMs: 60_000,
    });

    // The scheduler registered exactly one setInterval at the
    // configured cadence.
    expect(setIntervalSpy).toHaveBeenCalledTimes(1);
    expect(setIntervalSpy.mock.calls[0]?.[1]).toBe(60_000);

    // Wait for the immediate `void tick()` to settle. Dexie + fetch
    // both schedule work via real macrotasks (setTimeout(0)), so a
    // microtask drain is insufficient.
    for (let i = 0; i < 20 && calls.length === 0; i++) {
      await flushMacrotasks(50);
    }
    expect(calls.length).toBe(1);
    expect(calls[0]?.url).toContain('/devices/dev-1/prekeys');

    stop();

    // stop() invoked clearInterval with the handle from setInterval.
    expect(clearIntervalSpy).toHaveBeenCalledTimes(1);
    expect(clearIntervalSpy.mock.calls[0]?.[0]).toBe(
      setIntervalSpy.mock.results[0]?.value,
    );

    setIntervalSpy.mockRestore();
    clearIntervalSpy.mockRestore();

    // Drain any residual in-flight async work so the next test's
    // `beforeEach` clear doesn't race with a partially-flushed tick.
    await flushMacrotasks(100);
  });

  it('handles upload failures via onError without crashing the loop', async () => {
    await seedInitialBundle();
    // Drain to 0 unused so the immediate tick replenishes.
    const opks = await db.prekeys.where('keyType').equals('opk').toArray();
    const toConsume = opks
      .sort((a, b) => a.keyId - b.keyId)
      .map((row) => row.id!)
      .filter((id): id is number => typeof id === 'number');
    await db.prekeys
      .where('id')
      .anyOf(toConsume)
      .modify({ used: 1 as 0 | 1 });

    const { fetch: fetchImpl, calls } = makeRecorder(
      () =>
        new Response(JSON.stringify({ error: 'rate_limited' }), {
          status: 429,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });
    const errors: unknown[] = [];

    const stop = startOpkReplenishment({
      deviceId: 'dev-1',
      api,
      database: db,
      pollIntervalMs: 60_000,
      onError: (err) => errors.push(err),
    });

    for (let i = 0; i < 20 && errors.length === 0; i++) {
      await flushMacrotasks(50);
    }
    expect(calls.length).toBe(1);
    expect(errors.length).toBe(1);

    stop();
    await flushMacrotasks(100);
  });
});

describe('checkAndRotateSignedPreKey', () => {
  it('rotates and uploads when the current signed prekey is older than 7 days', async () => {
    await seedInitialBundle();
    // Backdate the signed-prekey row to 8 days ago.
    const eightDaysMs = 8 * 24 * 60 * 60 * 1000;
    const fakeNow = Date.now();
    const signedRow = (
      await db.prekeys.where('keyType').equals('signed').toArray()
    )[0];
    expect(signedRow).toBeDefined();
    await db.prekeys
      .where('id')
      .equals(signedRow!.id!)
      .modify({ createdAt: fakeNow - eightDaysMs });

    const { fetch: fetchImpl, calls } = makeRecorder(
      () => new Response(null, { status: 204 }),
    );
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });

    const result = await checkAndRotateSignedPreKey({
      deviceId: 'dev-1',
      api,
      database: db,
      now: () => fakeNow,
    });

    expect(result).not.toBeNull();
    expect(result!.signature.length).toBe(64);
    expect(result!.publicKey.length).toBe(32);

    // POST /devices/:id/signed-prekey upload.
    expect(calls.length).toBe(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain('/devices/dev-1/signed-prekey');
    const body = calls[0]?.body as {
      signedPreKey: { publicKey: string; signature: string };
    };
    expect(atob(body.signedPreKey.publicKey).length).toBe(32);
    expect(atob(body.signedPreKey.signature).length).toBe(64);

    // The cache reflects the new rotation timestamp.
    const cached = readLastRotatedAt();
    expect(cached).not.toBeNull();
    expect(cached).toBeGreaterThanOrEqual(fakeNow - 1);

    // A second rotation row exists in Dexie with a strictly larger keyId.
    const signedRows = await db.prekeys
      .where('keyType')
      .equals('signed')
      .toArray();
    expect(signedRows.length).toBe(2);
    expect(Math.max(...signedRows.map((r) => r.keyId))).toBeGreaterThan(
      signedRow!.keyId,
    );
  });

  it('does not rotate when the cached timestamp is fresh', async () => {
    await seedInitialBundle();
    const fakeNow = Date.now();
    // Cache reports "rotated 1 hour ago".
    localStorage.setItem(
      LAST_ROTATED_STORAGE_KEY,
      String(fakeNow - 60 * 60 * 1000),
    );

    const { fetch: fetchImpl, calls } = makeRecorder();
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });

    const result = await checkAndRotateSignedPreKey({
      deviceId: 'dev-1',
      api,
      database: db,
      now: () => fakeNow,
    });

    expect(result).toBeNull();
    expect(calls).toHaveLength(0);
    // Only the original signed prekey row exists.
    const signedRows = await db.prekeys
      .where('keyType')
      .equals('signed')
      .toArray();
    expect(signedRows.length).toBe(1);
  });

  it('returns null when no signed prekey exists yet (pre-enrollment)', async () => {
    // No seed: `prekeys` table is empty.
    const { fetch: fetchImpl, calls } = makeRecorder();
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });

    const result = await checkAndRotateSignedPreKey({
      deviceId: 'dev-1',
      api,
      database: db,
      now: () => Date.now(),
    });

    expect(result).toBeNull();
    expect(calls).toHaveLength(0);
  });
});

describe('startSignedPreKeyRotation', () => {
  it('runs the rotation check once and the stop callback prevents re-runs', async () => {
    await seedInitialBundle();
    const eightDaysMs = 8 * 24 * 60 * 60 * 1000;
    const fakeNow = Date.now();
    const signedRow = (
      await db.prekeys.where('keyType').equals('signed').toArray()
    )[0]!;
    await db.prekeys
      .where('id')
      .equals(signedRow.id!)
      .modify({ createdAt: fakeNow - eightDaysMs });

    const { fetch: fetchImpl, calls } = makeRecorder(
      () => new Response(null, { status: 204 }),
    );
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });

    const stop = startSignedPreKeyRotation({
      deviceId: 'dev-1',
      api,
      database: db,
      now: () => fakeNow,
    });

    // Drain real macrotasks so the in-flight tick settles.
    for (let i = 0; i < 20 && calls.length === 0; i++) {
      await flushMacrotasks(50);
    }
    expect(calls.length).toBe(1);

    // stop() prevents subsequent ticks (the scheduler is one-shot
    // anyway; this asserts the lifecycle API is symmetric with the
    // OPK scheduler).
    stop();
    await flushMacrotasks(50);
    expect(calls.length).toBe(1);
    await flushMacrotasks(100);
  });
});

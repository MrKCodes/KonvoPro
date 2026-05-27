// apps/api/test/prekeys-routes.test.ts
//
// Unit tests for the prekey-bundle endpoint (task 4.5 — Phase 3).
//
// Validates Requirements 3.5, 3.6, 3.10 at the route layer:
//
//   - 3.5  : atomic OPK consumption — first call returns one OPK, the
//            same OPK is never returned twice; concurrent calls don't
//            double-consume.
//   - 3.6  : when the device has no unused OPKs, the response carries
//            `oneTimePreKey: null` (degraded-X3DH fallback).
//   - 3.10 : 404 for non-existent handle and non-existent deviceId,
//            with NO OPK consumption on either path.
//
// Strategy mirrors `devices-routes.test.ts` and `broadcast-routes.test.ts`:
// we exercise `prekeyRoutes` against a fresh Fastify instance per test
// with a hand-rolled pg.Pool stub that mirrors a tiny in-memory subset of
// Postgres (users, devices, one_time_prekeys). The stub's atomic OPK
// UPDATE matches what the production SQL does — pick the lowest-id
// unused OPK, mark it used, return its (key_id, public_key). Concurrency
// is exercised by issuing parallel calls against the same fake pool;
// because JS is single-threaded the in-memory map mutation IS atomic
// from the route's point of view, so the test asserts the route's
// "consume exactly one row" SQL semantics rather than testing real
// Postgres locking. Real cross-process atomicity (`FOR UPDATE SKIP
// LOCKED`) is covered by the integration suite (deferred).

import { afterEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

import {
  prekeyRoutes,
  type PrekeyRoutesDeps,
} from '../src/routes/prekeys.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const ALICE_HANDLE = 'alice';
const ALICE_DEVICE = '33333333-3333-3333-3333-333333333333';

const BOB_ID = '22222222-2222-2222-2222-222222222222';
const BOB_HANDLE = 'bob';
const BOB_DEVICE = '44444444-4444-4444-4444-444444444444';

const NONEXISTENT_DEVICE = '99999999-9999-9999-9999-999999999999';

function b64(bytes: Uint8Array | Buffer): string {
  return Buffer.from(bytes).toString('base64');
}

/** A SignedPreKey JSONB cell, byte fields encoded as base64 (matches
 *  what `routes/devices.ts` writes via `encodeSignedPreKeyJson`). */
function makeSignedPreKeyJson(seed: number): Record<string, unknown> {
  return {
    keyId: 1,
    publicKey: b64(new Uint8Array(32).fill(seed)),
    signature: b64(new Uint8Array(64).fill(seed ^ 0xff)),
    createdAt: 1_700_000_000_000 + seed,
  };
}

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  handle: string;
}

interface DeviceRow {
  id: string;
  user_id: string;
  identity_pub: Buffer;
  registration_id: number;
  signed_prekey: Record<string, unknown>;
}

interface OpkRow {
  id: number;
  device_id: string;
  key_id: number;
  public_key: Buffer;
  used: boolean;
}

class FakeDb {
  users: UserRow[] = [];
  devices: DeviceRow[] = [];
  opks: OpkRow[] = [];
  #nextOpkId = 1;

  addUser(id: string, handle: string): void {
    this.users.push({ id, handle });
  }

  addDevice(opts: {
    id: string;
    userId: string;
    identityPubByte?: number;
    registrationId?: number;
    signedPreKeySeed?: number;
  }): void {
    this.devices.push({
      id: opts.id,
      user_id: opts.userId,
      identity_pub: Buffer.alloc(32, opts.identityPubByte ?? 0xab),
      registration_id: opts.registrationId ?? 1234,
      signed_prekey: makeSignedPreKeyJson(opts.signedPreKeySeed ?? 7),
    });
  }

  addOpk(deviceId: string, keyId: number, publicKeyByte: number): void {
    this.opks.push({
      id: this.#nextOpkId++,
      device_id: deviceId,
      key_id: keyId,
      public_key: Buffer.alloc(32, publicKeyByte),
      used: false,
    });
  }

  unusedOpkCount(deviceId: string): number {
    return this.opks.filter((o) => o.device_id === deviceId && !o.used).length;
  }
}

/** Build a `pg.Pool`-shaped object that the route can call. We match
 *  SQL by leading-token substrings so the test is robust to whitespace
 *  changes in the route's queries. The OPK UPDATE branch implements the
 *  same "pick lowest-id unused, mark used, return it" semantics as the
 *  production SQL — the in-memory mutation is atomic by virtue of
 *  Node's single-threaded execution model, which is exactly what we
 *  want to test the route's "consume exactly one row" expectation. */
function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase().trim();

      // ---- SELECT id FROM users WHERE handle = $1 LIMIT 1 ----
      if (
        lower.startsWith('select id from users') &&
        lower.includes('where handle =')
      ) {
        const handle = String(params[0]).toLowerCase();
        const found = db.users.find((u) => u.handle.toLowerCase() === handle);
        if (found === undefined) return { rows: [], rowCount: 0 };
        return { rows: [{ id: found.id } as unknown as T], rowCount: 1 };
      }

      // ---- SELECT identity_pub, registration_id, signed_prekey FROM devices … ----
      if (
        lower.startsWith('select identity_pub') &&
        lower.includes('from devices') &&
        lower.includes('where id =')
      ) {
        const id = String(params[0]);
        const userId = String(params[1]);
        const found = db.devices.find(
          (d) => d.id === id && d.user_id === userId,
        );
        if (found === undefined) return { rows: [], rowCount: 0 };
        return {
          rows: [
            {
              identity_pub: found.identity_pub,
              registration_id: found.registration_id,
              signed_prekey: found.signed_prekey,
            } as unknown as T,
          ],
          rowCount: 1,
        };
      }

      // ---- UPDATE one_time_prekeys SET used = TRUE WHERE id = (SELECT … LIMIT 1) RETURNING key_id, public_key ----
      if (lower.startsWith('update one_time_prekeys')) {
        const deviceId = String(params[0]);
        // Pick the lowest-id unused OPK for this device — mirrors the
        // route's `ORDER BY id ASC LIMIT 1`.
        let target: OpkRow | undefined;
        for (const o of db.opks) {
          if (o.device_id !== deviceId || o.used) continue;
          if (target === undefined || o.id < target.id) target = o;
        }
        if (target === undefined) return { rows: [], rowCount: 0 };
        target.used = true;
        return {
          rows: [
            {
              key_id: target.key_id,
              public_key: target.public_key,
            } as unknown as T,
          ],
          rowCount: 1,
        };
      }

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface Harness {
  app: FastifyInstance;
  db: FakeDb;
}

async function buildHarness(): Promise<Harness> {
  const db = new FakeDb();
  // Always seed two users with one device each so individual tests
  // can pick the scenario they need without re-seeding boilerplate.
  db.addUser(ALICE_ID, ALICE_HANDLE);
  db.addUser(BOB_ID, BOB_HANDLE);
  db.addDevice({ id: ALICE_DEVICE, userId: ALICE_ID, identityPubByte: 0x11 });
  db.addDevice({ id: BOB_DEVICE, userId: BOB_ID, identityPubByte: 0x22 });

  const app = Fastify({ logger: false });
  const deps: PrekeyRoutesDeps = { pool: makePool(db) };
  await app.register(prekeyRoutes, deps);
  await app.ready();
  return { app, db };
}

let activeApp: FastifyInstance | null = null;
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
});

// Wire-shape mirror of `RemotePreKeyBundleResponse` with byte fields
// projected to base64 strings (the route serializes them that way for
// JSON transport — see `routes/prekeys.ts` header).
interface BundleResponseWire {
  recipientDeviceId: string;
  identityPub: string;
  registrationId: number;
  signedPreKey: {
    keyId: number;
    publicKey: string;
    signature: string;
    createdAt: number;
  };
  oneTimePreKey:
    | {
        keyId: number;
        publicKey: string;
      }
    | null;
}

// ---------------------------------------------------------------------------
// Atomic consumption + degraded-X3DH (Requirements 3.5, 3.6)
// ---------------------------------------------------------------------------

describe('GET /users/:handle/prekey-bundle', () => {
  it('returns an OPK on the first call and null on the second when only one OPK is present', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addOpk(ALICE_DEVICE, 42, 0xee);
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(1);

    // First call: consumes the OPK.
    const r1 = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${ALICE_DEVICE}`,
    });
    expect(r1.statusCode).toBe(200);
    const b1 = r1.json() as BundleResponseWire;
    expect(b1.recipientDeviceId).toBe(ALICE_DEVICE);
    expect(b1.oneTimePreKey).not.toBeNull();
    expect(b1.oneTimePreKey?.keyId).toBe(42);
    expect(b1.oneTimePreKey?.publicKey).toBe(b64(Buffer.alloc(32, 0xee)));
    // The bundle's identity / signed-prekey payload is well-formed.
    expect(b1.identityPub).toBe(b64(Buffer.alloc(32, 0x11)));
    expect(typeof b1.signedPreKey.publicKey).toBe('string');
    expect(typeof b1.signedPreKey.signature).toBe('string');
    // OPK pool is now empty.
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(0);

    // Second call: degraded-X3DH branch returns null OPK without
    // erroring (Requirement 3.6).
    const r2 = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${ALICE_DEVICE}`,
    });
    expect(r2.statusCode).toBe(200);
    const b2 = r2.json() as BundleResponseWire;
    expect(b2.oneTimePreKey).toBeNull();
    // The non-OPK fields are still intact — degraded mode returns the
    // same identity / signed prekey, just without an ephemeral OPK.
    expect(b2.identityPub).toBe(b1.identityPub);
    expect(b2.signedPreKey).toEqual(b1.signedPreKey);
  });

  it('concurrent calls each receive a different OPK and never double-consume', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Stock the device with 5 OPKs.
    for (let i = 0; i < 5; i++) {
      h.db.addOpk(ALICE_DEVICE, 100 + i, 0x10 + i);
    }
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(5);

    // Fire 5 calls in parallel. Even if Node's event loop interleaves
    // the route handlers, the in-memory UPDATE branch flips `used`
    // before the next call observes the row, so the 5 calls MUST
    // collectively consume 5 distinct OPKs.
    const responses = await Promise.all(
      Array.from({ length: 5 }, () =>
        h.app.inject({
          method: 'GET',
          url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${ALICE_DEVICE}`,
        }),
      ),
    );
    for (const r of responses) expect(r.statusCode).toBe(200);
    const bundles = responses.map((r) => r.json() as BundleResponseWire);
    const keyIds = bundles
      .map((b) => b.oneTimePreKey?.keyId)
      .filter((k): k is number => k !== undefined);
    expect(keyIds).toHaveLength(5);
    // No duplicates: 5 calls returned 5 distinct keyIds.
    expect(new Set(keyIds).size).toBe(5);
    // Pool is fully drained.
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(0);

    // A 6th call now falls into the degraded-X3DH branch.
    const r6 = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${ALICE_DEVICE}`,
    });
    expect(r6.statusCode).toBe(200);
    expect((r6.json() as BundleResponseWire).oneTimePreKey).toBeNull();
  });

  it('degraded-X3DH on first contact when the device starts with zero unused OPKs', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Don't seed any OPKs — exercise the immediate-fallback path.
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(0);

    const r = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${ALICE_DEVICE}`,
    });
    expect(r.statusCode).toBe(200);
    const b = r.json() as BundleResponseWire;
    expect(b.oneTimePreKey).toBeNull();
    // The non-OPK fields still resolve.
    expect(b.recipientDeviceId).toBe(ALICE_DEVICE);
    expect(b.identityPub.length).toBeGreaterThan(0);
    expect(b.signedPreKey.publicKey.length).toBeGreaterThan(0);
    expect(b.signedPreKey.signature.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // 404 paths (Requirement 3.10) — must NOT consume any OPK
  // -------------------------------------------------------------------------

  it('returns 404 for a non-existent handle without consuming any OPK', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Pre-stock OPKs on Alice's real device so we can assert the
    // unknown-handle path didn't consume one by mistake.
    h.db.addOpk(ALICE_DEVICE, 1, 0xa1);
    h.db.addOpk(ALICE_DEVICE, 2, 0xa2);
    const before = h.db.unusedOpkCount(ALICE_DEVICE);

    const r = await h.app.inject({
      method: 'GET',
      url: `/users/nosuch/prekey-bundle?deviceId=${ALICE_DEVICE}`,
    });
    expect(r.statusCode).toBe(404);
    // OPK pool unchanged.
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(before);
  });

  it('returns 404 when the handle is malformed (uppercase) without consuming any OPK', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addOpk(ALICE_DEVICE, 1, 0xa1);
    const before = h.db.unusedOpkCount(ALICE_DEVICE);

    const r = await h.app.inject({
      method: 'GET',
      url: `/users/Alice/prekey-bundle?deviceId=${ALICE_DEVICE}`,
    });
    expect(r.statusCode).toBe(404);
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(before);
  });

  it("returns 404 when the deviceId doesn't belong to that handle without consuming any OPK", async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addOpk(BOB_DEVICE, 9, 0xb1);
    h.db.addOpk(ALICE_DEVICE, 1, 0xa1);
    const beforeAlice = h.db.unusedOpkCount(ALICE_DEVICE);
    const beforeBob = h.db.unusedOpkCount(BOB_DEVICE);

    // Alice's handle, Bob's device id — must 404, must not consume on
    // either side.
    const r = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${BOB_DEVICE}`,
    });
    expect(r.statusCode).toBe(404);
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(beforeAlice);
    expect(h.db.unusedOpkCount(BOB_DEVICE)).toBe(beforeBob);
  });

  it('returns 404 for a well-formed but absent deviceId without consuming any OPK', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addOpk(ALICE_DEVICE, 1, 0xa1);
    const before = h.db.unusedOpkCount(ALICE_DEVICE);

    const r = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=${NONEXISTENT_DEVICE}`,
    });
    expect(r.statusCode).toBe(404);
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(before);
  });

  it('returns 404 when the deviceId is malformed (not a UUID) without consuming any OPK', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addOpk(ALICE_DEVICE, 1, 0xa1);
    const before = h.db.unusedOpkCount(ALICE_DEVICE);

    const r = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle?deviceId=not-a-uuid`,
    });
    expect(r.statusCode).toBe(404);
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(before);
  });

  it('returns 404 when the deviceId query parameter is missing without consuming any OPK', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addOpk(ALICE_DEVICE, 1, 0xa1);
    const before = h.db.unusedOpkCount(ALICE_DEVICE);

    const r = await h.app.inject({
      method: 'GET',
      url: `/users/${ALICE_HANDLE}/prekey-bundle`,
    });
    expect(r.statusCode).toBe(404);
    expect(h.db.unusedOpkCount(ALICE_DEVICE)).toBe(before);
  });
});

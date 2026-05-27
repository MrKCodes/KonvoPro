// apps/api/test/devices-routes.test.ts
//
// Unit tests for the device-enrollment REST routes (task 2.6 — Phase 1).
//
// Validates Requirements 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.1, 3.2, 3.4, 3.8,
// 3.9, and 19.4 (rate limit 100/min/device on prekey replenish) at the
// route layer.
//
// Strategy mirrors `broadcast-routes.test.ts`:
//   - We exercise `devicesRoutes` against a fresh Fastify instance per
//     test, with a hand-rolled `pg.Pool` stub that mirrors a tiny
//     in-memory subset of Postgres (users, devices, one_time_prekeys).
//     This is a UNIT test of route behaviour: we do not exercise real
//     Postgres, real pg driver semantics, or real pino logging.
//   - The signed-prekey signature is produced by `@konvo/crypto`'s real
//     `generateInitialBundle` over an in-tree `MemoryIdentityStore` and
//     `MemoryPreKeyStore`, so we verify the route behaves identically to
//     what a real Web_Client would produce. No mocking of crypto.
//   - The `requireAuth` preHandler is replaced by a trivial stub that
//     reads `Authorization: Bearer test:<userId>:<deviceId>`. The real
//     preHandler is exercised in `auth-routes.test.ts`.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

import {
  generateInitialBundle,
  getOrCreateIdentity,
  MemoryIdentityStore,
  type IdentityKeyPair,
  type OneTimePreKey,
  type PreKeyStore,
  type PreKeyBundleUpload,
  type SignedPreKeyRecord,
  type OneTimePreKeyRecord,
} from '@konvo/crypto';

import {
  devicesRoutes,
  type DevicesRoutesDeps,
} from '../src/routes/devices.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// In-memory PreKeyStore for crypto bundle generation
// ---------------------------------------------------------------------------
//
// `generateInitialBundle` needs a `PreKeyStore`; the real one ships in
// task 2.9 as a Dexie wrapper. Tests use this dead-simple in-memory
// implementation that meets the contract: monotonically-increasing
// keyIds, separate signed-prekey vs OPK rows, fast count.

class MemoryPreKeyStore implements PreKeyStore {
  #signedPreKeys: SignedPreKeyRecord[] = [];
  #oneTimePreKeys: OneTimePreKeyRecord[] = [];
  #nextSpkId = 1;
  #nextOpkId = 1;

  async listUnusedOneTimePreKeyCount(): Promise<number> {
    return this.#oneTimePreKeys.filter((r) => !r.used).length;
  }
  async getNextSignedPreKeyId(): Promise<number> {
    return this.#nextSpkId++;
  }
  async getNextOneTimePreKeyId(): Promise<number> {
    return this.#nextOpkId++;
  }
  async saveSignedPreKey(record: SignedPreKeyRecord): Promise<void> {
    this.#signedPreKeys.push(record);
  }
  async saveOneTimePreKey(record: OneTimePreKeyRecord): Promise<void> {
    this.#oneTimePreKeys.push(record);
  }
  async getCurrentSignedPreKey(): Promise<SignedPreKeyRecord | null> {
    if (this.#signedPreKeys.length === 0) return null;
    return this.#signedPreKeys.reduce((a, b) => (a.keyId > b.keyId ? a : b));
  }
}

async function freshIdentityAndBundle(): Promise<{
  identity: IdentityKeyPair;
  bundle: PreKeyBundleUpload;
}> {
  const idStore = new MemoryIdentityStore();
  const identity = await getOrCreateIdentity(idStore);
  const kek = await idStore.getOrCreateAesKwKey();
  const pkStore = new MemoryPreKeyStore();
  const bundle = await generateInitialBundle(identity, pkStore, kek);
  return { identity, bundle };
}

// ---------------------------------------------------------------------------
// Wire-encoding helpers — base64 the byte fields the way the route expects
// ---------------------------------------------------------------------------

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function bundleToBody(
  bundle: PreKeyBundleUpload,
  name = 'browser-1',
): Record<string, unknown> {
  return {
    name,
    identityPub: b64(bundle.identityPub),
    identityEdPub: b64(bundle.identityEdPub),
    registrationId: bundle.registrationId,
    signedPreKey: {
      keyId: bundle.signedPreKey.keyId,
      publicKey: b64(bundle.signedPreKey.publicKey),
      signature: b64(bundle.signedPreKey.signature),
      createdAt: bundle.signedPreKey.createdAt,
    },
    oneTimePreKeys: bundle.oneTimePreKeys.map((opk) => ({
      keyId: opk.keyId,
      publicKey: b64(opk.publicKey),
    })),
  };
}

function opkListToBody(
  opks: readonly OneTimePreKey[],
): Record<string, unknown> {
  return {
    oneTimePreKeys: opks.map((o) => ({
      keyId: o.keyId,
      publicKey: b64(o.publicKey),
    })),
  };
}

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------

interface DeviceRow {
  id: string;
  user_id: string;
  name: string;
  identity_pub: Buffer;
  identity_ed_pub: Buffer;
  registration_id: number;
  signed_prekey: unknown; // jsonb — we don't introspect it
  last_seen_at: Date | null;
  created_at: Date;
}

interface OpkRow {
  device_id: string;
  key_id: number;
  public_key: Buffer;
  used: boolean;
}

class FakeDb {
  devices: DeviceRow[] = [];
  opks: OpkRow[] = [];
  #nextDeviceSeq = 1;

  addDeviceWith(userId: string, id?: string): string {
    const deviceId = id ?? this.newDeviceId();
    this.devices.push({
      id: deviceId,
      user_id: userId,
      name: `prepop-${deviceId}`,
      identity_pub: Buffer.alloc(32),
      identity_ed_pub: Buffer.alloc(32),
      registration_id: 1,
      signed_prekey: {},
      last_seen_at: null,
      created_at: new Date(Date.now() + this.#nextDeviceSeq),
    });
    return deviceId;
  }

  /** Generate a deterministic UUID-shaped string. The route validates
   *  `:id` as a UUID via zod, so anything else 404s. We just need
   *  something that satisfies `[0-9a-f]{8}-…` — actual cryptographic
   *  randomness is not required for these tests. */
  newDeviceId(): string {
    const seq = String(this.#nextDeviceSeq++).padStart(12, '0');
    return `aaaaaaaa-bbbb-4ccc-8ddd-${seq}`;
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase().trim();

      // ---- COUNT(*) FROM devices WHERE user_id = $1 ----
      if (
        lower.startsWith('select count(*)') &&
        lower.includes('from devices')
      ) {
        const userId = String(params[0]);
        const c = db.devices.filter((d) => d.user_id === userId).length;
        return {
          rows: [{ c: String(c) } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- INSERT INTO devices ... RETURNING id ----
      if (lower.startsWith('insert into devices')) {
        const [
          userId,
          name,
          identityPub,
          signedPreKeyJson,
          registrationId,
          identityEdPub,
        ] = params as [string, string, Buffer, string, number, Buffer];
        const id = db.newDeviceId();
        let parsedSpk: unknown;
        try {
          parsedSpk =
            typeof signedPreKeyJson === 'string'
              ? JSON.parse(signedPreKeyJson)
              : signedPreKeyJson;
        } catch {
          parsedSpk = signedPreKeyJson;
        }
        db.devices.push({
          id,
          user_id: userId,
          name,
          identity_pub: identityPub,
          identity_ed_pub: identityEdPub,
          registration_id: registrationId,
          signed_prekey: parsedSpk,
          last_seen_at: null,
          created_at: new Date(),
        });
        return {
          rows: [{ id } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- INSERT INTO one_time_prekeys ----
      if (lower.startsWith('insert into one_time_prekeys')) {
        const [deviceId, keyId, publicKey] = params as [
          string,
          number,
          Buffer,
        ];
        if (
          db.opks.some(
            (o) => o.device_id === deviceId && o.key_id === keyId,
          )
        ) {
          const err: Error & { code?: string } = new Error(
            'duplicate key',
          );
          err.code = '23505';
          throw err;
        }
        db.opks.push({
          device_id: deviceId,
          key_id: keyId,
          public_key: publicKey,
          used: false,
        });
        return { rows: [], rowCount: 1 };
      }

      // ---- SELECT id, name, last_seen_at, created_at FROM devices WHERE user_id = $1 ----
      if (
        lower.startsWith('select id, name, last_seen_at, created_at') &&
        lower.includes('from devices')
      ) {
        const userId = String(params[0]);
        const rows = db.devices
          .filter((d) => d.user_id === userId)
          .sort(
            (a, b) => a.created_at.getTime() - b.created_at.getTime(),
          )
          .map((d) => ({
            id: d.id,
            name: d.name,
            last_seen_at: d.last_seen_at,
            created_at: d.created_at,
          }));
        return { rows: rows as unknown as T[], rowCount: rows.length };
      }

      // ---- DELETE FROM devices WHERE id = $1 AND user_id = $2 RETURNING id ----
      if (lower.startsWith('delete from devices')) {
        const id = String(params[0]);
        const userId = String(params[1]);
        const idx = db.devices.findIndex(
          (d) => d.id === id && d.user_id === userId,
        );
        if (idx === -1) return { rows: [], rowCount: 0 };
        const [removed] = db.devices.splice(idx, 1);
        // Cascade: drop matching OPKs (mirrors ON DELETE CASCADE).
        db.opks = db.opks.filter((o) => o.device_id !== id);
        return {
          rows: [{ id: removed!.id } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- SELECT id FROM devices WHERE id = $1 AND user_id = $2 LIMIT 1 ----
      if (
        lower.startsWith('select id from devices') &&
        lower.includes('where id =')
      ) {
        const id = String(params[0]);
        const userId = String(params[1]);
        const found = db.devices.find(
          (d) => d.id === id && d.user_id === userId,
        );
        if (found === undefined) return { rows: [], rowCount: 0 };
        return {
          rows: [{ id: found.id } as unknown as T],
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

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const BOB_ID = '22222222-2222-2222-2222-222222222222';
const ALICE_DEVICE = '33333333-3333-3333-3333-333333333333';
// A valid UUID4 string used when the test wants to talk about a device id
// that doesn't exist in the FakeDb.
const NONEXISTENT_DEVICE = '99999999-9999-9999-9999-999999999999';
// A UUID owned by Bob — used to test 404 on cross-user delete/replenish.
const BOB_OWNED_DEVICE = '88888888-8888-8888-8888-888888888888';

const fakeRequireAuth = async (
  req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
): Promise<void> => {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer test:')) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const payload = header.slice('Bearer test:'.length);
  const parts = payload.split(':');
  const userId = parts[0];
  const deviceId = parts[1];
  if (
    typeof userId !== 'string' ||
    typeof deviceId !== 'string' ||
    userId.length === 0
  ) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const principal: AuthenticatedUser = { userId, deviceId };
  req.authUser = principal;
};

interface Harness {
  app: FastifyInstance;
  db: FakeDb;
  setNow: (ms: number) => void;
}

async function buildHarness(opts?: {
  prekeyRateLimitMax?: number;
  prekeyRateLimitWindowMs?: number;
  maxDevicesPerUser?: number;
}): Promise<Harness> {
  const db = new FakeDb();

  let nowMs = Date.now();
  const setNow = (ms: number): void => {
    nowMs = ms;
  };

  const app = Fastify({ logger: false });
  const deps: DevicesRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
    now: () => nowMs,
    ...(opts?.prekeyRateLimitMax !== undefined
      ? { prekeyRateLimitMax: opts.prekeyRateLimitMax }
      : {}),
    ...(opts?.prekeyRateLimitWindowMs !== undefined
      ? { prekeyRateLimitWindowMs: opts.prekeyRateLimitWindowMs }
      : {}),
    ...(opts?.maxDevicesPerUser !== undefined
      ? { maxDevicesPerUser: opts.maxDevicesPerUser }
      : {}),
  };
  await app.register(devicesRoutes, deps);
  await app.ready();
  return { app, db, setNow };
}

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
}

let activeApp: FastifyInstance | null = null;
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
});

// One bundle per test file is enough; generation is deterministic apart
// from key material, but every test that mutates DB state runs against a
// fresh Harness, so we share the bundle across tests.
let bundle: PreKeyBundleUpload;
beforeEach(async () => {
  ({ bundle } = await freshIdentityAndBundle());
});

// ---------------------------------------------------------------------------
// POST /devices — happy path + validation
// ---------------------------------------------------------------------------

describe('POST /devices', () => {
  it('happy path: persists device + 100 OPKs and returns 201 { deviceId }', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: bundleToBody(bundle, 'firefox'),
    });

    expect(res.statusCode).toBe(201);
    const body = res.json() as { deviceId: string };
    expect(typeof body.deviceId).toBe('string');
    expect(body.deviceId.length).toBeGreaterThan(0);

    expect(h.db.devices).toHaveLength(1);
    const dev = h.db.devices[0]!;
    expect(dev.user_id).toBe(ALICE_ID);
    expect(dev.name).toBe('firefox');
    expect(dev.identity_pub.length).toBe(32);
    expect(dev.identity_ed_pub.length).toBe(32);
    expect(dev.registration_id).toBe(bundle.registrationId);

    // All 100 OPKs persisted to one_time_prekeys.
    expect(h.db.opks.filter((o) => o.device_id === dev.id)).toHaveLength(
      100,
    );
  });

  it('rejects identity_pub of wrong length with 400 and persists nothing', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const body = bundleToBody(bundle);
    // 31 bytes instead of 32.
    body['identityPub'] = b64(new Uint8Array(31));

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.devices).toHaveLength(0);
    expect(h.db.opks).toHaveLength(0);
  });

  it('rejects signed-prekey signature of wrong length with 400 and persists nothing', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const body = bundleToBody(bundle);
    // 63 bytes instead of 64.
    (body['signedPreKey'] as Record<string, unknown>)['signature'] = b64(
      new Uint8Array(63),
    );

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.devices).toHaveLength(0);
    expect(h.db.opks).toHaveLength(0);
  });

  it('rejects an invalid signed-prekey signature with 400 and persists nothing', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    // Flip one byte of the signature so the Ed25519 verify fails. Length
    // remains 64 so this exercises the cryptographic check, not the
    // length check.
    const tampered = new Uint8Array(bundle.signedPreKey.signature);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    const body = bundleToBody(bundle);
    (body['signedPreKey'] as Record<string, unknown>)['signature'] =
      b64(tampered);

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    const j = res.json() as { error: string };
    expect(j.error).toBe('invalid_signed_prekey');
    expect(h.db.devices).toHaveLength(0);
    expect(h.db.opks).toHaveLength(0);
  });

  it('rejects oneTimePreKeys with wrong public-key length with 400', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const body = bundleToBody(bundle);
    const opks = body['oneTimePreKeys'] as Array<Record<string, unknown>>;
    opks[0]!['publicKey'] = b64(new Uint8Array(31));

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.devices).toHaveLength(0);
    expect(h.db.opks).toHaveLength(0);
  });

  it('rejects oneTimePreKeys when length is 0 or > 100 with 400', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    // 0 entries.
    const empty = bundleToBody(bundle);
    empty['oneTimePreKeys'] = [];
    const r1 = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: empty,
    });
    expect(r1.statusCode).toBe(400);

    // 101 entries (duplicate the bundle's first entry to grow it).
    const big = bundleToBody(bundle);
    const opks = big['oneTimePreKeys'] as Array<unknown>;
    opks.push({ ...(opks[0] as object) });
    const r2 = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: big,
    });
    expect(r2.statusCode).toBe(400);

    expect(h.db.devices).toHaveLength(0);
    expect(h.db.opks).toHaveLength(0);
  });

  it('rejects 6th device for the same user with 409 device_limit', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Pre-populate 5 devices for Alice.
    for (let i = 0; i < 5; i++) h.db.addDeviceWith(ALICE_ID);

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: bundleToBody(bundle),
    });

    expect(res.statusCode).toBe(409);
    expect((res.json() as { error: string }).error).toBe('device_limit');
    // No new device row.
    expect(h.db.devices).toHaveLength(5);
  });

  it('returns 401 when the request has no Authorization header', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices',
      payload: bundleToBody(bundle),
    });

    expect(res.statusCode).toBe(401);
    expect(h.db.devices).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GET /devices
// ---------------------------------------------------------------------------

describe('GET /devices', () => {
  it("lists only the authenticated user's devices", async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const a1 = h.db.addDeviceWith(ALICE_ID);
    const a2 = h.db.addDeviceWith(ALICE_ID);
    h.db.addDeviceWith(BOB_ID);

    const res = await h.app.inject({
      method: 'GET',
      url: '/devices',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      devices: Array<{ id: string; name: string; createdAt: string }>;
    };
    expect(body.devices.map((d) => d.id).sort()).toEqual([a1, a2].sort());
  });

  it('returns 401 without auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const res = await h.app.inject({ method: 'GET', url: '/devices' });
    expect(res.statusCode).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// DELETE /devices/:id
// ---------------------------------------------------------------------------

describe('DELETE /devices/:id', () => {
  it('204 + drops device row + cascades to one_time_prekeys', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const dev = h.db.addDeviceWith(ALICE_ID);
    h.db.opks.push({
      device_id: dev,
      key_id: 1,
      public_key: Buffer.alloc(32),
      used: false,
    });

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/devices/${dev}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(204);
    expect(h.db.devices.find((d) => d.id === dev)).toBeUndefined();
    expect(h.db.opks.filter((o) => o.device_id === dev)).toHaveLength(0);
  });

  it('returns 404 when deleting a device owned by another user', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addDeviceWith(BOB_ID, BOB_OWNED_DEVICE);

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/devices/${BOB_OWNED_DEVICE}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
    // Bob's device must remain.
    expect(
      h.db.devices.find((d) => d.id === BOB_OWNED_DEVICE),
    ).toBeDefined();
  });

  it('returns 404 when the device id is well-formed but absent', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/devices/${NONEXISTENT_DEVICE}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });

  it('returns 404 when the device id is malformed (not a UUID)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'DELETE',
      url: '/devices/not-a-uuid',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const dev = h.db.addDeviceWith(ALICE_ID);
    const res = await h.app.inject({
      method: 'DELETE',
      url: `/devices/${dev}`,
    });
    expect(res.statusCode).toBe(401);
    expect(h.db.devices.find((d) => d.id === dev)).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// POST /devices/:id/prekeys
// ---------------------------------------------------------------------------

describe('POST /devices/:id/prekeys', () => {
  it('happy path: persists OPKs and returns 200 { count }', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const dev = h.db.addDeviceWith(ALICE_ID);

    // Use the bundle's first 5 OPKs as fresh keyIds: the FakeDb's
    // (device_id, key_id) UNIQUE check is empty for `dev` so any
    // keyIds will land cleanly.
    const opks = bundle.oneTimePreKeys.slice(0, 5);

    const res = await h.app.inject({
      method: 'POST',
      url: `/devices/${dev}/prekeys`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: opkListToBody(opks),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { count: number };
    expect(body.count).toBe(5);
    expect(h.db.opks.filter((o) => o.device_id === dev)).toHaveLength(5);
  });

  it('returns 404 when the device is owned by another user', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addDeviceWith(BOB_ID, BOB_OWNED_DEVICE);

    const opks = bundle.oneTimePreKeys.slice(0, 3);

    const res = await h.app.inject({
      method: 'POST',
      url: `/devices/${BOB_OWNED_DEVICE}/prekeys`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: opkListToBody(opks),
    });

    expect(res.statusCode).toBe(404);
    // No OPKs persisted to Bob's device under Alice's auth.
    expect(
      h.db.opks.filter((o) => o.device_id === BOB_OWNED_DEVICE),
    ).toHaveLength(0);
  });

  it('returns 404 when the device id is malformed', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const opks = bundle.oneTimePreKeys.slice(0, 1);

    const res = await h.app.inject({
      method: 'POST',
      url: '/devices/not-a-uuid/prekeys',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: opkListToBody(opks),
    });

    expect(res.statusCode).toBe(404);
  });

  it('rate-limits per device (101st in window → 429)', async () => {
    // Tighten the limit so the test runs in <100ms instead of looping
    // 101 times. The rate-limit logic is the same regardless of `max`.
    const h = await buildHarness({
      prekeyRateLimitMax: 2,
      prekeyRateLimitWindowMs: 60_000,
    });
    activeApp = h.app;
    const dev = h.db.addDeviceWith(ALICE_ID);
    const opk = bundle.oneTimePreKeys.slice(0, 1);
    let nextKeyId = 1000;

    function bodyWithFreshKeyId(): Record<string, unknown> {
      return {
        oneTimePreKeys: [
          {
            keyId: nextKeyId++,
            publicKey: b64(opk[0]!.publicKey),
          },
        ],
      };
    }

    // Two within the window — both admitted.
    for (let i = 0; i < 2; i++) {
      const r = await h.app.inject({
        method: 'POST',
        url: `/devices/${dev}/prekeys`,
        headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
        payload: bodyWithFreshKeyId(),
      });
      expect(r.statusCode).toBe(200);
    }

    // Third within the same window — rejected.
    const r3 = await h.app.inject({
      method: 'POST',
      url: `/devices/${dev}/prekeys`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: bodyWithFreshKeyId(),
    });
    expect(r3.statusCode).toBe(429);
  });

  it('returns 401 without auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const dev = h.db.addDeviceWith(ALICE_ID);

    const res = await h.app.inject({
      method: 'POST',
      url: `/devices/${dev}/prekeys`,
      payload: opkListToBody(bundle.oneTimePreKeys.slice(0, 1)),
    });
    expect(res.statusCode).toBe(401);
  });
});

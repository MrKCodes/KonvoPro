// apps/api/test/phase1-two-browsers-one-user.test.ts
//
// Phase 1 verification test (task 2.13): one user, two browser profiles.
//
// Realizes the verification slice of design.md §21 Phase 1:
//   "Sign up one user; log in from two browser profiles; confirm both
//    appear in GET /devices with distinct device ids and distinct
//    identity_pub values."
//
// Validates Requirements 2.4 (POST /devices persists a device record per
// valid bundle) and 2.6 (GET /devices lists the authenticated user's
// devices with id, name, lastSeenAt, createdAt).
//
// Strategy mirrors `devices-routes.test.ts`:
//   - We exercise the real `devicesRoutes` plugin against a fresh
//     Fastify instance, with a hand-rolled `pg.Pool` stub that mirrors
//     a tiny in-memory subset of Postgres (`users`, `devices`,
//     `one_time_prekeys`).
//   - Two independent identity bundles are produced via `@konvo/crypto`'s
//     real `getOrCreateIdentity` + `generateInitialBundle` over an
//     in-tree `MemoryIdentityStore` and `MemoryPreKeyStore`. This
//     mirrors what two physical browsers would each compute on first
//     run — distinct Curve25519 keys, distinct Ed25519 keys, distinct
//     registration IDs, distinct signed-prekey signatures.
//
// Why we don't import `authRoutes`:
//   The real `routes/auth.ts` transitively imports `otplib`,
//   `@fastify/cookie`, and route-level `@fastify/rate-limit` config.
//   In this checkout `otplib`, `@fastify/cookie`, and
//   `@fastify/rate-limit` are not resolvable (per the task brief, this
//   is a pre-existing module-resolution issue we deliberately do not
//   block on). To keep this verification self-contained we inline a
//   minimal `/auth/signup` handler whose contract matches the real
//   route's SQL — `argon2.hash(password)` + `INSERT INTO users
//   (handle, password_hash) RETURNING id`. Tests for the real signup
//   route's full validation surface live in `auth-routes.test.ts`;
//   the goal here is the multi-device verification, not re-litigating
//   auth's body-shape rules.
//
// What we assert end-to-end:
//   1. POST /auth/signup with a valid handle + password returns 201 +
//      a `{ userId }` payload that we then carry as the authenticated
//      principal for both device-enrolment requests.
//   2. POST /devices succeeds twice with two distinct bundles, each
//      returning a 201 + `{ deviceId }` and a deviceId distinct from
//      the other.
//   3. GET /devices returns exactly two entries, both belonging to the
//      authenticated user; their `id`s match the two enrolled deviceIds
//      and are distinct from each other.
//   4. The response shape of GET /devices matches `DeviceListResponse`
//      from `@konvo/protocol` (each item carries `id`, `name`,
//      `lastSeenAt`, `createdAt` with the right types and ISO-8601 UTC
//      formatting).
//   5. The persisted `identity_pub` values for the two devices are
//      distinct, byte-for-byte. GET /devices doesn't return identity_pub
//      on the wire (it would be a needless exposure), so we read the
//      persisted bytea directly from the FakeDb to perform this
//      assertion. This is the strongest expression of "two browsers,
//      two distinct identity keys" available at this layer of the
//      stack.

import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { z } from 'zod';

import {
  generateInitialBundle,
  getOrCreateIdentity,
  MemoryIdentityStore,
  type IdentityKeyPair,
  type PreKeyBundleUpload,
  type PreKeyStore,
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
// Same shape as `devices-routes.test.ts`'s `MemoryPreKeyStore`. We need
// independent instances per simulated browser so the two bundles use
// disjoint key identifiers and don't share state.

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

/** Generate one fresh identity + bundle. Each call produces independent
 *  Curve25519 / Ed25519 keypairs, so calling this twice yields the two
 *  "browser profiles" the verification needs. */
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
// Wire helpers
// ---------------------------------------------------------------------------

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function bundleToBody(
  bundle: PreKeyBundleUpload,
  name: string,
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

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub (covers users + devices + one_time_prekeys)
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  handle: string;
  password_hash: string;
  totp_secret: string | null;
}
interface DeviceRow {
  id: string;
  user_id: string;
  name: string;
  identity_pub: Buffer;
  identity_ed_pub: Buffer;
  registration_id: number;
  signed_prekey: unknown;
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
  users: UserRow[] = [];
  devices: DeviceRow[] = [];
  opks: OpkRow[] = [];
  #nextUserSeq = 1;
  #nextDeviceSeq = 1;

  /** Issue a deterministic UUID-shaped string for a fresh user. */
  newUserId(): string {
    const seq = String(this.#nextUserSeq++).padStart(12, '0');
    return `cccccccc-dddd-4eee-8fff-${seq}`;
  }
  /** Issue a deterministic UUID-shaped string for a fresh device. The
   *  devices route validates `:id` as a UUID via zod, so anything else
   *  404s — but POST /devices itself just round-trips the value the
   *  pool returns. */
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

      // ---- INSERT INTO users ... RETURNING id ----
      if (lower.startsWith('insert into users')) {
        const [handle, passwordHash] = params as [string, string];
        if (
          db.users.some((u) => u.handle.toLowerCase() === handle.toLowerCase())
        ) {
          const err: Error & { code?: string } = new Error(
            'duplicate key value violates unique constraint "users_handle_key"',
          );
          err.code = '23505';
          throw err;
        }
        const id = db.newUserId();
        db.users.push({
          id,
          handle,
          password_hash: passwordHash,
          totp_secret: null,
        });
        return { rows: [{ id } as unknown as T], rowCount: 1 };
      }

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
          // Stagger creation timestamps so GET /devices' ORDER BY
          // created_at ASC is well-defined for the assertion.
          created_at: new Date(Date.now() + db.devices.length),
        });
        return { rows: [{ id } as unknown as T], rowCount: 1 };
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

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Minimal /auth/signup handler — mirrors the SQL contract of routes/auth.ts
// ---------------------------------------------------------------------------
//
// The real route imports otplib (for /auth/login TOTP) and registers
// `config.rateLimit` route options that depend on @fastify/rate-limit.
// In this checkout neither is resolvable, so registering the real
// `authRoutes` plugin would fail at import time. Per the task brief
// we don't block on those pre-existing failures — instead we register
// a slim signup-only plugin that:
//
//   - validates handle (`^[a-z0-9_]{3,32}$`) and password (12..128) with
//     the same zod shape as the real route,
//   - "hashes" the password via the same `mock$<password>` sentinel
//     used in `auth-routes.test.ts` (so we don't pull in the native
//     argon2 binding), and
//   - issues the same `INSERT INTO users (handle, password_hash)
//     RETURNING id` against the FakeDb pool.
//
// This is enough to satisfy the verification's "sign up one user" step
// while keeping the test self-contained. The real auth route's full
// validation surface is covered separately in `auth-routes.test.ts`.

const SignupBodySchema = z
  .object({
    handle: z.string().regex(/^[a-z0-9_]{3,32}$/),
    password: z.string().min(12).max(128),
  })
  .strict();

interface SignupRoutesDeps {
  readonly pool: { query: ReturnType<typeof makePool>['query'] };
}

async function signupOnlyRoutes(
  app: FastifyInstance,
  deps: SignupRoutesDeps,
): Promise<void> {
  app.post('/auth/signup', async (req, reply) => {
    const parsed = SignupBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    const { handle, password } = parsed.data;
    const passwordHash = `mock$${password}`;
    try {
      const insert = await deps.pool.query<{ id: string }>(
        `INSERT INTO users (handle, password_hash)
         VALUES ($1, $2)
         RETURNING id`,
        [handle, passwordHash],
      );
      if (insert.rowCount !== 1 || insert.rows[0] === undefined) {
        return reply.status(500).send({ error: 'internal' });
      }
      return reply.status(201).send({ userId: insert.rows[0].id });
    } catch (err: unknown) {
      const code =
        typeof err === 'object' && err !== null && 'code' in err
          ? (err as { code?: unknown }).code
          : undefined;
      if (code === '23505') {
        return reply.status(409).send({ error: 'handle_unavailable' });
      }
      throw err;
    }
  });
}

// ---------------------------------------------------------------------------
// devices-route auth stub
// ---------------------------------------------------------------------------
//
// Same shape as `devices-routes.test.ts`'s fakeRequireAuth: read the
// principal out of `Authorization: Bearer test:<userId>:<deviceId>`.
// In this verification we generate the userId from /auth/signup and
// re-use it across both device-enrolment requests with arbitrary,
// distinct device-id placeholders for the access-token's `did` claim.
// The `did` is irrelevant to /devices itself; it would matter at WS
// auth time per Phase 2.

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

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
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
  const pool = makePool(db);
  const app = Fastify({ logger: false });

  await app.register(signupOnlyRoutes, { pool });

  const deviceDeps: DevicesRoutesDeps = {
    pool,
    requireAuth: fakeRequireAuth,
  };
  await app.register(devicesRoutes, deviceDeps);

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

// Generate the two browser bundles once for the whole suite. They are
// independent of any per-test state, and producing them is the most
// expensive bit of the test (Curve25519 keygen + Ed25519 sign).
let browser1: PreKeyBundleUpload;
let browser2: PreKeyBundleUpload;
beforeAll(async () => {
  ({ bundle: browser1 } = await freshIdentityAndBundle());
  ({ bundle: browser2 } = await freshIdentityAndBundle());
});

// ---------------------------------------------------------------------------
// The verification
// ---------------------------------------------------------------------------

describe('Phase 1 verification — two browsers, one user (task 2.13)', () => {
  it('signup + 2x POST /devices + GET /devices yields two distinct devices with distinct identity_pub', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    // 1. Sign up one user.
    const signup = await h.app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: {
        handle: 'alice_2br',
        password: 'correct horse battery',
      },
    });
    expect(signup.statusCode).toBe(201);
    const signupBody = signup.json() as { userId: string };
    expect(typeof signupBody.userId).toBe('string');
    expect(signupBody.userId.length).toBeGreaterThan(0);
    const userId = signupBody.userId;

    // The mock-argon2 sentinel is `mock$<password>`; assert that's
    // what the FakeDb persisted, confirming the hash ran before the
    // INSERT (i.e. raw password never reaches the row).
    expect(h.db.users).toHaveLength(1);
    expect(h.db.users[0]?.handle).toBe('alice_2br');
    expect(h.db.users[0]?.password_hash).toBe('mock$correct horse battery');

    // Pre-condition: the two bundles really are distinct browser
    // identities. If `freshIdentityAndBundle` ever degenerated (e.g.
    // shared RNG state), this assertion fails fast and tells us the
    // verification is meaningless.
    expect(
      Buffer.from(browser1.identityPub).equals(Buffer.from(browser2.identityPub)),
    ).toBe(false);
    expect(
      Buffer.from(browser1.identityEdPub).equals(
        Buffer.from(browser2.identityEdPub),
      ),
    ).toBe(false);

    // 2. First browser profile enrolls.
    //
    // The Phase-1 device-id caveat in routes/auth.ts means the access
    // token issued at login does not yet bind a deviceId on a brand-
    // new browser; the client uses an arbitrary placeholder for the
    // `did` claim until /auth/refresh runs after enrolment. The
    // fakeRequireAuth stub mirrors that — `did` is not consulted by
    // /devices at all.
    const r1 = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: {
        authorization: authHeader(
          userId,
          '00000000-0000-4000-8000-000000000001',
        ),
      },
      payload: bundleToBody(browser1, 'firefox-profile'),
    });
    expect(r1.statusCode).toBe(201);
    const enroll1 = r1.json() as { deviceId: string };
    expect(typeof enroll1.deviceId).toBe('string');

    // 3. Second browser profile enrolls under the same user.
    const r2 = await h.app.inject({
      method: 'POST',
      url: '/devices',
      headers: {
        authorization: authHeader(
          userId,
          '00000000-0000-4000-8000-000000000002',
        ),
      },
      payload: bundleToBody(browser2, 'chrome-profile'),
    });
    expect(r2.statusCode).toBe(201);
    const enroll2 = r2.json() as { deviceId: string };
    expect(typeof enroll2.deviceId).toBe('string');

    // The two enrolment responses must carry distinct device ids.
    expect(enroll1.deviceId).not.toBe(enroll2.deviceId);

    // 4. GET /devices: both must be listed under this user, and the
    //    response shape must match `DeviceListResponse` from
    //    @konvo/protocol — Requirement 2.6.
    const list = await h.app.inject({
      method: 'GET',
      url: '/devices',
      headers: {
        authorization: authHeader(
          userId,
          '00000000-0000-4000-8000-000000000001',
        ),
      },
    });
    expect(list.statusCode).toBe(200);

    const listBody = list.json() as {
      devices: Array<{
        id: string;
        name: string;
        lastSeenAt: string | null;
        createdAt: string;
      }>;
    };
    expect(Array.isArray(listBody.devices)).toBe(true);
    expect(listBody.devices).toHaveLength(2);

    // The listed ids must equal the two enrolment ids and be distinct.
    const listedIds = listBody.devices.map((d) => d.id).sort();
    const expectedIds = [enroll1.deviceId, enroll2.deviceId].sort();
    expect(listedIds).toEqual(expectedIds);
    expect(listBody.devices[0]?.id).not.toBe(listBody.devices[1]?.id);

    // Each item must carry the four documented fields with the right
    // types (Requirement 2.6, design.md §9 GET /devices schema).
    const namesSeen: string[] = [];
    for (const d of listBody.devices) {
      expect(typeof d.id).toBe('string');
      expect(d.id.length).toBeGreaterThan(0);

      expect(typeof d.name).toBe('string');
      expect(d.name.length).toBeGreaterThanOrEqual(1);
      expect(d.name.length).toBeLessThanOrEqual(64);
      namesSeen.push(d.name);

      // lastSeenAt is nullable per the route + DTO; for freshly-
      // enrolled devices it should be null.
      expect(d.lastSeenAt === null || typeof d.lastSeenAt === 'string').toBe(
        true,
      );
      expect(d.lastSeenAt).toBeNull();

      // createdAt must be ISO-8601 UTC. We don't assert the exact
      // value (FakeDb staggers it for ordering); we only check the
      // shape — it must round-trip through Date and end in 'Z'.
      expect(typeof d.createdAt).toBe('string');
      expect(d.createdAt.endsWith('Z')).toBe(true);
      expect(Number.isFinite(new Date(d.createdAt).getTime())).toBe(true);
    }
    // The two `name` fields should match what the client uploaded —
    // i.e. the two browser-profile labels — proving both enrolments
    // landed under this user.
    expect(namesSeen.sort()).toEqual(
      ['firefox-profile', 'chrome-profile'].sort(),
    );

    // 5. Distinct identity_pub values, byte-for-byte.
    //
    // GET /devices does not return identity_pub on the wire (it would
    // be a needless exposure of cryptographic material that the API
    // already publishes via /users/:handle/prekey-bundle). The
    // verification therefore reads the persisted bytea directly from
    // the FakeDb, which is the test layer's analogue of `psql -c
    // "SELECT id, identity_pub FROM devices WHERE user_id=$1"`.
    const persisted1 = h.db.devices.find((d) => d.id === enroll1.deviceId);
    const persisted2 = h.db.devices.find((d) => d.id === enroll2.deviceId);
    expect(persisted1).toBeDefined();
    expect(persisted2).toBeDefined();
    if (persisted1 === undefined || persisted2 === undefined) {
      throw new Error('unreachable: device rows missing after enrolment');
    }

    // Each persisted identity_pub must be exactly 32 bytes (Curve25519
    // X25519 public key, Requirement 2.4).
    expect(persisted1.identity_pub.length).toBe(32);
    expect(persisted2.identity_pub.length).toBe(32);

    // The two identity_pubs must differ. This is the headline
    // assertion of the Phase-1 verification: two browser profiles
    // enrolled under one user MUST carry distinct device identities,
    // otherwise multi-device E2EE collapses to a single shared key
    // per user.
    expect(persisted1.identity_pub.equals(persisted2.identity_pub)).toBe(
      false,
    );

    // The persisted bytes must match what each browser uploaded — this
    // proves the route did not accidentally swap or normalize the keys
    // between request and storage.
    expect(
      persisted1.identity_pub.equals(Buffer.from(browser1.identityPub)),
    ).toBe(true);
    expect(
      persisted2.identity_pub.equals(Buffer.from(browser2.identityPub)),
    ).toBe(true);

    // For the same reasons, the registration IDs and Ed25519 keys
    // should also be distinct between the two browsers — the bundle
    // factory uses an independent RNG per call.
    expect(persisted1.registration_id).not.toBe(persisted2.registration_id);
    expect(
      persisted1.identity_ed_pub.equals(persisted2.identity_ed_pub),
    ).toBe(false);

    // Both devices belong to the same user (the one created at
    // signup) — this is the "one user, two browsers" half of the
    // verification.
    expect(persisted1.user_id).toBe(userId);
    expect(persisted2.user_id).toBe(userId);

    // Each browser uploaded 100 OPKs (Requirement 3.1) which must
    // have landed in one_time_prekeys partitioned by device.
    expect(
      h.db.opks.filter((o) => o.device_id === enroll1.deviceId),
    ).toHaveLength(100);
    expect(
      h.db.opks.filter((o) => o.device_id === enroll2.deviceId),
    ).toHaveLength(100);
  });
});

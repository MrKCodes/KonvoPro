// apps/api/test/broadcast-routes.test.ts
//
// Unit tests for the broadcast room REST routes (task 7.2 — Phase 6).
//
// Validates Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8,
// 10.9, 10.12, 10.13, 10.14, and 19.4 (rate limit 1/s/admin/room) at the
// route layer.
//
// Strategy:
//   - We exercise `broadcastRoutes` against a fresh Fastify instance per
//     test, with a hand-rolled pg.Pool stub that mirrors a tiny in-memory
//     Postgres (rooms, members, messages, devices, users). This is a
//     UNIT test of route behaviour: it does not exercise real Postgres,
//     real pg/`code: '23505'` driver semantics, or real pino logging.
//     Those are covered by integration tests (deferred to CI).
//   - Signing uses `@konvo/crypto`'s `signBroadcastPost` against an
//     identity produced by the in-tree `MemoryIdentityStore`, so we
//     verify the route behaves identically to what a real Web_Client
//     would produce. No mocking of the crypto layer.
//
// The real `requireAuth` preHandler reads `Authorization: Bearer <jwt>`,
// verifies via `AccessTokenService`, and decorates `req.authUser`. To keep
// tests pure (no jose, no token signing) we substitute a trivial
// preHandler that decorates `req.authUser` straight from a stubbed
// `Authorization: Bearer test:<userId>:<deviceId>` header. This lets us
// drive auth state from the request without bringing the JWT machinery
// online; the real preHandler is exercised in `auth-routes.test.ts`.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

import {
  signBroadcastPost,
  MemoryIdentityStore,
  getOrCreateIdentity,
  type IdentityKeyPair,
} from '@konvo/crypto';

import {
  broadcastRoutes,
  type BroadcastRoutesDeps,
} from '../src/routes/broadcast.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------
//
// We model just enough of Postgres to exercise the route logic:
//   - users: id → handle
//   - devices: id → { userId, identityEdPub }
//   - broadcast_rooms: keyed by id, indexed by slug
//   - broadcast_members: composite (room_id, user_id) → role
//   - broadcast_messages: ordered by created_at DESC
//
// The stub matches SQL strings on substrings (a brittle but very small
// translator) so the test is robust to whitespace changes in the route
// SQL. If the route SQL is restructured, only the matchers below need
// to change.

interface UserRow {
  id: string;
  handle: string;
}
interface DeviceRow {
  id: string;
  user_id: string;
  identity_ed_pub: Uint8Array | null;
}
interface RoomDbRow {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  owner_user: string;
  created_at: Date;
}
interface MemberRow {
  room_id: string;
  user_id: string;
  role: 'admin' | 'subscriber';
}
interface MessageRow {
  id: string; // numeric string
  room_id: string;
  author_user: string;
  author_device: string | null;
  body: string;
  author_signature: Uint8Array;
  created_at: Date;
}

class FakeDb {
  users = new Map<string, UserRow>();
  devices = new Map<string, DeviceRow>();
  rooms = new Map<string, RoomDbRow>();
  roomsBySlug = new Map<string, RoomDbRow>();
  members: MemberRow[] = [];
  messages: MessageRow[] = [];
  insertRoomShouldThrowDuplicate = false;
  #nextMessageId = 1;

  addUser(id: string, handle: string): void {
    this.users.set(id, { id, handle });
  }

  addDevice(id: string, userId: string, identityEdPub: Uint8Array): void {
    this.devices.set(id, {
      id,
      user_id: userId,
      identity_ed_pub: identityEdPub,
    });
  }

  addRoom(row: Omit<RoomDbRow, 'created_at'> & { created_at?: Date }): void {
    const r: RoomDbRow = {
      ...row,
      created_at: row.created_at ?? new Date(),
    };
    this.rooms.set(r.id, r);
    this.roomsBySlug.set(r.slug.toLowerCase(), r);
  }

  setMember(room_id: string, user_id: string, role: 'admin' | 'subscriber') {
    const i = this.members.findIndex(
      (m) => m.room_id === room_id && m.user_id === user_id,
    );
    if (i >= 0) this.members.splice(i, 1);
    this.members.push({ room_id, user_id, role });
  }

  nextMessageId(): string {
    const n = this.#nextMessageId;
    this.#nextMessageId += 1;
    return n.toString();
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase();

      // ---- broadcast_rooms SELECT JOIN users ----
      if (
        lower.includes('from broadcast_rooms') &&
        lower.includes('join users')
      ) {
        const slug = String(params[0]);
        const room = db.roomsBySlug.get(slug.toLowerCase());
        if (room === undefined) return { rows: [], rowCount: 0 };
        const owner = db.users.get(room.owner_user);
        const out = {
          id: room.id,
          slug: room.slug,
          name: room.name,
          description: room.description,
          owner_user: room.owner_user,
          owner_handle: owner?.handle ?? '',
          created_at: room.created_at,
        };
        return { rows: [out as unknown as T], rowCount: 1 };
      }

      // ---- broadcast_rooms INSERT ----
      if (lower.startsWith('insert into broadcast_rooms')) {
        const [slug, name, description, owner_user] = params as [
          string,
          string,
          string | null,
          string,
        ];
        if (db.insertRoomShouldThrowDuplicate) {
          const err: Error & { code?: string } = new Error('duplicate slug');
          err.code = '23505';
          throw err;
        }
        if (db.roomsBySlug.has(slug.toLowerCase())) {
          const err: Error & { code?: string } = new Error('duplicate slug');
          err.code = '23505';
          throw err;
        }
        const id = `room-${db.rooms.size + 1}`;
        const created_at = new Date();
        db.addRoom({ id, slug, name, description, owner_user, created_at });
        return {
          rows: [{ id, created_at } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- broadcast_members INSERT ----
      if (lower.startsWith('insert into broadcast_members')) {
        const [room_id, user_id, ...rest] = params as [
          string,
          string,
          ...unknown[],
        ];
        void rest;
        // Detect the role from the SQL literal (the route inlines it).
        const role: 'admin' | 'subscriber' = lower.includes("'admin'")
          ? 'admin'
          : 'subscriber';

        const existing = db.members.find(
          (m) => m.room_id === room_id && m.user_id === user_id,
        );
        if (existing !== undefined) {
          // The room-creation INSERT uses ON CONFLICT DO UPDATE SET role='admin';
          // the subscribe INSERT uses ON CONFLICT DO NOTHING. Disambiguate by
          // looking at the SQL.
          if (
            lower.includes('do update set') &&
            lower.includes("role = 'admin'")
          ) {
            existing.role = 'admin';
          }
          return { rows: [], rowCount: 0 };
        }
        db.members.push({ room_id, user_id, role });
        return { rows: [], rowCount: 1 };
      }

      // ---- users SELECT handle ----
      if (lower.includes('select handle from users')) {
        const id = String(params[0]);
        const u = db.users.get(id);
        if (u === undefined) return { rows: [], rowCount: 0 };
        return {
          rows: [{ handle: u.handle } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- broadcast_members SELECT role ----
      if (lower.includes('select role from broadcast_members')) {
        const room_id = String(params[0]);
        const user_id = String(params[1]);
        const m = db.members.find(
          (x) => x.room_id === room_id && x.user_id === user_id,
        );
        if (m === undefined) return { rows: [], rowCount: 0 };
        return {
          rows: [{ role: m.role } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- devices SELECT identity_ed_pub ----
      if (lower.includes('from devices') && lower.includes('identity_ed_pub')) {
        const device_id = String(params[0]);
        const user_id = String(params[1]);
        const d = db.devices.get(device_id);
        if (d === undefined || d.user_id !== user_id) {
          return { rows: [], rowCount: 0 };
        }
        return {
          rows: [{ identity_ed_pub: d.identity_ed_pub } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- broadcast_messages INSERT ----
      if (lower.startsWith('insert into broadcast_messages')) {
        const [room_id, author_user, body, author_signature, author_device] =
          params as [
            string,
            string,
            string,
            Buffer | Uint8Array,
            string,
            number,
          ];
        const createdAtMs = params[5] as number;
        const created_at = new Date(createdAtMs);
        const id = db.nextMessageId();
        const sigBytes =
          author_signature instanceof Uint8Array
            ? new Uint8Array(author_signature)
            : new Uint8Array(author_signature);
        db.messages.push({
          id,
          room_id,
          author_user,
          author_device,
          body,
          author_signature: sigBytes,
          created_at,
        });
        return {
          rows: [{ id, created_at } as unknown as T],
          rowCount: 1,
        };
      }

      // ---- broadcast_messages SELECT history ----
      if (lower.includes('from broadcast_messages')) {
        const room_id = String(params[0]);
        let beforeDate: Date | null = null;
        let limit: number;
        if (lower.includes('m.created_at < $2')) {
          beforeDate = params[1] as Date;
          limit = params[2] as number;
        } else {
          limit = params[1] as number;
        }
        const filtered = db.messages
          .filter((m) => m.room_id === room_id)
          .filter((m) =>
            beforeDate === null ? true : m.created_at < beforeDate,
          )
          .sort(
            (a, b) =>
              b.created_at.getTime() - a.created_at.getTime() ||
              Number(BigInt(b.id) - BigInt(a.id)),
          )
          .slice(0, limit)
          .map((m) => {
            const author = db.users.get(m.author_user);
            const dev =
              m.author_device !== null ? db.devices.get(m.author_device) : null;
            return {
              id: m.id,
              room_id: m.room_id,
              author_user: m.author_user,
              author_handle: author?.handle ?? '',
              author_identity_ed_pub: dev?.identity_ed_pub ?? null,
              body: m.body,
              author_signature: m.author_signature,
              created_at: m.created_at,
            };
          });
        return { rows: filtered as unknown as T[], rowCount: filtered.length };
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
const BOB_DEVICE = '44444444-4444-4444-4444-444444444444';

let aliceIdentity: IdentityKeyPair;
let bobIdentity: IdentityKeyPair;

async function freshIdentity(): Promise<IdentityKeyPair> {
  return getOrCreateIdentity(new MemoryIdentityStore());
}

/** Trivial preHandler that reads `Authorization: Bearer test:<uid>:<did>`
 *  and decorates `req.authUser`. Anything else → 401. We bypass JWT
 *  signing here so tests don't need an `AccessTokenService`. */
const fakeRequireAuth = async (
  req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
): Promise<void> => {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer test:')) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  // Header format: `Bearer test:<userId>:<deviceId>`. Strip the
  // `Bearer test:` prefix first so the remaining payload splits
  // cleanly on `:` into [userId, deviceId].
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
  clockSkewWindowMs?: number;
  postRateLimitWindowMs?: number;
}): Promise<Harness> {
  const db = new FakeDb();
  db.addUser(ALICE_ID, 'alice');
  db.addUser(BOB_ID, 'bob');
  db.addDevice(ALICE_DEVICE, ALICE_ID, aliceIdentity.ed25519PublicKey);
  db.addDevice(BOB_DEVICE, BOB_ID, bobIdentity.ed25519PublicKey);

  let nowMs = Date.now();
  const setNow = (ms: number): void => {
    nowMs = ms;
  };

  const app = Fastify({ logger: false });
  const deps: BroadcastRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
    now: () => nowMs,
    ...(opts?.clockSkewWindowMs !== undefined
      ? { clockSkewWindowMs: opts.clockSkewWindowMs }
      : {}),
    ...(opts?.postRateLimitWindowMs !== undefined
      ? { postRateLimitWindowMs: opts.postRateLimitWindowMs }
      : {}),
  };
  await app.register(broadcastRoutes, deps);
  await app.ready();
  return { app, db, setNow };
}

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
}

beforeEach(async () => {
  aliceIdentity = await freshIdentity();
  bobIdentity = await freshIdentity();
});

let activeApp: FastifyInstance | null = null;
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
});

// ---------------------------------------------------------------------------
// POST /rooms
// ---------------------------------------------------------------------------

describe('POST /rooms', () => {
  it('creates a room, makes the creator admin, returns 201', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: { slug: 'general', name: 'General' },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json() as {
      id: string;
      slug: string;
      name: string;
      description: string | null;
      ownerHandle: string;
    };
    expect(body.slug).toBe('general');
    expect(body.name).toBe('General');
    expect(body.ownerHandle).toBe('alice');
    expect(body.description).toBeNull();
    expect(h.db.rooms.size).toBe(1);
    const member = h.db.members.find(
      (m) => m.user_id === ALICE_ID && m.room_id === body.id,
    );
    expect(member?.role).toBe('admin');
  });

  it('returns 400 when slug fails the [a-z0-9-]{3,64} regex', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    for (const badSlug of ['ab', 'AAA', 'has space', 'has_underscore', 'a'.repeat(65), '']) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/rooms',
        headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
        payload: { slug: badSlug, name: 'Foo' },
      });
      expect(res.statusCode, `slug=${JSON.stringify(badSlug)}`).toBe(400);
    }
    expect(h.db.rooms.size).toBe(0);
  });

  it('returns 400 when name is empty or > 100 chars', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    for (const badName of ['', 'a'.repeat(101)]) {
      const res = await h.app.inject({
        method: 'POST',
        url: '/rooms',
        headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
        payload: { slug: 'valid-slug', name: badName },
      });
      expect(res.statusCode).toBe(400);
    }
    expect(h.db.rooms.size).toBe(0);
  });

  it('returns 401 when the request has no Authorization header', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms',
      payload: { slug: 'unauthed', name: 'Foo' },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'auth_required' });
    expect(h.db.rooms.size).toBe(0);
  });

  it('returns 409 on duplicate slug (Postgres unique_violation)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    // Pre-existing room with the same slug.
    h.db.addRoom({
      id: 'room-existing',
      slug: 'duped',
      name: 'Existing',
      description: null,
      owner_user: BOB_ID,
    });

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: { slug: 'duped', name: 'Mine' },
    });
    expect(res.statusCode).toBe(409);
  });
});

// ---------------------------------------------------------------------------
// GET /rooms/:slug
// ---------------------------------------------------------------------------

describe('GET /rooms/:slug', () => {
  it('returns 200 without auth and includes ownerHandle', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addRoom({
      id: 'room-alpha',
      slug: 'alpha',
      name: 'Alpha',
      description: 'descr',
      owner_user: ALICE_ID,
    });

    const res = await h.app.inject({ method: 'GET', url: '/rooms/alpha' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as RoomLite;
    expect(body.slug).toBe('alpha');
    expect(body.ownerHandle).toBe('alice');
    expect(body.description).toBe('descr');
  });

  it('returns 404 on unknown slug', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const res = await h.app.inject({ method: 'GET', url: '/rooms/missing' });
    expect(res.statusCode).toBe(404);
  });

  it('returns 404 on a slug that does not match the regex', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const res = await h.app.inject({ method: 'GET', url: '/rooms/AB' });
    expect(res.statusCode).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// GET /rooms/:slug/messages
// ---------------------------------------------------------------------------

interface RoomLite {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  ownerHandle: string;
  createdAt: string;
}

describe('GET /rooms/:slug/messages', () => {
  it('returns paginated history without auth, ordered by createdAt DESC', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    h.db.addRoom({
      id: 'room-paginate',
      slug: 'paginate',
      name: 'Paginate',
      description: null,
      owner_user: ALICE_ID,
    });

    // Seed 5 messages 1 second apart so the DESC order is well-defined.
    const t0 = Date.parse('2025-01-01T00:00:00Z');
    for (let i = 0; i < 5; i++) {
      h.db.messages.push({
        id: String(i + 1),
        room_id: 'room-paginate',
        author_user: ALICE_ID,
        author_device: ALICE_DEVICE,
        body: `msg-${i}`,
        author_signature: new Uint8Array(64),
        created_at: new Date(t0 + i * 1000),
      });
    }

    // First page, no `before`, limit=2 → [msg-4, msg-3].
    const r1 = await h.app.inject({
      method: 'GET',
      url: '/rooms/paginate/messages?limit=2',
    });
    expect(r1.statusCode).toBe(200);
    const b1 = r1.json() as {
      messages: Array<{ body: string; createdAt: string }>;
      nextBefore: string | null;
    };
    expect(b1.messages.map((m) => m.body)).toEqual(['msg-4', 'msg-3']);
    expect(b1.nextBefore).not.toBeNull();

    // Second page using nextBefore.
    const r2 = await h.app.inject({
      method: 'GET',
      url: `/rooms/paginate/messages?limit=2&before=${encodeURIComponent(b1.nextBefore!)}`,
    });
    expect(r2.statusCode).toBe(200);
    const b2 = r2.json() as { messages: Array<{ body: string }> };
    expect(b2.messages.map((m) => m.body)).toEqual(['msg-2', 'msg-1']);
  });

  it('returns 400 when limit is out of range', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addRoom({
      id: 'room-limit',
      slug: 'limited',
      name: 'X',
      description: null,
      owner_user: ALICE_ID,
    });
    const res = await h.app.inject({
      method: 'GET',
      url: '/rooms/limited/messages?limit=51',
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns 404 when slug does not exist', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const res = await h.app.inject({
      method: 'GET',
      url: '/rooms/no-such/messages',
    });
    expect(res.statusCode).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// POST /rooms/:slug/subscribe
// ---------------------------------------------------------------------------

describe('POST /rooms/:slug/subscribe', () => {
  it('records membership and returns 204 (idempotent)', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addRoom({
      id: 'room-sub',
      slug: 'sub',
      name: 'X',
      description: null,
      owner_user: ALICE_ID,
    });

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms/sub/subscribe',
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });
    expect(res.statusCode).toBe(204);
    expect(
      h.db.members.find((m) => m.user_id === BOB_ID)?.role,
    ).toBe('subscriber');

    // Idempotent — repeat does not change anything.
    const res2 = await h.app.inject({
      method: 'POST',
      url: '/rooms/sub/subscribe',
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });
    expect(res2.statusCode).toBe(204);
    expect(
      h.db.members.filter((m) => m.user_id === BOB_ID).length,
    ).toBe(1);
  });

  it('does NOT downgrade an admin to subscriber on repeat call', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addRoom({
      id: 'room-admin-sub',
      slug: 'adminsub',
      name: 'X',
      description: null,
      owner_user: ALICE_ID,
    });
    h.db.setMember('room-admin-sub', ALICE_ID, 'admin');

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms/adminsub/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });
    expect(res.statusCode).toBe(204);
    expect(
      h.db.members.find((m) => m.user_id === ALICE_ID)?.role,
    ).toBe('admin');
  });

  it('returns 401 without auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addRoom({
      id: 'room-x',
      slug: 'noauth',
      name: 'X',
      description: null,
      owner_user: ALICE_ID,
    });

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms/noauth/subscribe',
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns 404 on unknown slug', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms/missing/subscribe',
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });
    expect(res.statusCode).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// POST /rooms/:slug/messages
// ---------------------------------------------------------------------------

async function postMessageHelper(
  h: Harness,
  opts: {
    slug: string;
    roomId: string;
    body: string;
    createdAtMs: number;
    signer: IdentityKeyPair;
    asUser: string;
    asDevice: string;
    signDeviceId?: string;
    tamperSig?: boolean;
  },
): Promise<import('light-my-request').Response> {
  const sig = signBroadcastPost(
    opts.body,
    opts.roomId,
    opts.createdAtMs,
    opts.signer.ed25519PrivateKey,
  );
  if (opts.tamperSig === true && sig.length > 0) {
    sig[0] = sig[0] === 0 ? 1 : ((sig[0] ?? 0) ^ 1);
  }
  return h.app.inject({
    method: 'POST',
    url: `/rooms/${opts.slug}/messages`,
    headers: { authorization: authHeader(opts.asUser, opts.asDevice) },
    payload: {
      body: opts.body,
      signature: Buffer.from(sig).toString('base64'),
      createdAtMs: opts.createdAtMs,
      deviceId: opts.signDeviceId ?? opts.asDevice,
    },
  });
}

describe('POST /rooms/:slug/messages', () => {
  const ROOM_ID = 'room-post';
  const SLUG = 'posted';

  function seed(h: Harness): void {
    h.db.addRoom({
      id: ROOM_ID,
      slug: SLUG,
      name: 'Posted',
      description: null,
      owner_user: ALICE_ID,
    });
    h.db.setMember(ROOM_ID, ALICE_ID, 'admin');
    h.db.setMember(ROOM_ID, BOB_ID, 'subscriber');
  }

  it('admin with valid signature → 201 and persists message', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    seed(h);

    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const res = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: 'hello world',
      createdAtMs,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
    });

    expect(res.statusCode).toBe(201);
    const body = res.json() as { id: string; createdAt: string };
    expect(body.id).toBeTypeOf('string');
    expect(h.db.messages).toHaveLength(1);
    expect(h.db.messages[0]?.body).toBe('hello world');
    expect(h.db.messages[0]?.author_user).toBe(ALICE_ID);
    expect(h.db.messages[0]?.author_device).toBe(ALICE_DEVICE);
  });

  it('non-admin (subscriber) → 403 and does not persist', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    seed(h);
    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const res = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: 'hi',
      createdAtMs,
      signer: bobIdentity,
      asUser: BOB_ID,
      asDevice: BOB_DEVICE,
    });

    expect(res.statusCode).toBe(403);
    expect(h.db.messages).toHaveLength(0);
  });

  it('body > 4 KiB → 413 and does not persist', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    seed(h);
    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const big = 'a'.repeat(4097);
    const res = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: big,
      createdAtMs,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
    });

    expect(res.statusCode).toBe(413);
    expect(h.db.messages).toHaveLength(0);
  });

  it('createdAtMs > 60 s drift → 400 and does not persist', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    seed(h);
    const serverNow = 1_700_000_000_000;
    h.setNow(serverNow);

    const staleMs = serverNow - 61_000;
    const res = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: 'too late',
      createdAtMs: staleMs,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.messages).toHaveLength(0);
  });

  it('tampered signature → 400 invalid_signature, no persist', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    seed(h);
    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const res = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: 'tampered',
      createdAtMs,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
      tamperSig: true,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.messages).toHaveLength(0);
  });

  it('rate limit: 2 admin posts within 1 s → second is 429, no persist', async () => {
    const h = await buildHarness({ postRateLimitWindowMs: 1000 });
    activeApp = h.app;
    seed(h);
    const t = Date.now();
    h.setNow(t);

    const r1 = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: 'first',
      createdAtMs: t,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
    });
    expect(r1.statusCode).toBe(201);

    h.setNow(t + 100); // still inside the 1-second window
    const r2 = await postMessageHelper(h, {
      slug: SLUG,
      roomId: ROOM_ID,
      body: 'second',
      createdAtMs: t + 100,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
    });
    expect(r2.statusCode).toBe(429);
    expect(h.db.messages).toHaveLength(1);
  });

  it('returns 401 without auth even when body is otherwise valid', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    seed(h);
    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const sig = signBroadcastPost(
      'no auth',
      ROOM_ID,
      createdAtMs,
      aliceIdentity.ed25519PrivateKey,
    );
    const res = await h.app.inject({
      method: 'POST',
      url: `/rooms/${SLUG}/messages`,
      payload: {
        body: 'no auth',
        signature: Buffer.from(sig).toString('base64'),
        createdAtMs,
        deviceId: ALICE_DEVICE,
      },
    });
    expect(res.statusCode).toBe(401);
    expect(h.db.messages).toHaveLength(0);
  });

  it('returns 404 when slug does not exist', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const createdAtMs = Date.now();
    h.setNow(createdAtMs);
    const res = await postMessageHelper(h, {
      slug: 'no-room',
      roomId: 'no-room',
      body: 'orphan',
      createdAtMs,
      signer: aliceIdentity,
      asUser: ALICE_ID,
      asDevice: ALICE_DEVICE,
    });
    expect(res.statusCode).toBe(404);
  });
});

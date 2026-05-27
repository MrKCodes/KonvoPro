// apps/api/test/broadcast-live-routes.test.ts
//
// Unit tests for the broadcast-live LiveKit token routes
// (task 8.1 — Phase 7).
//
// Validates Requirements 11.1 and 11.2 at the route layer:
//
//   - 11.1 : POST /rooms/:slug/live mints a publisher token for an
//            admin and returns 200 with { token, url, role: 'publisher' };
//            non-admin → 403; missing slug → 404; no auth → 401.
//   - 11.2 : GET /rooms/:slug/live/viewer-token mints a viewer token
//            for any authenticated user and returns
//            { token, url, role: 'subscriber' }; missing slug → 404;
//            no auth → 401.
//
// Strategy:
//   - Real `LiveKitTokenSigner` (no mock) — task 8.1's brief calls for
//     verifying the JWT shape with `jose.jwtVerify` against the
//     apiSecret. We sign with a known secret and decode with that
//     same secret to assert `(roomJoin, room, canPublish, canSubscribe)`
//     grants are correct.
//   - In-memory pg.Pool stub mirrors the pattern from
//     `broadcast-routes.test.ts` (a tiny SQL-string router over an
//     in-memory dataset).
//   - The auth preHandler is the same ad-hoc test-only stub used by
//     the broadcast routes test: `Authorization: Bearer test:<uid>:<did>`.
//     Real JWT auth is exercised by `auth-routes.test.ts`.
//
// We do NOT spin up a real LiveKit server; the test asserts:
//   - Response shape matches LiveKitTokenResponse
//   - `token` is a non-empty string
//   - `url` matches the configured `LIVEKIT_URL`
//   - The token decodes with the same apiSecret and carries the right
//     `video.room` grant + `canPublish` flag

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { jwtVerify } from 'jose';

import {
  broadcastLiveRoutes,
  type BroadcastLiveRoutesDeps,
} from '../src/routes/broadcast-live.js';
import { createLiveKitTokenSigner } from '../src/services/livekit.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// Test-only constants
// ---------------------------------------------------------------------------

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const BOB_ID = '22222222-2222-2222-2222-222222222222';
const ALICE_DEVICE = '33333333-3333-3333-3333-333333333333';
const BOB_DEVICE = '44444444-4444-4444-4444-444444444444';

const TEST_API_KEY = 'devkey';
// 32+ chars to match the production `LIVEKIT_API_SECRET` validation in
// `apps/api/src/config.ts`. Tests pass this directly to the signer
// rather than going through the config loader.
const TEST_API_SECRET = 'test-livekit-secret-32-bytes-min-XYZ';
const TEST_LIVEKIT_URL = 'wss://livekit.test.local';

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------

interface RoomDbRow {
  id: string;
  slug: string;
}
interface MemberRow {
  room_id: string;
  user_id: string;
  role: 'admin' | 'subscriber';
}

class FakeDb {
  rooms = new Map<string, RoomDbRow>();
  roomsBySlug = new Map<string, RoomDbRow>();
  members: MemberRow[] = [];

  addRoom(id: string, slug: string): void {
    const row = { id, slug };
    this.rooms.set(id, row);
    this.roomsBySlug.set(slug.toLowerCase(), row);
  }

  setMember(room_id: string, user_id: string, role: 'admin' | 'subscriber') {
    const i = this.members.findIndex(
      (m) => m.room_id === room_id && m.user_id === user_id,
    );
    if (i >= 0) this.members.splice(i, 1);
    this.members.push({ room_id, user_id, role });
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase();

      if (
        lower.includes('from broadcast_rooms') &&
        lower.includes('where slug = $1')
      ) {
        const slug = String(params[0]);
        const room = db.roomsBySlug.get(slug.toLowerCase());
        if (room === undefined) return { rows: [], rowCount: 0 };
        return {
          rows: [{ id: room.id, slug: room.slug } as unknown as T],
          rowCount: 1,
        };
      }

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

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Test-only requireAuth (matches `broadcast-routes.test.ts`)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface Harness {
  app: FastifyInstance;
  db: FakeDb;
}

const ROOM_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const ROOM_SLUG = 'live-room';

async function buildHarness(): Promise<Harness> {
  const db = new FakeDb();
  db.addRoom(ROOM_ID, ROOM_SLUG);
  db.setMember(ROOM_ID, ALICE_ID, 'admin');
  db.setMember(ROOM_ID, BOB_ID, 'subscriber');

  const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
  const app = Fastify({ logger: false });
  const deps: BroadcastLiveRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
    livekitSigner: signer,
    livekitUrl: TEST_LIVEKIT_URL,
  };
  await app.register(broadcastLiveRoutes, deps);
  await app.ready();
  return { app, db };
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

// ---------------------------------------------------------------------------
// LiveKit JWT decoding helpers
// ---------------------------------------------------------------------------

interface VideoGrantClaim {
  room?: string;
  roomJoin?: boolean;
  canPublish?: boolean;
  canSubscribe?: boolean;
}

/** Decode a LiveKit JWT against the same apiSecret used to sign it.
 *  Returns the parsed `(sub, video)` pair. */
async function decodeLiveKitJwt(token: string): Promise<{
  sub: string;
  video: VideoGrantClaim;
}> {
  const key = new TextEncoder().encode(TEST_API_SECRET);
  const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'] });
  // LiveKit places the `VideoGrant` under the top-level `video` claim.
  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  const video = (payload['video'] as VideoGrantClaim) ?? {};
  return { sub, video };
}

// ---------------------------------------------------------------------------
// POST /rooms/:slug/live
// ---------------------------------------------------------------------------

describe('POST /rooms/:slug/live', () => {
  it('admin caller → 200, returns LiveKitTokenResponse with publisher role', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: `/rooms/${ROOM_SLUG}/live`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      token: string;
      url: string;
      role: string;
    };
    expect(body.role).toBe('publisher');
    expect(body.url).toBe(TEST_LIVEKIT_URL);
    expect(typeof body.token).toBe('string');
    expect(body.token.length).toBeGreaterThan(0);

    const decoded = await decodeLiveKitJwt(body.token);
    expect(decoded.sub).toBe(ALICE_ID);
    expect(decoded.video.roomJoin).toBe(true);
    // The LiveKit `video.room` grant carries the broadcast SLUG, not
    // the `broadcast_rooms.id` UUID — task 6.6 / Requirements 7.10,
    // 11.7, 11.8, 22.7 require LiveKit room ids to never look like a
    // 1:1 DM call id (UUID).
    expect(decoded.video.room).toBe(ROOM_SLUG);
    expect(decoded.video.canPublish).toBe(true);
    expect(decoded.video.canSubscribe).toBe(true);
  });

  it('non-admin caller (subscriber) → 403, no token issued', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: `/rooms/${ROOM_SLUG}/live`,
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json() as { error: string; token?: string };
    expect(body.error).toBe('forbidden');
    expect(body.token).toBeUndefined();
  });

  it('non-member caller (no membership row) → 403', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const STRANGER = '99999999-9999-9999-9999-999999999999';
    const STRANGER_DEVICE = '88888888-8888-8888-8888-888888888888';
    const res = await h.app.inject({
      method: 'POST',
      url: `/rooms/${ROOM_SLUG}/live`,
      headers: { authorization: authHeader(STRANGER, STRANGER_DEVICE) },
    });

    expect(res.statusCode).toBe(403);
  });

  it('no Authorization header → 401', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: `/rooms/${ROOM_SLUG}/live`,
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'auth_required' });
  });

  it('unknown slug → 404', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms/no-such-room/live',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });

  it('slug fails the regex → 404', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    // `BAD` (uppercase) violates `^[a-z0-9-]{3,64}$`.
    const res = await h.app.inject({
      method: 'POST',
      url: '/rooms/BAD/live',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// GET /rooms/:slug/live/viewer-token
// ---------------------------------------------------------------------------

describe('GET /rooms/:slug/live/viewer-token', () => {
  it('any authenticated user → 200, returns subscriber token', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: `/rooms/${ROOM_SLUG}/live/viewer-token`,
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      token: string;
      url: string;
      role: string;
    };
    expect(body.role).toBe('subscriber');
    expect(body.url).toBe(TEST_LIVEKIT_URL);
    expect(typeof body.token).toBe('string');
    expect(body.token.length).toBeGreaterThan(0);

    const decoded = await decodeLiveKitJwt(body.token);
    expect(decoded.sub).toBe(BOB_ID);
    expect(decoded.video.roomJoin).toBe(true);
    // Same as the publisher path: viewer JWTs also bind to the slug
    // (task 6.6).
    expect(decoded.video.room).toBe(ROOM_SLUG);
    expect(decoded.video.canPublish).toBe(false);
    expect(decoded.video.canSubscribe).toBe(true);
  });

  it('admin caller also gets a viewer token (no role gate on this route)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: `/rooms/${ROOM_SLUG}/live/viewer-token`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { role: string };
    expect(body.role).toBe('subscriber');
  });

  it('no Authorization header → 401', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: `/rooms/${ROOM_SLUG}/live/viewer-token`,
    });
    expect(res.statusCode).toBe(401);
  });

  it('unknown slug → 404', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/rooms/no-such-room/live/viewer-token',
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });
    expect(res.statusCode).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// LiveKitTokenSigner unit assertions
// ---------------------------------------------------------------------------

describe('createLiveKitTokenSigner', () => {
  it('signPublisher mints HS256 JWT with canPublish=true', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    const token = await signer.signPublisher({
      userId: ALICE_ID,
      roomId: ROOM_SLUG,
    });
    const decoded = await decodeLiveKitJwt(token);
    expect(decoded.sub).toBe(ALICE_ID);
    expect(decoded.video.canPublish).toBe(true);
    expect(decoded.video.canSubscribe).toBe(true);
    expect(decoded.video.room).toBe(ROOM_SLUG);
  });

  it('signViewer mints HS256 JWT with canPublish=false', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    const token = await signer.signViewer({
      userId: BOB_ID,
      roomId: ROOM_SLUG,
    });
    const decoded = await decodeLiveKitJwt(token);
    expect(decoded.sub).toBe(BOB_ID);
    expect(decoded.video.canPublish).toBe(false);
    expect(decoded.video.canSubscribe).toBe(true);
  });

  it('rejects empty apiKey / apiSecret at construction', () => {
    expect(() => createLiveKitTokenSigner('', TEST_API_SECRET)).toThrow();
    expect(() => createLiveKitTokenSigner(TEST_API_KEY, '')).toThrow();
  });

  it('rejects empty userId / roomId at sign time', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    await expect(
      signer.signPublisher({ userId: '', roomId: ROOM_SLUG }),
    ).rejects.toThrow();
    await expect(
      signer.signViewer({ userId: ALICE_ID, roomId: '' }),
    ).rejects.toThrow();
  });
});

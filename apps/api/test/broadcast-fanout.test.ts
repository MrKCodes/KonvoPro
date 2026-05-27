// apps/api/test/broadcast-fanout.test.ts
//
// Unit tests for task 7.3 — broadcast post fan-out.
//
// Validates Requirement 10.4: a successful `POST /rooms/:slug/messages`
// PUBLISHes a JSON `BroadcastPostFanoutPayload` to Redis channel
// `room:{slug}` AFTER persisting the row, and the WS gateway's
// `makeRoomListener` decodes that payload and forwards it as an
// `S2C.ROOM_POST` frame on every subscribed connection.
//
// Two layers are exercised here, each pure-JS so we avoid pulling
// real Postgres / Redis / @fastify/websocket into the test bundle:
//
//   1. Route layer — same in-memory `FakeDb` + `pg.Pool`-shaped stub
//      pattern as `broadcast-routes.test.ts`. We thread a fake
//      `WSRedisPublisher` into the route plugin and assert that the
//      publish runs on `room:{slug}` exactly once per accepted post,
//      with a JSON payload whose fields match the persisted row.
//
//   2. Gateway listener — we exercise `onSubscribeRoom` against the
//      same fake redis (same pattern as `ws-handlers.test.ts`),
//      then have the route layer publish through it. The listener
//      registered by the gateway decodes the JSON and `ctx.send`s an
//      `S2C.ROOM_POST` frame; we decode that frame back and verify
//      every BroadcastPost field matches the persisted row.
//
// What we do NOT cover here (out of scope for task 7.3):
//   - HTTP-layer signature verification (covered in
//     `broadcast-routes.test.ts`).
//   - WS connection upgrade / HELLO handshake (covered in
//     `ws-gateway.test.ts`).
//   - End-to-end /metrics or rate-limit interactions (covered in
//     `broadcast-routes.test.ts` and `metrics.test.ts`).

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

import {
  signBroadcastPost,
  MemoryIdentityStore,
  getOrCreateIdentity,
  type IdentityKeyPair,
} from '@konvo/crypto';

import {
  S2C,
  decodeS2C,
  type ServerToClient,
} from '@konvo/protocol';

import {
  broadcastRoutes,
  roomChannelFor,
  type BroadcastPostFanoutPayload,
  type BroadcastRoutesDeps,
} from '../src/routes/broadcast.js';
import {
  buildContext,
  onSubscribeRoom,
} from '../src/ws/gateway.js';
import type {
  RoomMessageListener,
  WSContext,
  WSRedisPublisher,
  WSSocket,
} from '../src/ws/types.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub (mirrors broadcast-routes.test.ts)
// ---------------------------------------------------------------------------
//
// Restated here so this file is self-contained: any future change to
// `broadcast-routes.test.ts` (which exercises the auth/persist/sig
// paths exhaustively) does not silently change what we assert in this
// file. The two stubs deliberately diverge only on the device-lookup
// row shape, where this stub returns BOTH `identity_ed_pub` AND
// `author_handle` (the new joined SQL added in task 7.3).

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
  owner_user: string;
  created_at: Date;
}
interface MemberRow {
  room_id: string;
  user_id: string;
  role: 'admin' | 'subscriber';
}
interface MessageRow {
  id: string;
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
  #nextMessageId = 1;

  addUser(id: string, handle: string): void {
    this.users.set(id, { id, handle });
  }
  addDevice(id: string, userId: string, identityEdPub: Uint8Array): void {
    this.devices.set(id, { id, user_id: userId, identity_ed_pub: identityEdPub });
  }
  addRoom(row: Omit<RoomDbRow, 'created_at'> & { created_at?: Date }): void {
    const r: RoomDbRow = { ...row, created_at: row.created_at ?? new Date() };
    this.rooms.set(r.id, r);
    this.roomsBySlug.set(r.slug.toLowerCase(), r);
  }
  setMember(room_id: string, user_id: string, role: 'admin' | 'subscriber'): void {
    const i = this.members.findIndex((m) => m.room_id === room_id && m.user_id === user_id);
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

      if (lower.includes('from broadcast_rooms') && lower.includes('join users')) {
        const slug = String(params[0]);
        const room = db.roomsBySlug.get(slug.toLowerCase());
        if (room === undefined) return { rows: [], rowCount: 0 };
        const owner = db.users.get(room.owner_user);
        const out = {
          id: room.id,
          slug: room.slug,
          name: room.name,
          description: null as string | null,
          owner_user: room.owner_user,
          owner_handle: owner?.handle ?? '',
          created_at: room.created_at,
        };
        return { rows: [out as unknown as T], rowCount: 1 };
      }

      if (lower.includes('select role from broadcast_members')) {
        const room_id = String(params[0]);
        const user_id = String(params[1]);
        const m = db.members.find((x) => x.room_id === room_id && x.user_id === user_id);
        if (m === undefined) return { rows: [], rowCount: 0 };
        return { rows: [{ role: m.role } as unknown as T], rowCount: 1 };
      }

      // Task 7.3 added `JOIN users` to the device-lookup so the
      // route can carry `author_handle` in the fan-out payload
      // without a second SELECT. Match on both substrings.
      if (
        lower.includes('from devices') &&
        lower.includes('identity_ed_pub') &&
        lower.includes('join users')
      ) {
        const device_id = String(params[0]);
        const user_id = String(params[1]);
        const d = db.devices.get(device_id);
        if (d === undefined || d.user_id !== user_id) {
          return { rows: [], rowCount: 0 };
        }
        const u = db.users.get(d.user_id);
        return {
          rows: [
            {
              identity_ed_pub: d.identity_ed_pub,
              author_handle: u?.handle ?? '',
            } as unknown as T,
          ],
          rowCount: 1,
        };
      }

      if (lower.startsWith('insert into broadcast_messages')) {
        const [room_id, author_user, body, author_signature, author_device] = params as [
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
        return { rows: [{ id, created_at } as unknown as T], rowCount: 1 };
      }

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Fake WSRedisPublisher — reused across both layers
// ---------------------------------------------------------------------------

interface FakeRedis extends WSRedisPublisher {
  readonly published: Array<{ channel: string; payload: string }>;
  readonly subscribes: Array<{ slug: string; listener: RoomMessageListener }>;
  failNextPublish: Error | null;
}

function makeFakeRedis(): FakeRedis {
  // Map channel → registered listeners. The fake mirrors the real
  // ioredis-backed publisher's "subscribed listeners receive every
  // publish" semantics so we can exercise route → publisher → listener
  // → ctx.send end-to-end without any networking.
  const channelListeners = new Map<string, RoomMessageListener[]>();
  const fake: FakeRedis = {
    published: [],
    subscribes: [],
    failNextPublish: null,
    async publish(channel: string, payload: string): Promise<number> {
      if (fake.failNextPublish !== null) {
        const err = fake.failNextPublish;
        fake.failNextPublish = null;
        throw err;
      }
      fake.published.push({ channel, payload });
      const listeners = channelListeners.get(channel);
      if (listeners !== undefined) {
        for (const fn of listeners.slice()) fn(payload);
      }
      return listeners?.length ?? 0;
    },
    async setPresence(): Promise<void> {
      /* unused in this suite */
    },
    async subscribeRoom(slug: string, listener: RoomMessageListener): Promise<void> {
      fake.subscribes.push({ slug, listener });
      const channel = `room:${slug}`;
      let arr = channelListeners.get(channel);
      if (arr === undefined) {
        arr = [];
        channelListeners.set(channel, arr);
      }
      arr.push(listener);
    },
    async unsubscribeRoom(slug: string, listener: RoomMessageListener): Promise<void> {
      const channel = `room:${slug}`;
      const arr = channelListeners.get(channel);
      if (arr === undefined) return;
      const i = arr.indexOf(listener);
      if (i >= 0) arr.splice(i, 1);
      if (arr.length === 0) channelListeners.delete(channel);
    },
    async subscribeDevice(): Promise<void> {
      /* unused in this suite */
    },
    async unsubscribeDevice(): Promise<void> {
      /* unused in this suite */
    },
  };
  return fake;
}

// ---------------------------------------------------------------------------
// Fake WSSocket / logger / context
// ---------------------------------------------------------------------------

interface FakeSocket extends WSSocket {
  sent: Uint8Array[];
}

function makeFakeSocket(): FakeSocket {
  const sent: Uint8Array[] = [];
  const sock: FakeSocket = {
    readyState: 1,
    sent,
    send(data: Uint8Array | Buffer): void {
      sent.push(new Uint8Array(data));
    },
    close(): void {
      sock.readyState = 3;
    },
    on() {
      return sock;
    },
  } as FakeSocket;
  return sock;
}

const NULL_LOG = {
  fatal: () => {},
  error: () => {},
  warn: () => {},
  info: () => {},
  debug: () => {},
  trace: () => {},
  child: function () {
    return this;
  },
  level: 'info',
  silent: () => {},
} as unknown as Parameters<typeof buildContext>[3];

function lastS2C(sock: FakeSocket): ServerToClient {
  const last = sock.sent[sock.sent.length - 1];
  if (last === undefined) throw new Error('no frame sent');
  return decodeS2C(last);
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const ALICE_DEVICE = '33333333-3333-3333-3333-333333333333';
const VIEWER_DEVICE = '55555555-5555-5555-5555-555555555555';
const ROOM_ID = 'room-broadcast';
const SLUG = 'general';

let aliceIdentity: IdentityKeyPair;

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
  const [userId, deviceId] = payload.split(':');
  if (typeof userId !== 'string' || typeof deviceId !== 'string' || userId.length === 0) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const principal: AuthenticatedUser = { userId, deviceId };
  req.authUser = principal;
};

interface Harness {
  app: FastifyInstance;
  db: FakeDb;
  redis: FakeRedis;
  setNow: (ms: number) => void;
}

async function buildHarness(): Promise<Harness> {
  const db = new FakeDb();
  db.addUser(ALICE_ID, 'alice');
  db.addDevice(ALICE_DEVICE, ALICE_ID, aliceIdentity.ed25519PublicKey);
  db.addRoom({ id: ROOM_ID, slug: SLUG, name: 'General', owner_user: ALICE_ID });
  db.setMember(ROOM_ID, ALICE_ID, 'admin');

  const redis = makeFakeRedis();

  let nowMs = Date.now();
  const setNow = (ms: number): void => {
    nowMs = ms;
  };

  const app = Fastify({ logger: false });
  const deps: BroadcastRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
    now: () => nowMs,
    redis,
  };
  await app.register(broadcastRoutes, deps);
  await app.ready();

  return { app, db, redis, setNow };
}

async function postValidMessage(
  h: Harness,
  body: string,
  createdAtMs: number,
): Promise<import('light-my-request').Response> {
  const sig = signBroadcastPost(
    body,
    ROOM_ID,
    createdAtMs,
    aliceIdentity.ed25519PrivateKey,
  );
  return h.app.inject({
    method: 'POST',
    url: `/rooms/${SLUG}/messages`,
    headers: { authorization: `Bearer test:${ALICE_ID}:${ALICE_DEVICE}` },
    payload: {
      body,
      signature: Buffer.from(sig).toString('base64'),
      createdAtMs,
      deviceId: ALICE_DEVICE,
    },
  });
}

beforeEach(async () => {
  aliceIdentity = await getOrCreateIdentity(new MemoryIdentityStore());
});

let activeApp: FastifyInstance | null = null;
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
});

// ---------------------------------------------------------------------------
// Route → Redis publish
// ---------------------------------------------------------------------------

describe('POST /rooms/:slug/messages → publishes to room:{slug}', () => {
  it('publishes a single JSON BroadcastPostFanoutPayload on accepted post', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const res = await postValidMessage(h, 'hello world', createdAtMs);
    expect(res.statusCode).toBe(201);

    // One row persisted, one publish.
    expect(h.db.messages).toHaveLength(1);
    expect(h.redis.published).toHaveLength(1);

    const pub = h.redis.published[0]!;
    expect(pub.channel).toBe(roomChannelFor(SLUG));

    const decoded = JSON.parse(pub.payload) as BroadcastPostFanoutPayload;
    // Persisted row drives the contract: every fan-out field is
    // sourced from the row that just landed.
    const row = h.db.messages[0]!;
    expect(decoded.id).toBe(row.id);
    expect(decoded.roomId).toBe(ROOM_ID);
    expect(decoded.authorUserId).toBe(ALICE_ID);
    expect(decoded.authorHandle).toBe('alice');
    expect(decoded.body).toBe('hello world');
    expect(decoded.createdAtMs).toBe(row.created_at.getTime());
    // authorIdentityPub round-trips to the same 32-byte key Alice
    // signed with — viewers will re-verify against this on receive.
    expect(
      Buffer.from(decoded.authorIdentityPub, 'base64').toString('hex'),
    ).toBe(Buffer.from(aliceIdentity.ed25519PublicKey).toString('hex'));
    // authorSignature round-trips to the same 64-byte signature the
    // server stored after Ed25519 verification.
    expect(
      Buffer.from(decoded.authorSignature, 'base64').toString('hex'),
    ).toBe(Buffer.from(row.author_signature).toString('hex'));
  });

  it('does NOT publish when the post is rejected (rate-limited 429)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const t = Date.now();
    h.setNow(t);

    const r1 = await postValidMessage(h, 'first', t);
    expect(r1.statusCode).toBe(201);
    h.setNow(t + 100); // still inside the 1s rate-limit window
    const r2 = await postValidMessage(h, 'second', t + 100);
    expect(r2.statusCode).toBe(429);

    expect(h.db.messages).toHaveLength(1);
    expect(h.redis.published).toHaveLength(1);
  });

  it('still returns 201 if redis.publish rejects (post is durably persisted)', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.redis.failNextPublish = new Error('redis down');

    const createdAtMs = Date.now();
    h.setNow(createdAtMs);

    const res = await postValidMessage(h, 'hello after redis blip', createdAtMs);
    expect(res.statusCode).toBe(201);
    // Row persisted; publish failed but didn't crash the request.
    expect(h.db.messages).toHaveLength(1);
    expect(h.redis.published).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Route → Redis → Subscribed WS context (S2C.ROOM_POST forwarding)
//
// These tests transitively import `apps/api/src/ws/gateway.ts`, which
// depends on `obs/metrics.ts` / `prom-client`. Outside of that import
// chain they're identical in structure to the route-only tests above:
// a fake redis, a fake ws socket, and the real `onSubscribeRoom`
// (so the listener wiring under test is the same function reference
// the production gateway installs).
// ---------------------------------------------------------------------------

describe('subscribed WS context receives S2C.ROOM_POST', () => {
  it('forwards the JSON publish to the gateway listener as S2C.ROOM_POST', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    // Build a viewer WS context and subscribe it to the room. We use
    // the real `onSubscribeRoom` so the listener wiring is the same
    // function reference the production gateway installs.
    const sock = makeFakeSocket();
    const ctx: WSContext = buildContext(sock, ALICE_ID, VIEWER_DEVICE, NULL_LOG);
    ctx.helloReceived = true;

    await onSubscribeRoom(ctx, { slug: SLUG }, { redis: h.redis });
    expect(ctx.subscribedRooms.has(SLUG)).toBe(true);

    // Now POST a valid broadcast message; the fan-out should reach
    // the subscribed context as a single S2C.ROOM_POST frame.
    const createdAtMs = Date.now();
    h.setNow(createdAtMs);
    const res = await postValidMessage(h, 'broadcast body', createdAtMs);
    expect(res.statusCode).toBe(201);
    expect(h.redis.published).toHaveLength(1);

    // The viewer received exactly one frame.
    expect(sock.sent).toHaveLength(1);
    const frame = lastS2C(sock);
    expect(frame.t).toBe(S2C.ROOM_POST);
    if (frame.t !== S2C.ROOM_POST) throw new Error('unreachable');

    const row = h.db.messages[0]!;
    const post = frame.post;
    // bigint id matches the BIGSERIAL row.
    expect(post.id).toBe(BigInt(row.id));
    expect(post.roomId).toBe(ROOM_ID);
    expect(post.authorUserId).toBe(ALICE_ID);
    expect(post.authorHandle).toBe('alice');
    expect(post.body).toBe('broadcast body');
    expect(post.createdAt).toBe(row.created_at.getTime());
    // Bytes round-trip exactly: pubkey is 32 bytes; signature is 64.
    expect(post.authorIdentityPub.length).toBe(32);
    expect(post.authorSignature.length).toBe(64);
    expect(Buffer.from(post.authorIdentityPub).toString('hex')).toBe(
      Buffer.from(aliceIdentity.ed25519PublicKey).toString('hex'),
    );
    expect(Buffer.from(post.authorSignature).toString('hex')).toBe(
      Buffer.from(row.author_signature).toString('hex'),
    );
  });

  it('does not forward to a context that has unsubscribed', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const sock = makeFakeSocket();
    const ctx: WSContext = buildContext(sock, ALICE_ID, VIEWER_DEVICE, NULL_LOG);
    ctx.helloReceived = true;

    await onSubscribeRoom(ctx, { slug: SLUG }, { redis: h.redis });
    // Drop the subscription via the same redis fake — directly
    // invoking unsubscribeRoom with the registered listener mirrors
    // what `onUnsubscribeRoom` does inside the gateway.
    const sub = h.redis.subscribes[0]!;
    await h.redis.unsubscribeRoom(sub.slug, sub.listener);

    const createdAtMs = Date.now();
    h.setNow(createdAtMs);
    const res = await postValidMessage(h, 'after unsub', createdAtMs);
    expect(res.statusCode).toBe(201);
    // Publish still happens (route doesn't know about subscribers),
    // but no listener fires → no frame sent.
    expect(h.redis.published).toHaveLength(1);
    expect(sock.sent).toHaveLength(0);
  });
});

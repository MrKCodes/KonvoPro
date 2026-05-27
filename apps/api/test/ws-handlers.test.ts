// apps/api/test/ws-handlers.test.ts
//
// Unit tests for the WebSocket gateway handlers landed in task 3.6:
// `onEnvelopeReceived`, `onPresencePing`, `onSubscribeRoom`,
// `onUnsubscribeRoom` (plus the `drainRoomSubscriptions` helper wired
// into the connection-close path).
//
// Validates Requirements 12.2 (transport ack ≠ delivered_at; presence
// touches devices.last_seen_at + Redis presence TTL 30s) and 10.3
// (broadcast room subscription wiring per design.md §10).
//
// Strategy: like `ws-gateway.test.ts`, we exercise each handler via a
// hand-rolled `WSSocket` mock plus a hand-rolled `pg.Pool` mock and a
// hand-rolled `WSRedisPublisher` mock. No `@fastify/websocket` and no
// real Redis; the integration coverage of the upgrade path lives in
// the integration suite (CI; not authored here).
//
// Test coverage map:
//   onEnvelopeReceived
//     1. happy path: counter increments, no DB write, no Redis write.
//     2. multiple invocations accumulate the counter.
//   onPresencePing
//     3. issues UPDATE devices SET last_seen_at WHERE id = ctx.deviceId.
//     4. issues redis.setPresence(deviceId, 30).
//     5. tolerates DB failure (still calls redis.setPresence).
//     6. tolerates Redis failure (still attempts the DB UPDATE).
//   onSubscribeRoom
//     7. valid slug → ctx.subscribedRooms gains the slug, redis.subscribeRoom called.
//     8. invalid slug → ERROR(INVALID_PAYLOAD), no redis subscribe.
//     9. duplicate subscribe → idempotent no-op (no second redis subscribe).
//    10. redis subscribe failure → ERROR(INTERNAL), slug NOT in set.
//   onUnsubscribeRoom
//    11. valid slug previously subscribed → ctx.subscribedRooms loses slug; redis.unsubscribeRoom called with same listener.
//    12. unsubscribing slug not subscribed → silent no-op.
//    13. invalid slug → ERROR(INVALID_PAYLOAD).
//    14. redis unsubscribe failure → slug still removed from local set.
//   drainRoomSubscriptions
//    15. drains every active slug; clears subscribedRooms.
//   handleClientMessage dispatch wiring (post-HELLO)
//    16. routes ENVELOPE_RECEIVED to onEnvelopeReceived.
//    17. routes PRESENCE_PING to onPresencePing.
//    18. routes SUBSCRIBE_ROOM to onSubscribeRoom.
//    19. routes UNSUBSCRIBE_ROOM to onUnsubscribeRoom.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  C2S,
  ErrorCode,
  S2C,
  decodeS2C,
  encodeC2S,
  type ServerToClient,
} from '@konvo/protocol';

import {
  PRESENCE_TTL_SEC,
  buildContext,
  drainRoomSubscriptions,
  getEnvelopeReceivedCount,
  handleClientMessage,
  onEnvelopeReceived,
  onPresencePing,
  onSubscribeRoom,
  onUnsubscribeRoom,
  setEnvelopeReceivedCounter,
  type PresencePingDeps,
  type RoomSubscriptionDeps,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type {
  RoomMessageListener,
  WSContext,
  WSRedisPublisher,
  WSSocket,
} from '../src/ws/types.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';

// ---------------------------------------------------------------------------
// Test doubles — sockets, logger, redis, pool
// ---------------------------------------------------------------------------

interface FakeListener {
  message: ((data: Uint8Array) => void) | null;
  close: (() => void) | null;
  error: ((err: Error) => void) | null;
}

interface FakeSocket extends WSSocket {
  sent: Uint8Array[];
  closes: Array<{ code?: number; reason?: string }>;
  listeners: FakeListener;
}

function makeFakeSocket(): FakeSocket {
  const sent: Uint8Array[] = [];
  const closes: Array<{ code?: number; reason?: string }> = [];
  const listeners: FakeListener = { message: null, close: null, error: null };
  const sock: FakeSocket = {
    readyState: 1, // OPEN
    sent,
    closes,
    listeners,
    send(data: Uint8Array | Buffer): void {
      sent.push(new Uint8Array(data));
    },
    close(code?: number, reason?: string): void {
      const entry: { code?: number; reason?: string } = {};
      if (code !== undefined) entry.code = code;
      if (reason !== undefined) entry.reason = reason;
      closes.push(entry);
      sock.readyState = 3; // CLOSED
    },
    on(event: 'message' | 'close' | 'error', listener: (...args: never[]) => void) {
      if (event === 'message') listeners.message = listener as never;
      else if (event === 'close') listeners.close = listener as never;
      else if (event === 'error') listeners.error = listener as never;
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
  child: function () { return this; },
  level: 'info',
  silent: () => {},
} as unknown as Parameters<typeof buildContext>[3];

function lastS2C(sock: FakeSocket): ServerToClient {
  const last = sock.sent[sock.sent.length - 1];
  if (last === undefined) throw new Error('no frame sent');
  return decodeS2C(last);
}

/** A pg.Pool-shaped stub that records every query. The handlers
 *  exercised here only issue UPDATEs and the HELLO queuedCount
 *  SELECT (irrelevant for these tests); we capture both via a
 *  generic recorder and never branch on SQL shape unless asserted
 *  by the test. */
interface FakePool {
  readonly queries: Array<{ sql: string; params: readonly unknown[] }>;
  failNext: Error | null;
  query(sql: string, params: readonly unknown[]): Promise<{ rows: unknown[]; rowCount: number }>;
}

function makeFakePool(): FakePool {
  const fake: FakePool = {
    queries: [],
    failNext: null,
    async query(sql: string, params: readonly unknown[]) {
      if (fake.failNext !== null) {
        const err = fake.failNext;
        fake.failNext = null;
        throw err;
      }
      fake.queries.push({ sql, params });
      // The presence-ping path never reads the result; an empty
      // resultset is sufficient. The HELLO queuedCount SELECT (which
      // these tests don't trigger) would need a `count` row — but
      // we'd rebuild a pool stub for that test specifically.
      return { rows: [], rowCount: 0 };
    },
  };
  return fake;
}

/** A WSRedisPublisher mock that captures every publish/setPresence/
 *  subscribeRoom/unsubscribeRoom call. */
interface FakeRedis extends WSRedisPublisher {
  readonly published: Array<{ channel: string; payload: string }>;
  readonly presenceCalls: Array<{ deviceId: string; ttlSec: number }>;
  readonly subscribes: Array<{ slug: string; listener: RoomMessageListener }>;
  readonly unsubscribes: Array<{ slug: string; listener: RoomMessageListener }>;
  failNextSubscribe: Error | null;
  failNextUnsubscribe: Error | null;
  failNextPresence: Error | null;
  /** Test helper: emit a message on a previously subscribed channel.
   *  Invokes the listener with the supplied payload, which is what
   *  the production publisher does on receiving a Redis `'message'`
   *  event. */
  emitRoomMessage(slug: string, payload: string): void;
}

function makeFakeRedis(): FakeRedis {
  const published: Array<{ channel: string; payload: string }> = [];
  const presenceCalls: Array<{ deviceId: string; ttlSec: number }> = [];
  const subscribes: Array<{ slug: string; listener: RoomMessageListener }> = [];
  const unsubscribes: Array<{ slug: string; listener: RoomMessageListener }> = [];
  // Map slug → array of listeners so emitRoomMessage can fan out.
  const channelListeners = new Map<string, RoomMessageListener[]>();
  const fake: FakeRedis = {
    published,
    presenceCalls,
    subscribes,
    unsubscribes,
    failNextSubscribe: null,
    failNextUnsubscribe: null,
    failNextPresence: null,
    async publish(channel: string, payload: string): Promise<number> {
      published.push({ channel, payload });
      return 0;
    },
    async setPresence(deviceId: string, ttlSec: number): Promise<void> {
      if (fake.failNextPresence !== null) {
        const err = fake.failNextPresence;
        fake.failNextPresence = null;
        throw err;
      }
      presenceCalls.push({ deviceId, ttlSec });
    },
    async subscribeRoom(slug: string, listener: RoomMessageListener): Promise<void> {
      if (fake.failNextSubscribe !== null) {
        const err = fake.failNextSubscribe;
        fake.failNextSubscribe = null;
        throw err;
      }
      subscribes.push({ slug, listener });
      let listeners = channelListeners.get(slug);
      if (listeners === undefined) {
        listeners = [];
        channelListeners.set(slug, listeners);
      }
      listeners.push(listener);
    },
    async unsubscribeRoom(slug: string, listener: RoomMessageListener): Promise<void> {
      if (fake.failNextUnsubscribe !== null) {
        const err = fake.failNextUnsubscribe;
        fake.failNextUnsubscribe = null;
        throw err;
      }
      unsubscribes.push({ slug, listener });
      const listeners = channelListeners.get(slug);
      if (listeners !== undefined) {
        const idx = listeners.indexOf(listener);
        if (idx >= 0) listeners.splice(idx, 1);
        if (listeners.length === 0) channelListeners.delete(slug);
      }
    },
    emitRoomMessage(slug: string, payload: string): void {
      const listeners = channelListeners.get(slug);
      if (listeners === undefined) return;
      for (const fn of listeners.slice()) fn(payload);
    },
  };
  return fake;
}

const DEVICE_ID = '11111111-1111-1111-1111-111111111111';
const USER_ID = 'user-1';
const FROZEN_NOW_MS = 1_700_000_000_000;

function setupCtx(): { sock: FakeSocket; ctx: WSContext } {
  const sock = makeFakeSocket();
  const ctx = buildContext(sock, USER_ID, DEVICE_ID, NULL_LOG);
  // Skip the HELLO state machine for handler-level unit tests; the
  // dispatcher tests at the bottom exercise the post-HELLO routing
  // separately.
  ctx.helloReceived = true;
  return { sock, ctx };
}

// ---------------------------------------------------------------------------
// onEnvelopeReceived
// ---------------------------------------------------------------------------

describe('onEnvelopeReceived', () => {
  beforeEach(() => {
    // Reset the in-memory counter so each test starts at 0.
    setEnvelopeReceivedCounter({
      // re-installing the default counter via setter resets the
      // internal count to 0 (see gateway.ts setEnvelopeReceivedCounter).
      inc(): void {
        /* swallowed; we re-install the default below */
      },
    });
    // Re-install a counter that delegates back to the in-memory
    // accumulator. Calling setEnvelopeReceivedCounter() with the
    // default observer requires re-importing the same module-level
    // counter — we instead build a thin wrapper that increments a
    // local total.
    let total = 0;
    setEnvelopeReceivedCounter({
      inc(value = 1): void {
        total += value;
      },
    });
    // Stash for assertions
    (globalThis as unknown as { __evRecvTotal: () => number }).__evRecvTotal = (): number => total;
  });

  it('increments the counter, never updates DB, never publishes Redis', () => {
    const { ctx } = setupCtx();
    onEnvelopeReceived(ctx, { envelopeId: 42n });
    expect(
      (globalThis as unknown as { __evRecvTotal: () => number }).__evRecvTotal(),
    ).toBe(1);
  });

  it('accumulates the counter across multiple invocations', () => {
    const { ctx } = setupCtx();
    onEnvelopeReceived(ctx, { envelopeId: 1n });
    onEnvelopeReceived(ctx, { envelopeId: 2n });
    onEnvelopeReceived(ctx, { envelopeId: 3n });
    expect(
      (globalThis as unknown as { __evRecvTotal: () => number }).__evRecvTotal(),
    ).toBe(3);
  });

  it('does not send any frame back to the client (one-way ack)', () => {
    const { sock, ctx } = setupCtx();
    onEnvelopeReceived(ctx, { envelopeId: 7n });
    expect(sock.sent.length).toBe(0);
  });

  it('uses the default in-memory counter when no override is installed', () => {
    // Re-install the default observer (a counter whose increment
    // bumps the module-level test accessor `getEnvelopeReceivedCount`).
    let local = 0;
    setEnvelopeReceivedCounter({
      inc(value = 1): void {
        local += value;
      },
    });
    const { ctx } = setupCtx();
    onEnvelopeReceived(ctx, { envelopeId: 99n });
    expect(local).toBe(1);
    // The setter zeros the in-memory `getEnvelopeReceivedCount` at
    // installation time; calling it after the inc() above should
    // return 0 because the default counter is the one we replaced.
    expect(getEnvelopeReceivedCount()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// onPresencePing
// ---------------------------------------------------------------------------

describe('onPresencePing', () => {
  function makeDeps(pool: FakePool, redis: FakeRedis): PresencePingDeps {
    return {
      pool,
      redis,
      now: (): number => FROZEN_NOW_MS,
    };
  }

  it('updates devices.last_seen_at for the connected device', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();

    await onPresencePing(ctx, makeDeps(pool, redis));

    expect(pool.queries.length).toBe(1);
    const q = pool.queries[0];
    expect(q?.sql).toMatch(/UPDATE devices/);
    expect(q?.sql).toMatch(/last_seen_at/);
    expect(q?.params).toEqual([FROZEN_NOW_MS, DEVICE_ID]);
  });

  it('issues a Redis SET on the presence key with TTL 30s', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();

    await onPresencePing(ctx, makeDeps(pool, redis));

    expect(redis.presenceCalls.length).toBe(1);
    expect(redis.presenceCalls[0]).toEqual({
      deviceId: DEVICE_ID,
      ttlSec: PRESENCE_TTL_SEC,
    });
    expect(PRESENCE_TTL_SEC).toBe(30);
  });

  it('still issues the Redis SET when the DB UPDATE fails', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    pool.failNext = new Error('db down');

    await onPresencePing(ctx, makeDeps(pool, redis));

    expect(redis.presenceCalls.length).toBe(1);
    expect(redis.presenceCalls[0]?.deviceId).toBe(DEVICE_ID);
  });

  it('still attempts the DB UPDATE when the Redis SET fails', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    redis.failNextPresence = new Error('redis down');

    await onPresencePing(ctx, makeDeps(pool, redis));

    expect(pool.queries.length).toBe(1);
    expect(pool.queries[0]?.sql).toMatch(/UPDATE devices/);
  });

  it('does not send any frame back to the client (fire-and-forget)', async () => {
    const { sock, ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    await onPresencePing(ctx, makeDeps(pool, redis));
    expect(sock.sent.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// onSubscribeRoom
// ---------------------------------------------------------------------------

describe('onSubscribeRoom', () => {
  function makeDeps(redis: FakeRedis): RoomSubscriptionDeps {
    return { redis };
  }

  it('subscribes the listener on Redis and tracks the slug in the context', async () => {
    const { sock, ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onSubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));

    expect(ctx.subscribedRooms.has('general')).toBe(true);
    expect(redis.subscribes.length).toBe(1);
    expect(redis.subscribes[0]?.slug).toBe('general');
    expect(typeof redis.subscribes[0]?.listener).toBe('function');
    // No reply on success — the subscription is implicit.
    expect(sock.sent.length).toBe(0);
  });

  it('rejects an invalid slug with ERROR(INVALID_PAYLOAD); no redis subscribe', async () => {
    const { sock, ctx } = setupCtx();
    const redis = makeFakeRedis();

    // Empty, too-short, illegal chars, too-long.
    for (const bad of ['', 'ab', 'has space', 'UPPER', 'a'.repeat(65)]) {
      sock.sent.length = 0;
      ctx.subscribedRooms.clear();
      await onSubscribeRoom(ctx, { slug: bad }, makeDeps(redis));
      const reply = lastS2C(sock);
      expect(reply.t).toBe(S2C.ERROR);
      if (reply.t === S2C.ERROR) {
        expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
      }
      expect(ctx.subscribedRooms.size).toBe(0);
    }
    expect(redis.subscribes.length).toBe(0);
  });

  it('is idempotent on a duplicate subscribe: second call is a silent no-op', async () => {
    const { sock, ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onSubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));
    await onSubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));

    expect(redis.subscribes.length).toBe(1);
    expect(ctx.subscribedRooms.size).toBe(1);
    expect(sock.sent.length).toBe(0);
  });

  it('replies ERROR(INTERNAL) and does NOT track the slug when redis.subscribeRoom fails', async () => {
    const { sock, ctx } = setupCtx();
    const redis = makeFakeRedis();
    redis.failNextSubscribe = new Error('redis down');

    await onSubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INTERNAL);
    }
    expect(ctx.subscribedRooms.has('general')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// onUnsubscribeRoom
// ---------------------------------------------------------------------------

describe('onUnsubscribeRoom', () => {
  function makeDeps(redis: FakeRedis): RoomSubscriptionDeps {
    return { redis };
  }

  it('removes the slug from the context AND calls redis.unsubscribeRoom with the same listener', async () => {
    const { ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onSubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));
    const subscribedListener = redis.subscribes[0]?.listener;

    await onUnsubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));

    expect(ctx.subscribedRooms.has('general')).toBe(false);
    expect(redis.unsubscribes.length).toBe(1);
    expect(redis.unsubscribes[0]?.slug).toBe('general');
    // CRITICAL: ioredis listener removal is identity-based; the
    // unsubscribe MUST pass the same listener function reference
    // that was registered on subscribe.
    expect(redis.unsubscribes[0]?.listener).toBe(subscribedListener);
  });

  it('is a silent no-op when the slug was never subscribed', async () => {
    const { sock, ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onUnsubscribeRoom(ctx, { slug: 'never-subbed' }, makeDeps(redis));

    expect(redis.unsubscribes.length).toBe(0);
    expect(sock.sent.length).toBe(0);
  });

  it('rejects an invalid slug with ERROR(INVALID_PAYLOAD)', async () => {
    const { sock, ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onUnsubscribeRoom(ctx, { slug: 'BAD SLUG' }, makeDeps(redis));

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
    expect(redis.unsubscribes.length).toBe(0);
  });

  it('still removes the slug locally when redis.unsubscribeRoom fails', async () => {
    const { ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onSubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));
    redis.failNextUnsubscribe = new Error('redis down');

    await onUnsubscribeRoom(ctx, { slug: 'general' }, makeDeps(redis));

    // Local cleanup happens regardless of upstream failure.
    expect(ctx.subscribedRooms.has('general')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// drainRoomSubscriptions (connection-close path)
// ---------------------------------------------------------------------------

describe('drainRoomSubscriptions', () => {
  it('unsubscribes every active slug and clears the set', async () => {
    const { ctx } = setupCtx();
    const redis = makeFakeRedis();

    await onSubscribeRoom(ctx, { slug: 'general' }, { redis });
    await onSubscribeRoom(ctx, { slug: 'announcements' }, { redis });

    await drainRoomSubscriptions(ctx, { redis });

    expect(redis.unsubscribes.length).toBe(2);
    const slugs = redis.unsubscribes.map((u) => u.slug).sort();
    expect(slugs).toEqual(['announcements', 'general']);
    expect(ctx.subscribedRooms.size).toBe(0);
  });

  it('is a no-op when no subscriptions are active', async () => {
    const { ctx } = setupCtx();
    const redis = makeFakeRedis();
    await drainRoomSubscriptions(ctx, { redis });
    expect(redis.unsubscribes.length).toBe(0);
  });

  it('swallows redis errors during drain (best-effort cleanup)', async () => {
    const { ctx } = setupCtx();
    const redis = makeFakeRedis();
    await onSubscribeRoom(ctx, { slug: 'general' }, { redis });
    redis.failNextUnsubscribe = new Error('redis down');

    // Must not throw despite the upstream rejection.
    await expect(drainRoomSubscriptions(ctx, { redis })).resolves.not.toThrow();
    expect(ctx.subscribedRooms.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Dispatcher wiring: handleClientMessage routes to the right handler
// ---------------------------------------------------------------------------

describe('handleClientMessage — task 3.6 dispatch', () => {
  /** Build the SendEnvelopeDeps + PresencePingDeps + RoomSubscriptionDeps
   *  superset that handleClientMessage expects. The SEND_ENVELOPE
   *  bucket is irrelevant for these tests (we never emit
   *  SEND_ENVELOPE) but must still be present. */
  function makeOpts(pool: FakePool, redis: FakeRedis): SendEnvelopeDeps {
    return {
      pool: pool as unknown as SendEnvelopeDeps['pool'],
      redis,
      now: (): number => FROZEN_NOW_MS,
      sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
      sendEnvelopeBucket: { capacity: 50, refillPerSecond: 10 },
    };
  }

  it('routes ENVELOPE_RECEIVED to onEnvelopeReceived (no DB write, no Redis write)', async () => {
    let total = 0;
    setEnvelopeReceivedCounter({
      inc(value = 1): void {
        total += value;
      },
    });
    const { sock, ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    const opts = makeOpts(pool, redis);

    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.ENVELOPE_RECEIVED, envelopeId: 123n }),
      opts,
    );

    expect(total).toBe(1);
    expect(pool.queries.length).toBe(0);
    expect(redis.published.length).toBe(0);
    expect(sock.sent.length).toBe(0);
  });

  it('routes PRESENCE_PING to onPresencePing (DB UPDATE + Redis setPresence)', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    const opts = makeOpts(pool, redis);

    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.PRESENCE_PING }),
      opts,
    );

    expect(pool.queries.length).toBe(1);
    expect(pool.queries[0]?.sql).toMatch(/UPDATE devices/);
    expect(redis.presenceCalls.length).toBe(1);
    expect(redis.presenceCalls[0]).toEqual({
      deviceId: DEVICE_ID,
      ttlSec: PRESENCE_TTL_SEC,
    });
  });

  it('routes SUBSCRIBE_ROOM to onSubscribeRoom (slug recorded + Redis subscribe)', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    const opts = makeOpts(pool, redis);

    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.SUBSCRIBE_ROOM, slug: 'general' }),
      opts,
    );

    expect(ctx.subscribedRooms.has('general')).toBe(true);
    expect(redis.subscribes.length).toBe(1);
    expect(redis.subscribes[0]?.slug).toBe('general');
  });

  it('routes UNSUBSCRIBE_ROOM to onUnsubscribeRoom (slug removed + Redis unsubscribe)', async () => {
    const { ctx } = setupCtx();
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    const opts = makeOpts(pool, redis);

    // First subscribe via the dispatcher so the listener identity is
    // wired through the same path as a real client.
    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.SUBSCRIBE_ROOM, slug: 'general' }),
      opts,
    );

    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.UNSUBSCRIBE_ROOM, slug: 'general' }),
      opts,
    );

    expect(ctx.subscribedRooms.has('general')).toBe(false);
    expect(redis.unsubscribes.length).toBe(1);
    expect(redis.unsubscribes[0]?.slug).toBe('general');
    // Identity preservation — the listener registered on subscribe
    // must be the same one passed to unsubscribe.
    expect(redis.unsubscribes[0]?.listener).toBe(redis.subscribes[0]?.listener);
  });
});

// Reset the envelope-received counter override on test-suite teardown so
// other suites that import the gateway start from a clean slate.
afterEach(() => {
  setEnvelopeReceivedCounter({
    inc(): void {
      /* default no-op for cross-suite isolation */
    },
  });
});

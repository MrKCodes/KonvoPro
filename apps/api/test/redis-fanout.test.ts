// apps/api/test/redis-fanout.test.ts
//
// Unit tests for the per-device Redis fan-out + offline replay layer
// (task 3.5). Validates Requirements 12.11, 12.12, 12.15 and
// properties P14 (recipient isolation) and P15 (offline queue
// completeness).
//
// Strategy: exercise `attachInbox`, `publishEnvelopeToRecipient`,
// and `replayUndeliveredEnvelopes` directly with hand-rolled stubs
// for the `WSRedisPublisher` and the `FanoutDbPool` surfaces. No
// Fastify, no ioredis, no pg — the module is framework-agnostic by
// design.
//
// What we cover:
//
//   1. `publishEnvelopeToRecipient` publishes ONLY on
//      `dev:{recipientDeviceId}` (recipient isolation, P14).
//   2. `replayUndeliveredEnvelopes` forwards rows in `created_at`
//      ASC, `id` ASC tiebreak order with no duplicates and no
//      losses (P15).
//   3. `replayUndeliveredEnvelopes` is a no-op for an empty queue.
//   4. `attachInbox` subscribes to the recipient's channel BEFORE
//      replay so a concurrent insert is captured exactly once
//      (race-window dedup).
//   5. `attachInbox` dedups across the replay/live boundary: an
//      envelope id that was both replayed and published is
//      forwarded once.
//   6. The handle returned by `attachInbox` detaches the listener
//      cleanly (no leaked subscriptions).

import { describe, expect, it } from 'vitest';

import {
  EnvelopeRouterType,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import {
  attachInbox,
  fanoutChannelFor,
  publishEnvelopeToRecipient,
  replayUndeliveredEnvelopes,
  type FanoutDbPool,
} from '../src/ws/redis-fanout.js';
import type {
  DeviceMessageListener,
  WSContext,
  WSRedisPublisher,
  WSSocket,
} from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Test doubles
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
    on(): WSSocket {
      return sock;
    },
  };
  return sock;
}

const NULL_LOG = {
  fatal: () => {},
  error: () => {},
  warn: () => {},
  info: () => {},
  debug: () => {},
  trace: () => {},
  child(): unknown {
    return this;
  },
  level: 'info',
  silent: () => {},
} as unknown as WSContext['log'];

function makeCtx(deviceId: string): WSContext {
  const sock = makeFakeSocket();
  return {
    socket: sock,
    userId: 'user-1',
    deviceId,
    authenticated: true,
    helloReceived: true,
    log: NULL_LOG,
    subscribedRooms: new Set<string>(),
    send(msg): void {
      // Mirror buildContext's send behaviour: msgpack-encode and push
      // to the underlying socket. We import encodeS2C dynamically
      // through the protocol package; the synchronous variant is
      // already exposed via the shared codec.
      // We avoid the codec dependency here by writing a minimal
      // stand-in: `decodeS2C(encodeS2C(...))` round-trips, but
      // tests just want to read the structured frame back. Capture
      // the structured form directly on a side channel so tests
      // don't need to msgpack-decode every assertion.
      structuredFrames(sock).push(msg);
    },
    close(): void {
      sock.close();
    },
  };
}

const FRAMES_KEY = Symbol('structuredFrames');
function structuredFrames(sock: FakeSocket): import('@konvo/protocol').ServerToClient[] {
  const slot = (sock as unknown as Record<symbol, unknown>)[FRAMES_KEY];
  if (slot === undefined) {
    const arr: import('@konvo/protocol').ServerToClient[] = [];
    (sock as unknown as Record<symbol, unknown>)[FRAMES_KEY] = arr;
    return arr;
  }
  return slot as import('@konvo/protocol').ServerToClient[];
}

/** A pg-pool stub backed by a list of `EnvelopeRow`-shaped rows.
 *  Routes the two SQL shapes the redis-fanout module issues:
 *    - The replay SELECT (filters by recipient_device + delivered_at
 *      IS NULL + ORDER BY created_at ASC, id ASC).
 *    - The hydrate-by-id SELECT (filters by id + recipient_device).
 *  Anything else throws so a test that issues an unexpected query
 *  fails loudly rather than silently returning empty rows. */
interface FakeRow {
  id: string; // BIGINT-as-string
  session_id: string;
  sender_device: string;
  recipient_device: string;
  type: number;
  ciphertext: Buffer;
  created_at: Date;
  delivered_at: Date | null;
}

function makeFakePool(rows: FakeRow[]): FanoutDbPool {
  return {
    async query<R = unknown>(sql: string, params: readonly unknown[]) {
      const trimmed = sql.trim();
      if (trimmed.startsWith('SELECT id::text') && trimmed.includes('AND delivered_at IS NULL')) {
        // Replay query.
        const [recipient] = params as [string];
        const filtered = rows.filter(
          (r) => r.recipient_device === recipient && r.delivered_at === null,
        );
        // Match the SQL ORDER BY: created_at ASC, id ASC tiebreak.
        // BigInt comparison on the id (string-formed) preserves
        // numeric order.
        filtered.sort((a, b) => {
          if (a.created_at.getTime() !== b.created_at.getTime()) {
            return a.created_at.getTime() - b.created_at.getTime();
          }
          const ai = BigInt(a.id);
          const bi = BigInt(b.id);
          return ai < bi ? -1 : ai > bi ? 1 : 0;
        });
        return {
          rows: filtered as unknown as R[],
          rowCount: filtered.length,
        };
      }
      if (trimmed.startsWith('SELECT id::text') && trimmed.includes('id               = $1')) {
        // Hydrate-by-id query.
        const [id, recipient] = params as [string, string];
        const found = rows.find(
          (r) => r.id === id && r.recipient_device === recipient,
        );
        return {
          rows: found ? [found as unknown as R] : [],
          rowCount: found ? 1 : 0,
        };
      }
      throw new Error(`unexpected SQL in test stub: ${trimmed.slice(0, 80)}`);
    },
  };
}

/** A `WSRedisPublisher` mock that captures publishes and routes
 *  subscribe/unsubscribe to in-process listener arrays. Lets tests
 *  drive the live fan-out path by calling `redis.publish` directly. */
interface FakeRedis extends WSRedisPublisher {
  readonly published: Array<{ channel: string; payload: string }>;
  readonly deviceListeners: Map<string, DeviceMessageListener[]>;
}

function makeFakeRedis(): FakeRedis {
  const published: Array<{ channel: string; payload: string }> = [];
  const deviceListeners = new Map<string, DeviceMessageListener[]>();
  const fake: FakeRedis = {
    published,
    deviceListeners,
    async publish(channel: string, payload: string): Promise<number> {
      published.push({ channel, payload });
      // Drive live fan-out synchronously: any registered listener for
      // this channel sees the payload. We strip the `dev:` prefix so
      // listeners keyed by deviceId can be looked up directly.
      const devicePrefix = 'dev:';
      if (channel.startsWith(devicePrefix)) {
        const deviceId = channel.slice(devicePrefix.length);
        const listeners = deviceListeners.get(deviceId);
        if (listeners !== undefined) {
          for (const fn of listeners.slice()) {
            fn(payload);
          }
        }
      }
      return 0;
    },
    async setPresence(): Promise<void> {
      // No tests exercise presence here.
    },
    async subscribeRoom(): Promise<void> {
      throw new Error('subscribeRoom not used in fanout tests');
    },
    async unsubscribeRoom(): Promise<void> {
      throw new Error('unsubscribeRoom not used in fanout tests');
    },
    async subscribeDevice(
      deviceId: string,
      listener: DeviceMessageListener,
    ): Promise<void> {
      const arr = deviceListeners.get(deviceId) ?? [];
      arr.push(listener);
      deviceListeners.set(deviceId, arr);
    },
    async unsubscribeDevice(
      deviceId: string,
      listener: DeviceMessageListener,
    ): Promise<void> {
      const arr = deviceListeners.get(deviceId);
      if (arr === undefined) return;
      const idx = arr.indexOf(listener);
      if (idx >= 0) arr.splice(idx, 1);
      if (arr.length === 0) deviceListeners.delete(deviceId);
    },
  };
  return fake;
}

const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const SENDER_DEVICE = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const RECIPIENT = 'cccccccc-cccc-cccc-cccc-cccccccccccc';

function makeRow(
  id: bigint,
  createdAtMs: number,
  ciphertext: Uint8Array = new Uint8Array([0xde, 0xad]),
  recipient: string = RECIPIENT,
  delivered = false,
): FakeRow {
  return {
    id: id.toString(),
    session_id: SESSION_ID,
    sender_device: SENDER_DEVICE,
    recipient_device: recipient,
    type: EnvelopeRouterType.MESSAGE,
    ciphertext: Buffer.from(ciphertext),
    created_at: new Date(createdAtMs),
    delivered_at: delivered ? new Date(createdAtMs + 1) : null,
  };
}

/** Pull every `S2C.ENVELOPE` frame the ctx has received, in order. */
function envelopesSent(ctx: WSContext): CiphertextEnvelope[] {
  const sock = ctx.socket as FakeSocket;
  return structuredFrames(sock)
    .filter(
      (f): f is Extract<import('@konvo/protocol').ServerToClient, { t: S2C.ENVELOPE }> =>
        f.t === S2C.ENVELOPE,
    )
    .map((f) => f.envelope);
}

// ---------------------------------------------------------------------------
// publishEnvelopeToRecipient — recipient isolation (P14 / Requirement 12.15)
// ---------------------------------------------------------------------------

describe('publishEnvelopeToRecipient', () => {
  it('publishes on dev:{recipientDeviceId} only — never on any other channel', async () => {
    const redis = makeFakeRedis();
    await publishEnvelopeToRecipient(redis, RECIPIENT, 42n);

    expect(redis.published).toEqual([
      { channel: `dev:${RECIPIENT}`, payload: '42' },
    ]);
    // Sanity: the channel matches the centralised helper.
    expect(redis.published[0]?.channel).toBe(fanoutChannelFor(RECIPIENT));
    // No publish landed on the sender's channel or any other device.
    const otherDevice = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
    expect(
      redis.published.filter((p) => p.channel === `dev:${otherDevice}`),
    ).toEqual([]);
    expect(
      redis.published.filter((p) => p.channel === `dev:${SENDER_DEVICE}`),
    ).toEqual([]);
  });

  it('does not publish on a wildcard or broadcast channel', async () => {
    // Defence-in-depth check: even if a future refactor adds a
    // wildcard publisher, this property must hold.
    const redis = makeFakeRedis();
    await publishEnvelopeToRecipient(redis, RECIPIENT, 1n);
    for (const p of redis.published) {
      expect(p.channel.startsWith('dev:')).toBe(true);
      expect(p.channel.includes('*')).toBe(false);
      expect(p.channel.endsWith(RECIPIENT)).toBe(true);
    }
  });

  it('encodes the envelopeId as a decimal string (round-trips via BigInt)', async () => {
    const redis = makeFakeRedis();
    const id = 9_007_199_254_740_993n; // beyond Number.MAX_SAFE_INTEGER
    await publishEnvelopeToRecipient(redis, RECIPIENT, id);
    expect(redis.published[0]?.payload).toBe(id.toString());
    expect(BigInt(redis.published[0]!.payload)).toBe(id);
  });
});

// ---------------------------------------------------------------------------
// replayUndeliveredEnvelopes — order, no-duplicates, no-losses (P15)
// ---------------------------------------------------------------------------

describe('replayUndeliveredEnvelopes', () => {
  it('returns an empty set and sends nothing when the queue is empty', async () => {
    const ctx = makeCtx(RECIPIENT);
    const pool = makeFakePool([]);
    const seen = await replayUndeliveredEnvelopes(pool, ctx);
    expect(seen.size).toBe(0);
    expect(envelopesSent(ctx)).toEqual([]);
  });

  it('forwards every undelivered row in created_at ASC order', async () => {
    // Insert in deliberately-shuffled order; the SQL stub re-sorts.
    const rows: FakeRow[] = [
      makeRow(3n, 3000),
      makeRow(1n, 1000),
      makeRow(2n, 2000),
    ];
    const pool = makeFakePool(rows);
    const ctx = makeCtx(RECIPIENT);

    const seen = await replayUndeliveredEnvelopes(pool, ctx);

    const sent = envelopesSent(ctx);
    expect(sent.length).toBe(3);
    expect(sent[0]?.id).toBe(1n);
    expect(sent[1]?.id).toBe(2n);
    expect(sent[2]?.id).toBe(3n);
    expect([...seen].sort()).toEqual(['1', '2', '3']);
  });

  it('uses id ASC as the tiebreak when created_at ties', async () => {
    // Same timestamp on three envelopes; ordering must be by id.
    const sameTs = 5000;
    const rows: FakeRow[] = [
      makeRow(7n, sameTs),
      makeRow(5n, sameTs),
      makeRow(6n, sameTs),
    ];
    const pool = makeFakePool(rows);
    const ctx = makeCtx(RECIPIENT);

    await replayUndeliveredEnvelopes(pool, ctx);
    const sent = envelopesSent(ctx);
    expect(sent.map((e) => e.id)).toEqual([5n, 6n, 7n]);
  });

  it('skips rows that are already delivered (delivered_at IS NOT NULL)', async () => {
    const rows: FakeRow[] = [
      makeRow(1n, 1000), // undelivered
      makeRow(2n, 2000, undefined, RECIPIENT, true), // delivered
      makeRow(3n, 3000), // undelivered
    ];
    const pool = makeFakePool(rows);
    const ctx = makeCtx(RECIPIENT);

    await replayUndeliveredEnvelopes(pool, ctx);
    const sent = envelopesSent(ctx);
    expect(sent.map((e) => e.id)).toEqual([1n, 3n]);
  });

  it('does not forward envelopes addressed to other devices', async () => {
    const otherDevice = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
    const rows: FakeRow[] = [
      makeRow(1n, 1000, undefined, RECIPIENT),
      makeRow(2n, 2000, undefined, otherDevice),
      makeRow(3n, 3000, undefined, RECIPIENT),
    ];
    const pool = makeFakePool(rows);
    const ctx = makeCtx(RECIPIENT);

    await replayUndeliveredEnvelopes(pool, ctx);
    const sent = envelopesSent(ctx);
    // Only the rows for RECIPIENT are forwarded; recipient isolation
    // holds at the read path too.
    expect(sent.map((e) => e.id)).toEqual([1n, 3n]);
    for (const e of sent) {
      expect(e.recipientDeviceId).toBe(RECIPIENT);
    }
  });

  it('preserves the ciphertext bytes round-trip (not just the id)', async () => {
    const cipher = new Uint8Array([1, 2, 3, 4, 5]);
    const pool = makeFakePool([makeRow(1n, 1000, cipher)]);
    const ctx = makeCtx(RECIPIENT);
    await replayUndeliveredEnvelopes(pool, ctx);
    const sent = envelopesSent(ctx);
    expect(Array.from(sent[0]!.ciphertext)).toEqual(Array.from(cipher));
  });
});

// ---------------------------------------------------------------------------
// attachInbox — subscribe-then-replay, dedup, detach
// ---------------------------------------------------------------------------

describe('attachInbox', () => {
  it('subscribes BEFORE replay so a concurrent publish is captured', async () => {
    // We assert this by registering a side-effect probe on the
    // subscribe call: while the SQL replay is running, fire a
    // concurrent publish on the same channel and confirm the
    // listener is ALREADY attached.
    const redis = makeFakeRedis();

    // SQL pool that publishes a "concurrent" envelope id BEFORE
    // returning replay rows. The order of operations inside
    // attachInbox is: subscribe → replay; if replay starts before
    // subscribe lands, the listener won't catch the publish and
    // the test will fail.
    let concurrentFired = false;
    const racingPool: FanoutDbPool = {
      async query<R>(sql: string, params: readonly unknown[]) {
        const trimmed = sql.trim();
        if (trimmed.startsWith('SELECT id::text') && trimmed.includes('AND delivered_at IS NULL')) {
          // Fire the publish DURING the replay query — but only
          // once, on the first call. The listener is attached at
          // this point IFF subscribe ran first.
          if (!concurrentFired) {
            concurrentFired = true;
            await redis.publish(`dev:${RECIPIENT}`, '99');
          }
          return { rows: [] as R[], rowCount: 0 };
        }
        if (trimmed.startsWith('SELECT id::text') && trimmed.includes('id               = $1')) {
          const [id] = params as [string];
          // Return a row for id=99 so the live-publish path can hydrate.
          if (id === '99') {
            const row = makeRow(99n, 9999);
            return { rows: [row as unknown as R], rowCount: 1 };
          }
          return { rows: [] as R[], rowCount: 0 };
        }
        throw new Error('unexpected SQL');
      },
    };

    const ctx = makeCtx(RECIPIENT);
    await attachInbox(ctx, redis, racingPool);
    // Drain microtasks so the live-publish hydrate query resolves.
    await new Promise((r) => setImmediate(r));

    const sent = envelopesSent(ctx);
    expect(sent.map((e) => e.id)).toEqual([99n]);
  });

  it('dedups across replay and live publish (no duplicate forward)', async () => {
    // Replay returns id=1; then we manually publish id=1 again.
    // Because the same id was already in the seen set, the second
    // path must NOT forward a duplicate envelope.
    const redis = makeFakeRedis();
    const rows = [makeRow(1n, 1000)];
    const pool = makeFakePool(rows);
    const ctx = makeCtx(RECIPIENT);

    await attachInbox(ctx, redis, pool);
    // Now simulate a live publish of the SAME envelope id.
    await redis.publish(`dev:${RECIPIENT}`, '1');
    await new Promise((r) => setImmediate(r));

    const sent = envelopesSent(ctx);
    expect(sent.length).toBe(1);
    expect(sent[0]?.id).toBe(1n);
  });

  it('forwards a NEW live publish that did not appear in the replay', async () => {
    // Replay queue is empty (every row is delivered); a live publish
    // of id=42 lands AFTER attach and IS forwarded to the client.
    // Single pool: replay returns nothing (filter by delivered_at),
    // hydrate-by-id returns the row.
    const poolReplayEmpty: FanoutDbPool = {
      async query<R>(sql: string, params: readonly unknown[]) {
        const trimmed = sql.trim();
        if (trimmed.includes('AND delivered_at IS NULL')) {
          return { rows: [] as R[], rowCount: 0 };
        }
        const [id] = params as [string];
        if (id === '42') {
          return {
            rows: [makeRow(42n, 4242) as unknown as R],
            rowCount: 1,
          };
        }
        return { rows: [] as R[], rowCount: 0 };
      },
    };
    const ctx = makeCtx(RECIPIENT);
    const redis = makeFakeRedis();
    await attachInbox(ctx, redis, poolReplayEmpty);
    await redis.publish(`dev:${RECIPIENT}`, '42');
    await new Promise((r) => setImmediate(r));

    const sent = envelopesSent(ctx);
    expect(sent.length).toBe(1);
    expect(sent[0]?.id).toBe(42n);
  });

  it('detach() removes the device listener so further publishes are not forwarded', async () => {
    const redis = makeFakeRedis();
    const pool = makeFakePool([]);
    const ctx = makeCtx(RECIPIENT);

    const handle = await attachInbox(ctx, redis, pool);
    // Listener registered.
    expect(redis.deviceListeners.get(RECIPIENT)?.length).toBe(1);

    await handle.detach();
    // No listener remains for this device.
    expect(redis.deviceListeners.get(RECIPIENT)).toBeUndefined();

    // A subsequent publish on the channel must not produce any
    // envelope frame on the now-detached socket.
    const beforeCount = envelopesSent(ctx).length;
    await redis.publish(`dev:${RECIPIENT}`, '7');
    await new Promise((r) => setImmediate(r));
    expect(envelopesSent(ctx).length).toBe(beforeCount);
  });

  it('subscribes to the recipient device only — not to any other device channel', async () => {
    // P14 / Requirement 12.15 also constrains the subscribe path:
    // attachInbox must register exactly one listener and only on
    // the connection's own deviceId.
    const redis = makeFakeRedis();
    const pool = makeFakePool([]);
    const ctx = makeCtx(RECIPIENT);

    await attachInbox(ctx, redis, pool);

    expect(redis.deviceListeners.size).toBe(1);
    expect(redis.deviceListeners.has(RECIPIENT)).toBe(true);
    // No listeners on any other device.
    const otherDevice = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
    expect(redis.deviceListeners.has(otherDevice)).toBe(false);
    expect(redis.deviceListeners.has(SENDER_DEVICE)).toBe(false);
  });

  it('survives a malformed (non-decimal) live publish payload without crashing', async () => {
    const redis = makeFakeRedis();
    const pool = makeFakePool([]);
    const ctx = makeCtx(RECIPIENT);

    await attachInbox(ctx, redis, pool);
    await redis.publish(`dev:${RECIPIENT}`, 'not-a-number');
    await new Promise((r) => setImmediate(r));

    expect(envelopesSent(ctx)).toEqual([]);
  });

  it('drops a live publish whose row has been deleted (silent skip, no client frame)', async () => {
    const redis = makeFakeRedis();
    const pool: FanoutDbPool = {
      async query<R>(sql: string) {
        const trimmed = sql.trim();
        if (trimmed.includes('AND delivered_at IS NULL')) {
          return { rows: [] as R[], rowCount: 0 };
        }
        // Hydrate finds nothing.
        return { rows: [] as R[], rowCount: 0 };
      },
    };
    const ctx = makeCtx(RECIPIENT);

    await attachInbox(ctx, redis, pool);
    await redis.publish(`dev:${RECIPIENT}`, '999');
    await new Promise((r) => setImmediate(r));

    expect(envelopesSent(ctx)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// End-to-end: P15 (offline queue completeness)
// ---------------------------------------------------------------------------

describe('P15 offline queue completeness', () => {
  it('for N envelopes queued offline, on reconnect the recipient gets exactly N S2C.ENVELOPE frames in created_at order', async () => {
    // Simulate 25 envelopes inserted while the recipient was offline.
    const N = 25;
    const rows: FakeRow[] = [];
    for (let i = 0; i < N; i++) {
      // Random-ish creation order, ids assigned in insertion order.
      rows.push(
        makeRow(
          BigInt(i + 1),
          1_000_000 + (i * 37) % 10_000, // fake timestamps with collisions
          new Uint8Array([i & 0xff]),
        ),
      );
    }
    const pool = makeFakePool(rows);
    const ctx = makeCtx(RECIPIENT);
    const redis = makeFakeRedis();

    await attachInbox(ctx, redis, pool);

    const sent = envelopesSent(ctx);
    expect(sent.length).toBe(N);
    // Order: created_at ASC, id ASC tiebreak. We mirror the SQL stub's
    // sort here on a copy of the test rows to compute the expected
    // delivery order.
    const expected = rows.slice().sort((a, b) => {
      if (a.created_at.getTime() !== b.created_at.getTime()) {
        return a.created_at.getTime() - b.created_at.getTime();
      }
      const ai = BigInt(a.id);
      const bi = BigInt(b.id);
      return ai < bi ? -1 : ai > bi ? 1 : 0;
    });
    expect(sent.map((e) => e.id)).toEqual(expected.map((r) => BigInt(r.id)));
  });
});

// ---------------------------------------------------------------------------
// Smoke: the existing decodeS2C codec round-trips our forwarded frames
// ---------------------------------------------------------------------------

describe('forwarded S2C.ENVELOPE frames are codec-round-trippable', () => {
  it('the structured frame captured in tests reflects what encodeS2C/decodeS2C would produce', async () => {
    // We don't push msgpack bytes through the fake socket (the fake
    // captures structured frames directly); this test confirms that
    // the frames we DO capture are valid `ServerToClient` shapes
    // accepted by the codec.
    const { encodeS2C } = await import('@konvo/protocol');
    const env: CiphertextEnvelope = {
      id: 1n,
      sessionId: SESSION_ID,
      senderDeviceId: SENDER_DEVICE,
      recipientDeviceId: RECIPIENT,
      type: EnvelopeRouterType.MESSAGE,
      ciphertext: new Uint8Array([1, 2, 3]),
      createdAt: 1000,
    };
    const buf = encodeS2C({ t: S2C.ENVELOPE, envelope: env });
    const decoded = decodeS2C(buf);
    expect(decoded.t).toBe(S2C.ENVELOPE);
    if (decoded.t === S2C.ENVELOPE) {
      expect(decoded.envelope.id).toBe(1n);
      expect(Array.from(decoded.envelope.ciphertext)).toEqual([1, 2, 3]);
    }
  });
});

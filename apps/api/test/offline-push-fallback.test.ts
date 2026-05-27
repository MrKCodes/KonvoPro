// apps/api/test/offline-push-fallback.test.ts
//
// Task 10.4 — scheduled offline push fallback (Requirement 12.10).
//
//   "WHEN a recipient device is offline at the time of envelope
//    insertion AND the envelope's router type is not `ACK`, THE
//    WS_Gateway SHALL schedule a Web_Push notification to the
//    recipient device within 2 seconds of envelope insertion."
//
// What this file proves (against `apps/api/src/ws/gateway.ts:onSendEnvelope`):
//
//   1. Recipient online (Redis publish reported a live subscriber AND/OR
//      the device id is in the local connected-devices registry) → no
//      offline push is scheduled. Wake-up is unnecessary because the
//      live WS connection has already received the envelope id via the
//      `dev:{recipient}` fan-out.
//
//   2. Recipient offline + `routerType === ACK` → no offline push is
//      scheduled. ACK envelopes are the recipient's transport-level
//      acknowledgement of an inbound message; pushing on them would
//      wake the device for its own outbound traffic ("push storm").
//
//   3. Recipient offline + `routerType === MESSAGE` → exactly one
//      offline push is scheduled, and the scheduled callback fires
//      within 2 s of envelope insertion. We pin the timing assertion
//      with `vi.useFakeTimers()` + `vi.advanceTimersByTimeAsync(2000)`.
//
//   4. Recipient offline + `routerType === MESSAGE` + no
//      `push_subscriptions` row → the `offlinePushSender` is invoked,
//      it returns `{ ok: false, reason: 'no_subscription' }`
//      gracefully (mirroring `sendPushNotification` — task 9.3), and
//      no error is thrown. The envelope row is still persisted; the
//      recipient receives it on next reconnect via offline replay
//      (Requirement 12.11).
//
//   5. The push payload contains EXACTLY the four-field shape
//      `{ deviceId, type, senderHandle, conversationId }`. No
//      plaintext (`body`), no ciphertext, no key material — the
//      argument shape is asserted field-for-field against the call
//      site, mirroring the strict
//      `apps/api/src/push/sender.ts:PushPayloadSchema` guard.
//
// Test strategy mirrors `apps/api/test/no-dm-call-recording.test.ts`:
//   - `FakePool` records every parameterised query. Inserts return a
//     monotonic `id` so the `ENVELOPE_QUEUED` reply path completes.
//   - `FakeRedis.publish` returns the configured "subscriber count" so
//     the gateway's online/offline check is driven by the harness.
//   - `FakeSocket` captures every `S2C` frame as a `Uint8Array` so we
//     can decode and assert without spinning up a real WS upgrade.
//   - `onSendEnvelope` is exercised directly; the full
//     `wsRoutes`/`@fastify/websocket` upgrade is out of scope for
//     these unit tests (covered by the broader `ws-gateway` suite).

import { Buffer } from 'node:buffer';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  EnvelopeRouterType,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import { createLogger, setRedactionFailureCounter } from '../src/obs/logger.js';
import {
  buildContext,
  defaultOfflinePushScheduler,
  OFFLINE_PUSH_DELAY_MS,
  OFFLINE_PUSH_MAX_DELAY_MS,
  onSendEnvelope,
  type OfflinePushArgs,
  type OfflinePushScheduler,
  type OfflinePushSender,
  type SendEnvelopeDeps,
  type SenderHandleResolver,
} from '../src/ws/gateway.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { WSRedisPublisher, WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Fixed identifiers
// ---------------------------------------------------------------------------

const SENDER_USER = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const SENDER_DEVICE = '11111111-1111-1111-1111-111111111111';
const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const SENDER_HANDLE = 'alice';
const NOW_MS = 1_700_000_000_000;

// ---------------------------------------------------------------------------
// Capturing log destination (mirrors `no-dm-call-recording.test.ts`)
// ---------------------------------------------------------------------------

interface CapturedSink {
  write(chunk: string): boolean;
  lines: string[];
}

function makeSink(): CapturedSink {
  const lines: string[] = [];
  return {
    lines,
    write(chunk: string): boolean {
      for (const part of chunk.split('\n')) {
        if (part.length > 0) lines.push(part);
      }
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// Socket mock — captures every encoded S2C frame
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
  } as FakeSocket;
  return sock;
}

// ---------------------------------------------------------------------------
// Pool mock — returns monotonic ids for the envelope INSERT path
// ---------------------------------------------------------------------------

interface FakePool {
  readonly queries: Array<{ sql: string; params: readonly unknown[] }>;
  query<T = unknown>(
    sql: string,
    params: readonly unknown[],
  ): Promise<{ rows: T[]; rowCount: number }>;
}

function makeFakePool(): FakePool {
  let nextId = 1n;
  const queries: Array<{ sql: string; params: readonly unknown[] }> = [];
  const fake: FakePool = {
    queries,
    async query(sql: string, params: readonly unknown[]) {
      queries.push({ sql, params });
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        const id = nextId++;
        return { rows: [{ id: id.toString() }] as never[], rowCount: 1 };
      }
      return { rows: [] as never[], rowCount: 0 };
    },
  };
  return fake;
}

// ---------------------------------------------------------------------------
// Redis publisher mock — `publish` returns a configurable subscriber count
// ---------------------------------------------------------------------------

interface FakeRedis extends WSRedisPublisher {
  readonly published: Array<{ channel: string; payload: string }>;
  /** Subscriber count reported by the next `publish` call. The
   *  gateway uses `> 0` as the "recipient has a remote subscriber"
   *  signal; setting this to 0 lets the harness simulate an offline
   *  recipient without otherwise mutating the publisher. */
  publishSubscriberCount: number;
}

function makeFakeRedis(initialSubscriberCount: number): FakeRedis {
  const published: Array<{ channel: string; payload: string }> = [];
  const fake: FakeRedis = {
    published,
    publishSubscriberCount: initialSubscriberCount,
    async publish(channel: string, payload: string): Promise<number> {
      published.push({ channel, payload });
      return fake.publishSubscriberCount;
    },
    async setPresence(): Promise<void> {
      /* unused on the SEND_ENVELOPE path */
    },
    async subscribeRoom(): Promise<void> {
      /* unused */
    },
    async unsubscribeRoom(): Promise<void> {
      /* unused */
    },
    async subscribeDevice(): Promise<void> {
      /* unused */
    },
    async unsubscribeDevice(): Promise<void> {
      /* unused */
    },
  };
  return fake;
}

// ---------------------------------------------------------------------------
// Harness construction
// ---------------------------------------------------------------------------

function messageEnvelope(ciphertext: Uint8Array): CiphertextEnvelope {
  return {
    sessionId: SESSION_ID,
    senderDeviceId: SENDER_DEVICE,
    recipientDeviceId: RECIPIENT_DEVICE,
    type: EnvelopeRouterType.MESSAGE,
    ciphertext,
  };
}

function ackEnvelope(ciphertext: Uint8Array): CiphertextEnvelope {
  return {
    sessionId: SESSION_ID,
    senderDeviceId: SENDER_DEVICE,
    recipientDeviceId: RECIPIENT_DEVICE,
    type: EnvelopeRouterType.ACK,
    ciphertext,
  };
}

interface BuildDepsOpts {
  readonly pool: FakePool;
  readonly redis: FakeRedis;
  readonly connectedDevices: Set<string>;
  readonly offlinePushSender?: OfflinePushSender;
  readonly senderHandleResolver?: SenderHandleResolver;
  readonly offlinePushScheduler?: OfflinePushScheduler;
  readonly offlinePushDelayMs?: number;
}

function buildDeps(opts: BuildDepsOpts): SendEnvelopeDeps {
  return {
    pool: opts.pool as unknown as SendEnvelopeDeps['pool'],
    redis: opts.redis,
    now: (): number => NOW_MS,
    sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
    // Headroom so a single test never trips the rate limiter.
    sendEnvelopeBucket: { capacity: 100, refillPerSecond: 100 },
    connectedDevices: opts.connectedDevices,
    ...(opts.offlinePushSender !== undefined
      ? { offlinePushSender: opts.offlinePushSender }
      : {}),
    ...(opts.senderHandleResolver !== undefined
      ? { senderHandleResolver: opts.senderHandleResolver }
      : {}),
    ...(opts.offlinePushScheduler !== undefined
      ? { offlinePushScheduler: opts.offlinePushScheduler }
      : {}),
    ...(opts.offlinePushDelayMs !== undefined
      ? { offlinePushDelayMs: opts.offlinePushDelayMs }
      : {}),
  };
}

interface Harness {
  ctx: ReturnType<typeof buildContext>;
  sock: FakeSocket;
  sink: CapturedSink;
  pool: FakePool;
  redis: FakeRedis;
  connectedDevices: Set<string>;
}

function setupHarness(opts: { initialSubscriberCount: number }): Harness {
  const sink = makeSink();
  const log = createLogger({ destination: sink, level: 'debug' });
  const child = log.child({ requestId: 'req-offline-push' });
  const sock = makeFakeSocket();
  const ctx = buildContext(
    sock,
    SENDER_USER,
    SENDER_DEVICE,
    child as unknown as Parameters<typeof buildContext>[3],
  );
  ctx.helloReceived = true;
  const pool = makeFakePool();
  const redis = makeFakeRedis(opts.initialSubscriberCount);
  const connectedDevices = new Set<string>();
  return { ctx, sock, sink, pool, redis, connectedDevices };
}

beforeEach(() => {
  // The redaction-failure counter is module-global; reset to a no-op
  // so log assertions in this file don't accumulate state from a
  // sibling test's failure injection.
  setRedactionFailureCounter({ inc(): void {} });
});

// ---------------------------------------------------------------------------
// Test 1 — recipient online → no push scheduled
// ---------------------------------------------------------------------------

describe('task 10.4 — offline push fallback (Requirement 12.10)', () => {
  it('recipient online (Redis publish reports a live subscriber) → no push scheduled', async () => {
    const h = setupHarness({ initialSubscriberCount: 1 });
    const offlinePushSender = vi.fn<[OfflinePushArgs], Promise<unknown>>(
      async () => ({ ok: true }),
    );
    const senderHandleResolver = vi.fn<[string], Promise<string | null>>(
      async () => SENDER_HANDLE,
    );
    const scheduler = vi.fn<Parameters<OfflinePushScheduler>, void>();

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-online',
        envelope: messageEnvelope(new Uint8Array([1, 2, 3, 4])),
      },
      buildDeps({
        pool: h.pool,
        redis: h.redis,
        connectedDevices: h.connectedDevices,
        offlinePushSender,
        senderHandleResolver,
        offlinePushScheduler: scheduler,
      }),
    );

    // The envelope was queued.
    expect(h.sock.sent.length).toBe(1);
    const frame = decodeS2C(h.sock.sent[0]!);
    expect(frame.t).toBe(S2C.ENVELOPE_QUEUED);

    // Recipient was online → scheduler / sender / handle resolver were
    // all left alone. There is no wake-up to send.
    expect(scheduler).not.toHaveBeenCalled();
    expect(offlinePushSender).not.toHaveBeenCalled();
    expect(senderHandleResolver).not.toHaveBeenCalled();
  });

  it('recipient locally connected (in connectedDevices set) → no push scheduled', async () => {
    // Even if Redis happened to report 0 subscribers (e.g. transient
    // unsubscribe/resubscribe race during a publish), a local WS
    // connection on this api replica is sufficient evidence the
    // recipient is online.
    const h = setupHarness({ initialSubscriberCount: 0 });
    h.connectedDevices.add(RECIPIENT_DEVICE);
    const offlinePushSender = vi.fn<[OfflinePushArgs], Promise<unknown>>(
      async () => ({ ok: true }),
    );
    const senderHandleResolver = vi.fn<[string], Promise<string | null>>(
      async () => SENDER_HANDLE,
    );
    const scheduler = vi.fn<Parameters<OfflinePushScheduler>, void>();

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-local',
        envelope: messageEnvelope(new Uint8Array([5, 6, 7, 8])),
      },
      buildDeps({
        pool: h.pool,
        redis: h.redis,
        connectedDevices: h.connectedDevices,
        offlinePushSender,
        senderHandleResolver,
        offlinePushScheduler: scheduler,
      }),
    );

    expect(h.sock.sent.length).toBe(1);
    expect(decodeS2C(h.sock.sent[0]!).t).toBe(S2C.ENVELOPE_QUEUED);
    expect(scheduler).not.toHaveBeenCalled();
    expect(offlinePushSender).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Test 2 — offline + ACK → no push scheduled
  // -------------------------------------------------------------------------

  it('recipient offline + routerType=ACK → no push scheduled (avoid push-storming on acks)', async () => {
    const h = setupHarness({ initialSubscriberCount: 0 });
    const offlinePushSender = vi.fn<[OfflinePushArgs], Promise<unknown>>(
      async () => ({ ok: true }),
    );
    const senderHandleResolver = vi.fn<[string], Promise<string | null>>(
      async () => SENDER_HANDLE,
    );
    const scheduler = vi.fn<Parameters<OfflinePushScheduler>, void>();

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-ack',
        envelope: ackEnvelope(new Uint8Array([9, 10, 11, 12])),
      },
      buildDeps({
        pool: h.pool,
        redis: h.redis,
        connectedDevices: h.connectedDevices,
        offlinePushSender,
        senderHandleResolver,
        offlinePushScheduler: scheduler,
      }),
    );

    // ACK envelope was still persisted + replied to.
    expect(h.sock.sent.length).toBe(1);
    expect(decodeS2C(h.sock.sent[0]!).t).toBe(S2C.ENVELOPE_QUEUED);

    // No push activity whatsoever — ACK envelopes are exempt.
    expect(scheduler).not.toHaveBeenCalled();
    expect(offlinePushSender).not.toHaveBeenCalled();
    expect(senderHandleResolver).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Test 3 — offline + MESSAGE → push fires within 2 s
  // -------------------------------------------------------------------------

  describe('with fake timers', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('recipient offline + routerType=MESSAGE → push scheduled and fires within 2 s', async () => {
      const h = setupHarness({ initialSubscriberCount: 0 });
      const offlinePushSender = vi.fn<[OfflinePushArgs], Promise<unknown>>(
        async () => ({ ok: true }),
      );
      const senderHandleResolver = vi.fn<[string], Promise<string | null>>(
        async () => SENDER_HANDLE,
      );

      // Use the production-default scheduler (`setTimeout(...).unref()`)
      // so the timing assertion is against the real wiring rather than
      // a synchronous shortcut. With `vi.useFakeTimers()` Vitest replaces
      // the global `setTimeout` with a controllable timer, which the
      // default scheduler picks up automatically.
      await onSendEnvelope(
        h.ctx,
        {
          clientNonce: 'nonce-offline-msg',
          envelope: messageEnvelope(new Uint8Array([13, 14, 15, 16])),
        },
        buildDeps({
          pool: h.pool,
          redis: h.redis,
          connectedDevices: h.connectedDevices,
          offlinePushSender,
          senderHandleResolver,
          offlinePushScheduler: defaultOfflinePushScheduler,
        }),
      );

      // The envelope was queued before the push fires.
      expect(h.sock.sent.length).toBe(1);
      expect(decodeS2C(h.sock.sent[0]!).t).toBe(S2C.ENVELOPE_QUEUED);

      // Sanity: the requirement-mandated upper bound is 2 s. The
      // gateway's chosen delay is `OFFLINE_PUSH_DELAY_MS` and MUST be
      // strictly less than the bound — otherwise a push could fire
      // exactly at 2 s and a clock skew would push it over.
      expect(OFFLINE_PUSH_DELAY_MS).toBeLessThan(OFFLINE_PUSH_MAX_DELAY_MS);

      // The push has not fired yet (the scheduled callback is queued
      // on the timer wheel; nothing has been awaited).
      expect(offlinePushSender).not.toHaveBeenCalled();

      // Advance the fake clock to the 2 s ceiling. Anything scheduled
      // strictly less than 2 s must have run by now. The `Async`
      // variant flushes queued microtasks too, so the IIFE inside
      // the scheduled callback completes before we assert.
      await vi.advanceTimersByTimeAsync(OFFLINE_PUSH_MAX_DELAY_MS);

      expect(offlinePushSender).toHaveBeenCalledTimes(1);
      expect(senderHandleResolver).toHaveBeenCalledTimes(1);
      expect(senderHandleResolver).toHaveBeenCalledWith(SENDER_USER);
    });

    // -----------------------------------------------------------------------
    // Test 4 — offline + no push subscription → no error thrown
    // -----------------------------------------------------------------------

    it('recipient offline + no push_subscriptions row → push attempt is graceful, no error thrown', async () => {
      const h = setupHarness({ initialSubscriberCount: 0 });
      // Mirror the production behaviour of `sendPushNotification`:
      // when no row exists for the recipient device, the call returns
      // `{ ok: false, reason: 'no_subscription' }` rather than throwing.
      // The gateway must not surface this as an error.
      const offlinePushSender = vi.fn<[OfflinePushArgs], Promise<unknown>>(
        async () => ({ ok: false, reason: 'no_subscription' as const }),
      );
      const senderHandleResolver = vi.fn<[string], Promise<string | null>>(
        async () => SENDER_HANDLE,
      );

      // We assert two things:
      //   (a) `onSendEnvelope` resolves without rejecting, AND
      //   (b) the scheduled push callback resolves without throwing.
      // A `process.on('unhandledRejection')` listener catches any
      // promise rejection that escapes the IIFE inside the scheduler
      // callback (the gateway uses `void (async () => { ... })()`,
      // which would surface a thrown error as an unhandled rejection).
      const unhandled: unknown[] = [];
      const handler = (err: unknown): void => {
        unhandled.push(err);
      };
      process.on('unhandledRejection', handler);

      try {
        await expect(
          onSendEnvelope(
            h.ctx,
            {
              clientNonce: 'nonce-no-sub',
              envelope: messageEnvelope(new Uint8Array([17, 18, 19, 20])),
            },
            buildDeps({
              pool: h.pool,
              redis: h.redis,
              connectedDevices: h.connectedDevices,
              offlinePushSender,
              senderHandleResolver,
              offlinePushScheduler: defaultOfflinePushScheduler,
            }),
          ),
        ).resolves.toBeUndefined();

        // The envelope row was still persisted — the recipient gets
        // it on next reconnect via offline replay (Requirement 12.11).
        const inserts = h.pool.queries.filter((q) =>
          q.sql.trim().startsWith('INSERT INTO ciphertext_envelopes'),
        );
        expect(inserts.length).toBe(1);

        // Drain the timer wheel so the scheduled callback runs.
        await vi.advanceTimersByTimeAsync(OFFLINE_PUSH_MAX_DELAY_MS);

        // The sender was invoked once and returned its no_subscription
        // result; the gateway treated that as a graceful no-op.
        expect(offlinePushSender).toHaveBeenCalledTimes(1);
        // No unhandled promise rejection escaped the scheduled callback.
        expect(unhandled).toEqual([]);
      } finally {
        process.off('unhandledRejection', handler);
      }
    });

    // -----------------------------------------------------------------------
    // Test 5 — push payload contains exactly the four whitelisted fields
    // -----------------------------------------------------------------------

    it('push payload contains exactly { deviceId, type, senderHandle, conversationId } — no plaintext, ciphertext, or keys', async () => {
      const h = setupHarness({ initialSubscriberCount: 0 });

      // Embed a canary inside the ciphertext bytes; the offline-push
      // payload must NEVER contain these bytes (in any encoding) and
      // must NEVER carry the literal canary string. The gateway only
      // reaches into the envelope's `sessionId` and `recipientDeviceId`
      // fields plus the resolved sender handle — never the ciphertext.
      const enc = new TextEncoder();
      const canary = enc.encode('__OFFLINE_PUSH_CANARY__');
      const ciphertext = new Uint8Array(64);
      ciphertext.set(canary, 0);
      for (let i = canary.length; i < ciphertext.length; i += 1) {
        ciphertext[i] = (i + 17) & 0xff;
      }

      const captured: OfflinePushArgs[] = [];
      const offlinePushSender: OfflinePushSender = async (args) => {
        // Defensive copy so a future implementation that mutates the
        // argument after the call doesn't poison the assertion.
        captured.push({ ...args });
        return { ok: true };
      };
      const senderHandleResolver = vi.fn<[string], Promise<string | null>>(
        async () => SENDER_HANDLE,
      );

      await onSendEnvelope(
        h.ctx,
        {
          clientNonce: 'nonce-payload-shape',
          envelope: messageEnvelope(ciphertext),
        },
        buildDeps({
          pool: h.pool,
          redis: h.redis,
          connectedDevices: h.connectedDevices,
          offlinePushSender,
          senderHandleResolver,
          offlinePushScheduler: defaultOfflinePushScheduler,
        }),
      );
      await vi.advanceTimersByTimeAsync(OFFLINE_PUSH_MAX_DELAY_MS);

      // Exactly one push was scheduled and fired.
      expect(captured.length).toBe(1);
      const args = captured[0]!;

      // The argument shape is exactly the four whitelisted fields.
      // Sorting the keys gives a stable comparison regardless of
      // construction order.
      expect(Object.keys(args).sort()).toEqual(
        ['conversationId', 'deviceId', 'senderHandle', 'type'].sort(),
      );

      // Field values come from the envelope's metadata + the resolved
      // handle — never from the ciphertext.
      expect(args.deviceId).toBe(RECIPIENT_DEVICE);
      expect(args.conversationId).toBe(SESSION_ID);
      expect(args.senderHandle).toBe(SENDER_HANDLE);
      // `type` is one of the documented push-type strings (Requirement
      // 13.5 / `apps/web/src/pwa/sw-push-handler.ts:GENERIC_BODIES`).
      // For an `EnvelopeRouterType.MESSAGE` envelope the gateway maps
      // to `'dm.message'`.
      expect(args.type).toBe('dm.message');

      // No forbidden fields slipped in via TypeScript laxity. Listing
      // a few common offenders explicitly so a future regression that
      // adds e.g. `body` or `ciphertext` to the payload fails this
      // assertion loudly.
      expect((args as Record<string, unknown>)['body']).toBeUndefined();
      expect((args as Record<string, unknown>)['ciphertext']).toBeUndefined();
      expect((args as Record<string, unknown>)['key']).toBeUndefined();
      expect((args as Record<string, unknown>)['privateKey']).toBeUndefined();
      expect((args as Record<string, unknown>)['identityPriv']).toBeUndefined();
      expect((args as Record<string, unknown>)['secret']).toBeUndefined();

      // Final defense-in-depth: no canary bytes (in any common
      // encoding) or canary string slipped into any payload field.
      const haystack = JSON.stringify(args);
      expect(haystack.includes('__OFFLINE_PUSH_CANARY__')).toBe(false);
      const hex = Buffer.from(ciphertext).toString('hex');
      expect(haystack.includes(hex)).toBe(false);
      const b64 = Buffer.from(ciphertext).toString('base64');
      expect(haystack.includes(b64)).toBe(false);
    });
  });
});

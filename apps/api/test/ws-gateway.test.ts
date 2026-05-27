// apps/api/test/ws-gateway.test.ts
//
// Unit tests for the WebSocket gateway (task 3.3) — authentication and
// HELLO handshake. Validates Requirements 12.1, 12.2, 12.13, 12.14.
//
// Strategy: we exercise the gateway entirely via its exported
// primitives (`authenticate`, `buildContext`, `handleConnection`,
// `handleClientMessage`, `queuedCountForDevice`) with a hand-rolled
// `WSSocket` mock and a hand-rolled `pg.Pool` mock. This is a UNIT
// test of gateway behaviour — it does NOT bring up `@fastify/websocket`
// or a real WebSocket; the integration test that exercises an actual
// upgrade lands in `apps/api/test/ws-gateway.integration.spec.ts`
// (CI; not authored here).
//
// Test cases (mapped to task brief):
//   1. Connection without token → close with auth error before any
//      frame is received.
//   2. Connection with token < 600s remaining → close with auth error.
//   3. HELLO not within 5s → ERROR + close.
//   4. HELLO with protoVersion: 2 → ERROR + close.
//   5. HELLO with protoVersion: 1 → HELLO_OK reply.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  C2S,
  ErrorCode,
  S2C,
  decodeS2C,
  encodeC2S,
  EnvelopeRouterType,
  type ServerToClient,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import {
  HELLO_TIMEOUT_MS,
  MIN_TOKEN_LIFETIME_SEC,
  QUEUED_COUNT_CAP,
  authenticate,
  buildContext,
  defaultSendEnvelopeBuckets,
  extractToken,
  fanoutChannelFor,
  handleClientMessage,
  handleConnection,
  onSendEnvelope,
  queuedCountForDevice,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type { WSSocket } from '../src/ws/types.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { AccessTokenService } from '../src/services/auth/tokens.js';

// ---------------------------------------------------------------------------
// Test doubles
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
  /** Helper: deliver a wire frame as if the client sent it. */
  deliverMessage(buf: Uint8Array): void;
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
      // Snapshot the bytes so a downstream caller mutating the buffer
      // can't retroactively rewrite history.
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
    deliverMessage(buf: Uint8Array): void {
      const fn = listeners.message;
      if (fn === null) throw new Error('no message listener attached');
      fn(buf);
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

/** Build an `AccessTokenService` mock that returns canned claims for a
 *  specific token string. Any other token rejects with a generic Error. */
function makeTokenService(tokens: Record<string, { sub: string; did: string; exp: number; iat: number }>): AccessTokenService {
  return {
    async sign(): Promise<string> {
      throw new Error('sign not used in gateway tests');
    },
    async verify(token: string) {
      const claims = tokens[token];
      if (claims === undefined) {
        throw new Error('invalid token');
      }
      return claims;
    },
  };
}

/** Build a `pg.Pool`-shaped stub with the given count of undelivered
 *  envelopes for any deviceId queried. */
function makePool(undeliveredCount: number) {
  return {
    async query(_sql: string, params: readonly unknown[]) {
      // The real query uses a `LIMIT cap+1` subquery. To honor that
      // shape the stub clamps the returned count by the LIMIT param
      // (`params[1]`) so callers see the same bounded behaviour.
      const limit =
        typeof params[1] === 'number' ? (params[1] as number) : Number.POSITIVE_INFINITY;
      const bounded = Math.min(undeliveredCount, limit);
      return { rows: [{ count: String(bounded) }], rowCount: 1 };
    },
  };
}

/** A Redis publisher mock that captures every `publish` call.
 *
 *  Captures `(channel, payload)` tuples in order and (optionally)
 *  fails the next `publish` to simulate a transient Redis outage. */
interface FakeRedis {
  readonly published: Array<{ channel: string; payload: string }>;
  /** If non-null, the next `publish` rejects with this error. Cleared
   *  after one rejection. */
  failNext: Error | null;
  publish(channel: string, payload: string): Promise<number>;
}

function makeFakeRedis(): FakeRedis {
  const fake: FakeRedis = {
    published: [],
    failNext: null,
    async publish(channel: string, payload: string): Promise<number> {
      if (fake.failNext !== null) {
        const err = fake.failNext;
        fake.failNext = null;
        throw err;
      }
      fake.published.push({ channel, payload });
      return 0;
    },
  };
  return fake;
}

/** A pg.Pool stub that simulates `ciphertext_envelopes` for SEND_ENVELOPE.
 *
 *  Routes:
 *    - The HELLO `queuedCount` query (SELECT count(*) FROM (SELECT 1 …))
 *      returns 0.
 *    - The SEND_ENVELOPE INSERT (`INSERT INTO ciphertext_envelopes …
 *      ON CONFLICT (sender_device, client_nonce) DO NOTHING RETURNING id`)
 *      stores the row keyed by `(sender_device, client_nonce)` and
 *      returns the assigned id on first insert; on conflict returns
 *      zero rows.
 *    - The SEND_ENVELOPE SELECT (`SELECT id FROM ciphertext_envelopes
 *      WHERE sender_device = $1 AND client_nonce = $2`) returns the
 *      previously-inserted id.
 *
 *  Failure mode: setting `failNextInsert` causes the next INSERT to
 *  throw — used to test the DB-failure path. The flag is cleared after
 *  one trigger.
 */
interface FakeEnvelopePool {
  readonly inserts: Array<{
    sessionId: string;
    senderDevice: string;
    recipientDevice: string;
    ciphertext: Buffer;
    type: number;
    clientNonce: string;
    id: bigint;
  }>;
  failNextInsert: Error | null;
  query(sql: string, params: readonly unknown[]): Promise<{ rows: unknown[]; rowCount: number }>;
}

function makeFakeEnvelopePool(): FakeEnvelopePool {
  let nextId = 1n;
  const fake: FakeEnvelopePool = {
    inserts: [],
    failNextInsert: null,
    async query(sql: string, params: readonly unknown[]) {
      // Route by leading SQL keyword. We don't try to be a SQL parser
      // — the gateway only issues three distinct shapes against this
      // stub and each starts with a unique keyword (SELECT for the
      // HELLO queuedCount and the conflict-lookup; INSERT for the
      // upsert).
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        if (fake.failNextInsert !== null) {
          const err = fake.failNextInsert;
          fake.failNextInsert = null;
          throw err;
        }
        const [sessionId, senderDevice, recipientDevice, ciphertext, type, clientNonce] =
          params as [string, string, string, Buffer, number, string];
        // Idempotency: if a row already exists for (senderDevice,
        // clientNonce), return zero rows to mirror ON CONFLICT DO
        // NOTHING.
        const existing = fake.inserts.find(
          (r) => r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing !== undefined) {
          return { rows: [], rowCount: 0 };
        }
        const id = nextId++;
        fake.inserts.push({
          sessionId,
          senderDevice,
          recipientDevice,
          ciphertext,
          type,
          clientNonce,
          id,
        });
        return { rows: [{ id: id.toString() }], rowCount: 1 };
      }
      if (
        trimmed.startsWith('SELECT id\n           FROM ciphertext_envelopes') ||
        trimmed.startsWith('SELECT id FROM ciphertext_envelopes')
      ) {
        const [senderDevice, clientNonce] = params as [string, string];
        const existing = fake.inserts.find(
          (r) => r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing === undefined) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ id: existing.id.toString() }], rowCount: 1 };
      }
      // HELLO queuedCount fallback — returns 0.
      return { rows: [{ count: '0' }], rowCount: 1 };
    },
  };
  return fake;
}

/** Build a fresh SEND_ENVELOPE deps object backed by the supplied
 *  pool + redis mocks. Each invocation uses an isolated bucket map
 *  and a small bucket (capacity 3, refill 1/s) for deterministic
 *  rate-limit assertions; tests that need the spec defaults override
 *  via the second argument. */
function makeSendEnvelopeDeps(
  pool: FakeEnvelopePool,
  redis: FakeRedis,
  overrides: Partial<SendEnvelopeDeps> = {},
): SendEnvelopeDeps {
  return {
    pool,
    redis,
    now: overrides.now ?? ((): number => 1_700_000_000_000),
    sendEnvelopeBuckets:
      overrides.sendEnvelopeBuckets ?? new Map<string, TokenBucketState>(),
    sendEnvelopeBucket:
      overrides.sendEnvelopeBucket ?? { capacity: 3, refillPerSecond: 1 },
  };
}

/** Helpers to read the most recent S2C frame the socket received. */
function lastS2C(sock: FakeSocket): ServerToClient {
  const last = sock.sent[sock.sent.length - 1];
  if (last === undefined) throw new Error('no frame sent');
  return decodeS2C(last);
}

/** Build the deps object `handleClientMessage` and `handleConnection`
 *  expect for tests that don't exercise SEND_ENVELOPE. The Redis
 *  publisher and bucket map are throwaway — any HELLO-only test that
 *  reaches into them is a bug. */
function makeStubDeps(
  pool: { query: (sql: string, params: readonly unknown[]) => Promise<unknown> },
  now: () => number,
): SendEnvelopeDeps {
  return {
    pool: pool as unknown as SendEnvelopeDeps['pool'],
    redis: makeFakeRedis(),
    now,
    sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
    sendEnvelopeBucket: { capacity: 50, refillPerSecond: 10 },
  };
}

// ---------------------------------------------------------------------------
// extractToken
// ---------------------------------------------------------------------------

describe('extractToken', () => {
  function makeReq(opts: {
    headers?: Record<string, string | undefined>;
    query?: Record<string, unknown>;
  }) {
    return {
      headers: opts.headers ?? {},
      query: opts.query ?? {},
    } as unknown as Parameters<typeof extractToken>[0];
  }

  it('reads from Authorization: Bearer header (preferred)', () => {
    const req = makeReq({
      headers: { authorization: 'Bearer header-token' },
      query: { token: 'query-token' },
    });
    expect(extractToken(req)).toBe('header-token');
  });

  it('falls back to ?token=... query parameter', () => {
    const req = makeReq({ query: { token: 'query-token' } });
    expect(extractToken(req)).toBe('query-token');
  });

  it('returns null when neither source carries a token', () => {
    expect(extractToken(makeReq({}))).toBeNull();
  });

  it('rejects malformed Authorization header (no scheme)', () => {
    const req = makeReq({ headers: { authorization: 'notbearer' } });
    expect(extractToken(req)).toBeNull();
  });

  it('rejects non-Bearer schemes', () => {
    const req = makeReq({ headers: { authorization: 'Basic abc' } });
    expect(extractToken(req)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// authenticate
// ---------------------------------------------------------------------------

describe('authenticate', () => {
  const NOW_SEC = 1_700_000_000;

  function makeReq(token: string | null) {
    return {
      headers: token === null ? {} : { authorization: `Bearer ${token}` },
      query: {},
    } as unknown as Parameters<typeof authenticate>[0];
  }

  it('returns missing_token when no token present', async () => {
    const svc = makeTokenService({});
    const result = await authenticate(makeReq(null), svc, NOW_SEC);
    expect(result).toEqual({ ok: false, reason: 'missing_token' });
  });

  it('returns invalid_token when verify throws', async () => {
    const svc = makeTokenService({});
    const result = await authenticate(makeReq('garbage'), svc, NOW_SEC);
    expect(result).toEqual({ ok: false, reason: 'invalid_token' });
  });

  it('returns token_too_short when remaining lifetime is below 600s', async () => {
    const svc = makeTokenService({
      'fresh-but-old': {
        sub: 'u',
        did: 'd',
        iat: NOW_SEC - 100,
        // exactly 599 seconds left
        exp: NOW_SEC + MIN_TOKEN_LIFETIME_SEC - 1,
      },
    });
    const result = await authenticate(makeReq('fresh-but-old'), svc, NOW_SEC);
    expect(result).toEqual({ ok: false, reason: 'token_too_short' });
  });

  it('returns invalid_token when did is empty (pre-enrollment)', async () => {
    const svc = makeTokenService({
      'no-device': {
        sub: 'user-1',
        did: '', // pre-enrollment placeholder
        iat: NOW_SEC,
        exp: NOW_SEC + 900,
      },
    });
    const result = await authenticate(makeReq('no-device'), svc, NOW_SEC);
    expect(result).toEqual({ ok: false, reason: 'invalid_token' });
  });

  it('returns ok with userId+deviceId when token has ≥600s remaining', async () => {
    const svc = makeTokenService({
      good: {
        sub: 'user-1',
        did: 'device-1',
        iat: NOW_SEC,
        exp: NOW_SEC + MIN_TOKEN_LIFETIME_SEC, // exactly 600s
      },
    });
    const result = await authenticate(makeReq('good'), svc, NOW_SEC);
    expect(result).toEqual({ ok: true, userId: 'user-1', deviceId: 'device-1' });
  });
});

// ---------------------------------------------------------------------------
// queuedCountForDevice
// ---------------------------------------------------------------------------

describe('queuedCountForDevice', () => {
  it('returns 0 when no rows queued', async () => {
    const pool = makePool(0);
    expect(await queuedCountForDevice(pool, 'd1')).toBe(0);
  });

  it('returns the exact count when below the cap', async () => {
    const pool = makePool(42);
    expect(await queuedCountForDevice(pool, 'd1')).toBe(42);
  });

  it('caps the returned count at QUEUED_COUNT_CAP (10000)', async () => {
    // The pool stub clamps to LIMIT (cap+1=10001). The function must
    // then collapse anything > cap back down to exactly cap.
    const pool = makePool(50_000);
    expect(await queuedCountForDevice(pool, 'd1')).toBe(QUEUED_COUNT_CAP);
  });
});

// ---------------------------------------------------------------------------
// handleClientMessage — HELLO state machine
// ---------------------------------------------------------------------------

describe('handleClientMessage — HELLO', () => {
  const DEVICE_ID = '11111111-1111-1111-1111-111111111111';
  const USER_ID = 'user-1';

  function setup(undeliveredCount = 0) {
    const sock = makeFakeSocket();
    const ctx = buildContext(sock, USER_ID, DEVICE_ID, NULL_LOG);
    const pool = makePool(undeliveredCount);
    const now = (): number => 1_700_000_000_000;
    const deps = makeStubDeps(pool, now);
    return { sock, ctx, pool, now, deps };
  }

  it('replies with HELLO_OK on valid HELLO with protoVersion 1', async () => {
    const { sock, ctx, deps } = setup(7);
    const frame = encodeC2S({
      t: C2S.HELLO,
      deviceId: DEVICE_ID,
      protoVersion: 1,
    });

    await handleClientMessage(ctx, frame, deps);

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.HELLO_OK);
    if (reply.t === S2C.HELLO_OK) {
      expect(reply.serverTimeMs).toBe(1_700_000_000_000);
      expect(reply.queuedCount).toBe(7);
    }
    expect(sock.closes).toEqual([]);
    expect(ctx.helloReceived).toBe(true);
  });

  it('caps HELLO_OK queuedCount at 10000', async () => {
    const { sock, ctx, deps } = setup(50_000);
    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.HELLO, deviceId: DEVICE_ID, protoVersion: 1 }),
      deps,
    );
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.HELLO_OK);
    if (reply.t === S2C.HELLO_OK) {
      expect(reply.queuedCount).toBe(QUEUED_COUNT_CAP);
    }
  });

  it('rejects HELLO with deviceId mismatching the token', async () => {
    const { sock, ctx, deps } = setup();
    await handleClientMessage(
      ctx,
      encodeC2S({
        t: C2S.HELLO,
        deviceId: '99999999-9999-9999-9999-999999999999',
        protoVersion: 1,
      }),
      deps,
    );

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.AUTH_REQUIRED);
    }
    expect(sock.closes.length).toBe(1);
    expect(sock.closes[0]?.code).toBe(1000);
    expect(ctx.helloReceived).toBe(false);
  });

  it('rejects malformed first frames with INVALID_PAYLOAD and closes', async () => {
    const { sock, ctx, deps } = setup();
    await handleClientMessage(ctx, new Uint8Array([0xff, 0xff, 0xff]), deps);
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
    expect(sock.closes.length).toBe(1);
    expect(sock.closes[0]?.code).toBe(1000);
  });

  it('rejects non-HELLO first frames with INVALID_PAYLOAD and closes', async () => {
    const { sock, ctx, deps } = setup();
    // PRESENCE_PING is well-formed but illegal pre-HELLO.
    await handleClientMessage(ctx, encodeC2S({ t: C2S.PRESENCE_PING }), deps);
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
    expect(sock.closes.length).toBe(1);
  });

  it('rejects a duplicate HELLO post-handshake', async () => {
    const { sock, ctx, deps } = setup();
    // First HELLO succeeds.
    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.HELLO, deviceId: DEVICE_ID, protoVersion: 1 }),
      deps,
    );
    expect(ctx.helloReceived).toBe(true);

    // Second HELLO is a protocol violation.
    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.HELLO, deviceId: DEVICE_ID, protoVersion: 1 }),
      deps,
    );
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
    expect(sock.closes.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// handleClientMessage — protoVersion 2 rejection
// ---------------------------------------------------------------------------
//
// The codec's static type narrowing pins `protoVersion` to the literal
// `1`, so we cannot construct a `ClientToServer` with `protoVersion: 2`
// through `encodeC2S`. The wire-level check is exercised by hand-
// crafting a msgpack frame whose discriminator is C2S.HELLO but whose
// `protoVersion` field is 2 — the codec's `assertLiteral(v, 1)` fires
// and the gateway maps that to the same `INVALID_PAYLOAD` close path
// as any other malformed frame. We assert that close path here.

describe('handleClientMessage — protoVersion ≠ 1', () => {
  it('closes with INVALID_PAYLOAD when protoVersion is not 1', async () => {
    const sock = makeFakeSocket();
    const ctx = buildContext(sock, 'user-1', 'device-1', NULL_LOG);
    const pool = makePool(0);
    const now = (): number => Date.now();
    const deps = makeStubDeps(pool, now);

    // Hand-roll the msgpack equivalent of `{ t: 1, deviceId: 'device-1',
    // protoVersion: 2 }`. The codec rejects this at decode time
    // (`assertLiteral(v, 1)` in the C2S validator) which collapses
    // to `CodecError('malformed')` per the codec contract — and the
    // gateway's `tryDecode` maps that to INVALID_PAYLOAD.
    //
    // We encode by starting from a valid `protoVersion: 1` HELLO via
    // `encodeC2S` and flipping the single byte that carries the
    // version. msgpack encodes small positive ints (`fixint`) as the
    // byte value itself, so the `0x01` byte that follows the
    // `protoVersion` key string can be located with `indexOf` and
    // overwritten with `0x02`. This avoids depending on
    // `@msgpack/msgpack` directly from the api package.
    const baseline = encodeC2S({
      t: C2S.HELLO,
      deviceId: 'device-1',
      protoVersion: 1,
    });
    // Find "protoVersion" key (12-char fixstr) and replace the value
    // byte that follows it.
    const keyBytes = new TextEncoder().encode('protoVersion');
    const offset = (() => {
      // msgpack fixstr header is 0xa0 | length; 12 → 0xac. Search for
      // the header byte followed by the key bytes.
      for (let i = 0; i < baseline.length - keyBytes.length - 1; i++) {
        if (baseline[i] !== 0xa0 + keyBytes.length) continue;
        let match = true;
        for (let j = 0; j < keyBytes.length; j++) {
          if (baseline[i + 1 + j] !== keyBytes[j]) {
            match = false;
            break;
          }
        }
        if (match) return i + 1 + keyBytes.length;
      }
      return -1;
    })();
    expect(offset).toBeGreaterThan(0);
    const frame = new Uint8Array(baseline);
    frame[offset] = 0x02; // overwrite protoVersion: 1 → 2

    await handleClientMessage(ctx, frame, deps);

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
    expect(sock.closes.length).toBe(1);
    expect(sock.closes[0]?.code).toBe(1000);
    expect(ctx.helloReceived).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// handleConnection — HELLO timeout
// ---------------------------------------------------------------------------

describe('handleConnection — HELLO timeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('closes the socket with INVALID_PAYLOAD when HELLO does not arrive in time', () => {
    const sock = makeFakeSocket();
    const ctx = buildContext(sock, 'user-1', 'device-1', NULL_LOG);
    const pool = makePool(0);

    handleConnection(ctx, {
      ...makeStubDeps(pool, (): number => Date.now()),
      pool,
      now: (): number => Date.now(),
      helloTimeoutMs: HELLO_TIMEOUT_MS,
    });

    // Just before the timeout: no close yet.
    vi.advanceTimersByTime(HELLO_TIMEOUT_MS - 1);
    expect(sock.closes).toEqual([]);

    // Cross the threshold: the timer fires.
    vi.advanceTimersByTime(2);
    expect(sock.closes.length).toBe(1);
    expect(sock.closes[0]?.code).toBe(1000);

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
  });

  it('does not fire the timeout once HELLO has been received', async () => {
    const sock = makeFakeSocket();
    const ctx = buildContext(sock, 'user-1', '11111111-1111-1111-1111-111111111111', NULL_LOG);
    const pool = makePool(0);
    const now = (): number => 1_700_000_000_000;

    handleConnection(ctx, {
      ...makeStubDeps(pool, now),
      pool,
      now,
      helloTimeoutMs: HELLO_TIMEOUT_MS,
    });

    // Deliver a valid HELLO immediately (the message listener was
    // wired up by handleConnection).
    sock.deliverMessage(
      encodeC2S({
        t: C2S.HELLO,
        deviceId: '11111111-1111-1111-1111-111111111111',
        protoVersion: 1,
      }),
    );

    // Drain the microtask queue so the async handler resolves.
    await vi.advanceTimersByTimeAsync(0);
    expect(ctx.helloReceived).toBe(true);

    // Now race past the timeout: no close should fire because the
    // timer's check is gated on `helloReceived`.
    vi.advanceTimersByTime(HELLO_TIMEOUT_MS + 100);
    expect(sock.closes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// SEND_ENVELOPE handler (task 3.4)
// ---------------------------------------------------------------------------

describe('onSendEnvelope', () => {
  const SENDER_DEVICE = '11111111-1111-1111-1111-111111111111';
  const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
  const OTHER_DEVICE = '33333333-3333-3333-3333-333333333333';
  const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

  function makeEnvelope(
    overrides: Partial<CiphertextEnvelope> = {},
  ): CiphertextEnvelope {
    return {
      sessionId: SESSION_ID,
      senderDeviceId: SENDER_DEVICE,
      recipientDeviceId: RECIPIENT_DEVICE,
      type: EnvelopeRouterType.MESSAGE,
      ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      ...overrides,
    };
  }

  function setup() {
    const sock = makeFakeSocket();
    const ctx = buildContext(sock, 'user-1', SENDER_DEVICE, NULL_LOG);
    ctx.helloReceived = true; // skip handshake; we're testing post-HELLO behaviour
    const pool = makeFakeEnvelopePool();
    const redis = makeFakeRedis();
    return { sock, ctx, pool, redis };
  }

  it('inserts a row, publishes on dev:{recipient}, and replies ENVELOPE_QUEUED on the happy path', async () => {
    const { sock, ctx, pool, redis } = setup();
    const deps = makeSendEnvelopeDeps(pool, redis);
    const envelope = makeEnvelope();

    await onSendEnvelope(ctx, { clientNonce: 'nonce-1', envelope }, deps);

    expect(pool.inserts.length).toBe(1);
    expect(pool.inserts[0]?.senderDevice).toBe(SENDER_DEVICE);
    expect(pool.inserts[0]?.recipientDevice).toBe(RECIPIENT_DEVICE);
    expect(pool.inserts[0]?.clientNonce).toBe('nonce-1');
    expect(pool.inserts[0]?.type).toBe(EnvelopeRouterType.MESSAGE);

    expect(redis.published).toEqual([
      { channel: fanoutChannelFor(RECIPIENT_DEVICE), payload: '1' },
    ]);

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ENVELOPE_QUEUED);
    if (reply.t === S2C.ENVELOPE_QUEUED) {
      expect(reply.clientNonce).toBe('nonce-1');
      expect(reply.envelopeId).toBe(1n);
      expect(reply.serverTimeMs).toBe(1_700_000_000_000);
    }
    expect(sock.closes).toEqual([]);
  });

  it('rejects sender mismatch with ERROR(INVALID_PAYLOAD); inserts no row, publishes nothing', async () => {
    const { sock, ctx, pool, redis } = setup();
    const deps = makeSendEnvelopeDeps(pool, redis);
    const envelope = makeEnvelope({ senderDeviceId: OTHER_DEVICE });

    await onSendEnvelope(ctx, { clientNonce: 'nonce-1', envelope }, deps);

    expect(pool.inserts).toEqual([]);
    expect(redis.published).toEqual([]);
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INVALID_PAYLOAD);
    }
    expect(sock.closes).toEqual([]); // socket stays open per design
  });

  it('does not consume a token bucket slot when sender mismatches', async () => {
    // P17 + spirit of P16: an impostor send is a strict no-op; it
    // should not eat into the real device's burst budget.
    const { ctx, pool, redis } = setup();
    const buckets = new Map<string, TokenBucketState>();
    const deps = makeSendEnvelopeDeps(pool, redis, {
      sendEnvelopeBuckets: buckets,
      sendEnvelopeBucket: { capacity: 1, refillPerSecond: 0 },
    });
    const impostor = makeEnvelope({ senderDeviceId: OTHER_DEVICE });

    await onSendEnvelope(ctx, { clientNonce: 'imp', envelope: impostor }, deps);

    // The bucket map for `ctx.deviceId` must still be untouched (no
    // entry yet). A subsequent legitimate send is allowed.
    expect(buckets.has(SENDER_DEVICE)).toBe(false);

    await onSendEnvelope(
      ctx,
      { clientNonce: 'real', envelope: makeEnvelope() },
      deps,
    );
    expect(pool.inserts.length).toBe(1);
  });

  it('returns the original envelopeId on a duplicate (senderDeviceId, clientNonce) — no second insert, no second publish', async () => {
    const { sock, ctx, pool, redis } = setup();
    const deps = makeSendEnvelopeDeps(pool, redis);
    const envelope = makeEnvelope();

    // First send.
    await onSendEnvelope(ctx, { clientNonce: 'nonce-7', envelope }, deps);
    expect(pool.inserts.length).toBe(1);
    expect(redis.published.length).toBe(1);
    const firstReply = lastS2C(sock);
    expect(firstReply.t).toBe(S2C.ENVELOPE_QUEUED);
    const originalId =
      firstReply.t === S2C.ENVELOPE_QUEUED ? firstReply.envelopeId : 0n;

    // Retry with the same nonce. Should not insert a new row, should
    // not publish a second time, and must return the same id.
    await onSendEnvelope(ctx, { clientNonce: 'nonce-7', envelope }, deps);

    expect(pool.inserts.length).toBe(1);
    expect(redis.published.length).toBe(1); // still exactly one publish (P13)

    const secondReply = lastS2C(sock);
    expect(secondReply.t).toBe(S2C.ENVELOPE_QUEUED);
    if (secondReply.t === S2C.ENVELOPE_QUEUED) {
      expect(secondReply.envelopeId).toBe(originalId);
      expect(secondReply.clientNonce).toBe('nonce-7');
    }
  });

  it('rate-limits with ERROR(RATE_LIMITED) once the per-device bucket is empty; spec defaults allow 50 sends in a single tick', async () => {
    const { sock, ctx, pool, redis } = setup();
    const buckets = new Map<string, TokenBucketState>();
    // Use the spec defaults so we explicitly verify the 50-burst
    // behaviour from Requirement 19.4.
    const deps = makeSendEnvelopeDeps(pool, redis, {
      sendEnvelopeBuckets: buckets,
      sendEnvelopeBucket: { capacity: 50, refillPerSecond: 10 },
      now: (): number => 1_700_000_000_000, // freeze clock so refill = 0
    });

    // Burst 50 distinct nonces — all accepted.
    for (let i = 0; i < 50; i++) {
      await onSendEnvelope(
        ctx,
        { clientNonce: `n-${i}`, envelope: makeEnvelope() },
        deps,
      );
    }
    expect(pool.inserts.length).toBe(50);
    expect(redis.published.length).toBe(50);

    // 51st send within the same tick is RATE_LIMITED — no new row,
    // no new publish.
    await onSendEnvelope(
      ctx,
      { clientNonce: 'n-50', envelope: makeEnvelope() },
      deps,
    );
    expect(pool.inserts.length).toBe(50);
    expect(redis.published.length).toBe(50);
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.RATE_LIMITED);
    }
  });

  it('replies ERROR(INTERNAL) and does NOT publish to Redis when the DB insert fails', async () => {
    const { sock, ctx, pool, redis } = setup();
    const deps = makeSendEnvelopeDeps(pool, redis);
    pool.failNextInsert = new Error('boom');

    await onSendEnvelope(
      ctx,
      { clientNonce: 'nonce-x', envelope: makeEnvelope() },
      deps,
    );

    // No row persisted, no publish.
    expect(pool.inserts).toEqual([]);
    expect(redis.published).toEqual([]);

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ERROR);
    if (reply.t === S2C.ERROR) {
      expect(reply.code).toBe(ErrorCode.INTERNAL);
    }
    expect(sock.closes).toEqual([]); // INTERNAL is a soft error; socket stays open
  });

  it('publishes only on the recipient device channel — not on any other device', async () => {
    // Property P14 / Requirement 12.15: recipient isolation. A send
    // to recipient X must not produce any publish on dev:Y for Y ≠ X.
    const { sock, ctx, pool, redis } = setup();
    const deps = makeSendEnvelopeDeps(pool, redis);

    await onSendEnvelope(
      ctx,
      {
        clientNonce: 'iso-1',
        envelope: makeEnvelope({ recipientDeviceId: RECIPIENT_DEVICE }),
      },
      deps,
    );

    expect(redis.published).toEqual([
      { channel: fanoutChannelFor(RECIPIENT_DEVICE), payload: '1' },
    ]);
    // Sanity: the channel is exactly `dev:{recipientDeviceId}`.
    expect(redis.published[0]?.channel).toBe(`dev:${RECIPIENT_DEVICE}`);
    expect(redis.published[0]?.channel).not.toBe(`dev:${OTHER_DEVICE}`);
    expect(redis.published[0]?.channel).not.toBe(`dev:${SENDER_DEVICE}`);

    expect(lastS2C(sock).t).toBe(S2C.ENVELOPE_QUEUED);
  });

  it('still acknowledges ENVELOPE_QUEUED when the Redis publish fails (row persists; offline replay covers delivery)', async () => {
    // Per design.md §13.6 a Redis publish failure must not block the
    // sender's outbox from advancing — the row IS persisted, so task
    // 3.5's `attachInbox` will replay on the recipient's next
    // reconnect (Requirement 12.11).
    const { sock, ctx, pool, redis } = setup();
    const deps = makeSendEnvelopeDeps(pool, redis);
    redis.failNext = new Error('redis down');

    await onSendEnvelope(
      ctx,
      { clientNonce: 'nonce-q', envelope: makeEnvelope() },
      deps,
    );

    expect(pool.inserts.length).toBe(1);
    expect(redis.published).toEqual([]); // publish never landed

    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ENVELOPE_QUEUED);
  });
});

// ---------------------------------------------------------------------------
// handleClientMessage routes SEND_ENVELOPE to onSendEnvelope (smoke)
// ---------------------------------------------------------------------------

describe('handleClientMessage — SEND_ENVELOPE routing', () => {
  const DEVICE_ID = '11111111-1111-1111-1111-111111111111';
  const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
  const SESSION_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

  it('post-HELLO SEND_ENVELOPE flows through onSendEnvelope and produces ENVELOPE_QUEUED', async () => {
    const sock = makeFakeSocket();
    const ctx = buildContext(sock, 'user-1', DEVICE_ID, NULL_LOG);
    const pool = makeFakeEnvelopePool();
    const redis = makeFakeRedis();
    const deps: SendEnvelopeDeps = {
      pool: pool as unknown as SendEnvelopeDeps['pool'],
      redis,
      now: (): number => 1_700_000_000_000,
      sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
      sendEnvelopeBucket: { capacity: 50, refillPerSecond: 10 },
    };

    // Drive the handshake first via the same dispatch entry point.
    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.HELLO, deviceId: DEVICE_ID, protoVersion: 1 }),
      deps,
    );
    sock.sent.length = 0;

    const env: CiphertextEnvelope = {
      sessionId: SESSION_ID,
      senderDeviceId: DEVICE_ID,
      recipientDeviceId: RECIPIENT_DEVICE,
      type: EnvelopeRouterType.MESSAGE,
      ciphertext: new Uint8Array([1, 2, 3]),
    };
    await handleClientMessage(
      ctx,
      encodeC2S({ t: C2S.SEND_ENVELOPE, clientNonce: 'route-1', envelope: env }),
      deps,
    );

    expect(pool.inserts.length).toBe(1);
    expect(redis.published.length).toBe(1);
    const reply = lastS2C(sock);
    expect(reply.t).toBe(S2C.ENVELOPE_QUEUED);
    if (reply.t === S2C.ENVELOPE_QUEUED) {
      expect(reply.clientNonce).toBe('route-1');
    }
    expect(sock.closes).toEqual([]);
  });

  it('defaultSendEnvelopeBuckets is a Map (module-level state survives reconnect)', () => {
    expect(defaultSendEnvelopeBuckets).toBeInstanceOf(Map);
  });
});

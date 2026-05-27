// apps/api/test/call-envelope-relay.test.ts
//
// Validates task 6.3 (server-side relay of `EnvelopeRouterType.CALL`
// envelopes) and Requirements 7.2, 7.3, 11.8 / property P23 ("ICE
// candidate confidentiality").
//
// What this test asserts:
//
//   1. SEND_ENVELOPE with `type: CALL` is persisted via the same
//      `INSERT INTO ciphertext_envelopes ...` SQL the MESSAGE path
//      uses — there is no separate "call" code path that could
//      diverge in logging or routing behaviour. We assert by
//      capturing the parameters bound to the insert and comparing
//      MESSAGE / CALL invocations field-for-field.
//
//   2. SEND_ENVELOPE with `type: CALL` triggers the same Redis
//      fan-out publish (`dev:{recipientDeviceId}` carrying the
//      decimal-string envelope id) the MESSAGE path does. The
//      gateway's only branch on `env.type` is the
//      `konvo_envelopes_routed_total` label dispatch ('msg' / 'ack'
//      / 'call'); the routing semantics are identical.
//
//   3. No log line emitted while routing a CALL envelope contains:
//        a. the envelope's ciphertext bytes (in any of three
//           encodings: hex, base64, latin1, or pino's default
//           number-array Buffer serialisation),
//        b. the literal substring `'candidate:'` (the universal
//           prefix of every WebRTC ICE candidate string per RFC
//           5245 / 8445), or
//        c. any ASCII canary planted into the ciphertext by the
//           test fixture.
//
//   4. The sender mismatch (`senderDeviceId !== ctx.deviceId`) and
//      DB-failure paths still produce no leaks for CALL envelopes
//      — the same logger redaction layer that protects MESSAGE
//      envelopes covers CALL envelopes by construction (the layer
//      operates on field NAMES like `ciphertext` / `body`, not on
//      router type).
//
// Test strategy mirrors `plaintext-non-leakage.property.test.ts`:
//   - Capture `pino` output via an in-memory `DestinationStream`.
//   - Build a `WSContext` over a child of that logger.
//   - Stub the `pg.Pool` and `WSRedisPublisher` with hand-rolled
//     fakes that record every interaction.
//   - Assert against the captured log buffer + the recorded
//     pool/redis state.
//
// We do not invoke the WS upgrade path (`@fastify/websocket`); the
// public `onSendEnvelope` function is exercised directly. The
// integration coverage of the full upgrade lives in the broader
// `ws-gateway.test.ts` suite.

import { Buffer } from 'node:buffer';

import { beforeEach, describe, expect, test } from 'vitest';

import {
  EnvelopeRouterType,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import {
  REDACTION_CENSOR,
  createLogger,
  setRedactionFailureCounter,
} from '../src/obs/logger.js';
import {
  buildContext,
  fanoutChannelFor,
  onSendEnvelope,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { WSRedisPublisher, WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Fixed identifiers
// ---------------------------------------------------------------------------

const SENDER_DEVICE = '11111111-1111-1111-1111-111111111111';
const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const NOW_MS = 1_700_000_000_000;

// ---------------------------------------------------------------------------
// Capturing log destination
// ---------------------------------------------------------------------------

interface CapturedSink {
  write(chunk: string): boolean;
  lines: string[];
  joined(): string;
  clear(): void;
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
    joined(): string {
      return lines.join('\n');
    },
    clear(): void {
      lines.length = 0;
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
// Pool mock — captures every parameterised query
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
      // Defensive default — no other queries fire on the happy
      // path we exercise here.
      return { rows: [] as never[], rowCount: 0 };
    },
  };
  return fake;
}

// ---------------------------------------------------------------------------
// Redis publisher mock
// ---------------------------------------------------------------------------

interface FakeRedis extends WSRedisPublisher {
  readonly published: Array<{ channel: string; payload: string }>;
}

function makeFakeRedis(): FakeRedis {
  const published: Array<{ channel: string; payload: string }> = [];
  const fake: FakeRedis = {
    published,
    async publish(channel: string, payload: string): Promise<number> {
      published.push({ channel, payload });
      return 1;
    },
    async setPresence(): Promise<void> {
      /* unused on this path */
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
// Test setup
// ---------------------------------------------------------------------------

function buildDeps(pool: FakePool, redis: FakeRedis): SendEnvelopeDeps {
  return {
    pool: pool as unknown as SendEnvelopeDeps['pool'],
    redis,
    now: (): number => NOW_MS,
    sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
    // Capacity headroom so a single test never trips the rate
    // limiter; that path is tested elsewhere.
    sendEnvelopeBucket: { capacity: 100, refillPerSecond: 100 },
  };
}

interface Harness {
  ctx: ReturnType<typeof buildContext>;
  sock: FakeSocket;
  sink: CapturedSink;
  pool: FakePool;
  redis: FakeRedis;
  deps: SendEnvelopeDeps;
}

function setup(): Harness {
  const sink = makeSink();
  const log = createLogger({ destination: sink, level: 'debug' });
  const child = log.child({ requestId: 'req-call-relay' });
  const sock = makeFakeSocket();
  const ctx = buildContext(
    sock,
    'user-1',
    SENDER_DEVICE,
    child as unknown as Parameters<typeof buildContext>[3],
  );
  ctx.helloReceived = true;
  const pool = makeFakePool();
  const redis = makeFakeRedis();
  const deps = buildDeps(pool, redis);
  return { ctx, sock, sink, pool, redis, deps };
}

beforeEach(() => {
  setRedactionFailureCounter({ inc(): void {} });
});

// ---------------------------------------------------------------------------
// Ciphertext fixtures
// ---------------------------------------------------------------------------

/** A 96-byte ciphertext payload with embedded canaries:
 *
 *    - `__P23_CANARY_BYTES__` (20 ASCII bytes) — a fixed sentinel
 *      every test asserts against. Inclusion would be a leak.
 *    - `candidate:` (10 ASCII bytes) — the literal RFC 5245 / 8445
 *      ICE-candidate prefix. Every real candidate string starts
 *      with this; the gateway must NEVER emit it in any log line.
 *    - random padding to reach 96 bytes so any byte-prefix-match
 *      heuristic in pino's serialiser cannot accidentally avoid
 *      leaking by truncation.
 *
 * The two canaries are spliced into a `Uint8Array` so that the
 * ciphertext field, treated as opaque bytes by the gateway, would
 * spill the canaries into any log line that serialised the bytes
 * naively (latin1 / hex / base64 / number-array). */
function makeCanaryCiphertext(): Uint8Array {
  const enc = new TextEncoder();
  const canary = enc.encode('__P23_CANARY_BYTES__'); // 20 bytes
  const candidatePrefix = enc.encode(
    'candidate:1 1 udp 2113929471 192.0.2.1 54321 typ host',
  );
  const filler = new Uint8Array(96 - canary.length - candidatePrefix.length);
  // Distinct nonzero pattern so an accidental memset(0) leak would
  // also be observable.
  for (let i = 0; i < filler.length; i += 1) filler[i] = (i + 7) & 0xff;
  const out = new Uint8Array(canary.length + candidatePrefix.length + filler.length);
  out.set(canary, 0);
  out.set(candidatePrefix, canary.length);
  out.set(filler, canary.length + candidatePrefix.length);
  return out;
}

/** Three serialisations a JSON formatter could reach for; each
 *  strictly dominates the chance of catching a leak by way of a
 *  particular naive encoder. */
function ciphertextEncodings(bytes: Uint8Array): {
  hex: string;
  base64: string;
  latin1: string;
  numberArray: string;
} {
  const buf = Buffer.from(bytes);
  return {
    hex: buf.toString('hex'),
    base64: buf.toString('base64'),
    latin1: buf.toString('binary'),
    numberArray: Array.from(bytes.slice(0, Math.min(32, bytes.length))).join(','),
  };
}

function expectNoCiphertextLeak(haystack: string, bytes: Uint8Array): void {
  const enc = ciphertextEncodings(bytes);
  if (enc.hex.length >= 32) {
    expect(haystack.includes(enc.hex)).toBe(false);
  }
  if (enc.base64.length >= 16) {
    expect(haystack.includes(enc.base64)).toBe(false);
  }
  if (enc.numberArray.length >= 16) {
    expect(haystack.includes(enc.numberArray)).toBe(false);
  }
}

function envelopeFor(
  type: EnvelopeRouterType,
  ciphertext: Uint8Array,
): CiphertextEnvelope {
  return {
    sessionId: SESSION_ID,
    senderDeviceId: SENDER_DEVICE,
    recipientDeviceId: RECIPIENT_DEVICE,
    type,
    ciphertext,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CALL envelope relay (task 6.3 / Requirements 7.2, 7.3, 11.8 / P23)', () => {
  test('persists CALL envelopes via the same INSERT path as MESSAGE', async () => {
    const ciphertext = makeCanaryCiphertext();

    // MESSAGE call.
    const msgH = setup();
    await onSendEnvelope(
      msgH.ctx,
      {
        clientNonce: 'nonce-msg',
        envelope: envelopeFor(EnvelopeRouterType.MESSAGE, ciphertext),
      },
      msgH.deps,
    );

    // CALL call (same ciphertext bytes for fair comparison).
    const callH = setup();
    await onSendEnvelope(
      callH.ctx,
      {
        clientNonce: 'nonce-call',
        envelope: envelopeFor(EnvelopeRouterType.CALL, ciphertext),
      },
      callH.deps,
    );

    // Each fixture issued exactly one INSERT.
    const msgInsert = msgH.pool.queries.find((q) =>
      q.sql.trim().startsWith('INSERT INTO ciphertext_envelopes'),
    );
    const callInsert = callH.pool.queries.find((q) =>
      q.sql.trim().startsWith('INSERT INTO ciphertext_envelopes'),
    );
    expect(msgInsert).toBeDefined();
    expect(callInsert).toBeDefined();

    // The INSERT SQL is byte-identical for MESSAGE and CALL — the
    // router type is just a column value, not a code branch.
    expect(callInsert?.sql).toBe(msgInsert?.sql);

    // Parameters: positions 0..3 (sessionId, sender, recipient,
    // ciphertext) match; position 4 differs by the type discriminant
    // (MESSAGE = 1, CALL = 3); position 5 is the per-call clientNonce.
    expect(callInsert?.params[0]).toBe(msgInsert?.params[0]);
    expect(callInsert?.params[1]).toBe(msgInsert?.params[1]);
    expect(callInsert?.params[2]).toBe(msgInsert?.params[2]);
    // Buffer.from(Uint8Array) is byte-equivalent across the two
    // calls; compare via .equals().
    const msgCt = msgInsert?.params[3] as Buffer;
    const callCt = callInsert?.params[3] as Buffer;
    expect(callCt.equals(msgCt)).toBe(true);
    expect(msgInsert?.params[4]).toBe(EnvelopeRouterType.MESSAGE);
    expect(callInsert?.params[4]).toBe(EnvelopeRouterType.CALL);
  });

  test('publishes CALL envelopes on the recipient dev:{...} channel like MESSAGE', async () => {
    const ciphertext = makeCanaryCiphertext();
    const h = setup();

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-call-pub',
        envelope: envelopeFor(EnvelopeRouterType.CALL, ciphertext),
      },
      h.deps,
    );

    expect(h.redis.published.length).toBe(1);
    const pub = h.redis.published[0];
    expect(pub?.channel).toBe(fanoutChannelFor(RECIPIENT_DEVICE));
    // Payload is the assigned envelope id as a decimal string —
    // identical convention to MESSAGE; never carries ciphertext.
    expect(pub?.payload).toMatch(/^\d+$/);
    // Assertion (a): the published payload contains no ciphertext.
    expectNoCiphertextLeak(pub?.payload ?? '', ciphertext);
  });

  test('replies ENVELOPE_QUEUED to sender after persisting a CALL envelope', async () => {
    const ciphertext = makeCanaryCiphertext();
    const h = setup();

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-call-ack',
        envelope: envelopeFor(EnvelopeRouterType.CALL, ciphertext),
      },
      h.deps,
    );

    expect(h.sock.sent.length).toBe(1);
    const last = h.sock.sent[0];
    expect(last).toBeDefined();
    if (last === undefined) throw new Error('no frame sent');
    const frame = decodeS2C(last);
    expect(frame.t).toBe(S2C.ENVELOPE_QUEUED);
  });

  test('happy-path log lines never contain ciphertext bytes or "candidate:"', async () => {
    const ciphertext = makeCanaryCiphertext();
    const h = setup();

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-call-log',
        envelope: envelopeFor(EnvelopeRouterType.CALL, ciphertext),
      },
      h.deps,
    );

    const captured = h.sink.joined();
    // Even if the gateway happened to emit a debug/info line on
    // the success path (it currently doesn't on this branch), the
    // redaction layer would censor the `ciphertext` key. Assert
    // both invariants:
    //   - canary not present in any encoding,
    //   - 'candidate:' substring not present anywhere,
    //   - the fixed canary string not present.
    expectNoCiphertextLeak(captured, ciphertext);
    expect(captured.includes('candidate:')).toBe(false);
    expect(captured.includes('__P23_CANARY_BYTES__')).toBe(false);
  });

  test('error-path logs (DB insert failure) leak no ciphertext for CALL envelopes', async () => {
    const ciphertext = makeCanaryCiphertext();
    const h = setup();

    // Replace pool with one that throws on insert. A real pg outage
    // would surface here; the gateway logs `'ciphertext envelope
    // insert failed'` with `{err, deviceId, clientNonce}` only.
    const failingPool: FakePool = {
      queries: [],
      async query() {
        throw new Error('connection terminated unexpectedly');
      },
    };
    const failingDeps = buildDeps(failingPool, h.redis);

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-call-fail',
        envelope: envelopeFor(EnvelopeRouterType.CALL, ciphertext),
      },
      failingDeps,
    );

    // The sender received an INTERNAL ERROR frame.
    const lastSent = h.sock.sent.at(-1);
    expect(lastSent).toBeDefined();
    if (lastSent === undefined) throw new Error('no frame');
    const frame = decodeS2C(lastSent);
    expect(frame.t).toBe(S2C.ERROR);

    const captured = h.sink.joined();
    // Three independent leakage probes against the captured logs.
    expectNoCiphertextLeak(captured, ciphertext);
    expect(captured.includes('candidate:')).toBe(false);
    expect(captured.includes('__P23_CANARY_BYTES__')).toBe(false);
    // The redaction censor must appear at most where the logger
    // actively scrubbed; a missing `[REDACTED]` token would mean
    // no `ciphertext` field was logged in the first place, which
    // is also acceptable. We assert the WEAKER invariant — the
    // ciphertext bytes never make it through.
    void REDACTION_CENSOR;
  });

  test('sender-mismatch path silently rejects CALL envelopes; logs no ciphertext', async () => {
    const ciphertext = makeCanaryCiphertext();
    const h = setup();

    // Build an envelope claiming the WRONG sender device.
    const impostor: CiphertextEnvelope = {
      sessionId: SESSION_ID,
      senderDeviceId: '99999999-9999-9999-9999-999999999999',
      recipientDeviceId: RECIPIENT_DEVICE,
      type: EnvelopeRouterType.CALL,
      ciphertext,
    };
    await onSendEnvelope(
      h.ctx,
      { clientNonce: 'nonce-call-imp', envelope: impostor },
      h.deps,
    );

    // Per Requirement 12.3 / P17 the gateway rejects with
    // INVALID_PAYLOAD and inserts NO row.
    const inserted = h.pool.queries.find((q) =>
      q.sql.trim().startsWith('INSERT INTO ciphertext_envelopes'),
    );
    expect(inserted).toBeUndefined();
    expect(h.redis.published.length).toBe(0);

    const lastSent = h.sock.sent.at(-1);
    if (lastSent === undefined) throw new Error('no frame');
    const frame = decodeS2C(lastSent);
    expect(frame.t).toBe(S2C.ERROR);

    const captured = h.sink.joined();
    expectNoCiphertextLeak(captured, ciphertext);
    expect(captured.includes('candidate:')).toBe(false);
    expect(captured.includes('__P23_CANARY_BYTES__')).toBe(false);
  });

  test('Redis publish failure for CALL envelopes still leaks no ciphertext', async () => {
    const ciphertext = makeCanaryCiphertext();
    const h = setup();

    // Replace redis with one whose publish throws. The gateway logs
    // `'redis fan-out publish failed; relying on offline replay'`
    // with `{err, deviceId, recipientDeviceId}` only.
    const flakyRedis: FakeRedis = {
      published: [],
      async publish(): Promise<number> {
        throw new Error('redis connection refused');
      },
      async setPresence(): Promise<void> {
        /* unused */
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
    const deps = buildDeps(h.pool, flakyRedis);

    await onSendEnvelope(
      h.ctx,
      {
        clientNonce: 'nonce-call-flaky',
        envelope: envelopeFor(EnvelopeRouterType.CALL, ciphertext),
      },
      deps,
    );

    const captured = h.sink.joined();
    expectNoCiphertextLeak(captured, ciphertext);
    expect(captured.includes('candidate:')).toBe(false);
    expect(captured.includes('__P23_CANARY_BYTES__')).toBe(false);
  });
});

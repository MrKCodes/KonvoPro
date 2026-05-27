// P16 — Validates Requirements 12.9, 19.4, 19.10, 21.16
//
// apps/api/test/rate-limit-conservation.property.test.ts
//
// Property test for task 10.10 (Phase 9) — P16: rate limit conservation.
//
// Property under test (design.md §16 / requirements.md §21.16):
//
//   For any client sending at rate r > 50 msg/s within a 1-second
//   window, at most 50 `SEND_ENVELOPE` are accepted; the remaining
//   sends are rejected with `ERROR { code: RATE_LIMITED }`. No accepted
//   envelope is silently dropped — every accepted send produces a row
//   in `ciphertext_envelopes` (we proxy the row insert through the
//   pool stub's `inserts` array).
//
// Strategy:
//   - Invoke `onSendEnvelope` directly with a frozen clock so a full
//     burst of `r` calls all fall inside the same 1-second window
//     (refill contribution within zero elapsed milliseconds is
//     exactly 0). This is the worst case for the limiter — it is
//     also the case design.md §17.6 calls out as the "burst flush
//     after a long offline window" scenario.
//   - Each iteration starts from a fresh per-device bucket map and a
//     fresh in-memory pool stub, so iterations don't leak state.
//   - Each of the `r` attempts uses a distinct `clientNonce` so that
//     the dedupe path in `onSendEnvelope` (UNIQUE INDEX on
//     `(sender_device, client_nonce)`) does NOT alias accepted
//     attempts together. Without this we couldn't distinguish a
//     "second send accepted" from "second send was an idempotent
//     retry of the first".
//   - For each attempt we capture the most recent S2C frame the
//     gateway emitted, classify it as ENVELOPE_QUEUED (accepted) or
//     ERROR with code RATE_LIMITED (rejected), and tally counts.
//
// Assertions per iteration:
//   a. accepted_count ≤ 50           — the spec ceiling (P16 / 19.4 /
//                                       21.16).
//   b. accepted_count + rate_limited_count === r
//                                    — conservation: every call gets
//                                       a typed answer back. This is
//                                       the "no silent drops at the
//                                       handler level" half of P16
//                                       (12.9: prior accepted
//                                       envelopes still receive
//                                       `ENVELOPE_QUEUED`).
//   c. every rejection has code: RATE_LIMITED — 19.10 (the rate-limit
//                                       reply code is exactly this
//                                       enum value, not INTERNAL or
//                                       INVALID_PAYLOAD).
//   d. accepted_count === pool.inserts.length — every accepted send
//                                       produced a ciphertext_envelopes
//                                       insert; no silent drop after
//                                       the bucket allowed the call.
//                                       (12.9 again: prior accepted
//                                       envelopes are persisted, not
//                                       discarded.)
//
// Iteration count comes from the global fast-check config in
// `test/setup.ts` (default 100 / nightly 500 via FAST_CHECK_RUNS).

import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  ErrorCode,
  EnvelopeRouterType,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
  type ServerToClient,
} from '@konvo/protocol';

import {
  buildContext,
  fanoutChannelFor,
  onSendEnvelope,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import { SEND_ENVELOPE_BUCKET, type TokenBucketState } from '../src/ws/rate-limit.js';
import type { WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Test doubles (mirrors the fakes in ws-gateway.test.ts; kept inline here
// so this property file is self-contained and can be invoked with a single
// vitest filter pattern).
// ---------------------------------------------------------------------------

interface FakeSocket extends WSSocket {
  sent: Uint8Array[];
}

function makeFakeSocket(): FakeSocket {
  const sent: Uint8Array[] = [];
  const sock: FakeSocket = {
    readyState: 1, // OPEN
    sent,
    send(data: Uint8Array | Buffer): void {
      sent.push(new Uint8Array(data));
    },
    close(): void {
      // not exercised in this test — every iteration ends with the
      // socket still open. Provided to satisfy WSSocket.
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

/** A pg.Pool stub that simulates `ciphertext_envelopes` for SEND_ENVELOPE.
 *
 *  Routes:
 *    - `INSERT INTO ciphertext_envelopes ... ON CONFLICT (sender_device,
 *      client_nonce) DO NOTHING RETURNING id` records the insert and
 *      returns the assigned id (or zero rows on dedupe conflict).
 *    - `SELECT id FROM ciphertext_envelopes WHERE sender_device=$1 AND
 *      client_nonce=$2` returns the previously-assigned id.
 *
 *  This file's property uses a unique nonce per attempt, so the
 *  conflict / SELECT branch is not exercised — but we route it
 *  faithfully anyway so the stub can't accidentally diverge from the
 *  production query shape.
 */
interface FakeEnvelopePool {
  readonly inserts: Array<{
    senderDevice: string;
    clientNonce: string;
    id: bigint;
  }>;
  query(sql: string, params: readonly unknown[]): Promise<{ rows: unknown[]; rowCount: number }>;
}

function makeFakeEnvelopePool(): FakeEnvelopePool {
  let nextId = 1n;
  const fake: FakeEnvelopePool = {
    inserts: [],
    async query(sql: string, params: readonly unknown[]) {
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        const [, senderDevice, , , , clientNonce] = params as [
          string,
          string,
          string,
          Buffer,
          number,
          string,
        ];
        const existing = fake.inserts.find(
          (r) => r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing !== undefined) {
          return { rows: [], rowCount: 0 };
        }
        const id = nextId++;
        fake.inserts.push({ senderDevice, clientNonce, id });
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
      // Defensive: any other shape (e.g. HELLO queuedCount) returns an
      // empty result so a regression here surfaces as a property
      // failure rather than a silent zero.
      return { rows: [], rowCount: 0 };
    },
  };
  return fake;
}

interface FakeRedis {
  readonly published: Array<{ channel: string; payload: string }>;
  publish(channel: string, payload: string): Promise<number>;
}

function makeFakeRedis(): FakeRedis {
  const fake: FakeRedis = {
    published: [],
    async publish(channel: string, payload: string): Promise<number> {
      fake.published.push({ channel, payload });
      return 0;
    },
  };
  return fake;
}

/** Decode the most recently sent frame on the socket. */
function lastS2C(sock: FakeSocket): ServerToClient {
  const last = sock.sent[sock.sent.length - 1];
  if (last === undefined) {
    throw new Error('expected a frame but socket has no sent frames');
  }
  return decodeS2C(last);
}

// ---------------------------------------------------------------------------
// Property
// ---------------------------------------------------------------------------

describe('P16 — rate limit conservation', () => {
  // Fixed sender / recipient / session for every iteration. The
  // property holds for any device id; varying it per iteration adds
  // noise without exercising any new branch (the bucket is keyed by
  // deviceId, but we're only modelling a single-device scenario per
  // P16's "for any client" wording).
  const SENDER_DEVICE = '11111111-1111-1111-1111-111111111111';
  const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
  const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';

  function makeEnvelope(): CiphertextEnvelope {
    return {
      sessionId: SESSION_ID,
      senderDeviceId: SENDER_DEVICE,
      recipientDeviceId: RECIPIENT_DEVICE,
      type: EnvelopeRouterType.MESSAGE,
      // Tiny ciphertext — the property doesn't depend on payload
      // bytes. Using a fixed 4-byte buffer keeps fast-check shrinks
      // deterministic for any test failure.
      ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    };
  }

  it('admits at most 50, rejects the rest with RATE_LIMITED, and inserts a row for every accepted send', async () => {
    await fc.assert(
      fc.asyncProperty(
        // r in [51, 200]: r > 50 puts us strictly above the bucket
        // capacity; the upper bound 200 keeps each iteration fast
        // (< 1ms in practice) while still covering 4× the limit.
        fc.integer({ min: 51, max: 200 }),
        async (r) => {
          // Fresh per-iteration state — no leakage between iterations.
          const sock = makeFakeSocket();
          const ctx = buildContext(sock, 'user-1', SENDER_DEVICE, NULL_LOG);
          ctx.helloReceived = true; // skip handshake; P16 is a post-HELLO property
          const pool = makeFakeEnvelopePool();
          const redis = makeFakeRedis();

          // Frozen wall-clock: every call sees the same instant, so
          // the continuous-refill formula contributes exactly zero
          // tokens. This is the worst case for the limiter and also
          // matches the "burst flush in a single tick" scenario the
          // bucket is sized for (design.md §17.6).
          const FROZEN_NOW_MS = 1_700_000_000_000;

          const buckets = new Map<string, TokenBucketState>();
          const deps: SendEnvelopeDeps = {
            pool: pool as unknown as SendEnvelopeDeps['pool'],
            redis,
            now: (): number => FROZEN_NOW_MS,
            sendEnvelopeBuckets: buckets,
            sendEnvelopeBucket: SEND_ENVELOPE_BUCKET, // 50 / 10 per second per Requirement 19.4
          };

          let acceptedCount = 0;
          let rateLimitedCount = 0;

          for (let i = 0; i < r; i += 1) {
            const beforeSent = sock.sent.length;
            // Distinct nonce per attempt so the idempotency dedupe
            // path is not aliasing two attempts together — without
            // this, attempt #2 with a duplicate nonce would be
            // counted as accepted (it replies ENVELOPE_QUEUED) but
            // would not produce a new insert, breaking property d.
            await onSendEnvelope(
              ctx,
              { clientNonce: `n-${i}`, envelope: makeEnvelope() },
              deps,
            );

            // Each call must produce exactly one S2C frame
            // (ENVELOPE_QUEUED on accept, ERROR(RATE_LIMITED) on
            // reject). This is the conservation property: no silent
            // drops at the handler level.
            expect(sock.sent.length).toBe(beforeSent + 1);

            const reply = lastS2C(sock);
            if (reply.t === S2C.ENVELOPE_QUEUED) {
              acceptedCount += 1;
            } else if (reply.t === S2C.ERROR) {
              // Property c: every rejection in this scenario is a
              // RATE_LIMITED rejection — not INTERNAL, not
              // INVALID_PAYLOAD. The frozen pool stub never errors
              // and the envelope is well-formed, so any other code
              // would indicate a regression.
              expect(reply.code).toBe(ErrorCode.RATE_LIMITED);
              rateLimitedCount += 1;
            } else {
              // Defensive: any other discriminator (HELLO_OK /
              // ENVELOPE / PRESENCE / SUBSCRIBE_OK / etc.) would mean
              // the gateway sent the wrong response type. Fail
              // explicitly so fast-check's shrinker surfaces it.
              throw new Error(`unexpected S2C frame type: ${reply.t}`);
            }
          }

          // (a) accepted ≤ 50 — the spec ceiling. With a frozen clock
          // and capacity = 50, this collapses to "= 50" for any r ≥
          // 50, but the looser bound matches the requirement wording
          // ("at most 50") and is robust to any future refill timing
          // change.
          expect(acceptedCount).toBeLessThanOrEqual(50);

          // (b) conservation: every call gets a typed answer back.
          expect(acceptedCount + rateLimitedCount).toBe(r);

          // (d) every accepted send produced a ciphertext_envelopes
          // insert AND a fan-out publish on the recipient channel.
          // No silent drop after the bucket allowed the call.
          expect(pool.inserts.length).toBe(acceptedCount);
          expect(redis.published.length).toBe(acceptedCount);
          for (const pub of redis.published) {
            expect(pub.channel).toBe(fanoutChannelFor(RECIPIENT_DEVICE));
          }

          // Sanity: with the frozen clock and r > 50, exactly 50 are
          // accepted. We don't fold this into property (a) above
          // because the property statement uses "at most 50" — but
          // verifying the tight bound here gives a stronger
          // regression signal if the bucket capacity is ever silently
          // changed.
          expect(acceptedCount).toBe(50);
          expect(rateLimitedCount).toBe(r - 50);
        },
      ),
    );
  });
});

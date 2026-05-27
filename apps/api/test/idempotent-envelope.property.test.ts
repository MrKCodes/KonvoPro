// P13 — Validates Requirements 4.7, 12.4, 21.13
//
// apps/api/test/idempotent-envelope.property.test.ts
//
// Property test for task 10.7 (Phase 9) — P13: Idempotent envelope
// delivery (design.md §14.3, requirements.md §21.13).
//
// Property under test:
//
//   For any `(senderDeviceId, clientNonce)`, repeated `SEND_ENVELOPE`
//   requests — up to 100 within a 60-s window — result in:
//     a. exactly one `ciphertext_envelopes` row
//     b. exactly one fan-out publish on `dev:{recipientDeviceId}`
//     c. every reply is `ENVELOPE_QUEUED` carrying the SAME envelopeId
//        (the id assigned on first insert)
//
// **Validates: Requirements 4.7, 12.4, 21.13**
//
// Strategy:
//   - Drive `onSendEnvelope` directly with a fake in-memory pool that
//     mirrors the production `INSERT ... ON CONFLICT (sender_device,
//     client_nonce) DO NOTHING RETURNING id` semantics, plus a fake
//     Redis publisher that captures every (channel, payload) tuple.
//   - These mocks mirror `makeFakeEnvelopePool` / `makeFakeRedis` from
//     `ws-gateway.test.ts`. We replicate them inline here rather than
//     importing because the unit-test module does not export them and
//     this property test should remain self-contained.
//   - Per iteration: pick a random `(senderDeviceId, clientNonce)`,
//     envelope payload, and N ∈ [1, 100]. Invoke `onSendEnvelope`
//     sequentially N times under a frozen clock so retries fall well
//     inside the 60-s window (the dedupe key is the unique index, not
//     a TTL — the 60-s wording in the task brief reflects the typical
//     client retry budget, not a server-side condition).
//   - Iteration count comes from the global fast-check config in
//     `test/setup.ts` (default 100; nightly via `FAST_CHECK_RUNS`).
//
// What we explicitly DO NOT test here:
//   - Concurrency (multiple in-flight inserts racing for the same
//     `(senderDeviceId, clientNonce)`): `onSendEnvelope` is awaited
//     sequentially in this property by design, mirroring the per-
//     socket message loop in `gateway.ts` (frames are processed in
//     order). Cross-connection concurrency is a database-level
//     guarantee from the UNIQUE INDEX and is covered by the integration
//     test for task 3.4 — out of scope for P13's "repeated requests".
//   - Rate limiting: the spec defaults of 50 burst / 10 per-second
//     would cap N at 50 within a single tick. We use a generous
//     test bucket (capacity 1000, refill 1000/s) so the rate limiter
//     never spuriously rejects a retry — that path is already covered
//     by the unit test for P16 and would mask P13 here.

import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  EnvelopeRouterType,
  S2C,
  type CiphertextEnvelope,
  type ServerToClient,
} from '@konvo/protocol';

import {
  buildContext,
  fanoutChannelFor,
  onSendEnvelope,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Test doubles (mirror makeFakeSocket / makeFakeEnvelopePool / makeFakeRedis
// from ws-gateway.test.ts; replicated to keep this property test
// self-contained.)
// ---------------------------------------------------------------------------

interface FakeSocket extends WSSocket {
  sent: Uint8Array[];
  // Replies as decoded ServerToClient frames. We capture by overriding
  // `WSContext.send` rather than hand-decoding msgpack so we can assert
  // structurally against the typed frame.
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
      // unused — onSendEnvelope never closes the socket on success or
      // on the failure paths covered by P13.
    },
    on(): WSSocket {
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

/** Captures every reply `onSendEnvelope` enqueues to the socket so we
 *  can assert the invariant "every reply is ENVELOPE_QUEUED with the
 *  same envelopeId". We override `ctx.send` rather than decoding the
 *  msgpack frames — the codec round-trip is exhaustively tested in
 *  `@konvo/protocol`'s own property tests. */
type Reply = ServerToClient;

interface FakePool {
  readonly inserts: Array<{
    senderDevice: string;
    clientNonce: string;
    id: bigint;
  }>;
  query(
    sql: string,
    params: readonly unknown[],
  ): Promise<{ rows: unknown[]; rowCount: number }>;
}

/** In-memory pool with the same idempotency semantics as the production
 *  schema's UNIQUE INDEX on `(sender_device, client_nonce)`. */
function makeFakePool(): FakePool {
  let nextId = 1n;
  const fake: FakePool = {
    inserts: [],
    async query(sql: string, params: readonly unknown[]) {
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        const senderDevice = params[1] as string;
        const clientNonce = params[5] as string;
        const existing = fake.inserts.find(
          (r) => r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing !== undefined) {
          // ON CONFLICT DO NOTHING → zero rows.
          return { rows: [], rowCount: 0 };
        }
        const id = nextId++;
        fake.inserts.push({ senderDevice, clientNonce, id });
        return { rows: [{ id: id.toString() }], rowCount: 1 };
      }
      if (trimmed.startsWith('SELECT id')) {
        const senderDevice = params[0] as string;
        const clientNonce = params[1] as string;
        const existing = fake.inserts.find(
          (r) => r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing === undefined) {
          return { rows: [], rowCount: 0 };
        }
        return {
          rows: [{ id: existing.id.toString() }],
          rowCount: 1,
        };
      }
      throw new Error(`unexpected SQL in P13 property test: ${sql}`);
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

// ---------------------------------------------------------------------------
// Property: P13 — idempotent envelope delivery
// ---------------------------------------------------------------------------

describe('P13: idempotent envelope delivery (Requirements 4.7, 12.4, 21.13)', () => {
  it('repeated SEND_ENVELOPE with same (senderDeviceId, clientNonce) → exactly one row, one publish, same envelopeId', async () => {
    // Arbitraries:
    //  - senderDeviceId / recipientDeviceId / sessionId / clientNonce:
    //    fast-check UUIDs. The wire types accept any string but using
    //    UUIDs keeps the generator close to production input shape.
    //  - ciphertext: bounded byte array (0..256 bytes is well within
    //    the 1 MiB frame ceiling and keeps memory bounded across 100×
    //    iterations).
    //  - retryCount: integer in [1, 100] per the task brief — "up to
    //    100 within a 60-s window". 1 is included so the property
    //    holds at the minimum-retry boundary (a single send is a
    //    degenerate "1 attempt" case where N=1).
    const arbSenderDevice = fc.uuid();
    const arbRecipientDevice = fc.uuid();
    const arbSessionId = fc.uuid();
    // clientNonce is opaque to the server — `string()` exercises a
    // wider input space than uuid() and matches the production wire
    // type (`z.string()`). minLength: 1 to avoid the degenerate empty
    // string (real clients always emit a non-empty UUID).
    const arbClientNonce = fc.string({ minLength: 1, maxLength: 64 });
    const arbCiphertext = fc
      .uint8Array({ minLength: 0, maxLength: 256 })
      .map((a) => new Uint8Array(a));
    const arbRetryCount = fc.integer({ min: 1, max: 100 });

    await fc.assert(
      fc.asyncProperty(
        arbSenderDevice,
        arbRecipientDevice,
        arbSessionId,
        arbClientNonce,
        arbCiphertext,
        arbRetryCount,
        async (
          senderDevice,
          recipientDevice,
          sessionId,
          clientNonce,
          ciphertext,
          retryCount,
        ) => {
          // Fresh fakes per iteration so cross-iteration state can't
          // mask a missing dedupe (the production unique index is
          // tablespace-wide, but a fresh fake is the per-iteration
          // analogue).
          const sock = makeFakeSocket();
          const ctx = buildContext(sock, 'user-test', senderDevice, NULL_LOG);
          ctx.helloReceived = true; // skip handshake; P13 is post-HELLO

          // Capture replies via send() override — see comment above
          // makeFakeSocket. The msgpack round-trip is exhaustively
          // tested in @konvo/protocol; here we want structural access
          // to the typed reply.
          const replies: Reply[] = [];
          ctx.send = (msg: ServerToClient): void => {
            replies.push(msg);
          };

          const pool = makeFakePool();
          const redis = makeFakeRedis();
          // Frozen clock: every retry occurs within the same
          // millisecond so we exercise the "within a 60-s window"
          // retry semantics. A real client would space retries over
          // backoff intervals; the dedupe behaviour is identical
          // because the unique index is the authority, not a TTL.
          const FROZEN_NOW_MS = 1_700_000_000_000;
          const deps: SendEnvelopeDeps = {
            pool: pool as unknown as SendEnvelopeDeps['pool'],
            redis,
            now: (): number => FROZEN_NOW_MS,
            sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
            // Generous bucket: 1000 burst / 1000 per-second so the
            // rate limiter (P16) cannot reject any of the 100 retries.
            // Rate limiting is covered by its own property test in
            // task 10.10; mixing it in here would mask P13.
            sendEnvelopeBucket: { capacity: 1000, refillPerSecond: 1000 },
          };

          const envelope: CiphertextEnvelope = {
            sessionId,
            senderDeviceId: senderDevice,
            recipientDeviceId: recipientDevice,
            type: EnvelopeRouterType.MESSAGE,
            ciphertext,
          };

          // Drive `retryCount` sequential SEND_ENVELOPE attempts with
          // the same `(senderDeviceId, clientNonce)`.
          for (let i = 0; i < retryCount; i++) {
            await onSendEnvelope(ctx, { clientNonce, envelope }, deps);
          }

          // Assertion (a): exactly one row in ciphertext_envelopes.
          if (pool.inserts.length !== 1) return false;

          // Assertion (b): exactly one publish on the recipient's
          // channel `dev:{recipientDeviceId}`.
          if (redis.published.length !== 1) return false;
          if (redis.published[0]?.channel !== fanoutChannelFor(recipientDevice)) {
            return false;
          }

          // Assertion (c): every reply is ENVELOPE_QUEUED with the
          // SAME envelopeId (the id assigned on first insert) and the
          // original clientNonce.
          if (replies.length !== retryCount) return false;
          const originalId = pool.inserts[0]!.id;
          for (const reply of replies) {
            if (reply.t !== S2C.ENVELOPE_QUEUED) return false;
            if (reply.envelopeId !== originalId) return false;
            if (reply.clientNonce !== clientNonce) return false;
          }

          // The publish payload must reference that same envelopeId
          // as a decimal string (per `onSendEnvelope` step 4).
          if (redis.published[0]?.payload !== originalId.toString()) {
            return false;
          }

          return true;
        },
      ),
    );
  });
});

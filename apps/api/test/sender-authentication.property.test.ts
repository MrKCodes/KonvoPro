// P17 — Validates Requirements 12.3, 21.17
//
// apps/api/test/sender-authentication.property.test.ts
//
// Property test for task 10.11 — P17: Sender authentication.
//
// Property under test (orchestrator-specified P17 wording, also
// design.md §14 / requirements.md §21.17):
//
//   For any `SEND_ENVELOPE` where `envelope.senderDeviceId !==
//   ctx.deviceId`, the WS_Gateway:
//     a. replies with `ERROR { code: ErrorCode.INVALID_PAYLOAD }`,
//     b. inserts NO row into `ciphertext_envelopes`,
//     c. NEVER calls `redis.publish` (no fan-out).
//
// **Validates: Requirements 12.3, 21.17**
//
// Strategy:
//   - Drive `onSendEnvelope` directly with a hand-rolled WSContext, a
//     fake `pg.Pool` that records every INSERT in an array, and a
//     fake Redis publisher that records every `publish` call. This
//     mirrors the unit-level harness in `ws-gateway.test.ts` so this
//     property test exercises the same code path without standing up
//     a real WebSocket / Postgres / Redis.
//   - Generate `(ctxDeviceId, senderDeviceId)` as two distinct UUIDs
//     using `fc.tuple(fc.uuid(), fc.uuid()).filter(([a, b]) => a !== b)`.
//     The filter keeps the input space focused on the property's
//     precondition (mismatch) and avoids a wasted iteration where
//     fast-check happens to pick equal UUIDs (very rare but possible).
//   - Iteration count comes from `test/setup.ts` (default 100, nightly
//     500 via `FAST_CHECK_RUNS`), satisfying the ≥ 100 minimum
//     required for property tests.
//
// Why we don't reuse the SEND_ENVELOPE rate-limit bucket from
// `ws-gateway.test.ts`: P17 is a sender-authority property and must
// hold even when the bucket is empty. Using a fresh bucket map per
// iteration with capacity 50 / refill 10/s means a single send per
// iteration always has a token available, isolating the property
// from rate-limit interference.

import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  EnvelopeRouterType,
  ErrorCode,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
  type ServerToClient,
} from '@konvo/protocol';

import {
  buildContext,
  onSendEnvelope,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { WSSocket } from '../src/ws/types.js';

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

/** A pg.Pool stub that records every INSERT to `ciphertext_envelopes`.
 *
 *  P17 only requires us to assert "no row inserted" on a sender
 *  mismatch — we don't even need to handle the SELECT id-lookup
 *  branch, because an impostor send must short-circuit before any
 *  DB call. Any unexpected SQL is therefore a property failure: it
 *  means the gateway reached a code path that should never run for
 *  a sender-authority rejection. We surface that as a thrown error
 *  so fast-check shrinks to the offending input. */
interface FakeEnvelopePool {
  readonly inserts: Array<{
    sessionId: string;
    senderDevice: string;
    recipientDevice: string;
    ciphertext: Buffer;
    type: number;
    clientNonce: string;
  }>;
  query(sql: string, params: readonly unknown[]): Promise<{ rows: unknown[]; rowCount: number }>;
}

function makeFakeEnvelopePool(): FakeEnvelopePool {
  const fake: FakeEnvelopePool = {
    inserts: [],
    async query(sql: string, params: readonly unknown[]) {
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        const [sessionId, senderDevice, recipientDevice, ciphertext, type, clientNonce] =
          params as [string, string, string, Buffer, number, string];
        fake.inserts.push({
          sessionId,
          senderDevice,
          recipientDevice,
          ciphertext,
          type,
          clientNonce,
        });
        return { rows: [{ id: '1' }], rowCount: 1 };
      }
      // Any other shape is unexpected on the impostor path.
      throw new Error(`unexpected SQL on sender-mismatch path: ${sql}`);
    },
  };
  return fake;
}

/** A Redis publisher mock that captures every `publish` call. P17
 *  requires zero publishes on the sender-mismatch path, so a single
 *  recorded entry is a property failure. */
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

/** Read the most recent S2C frame the socket received. */
function lastS2C(sock: FakeSocket): ServerToClient {
  const last = sock.sent[sock.sent.length - 1];
  if (last === undefined) throw new Error('no frame sent');
  return decodeS2C(last);
}

// ---------------------------------------------------------------------------
// Property: P17 — sender authentication
// ---------------------------------------------------------------------------

describe('P17: sender authentication (Requirements 12.3, 21.17)', () => {
  it('SEND_ENVELOPE with envelope.senderDeviceId !== ctx.deviceId is rejected with INVALID_PAYLOAD; no row, no publish', async () => {
    // Two distinct UUIDs — the precondition for P17. The filter is a
    // belt-and-suspenders guard against the (theoretically negligible)
    // chance that fast-check picks the same UUID twice; without it,
    // an equal-pair iteration would hit the happy path and this
    // property would not apply.
    const arbDistinctDeviceIds = fc
      .tuple(fc.uuid(), fc.uuid())
      .filter(([a, b]) => a !== b);

    // Envelope shape generators. `ciphertext` is bounded at 256 bytes
    // (well under the codec's 1 MiB cap) — the size doesn't matter
    // for P17, but smaller payloads keep iterations fast.
    const arbSessionId = fc.uuid();
    const arbRecipientDeviceId = fc.uuid();
    const arbCiphertext = fc.uint8Array({ minLength: 1, maxLength: 256 });
    const arbType = fc.constantFrom(
      EnvelopeRouterType.MESSAGE,
      EnvelopeRouterType.ACK,
      EnvelopeRouterType.CALL,
    );
    // Client nonces are arbitrary client-supplied strings; the gateway
    // only uses them as the second column of the (sender_device,
    // client_nonce) idempotency key. Bound the length so the
    // generator stays cheap.
    const arbClientNonce = fc.string({ minLength: 1, maxLength: 64 });

    await fc.assert(
      fc.asyncProperty(
        arbDistinctDeviceIds,
        arbSessionId,
        arbRecipientDeviceId,
        arbCiphertext,
        arbType,
        arbClientNonce,
        async (
          [ctxDeviceId, senderDeviceId],
          sessionId,
          recipientDeviceId,
          ciphertext,
          type,
          clientNonce,
        ) => {
          // Fresh fakes per iteration so the assertions on
          // `pool.inserts.length === 0` and `redis.published.length === 0`
          // can't be polluted by a previous iteration.
          const sock = makeFakeSocket();
          const ctx = buildContext(sock, 'user-1', ctxDeviceId, NULL_LOG);
          ctx.helloReceived = true; // P17 applies to post-HELLO state.
          const pool = makeFakeEnvelopePool();
          const redis = makeFakeRedis();

          const deps: SendEnvelopeDeps = {
            pool,
            redis,
            now: (): number => 1_700_000_000_000,
            // Spec defaults so a single send always has a token —
            // isolates this property from rate-limit interference.
            sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
            sendEnvelopeBucket: { capacity: 50, refillPerSecond: 10 },
          };

          const envelope: CiphertextEnvelope = {
            sessionId,
            senderDeviceId,
            recipientDeviceId,
            type,
            ciphertext,
          };

          await onSendEnvelope(ctx, { clientNonce, envelope }, deps);

          // (a) Exactly one S2C frame, decoding to ERROR(INVALID_PAYLOAD).
          if (sock.sent.length !== 1) return false;
          const reply = lastS2C(sock);
          if (reply.t !== S2C.ERROR) return false;
          if (reply.code !== ErrorCode.INVALID_PAYLOAD) return false;

          // (b) No row inserted into the fake `ciphertext_envelopes`.
          if (pool.inserts.length !== 0) return false;

          // (c) No fan-out publish on any Redis channel.
          if (redis.published.length !== 0) return false;

          // (d) Socket stays open — the rejection is a soft error per
          // design.md §13.6. Property P17 does not require this but
          // the broader spec does (sender mismatch is not a
          // close-the-socket condition).
          if (sock.closes.length !== 0) return false;

          return true;
        },
      ),
    );
  });
});

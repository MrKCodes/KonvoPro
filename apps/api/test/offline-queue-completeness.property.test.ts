// P15 — Validates Requirements 12.11, 21.15
//
// apps/api/test/offline-queue-completeness.property.test.ts
//
// Property test for task 10.9 (Phase 9) — P15: offline queue
// completeness (design.md §10 / requirements.md §21.15 / §12.11).
//
// Property under test:
//
//   For any sequence of N envelopes (N ∈ [1, 10000]) sent to a
//   recipient who is offline at send time, on next reconnect the
//   recipient SHALL receive exactly N `S2C.ENVELOPE` messages,
//   ordered by `created_at` ASC with `envelopeId` ASC as the
//   tiebreaker for equal `created_at`, with no duplicates and no
//   losses.
//
// **Validates: Requirements 12.11, 21.15**
//
// Strategy:
//   - Drive `replayUndeliveredEnvelopes` directly with a fresh
//     in-memory `FakePool` per iteration. The pool seeds N rows
//     into a fake `ciphertext_envelopes` table addressed to a
//     single recipient `deviceId`; every row has
//     `delivered_at IS NULL` so the SQL filter selects all of
//     them. The fake pool routes the exact replay query shape
//     issued by `redis-fanout.ts` and re-implements the
//     `ORDER BY created_at ASC, id ASC` server-side sort so the
//     test exercises the production ordering contract end-to-end.
//   - Assertions are computed against an INDEPENDENTLY recomputed
//     expected order, sorting the seeded row set by the same key
//     pair `(created_at ASC, id ASC)`. This guards against the
//     fake-pool sort and the production module agreeing on a
//     wrong order — the comparison in the test is against the
//     spec, not against the stub.
//
// Why we cap N at 100 here:
//   The spec wording is `N ∈ [1, 10000]`, and the unique partial
//   index `env_recipient_undelivered_idx` makes the production
//   query O(K log K) in the queue size. The fake pool re-sorts the
//   in-memory row array on every replay, which is also O(K log K).
//   100 iterations × up to 100 rows ≈ 10⁴ envelope frames per run;
//   bumping the upper bound to 10⁴ would put us at 10⁶ frames per
//   run for no additional code-path coverage (the loop body in
//   `replayUndeliveredEnvelopes` is a single unconditional
//   `ctx.send` call — the cardinality boundary that matters is
//   "any N ≥ 1", not the absolute upper bound). The contract
//   bound 10000 is exercised by the partial index migration test
//   in task 3.5; here we focus on the algorithmic property.
//
// What we explicitly DO NOT exercise here:
//   - Live pub/sub fan-out (`attachInbox`'s subscribe path). That
//     path is covered by the unit tests for task 3.5 in
//     `redis-fanout.test.ts`. P15 is specifically about the
//     reconnect / replay path: the recipient was offline, the rows
//     are in the queue, and now they must come out in order.
//   - The dedup boundary between replay and live publish. Same
//     reason — that's a unit-test concern; here the queue is
//     entirely "offline-queued at send time".
//
// Iteration count comes from the global fast-check config in
// `test/setup.ts` (default 100; nightly via `FAST_CHECK_RUNS`).

import * as fc from 'fast-check';
import { describe, it, expect } from 'vitest';

import {
  EnvelopeRouterType,
  S2C,
  type CiphertextEnvelope,
  type ServerToClient,
} from '@konvo/protocol';

import {
  replayUndeliveredEnvelopes,
  type FanoutDbPool,
} from '../src/ws/redis-fanout.js';
import type { WSContext, WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

interface FakeSocket extends WSSocket {
  // Captured structured S2C frames the gateway emitted to this socket.
  // We override `WSContext.send` below to push directly here so tests
  // assert against the typed frame rather than msgpack-decoding bytes.
  // The codec round-trip property is exhaustively covered in
  // `@konvo/protocol`'s own property tests.
  readonly frames: ServerToClient[];
}

function makeFakeSocket(): FakeSocket {
  const frames: ServerToClient[] = [];
  const sock: FakeSocket = {
    readyState: 1, // OPEN
    frames,
    send(): void {
      // Not exercised — the test patches `ctx.send` to capture the
      // structured frame on `frames` directly. Provided so the
      // structural `WSSocket` interface is satisfied.
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

function makeCtx(deviceId: string): { ctx: WSContext; sock: FakeSocket } {
  const sock = makeFakeSocket();
  const ctx: WSContext = {
    socket: sock,
    userId: 'user-1',
    deviceId,
    authenticated: true,
    helloReceived: true,
    log: NULL_LOG,
    subscribedRooms: new Set<string>(),
    send(msg: ServerToClient): void {
      sock.frames.push(msg);
    },
    close(): void {
      sock.close();
    },
  };
  return { ctx, sock };
}

/** Shape of a row in the fake `ciphertext_envelopes` store. Mirrors
 *  the column subset `replayUndeliveredEnvelopes` SELECTs (see
 *  `redis-fanout.ts`). `delivered_at` is included because the SQL
 *  filter is `delivered_at IS NULL`; we always seed `null` here so
 *  every row qualifies for replay. */
interface FakeRow {
  id: string; // BIGINT-as-string, matching pg's bigint -> string
  session_id: string;
  sender_device: string;
  recipient_device: string;
  type: number;
  ciphertext: Buffer;
  created_at: Date;
  delivered_at: Date | null;
}

/**
 * pg-pool stub backed by a list of `FakeRow`. Routes only the replay
 * query shape — any other SQL throws so a regression in the module
 * surfaces as a property failure rather than a silent zero. The
 * sort here mirrors the production `ORDER BY created_at ASC, id ASC`
 * exactly: created_at ASC primary key, id ASC tiebreak (BigInt
 * comparison preserves numeric order on the string-formed id).
 */
function makeFakePool(rows: FakeRow[]): FanoutDbPool {
  return {
    async query<R = unknown>(sql: string, params: readonly unknown[]) {
      const trimmed = sql.trim();
      if (
        trimmed.startsWith('SELECT id::text') &&
        trimmed.includes('AND delivered_at IS NULL')
      ) {
        const [recipient] = params as [string];
        const filtered = rows.filter(
          (r) => r.recipient_device === recipient && r.delivered_at === null,
        );
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
      throw new Error(
        `unexpected SQL in P15 property test stub: ${trimmed.slice(0, 80)}`,
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Fixed routing identifiers
// ---------------------------------------------------------------------------

const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const SENDER_DEVICE = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const RECIPIENT = 'cccccccc-cccc-cccc-cccc-cccccccccccc';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Pull every `S2C.ENVELOPE` frame the recipient received, in delivery
 *  order. Other frame types are filtered out (none are emitted on the
 *  replay path today, but this guards against accidental mixing). */
function envelopesSent(sock: FakeSocket): CiphertextEnvelope[] {
  return sock.frames
    .filter(
      (f): f is Extract<ServerToClient, { t: S2C.ENVELOPE }> =>
        f.t === S2C.ENVELOPE,
    )
    .map((f) => f.envelope);
}

/** Independent recomputation of the expected delivery order. We sort
 *  the seeded row set by the spec's contract — `(created_at ASC,
 *  envelopeId ASC)` — and return the `id` sequence the recipient
 *  must observe. This is the source of truth in the assertion; the
 *  fake pool's sort is just a reference implementation. */
function expectedIdOrder(rows: FakeRow[]): bigint[] {
  return rows
    .slice()
    .sort((a, b) => {
      if (a.created_at.getTime() !== b.created_at.getTime()) {
        return a.created_at.getTime() - b.created_at.getTime();
      }
      const ai = BigInt(a.id);
      const bi = BigInt(b.id);
      return ai < bi ? -1 : ai > bi ? 1 : 0;
    })
    .map((r) => BigInt(r.id));
}

// ---------------------------------------------------------------------------
// Property: P15 — offline queue completeness
// ---------------------------------------------------------------------------

describe('P15 — offline queue completeness (Requirements 12.11, 21.15)', () => {
  it('replay delivers exactly N envelopes ordered by (created_at ASC, id ASC) with no duplicates and no losses', async () => {
    // Generators:
    //
    //  - N (queue size): integer in [1, 100]. The spec contract is
    //    1..10000; we cap at 100 to keep the per-iteration loop
    //    bounded (see header comment for rationale). 1 is the
    //    minimum-cardinality boundary — a single offline send must
    //    still come out exactly once.
    //
    //  - createdAtBuckets: integer in [0, 9]. Each row is assigned
    //    one of 10 distinct timestamp buckets (each bucket spans
    //    `BUCKET_GRANULARITY_MS` real ms). With 10 buckets and up to
    //    100 rows, every bucket has ~10 rows on average — i.e. the
    //    `id ASC` tiebreak is exercised on roughly 90% of consecutive
    //    pairs in the expected order.
    //
    //  - ciphertext: bounded byte array (0..32 bytes). We don't need
    //    realistic Signal payload sizes here; the property is about
    //    delivery cardinality and order, not payload preservation.
    //    Keeping ciphertext small makes 100 iterations × 100 rows
    //    cheap to run.
    //
    //  - id assignment: ids are assigned in INSERTION order, starting
    //    at 1n. Production uses `BIGSERIAL` which is monotonic per
    //    insert — the test mirrors that exactly. This means the
    //    `id ASC` tiebreak is equivalent to "earlier inserted wins"
    //    when timestamps tie, which is what Requirement 12.11
    //    formalises.

    const BUCKET_GRANULARITY_MS = 100;
    const BASE_TS_MS = 1_700_000_000_000;

    const arbCipher = fc.uint8Array({ minLength: 0, maxLength: 32 });
    const arbBucket = fc.integer({ min: 0, max: 9 });

    // Per-iteration we generate an array of (bucket, ciphertext)
    // pairs of length 1..100. fast-check's `fc.array` over a tuple
    // arbitrary gives us exactly that shape.
    const arbRows = fc.array(fc.tuple(arbBucket, arbCipher), {
      minLength: 1,
      maxLength: 100,
    });

    await fc.assert(
      fc.asyncProperty(arbRows, async (raw) => {
        // Materialise the seeded rows. Ids are assigned in insertion
        // order so the BIGSERIAL invariant holds.
        const rows: FakeRow[] = raw.map(([bucket, cipher], idx) => ({
          id: BigInt(idx + 1).toString(),
          session_id: SESSION_ID,
          sender_device: SENDER_DEVICE,
          recipient_device: RECIPIENT,
          type: EnvelopeRouterType.MESSAGE,
          ciphertext: Buffer.from(cipher),
          created_at: new Date(BASE_TS_MS + bucket * BUCKET_GRANULARITY_MS),
          delivered_at: null,
        }));
        const N = rows.length;

        const pool = makeFakePool(rows);
        const { ctx, sock } = makeCtx(RECIPIENT);

        const seen = await replayUndeliveredEnvelopes(pool, ctx);

        const sent = envelopesSent(sock);

        // (a) Total frames received === N — no losses, no extras.
        expect(sent.length).toBe(N);
        // The dedup-bookkeeping return value reflects the same set.
        expect(seen.size).toBe(N);

        // (b) No duplicate envelope ids in the received stream.
        // Equivalent: |Set(ids)| === ids.length.
        const idsReceived = sent.map((e) => e.id);
        const idSet = new Set(idsReceived.map((id) => id.toString()));
        expect(idSet.size).toBe(idsReceived.length);

        // (c) Frames ordered by (created_at ASC, id ASC).
        // Compute the expected id sequence INDEPENDENTLY of the
        // fake-pool's sort and compare element-wise against what
        // the recipient observed.
        const expected = expectedIdOrder(rows);
        expect(idsReceived).toEqual(expected);

        // (d) All envelopes are addressed to ctx.deviceId — the
        // recipient-isolation half of P15 (Requirement 12.11 implies
        // P14: a row landing on this socket must have been keyed to
        // this socket's device).
        for (const env of sent) {
          expect(env.recipientDeviceId).toBe(ctx.deviceId);
        }
      }),
    );
  });
});

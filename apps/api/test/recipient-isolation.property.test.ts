// P14 — Validates Requirements 12.12, 21.14
//
// apps/api/test/recipient-isolation.property.test.ts
//
// Property test for task 10.8 — P14: Recipient isolation.
//
// Property under test (orchestrator-specified P14 wording, also
// design.md §14 / requirements.md §21.14):
//
//   For any envelope inserted with `recipientDeviceId = X`, no
//   fan-out occurs to any device `Y ≠ X`, including under up to
//   100 concurrent sends.
//
// **Validates: Requirements 12.12, 21.14**
//
// Strategy:
//   - Drive `onSendEnvelope` directly with fakes, mirroring the
//     unit-level harness used by `ws-gateway.test.ts` and the other
//     gateway property tests (`idempotent-envelope.property.test.ts`,
//     `sender-authentication.property.test.ts`,
//     `rate-limit-conservation.property.test.ts`). This exercises
//     the same code path that production traffic takes — including
//     `publishEnvelopeToRecipient` from `redis-fanout.ts`, which
//     is the single authoritative source of the channel-naming
//     convention `dev:{recipientDeviceId}` (Requirement 12.15) — but
//     without standing up a real WebSocket / Postgres / Redis.
//   - Per iteration: generate N ∈ [1, 100] (sender, recipient)
//     pairs with unique senders so the (sender_device, client_nonce)
//     idempotency key never causes two concurrent inserts to collide
//     on the unique index. The recipientDeviceIds are independent
//     UUIDs (some may repeat across the batch by coincidence — that
//     is FINE for the property, which only asserts isolation by
//     recipient: a recipient that receives two envelopes legitimately
//     shows up on `dev:{X}` twice).
//   - Run all sends concurrently via `Promise.all`. The fake pool
//     and fake redis are intentionally NOT awaiting — each `query`
//     and `publish` is a synchronous mutation wrapped in a resolved
//     Promise — so the v8 microtask interleaving stresses the
//     happens-before ordering between the fake DB insert and the
//     fan-out publish. Any code path in `onSendEnvelope` that
//     publishes BEFORE the row exists, or publishes on a channel
//     different from `dev:{recipientDeviceId}`, will be caught by
//     the per-publish channel assertion below.
//   - 50 iterations (override of the global default 100 in
//     `test/setup.ts`). Each iteration performs up to 100 concurrent
//     calls, so the upper bound on `onSendEnvelope` invocations is
//     ~5000. We constrain the per-iteration ciphertext size to 256
//     bytes so total memory stays bounded across the run.
//
// What we DELIBERATELY do not test here:
//   - Idempotent retries of the same `(sender_device, client_nonce)`:
//     P13 owns that property in
//     `idempotent-envelope.property.test.ts`. This test uses unique
//     `clientNonce` per send to keep the recipient-isolation property
//     orthogonal to dedup behaviour.
//   - Sender-authority (impostor) sends: P17 owns that property in
//     `sender-authentication.property.test.ts`. We always set
//     `envelope.senderDeviceId === ctx.deviceId` so recipient-
//     isolation can be evaluated on the happy path.
//   - Rate limiting: P16 owns that property in
//     `rate-limit-conservation.property.test.ts`. We use a generous
//     bucket (capacity 1000, refill 1000/s) so the rate limiter
//     never spuriously rejects a send. Each iteration also uses a
//     FRESH bucket map so cross-iteration state can't deplete the
//     limiter.

import * as fc from 'fast-check';
import { describe, it } from 'vitest';

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
// Test doubles (mirror the harness used by the other gateway property
// tests; replicated to keep this property test self-contained.)
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
      // unused — recipient-isolation paths never close the socket.
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

interface PoolInsert {
  readonly senderDevice: string;
  readonly recipientDevice: string;
  readonly clientNonce: string;
  readonly id: bigint;
}

interface FakePool {
  readonly inserts: PoolInsert[];
  query(
    sql: string,
    params: readonly unknown[],
  ): Promise<{ rows: unknown[]; rowCount: number }>;
}

/** In-memory pool with the same idempotency semantics as the
 *  production schema's UNIQUE INDEX on `(sender_device, client_nonce)`.
 *  Concurrent calls share the same `inserts` array; assignment of
 *  `nextId` runs on the synchronous tail of the await chain so each
 *  insert receives a unique monotonic id even under Promise.all. */
function makeFakePool(): FakePool {
  let nextId = 1n;
  const fake: FakePool = {
    inserts: [],
    async query(sql: string, params: readonly unknown[]) {
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        const senderDevice = params[1] as string;
        const recipientDevice = params[2] as string;
        const clientNonce = params[5] as string;
        const existing = fake.inserts.find(
          (r) =>
            r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing !== undefined) {
          return { rows: [], rowCount: 0 };
        }
        const id = nextId++;
        fake.inserts.push({ senderDevice, recipientDevice, clientNonce, id });
        return { rows: [{ id: id.toString() }], rowCount: 1 };
      }
      if (trimmed.startsWith('SELECT id')) {
        const senderDevice = params[0] as string;
        const clientNonce = params[1] as string;
        const existing = fake.inserts.find(
          (r) =>
            r.senderDevice === senderDevice && r.clientNonce === clientNonce,
        );
        if (existing === undefined) {
          return { rows: [], rowCount: 0 };
        }
        return {
          rows: [{ id: existing.id.toString() }],
          rowCount: 1,
        };
      }
      throw new Error(`unexpected SQL in P14 property test: ${sql}`);
    },
  };
  return fake;
}

interface PublishEntry {
  readonly channel: string;
  readonly payload: string;
}

interface FakeRedis {
  readonly published: PublishEntry[];
  publish(channel: string, payload: string): Promise<number>;
}

/** Captures every (channel, payload) tuple. The property under test
 *  is exclusively a channel-naming property: any publish on a
 *  non-`dev:{recipientDeviceId}` channel falsifies P14. */
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
// Property: P14 — recipient isolation
// ---------------------------------------------------------------------------

describe('P14: recipient isolation (Requirements 12.12, 21.14)', () => {
  it('any envelope with recipientDeviceId = X publishes on dev:{X} only, even under up to 100 concurrent sends', async () => {
    // Per-send shape generator. `senderDeviceId` is unique within a
    // batch (see `arbBatch` below) so concurrent sends never collide
    // on the (sender_device, client_nonce) unique key. The
    // recipientDeviceId is independent — repeats across the batch are
    // legitimate and don't affect P14.
    const arbSendSpec = fc.record({
      senderDeviceId: fc.uuid(),
      recipientDeviceId: fc.uuid(),
      sessionId: fc.uuid(),
      // clientNonce is opaque to the server; cap length to keep the
      // generator cheap.
      clientNonce: fc.string({ minLength: 1, maxLength: 64 }),
      // 1..256 bytes — well under the 1 MiB frame ceiling and
      // bounds memory across 5000 cumulative sends.
      ciphertext: fc.uint8Array({ minLength: 1, maxLength: 256 }),
      type: fc.constantFrom(
        EnvelopeRouterType.MESSAGE,
        EnvelopeRouterType.ACK,
        EnvelopeRouterType.CALL,
      ),
    });

    // A batch is up to 100 sends with unique senderDeviceIds. Using
    // `uniqueArray` with `selector` enforces uniqueness on the
    // sender field only — the (sender, recipient) pair is therefore
    // distinct across the batch as a trivial consequence (any pair
    // with a unique sender is a unique pair). minLength: 1 guards
    // against empty batches (a 0-send iteration would not exercise
    // the property at all).
    const arbBatch = fc.uniqueArray(arbSendSpec, {
      selector: (s) => s.senderDeviceId,
      minLength: 1,
      maxLength: 100,
    });

    await fc.assert(
      fc.asyncProperty(arbBatch, async (batch) => {
        // Fresh fakes per iteration so nothing leaks across runs.
        // Per-iteration state isolation is critical for the publish-
        // count assertion below: a stale entry would inflate the
        // count and falsely pass the equality check on a subsequent
        // iteration that misses a publish.
        const pool = makeFakePool();
        const redis = makeFakeRedis();
        // Fresh bucket map per iteration. Generous bucket so the
        // rate limiter never spuriously rejects (rate-limit
        // conservation is P16's responsibility, covered by
        // `rate-limit-conservation.property.test.ts`).
        const buckets = new Map<string, TokenBucketState>();

        const FROZEN_NOW_MS = 1_700_000_000_000;
        const deps: SendEnvelopeDeps = {
          pool: pool as unknown as SendEnvelopeDeps['pool'],
          redis,
          now: (): number => FROZEN_NOW_MS,
          sendEnvelopeBuckets: buckets,
          sendEnvelopeBucket: { capacity: 1000, refillPerSecond: 1000 },
        };

        // Build one (ctx, send-promise) per spec. Each ctx has its
        // OWN socket and OWN deviceId equal to the spec's
        // senderDeviceId — this models the production reality that
        // each device speaks over its own WS connection. The
        // envelope's senderDeviceId matches ctx.deviceId so the
        // sender-authority gate (P17) never fires; recipient-
        // isolation is evaluated on the happy path only.
        const promises: Promise<void>[] = batch.map((spec) => {
          const sock = makeFakeSocket();
          const ctx = buildContext(sock, 'user-test', spec.senderDeviceId, NULL_LOG);
          ctx.helloReceived = true; // skip handshake; P14 is post-HELLO

          // Capture replies via send() override so the per-iteration
          // reply tally can confirm one ENVELOPE_QUEUED per insert.
          const replies: ServerToClient[] = [];
          ctx.send = (msg: ServerToClient): void => {
            replies.push(msg);
          };
          (sock as unknown as { replies: ServerToClient[] }).replies = replies;

          const envelope: CiphertextEnvelope = {
            sessionId: spec.sessionId,
            senderDeviceId: spec.senderDeviceId,
            recipientDeviceId: spec.recipientDeviceId,
            type: spec.type,
            ciphertext: spec.ciphertext,
          };

          return onSendEnvelope(
            ctx,
            { clientNonce: spec.clientNonce, envelope },
            deps,
          );
        });

        // True concurrent execution — Promise.all interleaves the
        // microtask queue across all sends. Any happens-before bug
        // between the DB insert and the Redis publish would surface
        // as a publish without a corresponding insert (caught below
        // by the count equality) or as a publish on a channel that
        // doesn't match the recipient (caught by per-publish
        // channel assertion).
        await Promise.all(promises);

        // ------------------------------------------------------------------
        // (a) For each successful insert, exactly one publish landed
        //     on `dev:{recipientDeviceId}` matching the envelope's
        //     recipient.
        //
        // We pair inserts to publishes by the publish payload (the
        // envelope id as a decimal string, per `onSendEnvelope` step
        // 4 / `redis-fanout.ts:publishEnvelopeToRecipient`). Every
        // insert must have a matching publish, and that publish's
        // channel must be `fanoutChannelFor(insert.recipientDevice)`.
        // ------------------------------------------------------------------
        const publishesByPayload = new Map<string, PublishEntry[]>();
        for (const entry of redis.published) {
          const list = publishesByPayload.get(entry.payload) ?? [];
          list.push(entry);
          publishesByPayload.set(entry.payload, list);
        }

        for (const insert of pool.inserts) {
          const payload = insert.id.toString();
          const matching = publishesByPayload.get(payload);
          // Every insert must have exactly one matching publish.
          if (matching === undefined || matching.length !== 1) {
            return false;
          }
          // The matching publish must land on the recipient's
          // channel — and ONLY on the recipient's channel.
          const expectedChannel = fanoutChannelFor(insert.recipientDevice);
          if (matching[0]!.channel !== expectedChannel) {
            return false;
          }
        }

        // ------------------------------------------------------------------
        // (b) No publish landed on any channel other than
        //     `dev:{recipientDeviceId}` for some recipient device that
        //     was the recipient of an inserted envelope.
        //
        // This is the strictly stronger statement than (a): even a
        // publish that happens to use the `dev:` prefix but targets
        // an UNRELATED device id (one that never appeared as a
        // recipient in this batch) falsifies P14. The check walks
        // every recorded publish and verifies its channel is
        // `dev:{X}` for some X that is the recipient of the
        // envelope identified by the publish's payload.
        // ------------------------------------------------------------------
        const insertById = new Map<string, PoolInsert>();
        for (const insert of pool.inserts) {
          insertById.set(insert.id.toString(), insert);
        }
        for (const entry of redis.published) {
          const insert = insertById.get(entry.payload);
          if (insert === undefined) {
            // A publish whose payload doesn't reference any
            // persisted envelope is a fan-out without a row —
            // forbidden by Requirement 12.12 (P18) and falsifies
            // P14's premise (no envelope was inserted with a
            // matching recipient).
            return false;
          }
          if (entry.channel !== fanoutChannelFor(insert.recipientDevice)) {
            return false;
          }
          // Channel must NEVER be one of the OTHER batch members'
          // recipient channels (the sharper "no fan-out to Y ≠ X"
          // wording of P14). The check is implicit in the equality
          // above — `fanoutChannelFor` is a one-to-one function of
          // the recipient device id, so a channel mismatch means
          // some other Y was targeted. We assert the equality
          // explicitly for clarity.
        }

        // ------------------------------------------------------------------
        // (c) Total publish count equals total successful insert count.
        //
        // P14 forbids both kinds of asymmetry:
        //   - more publishes than inserts → fan-out happened to a
        //     device that wasn't the recipient of a persisted
        //     envelope (catches a fan-out duplication or a wrong-
        //     recipient publish bug).
        //   - more inserts than publishes → a row was persisted but
        //     not delivered live (covered defensively here; the
        //     primary owner is P15 offline-replay completeness in
        //     a future task, but for P14's purposes the fan-out
        //     must be exactly per-recipient and exactly once).
        // ------------------------------------------------------------------
        if (redis.published.length !== pool.inserts.length) {
          return false;
        }

        // ------------------------------------------------------------------
        // Sanity: each batch entry produced exactly one insert (no
        // dedup hit, no rate-limit reject) — this rules out the
        // degenerate case where the property holds vacuously because
        // every send was rejected before reaching the publish step.
        // ------------------------------------------------------------------
        if (pool.inserts.length !== batch.length) {
          return false;
        }

        return true;
      }),
      // 50 iterations overrides the global default 100. Each
      // iteration runs up to 100 concurrent sends, so the upper
      // bound on `onSendEnvelope` invocations is ~5000 — sufficient
      // coverage of the concurrency space without inflating CI time.
      { numRuns: 50 },
    );
  });
});

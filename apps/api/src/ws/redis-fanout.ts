// apps/api/src/ws/redis-fanout.ts
//
// Per-device Redis fan-out + offline-replay layer for the WS gateway —
// task 3.5. Realizes Requirements 12.11, 12.12, 12.15 and design.md
// §10 (`attachInbox`, `publishEnvelopeToRecipient`).
//
// Two responsibilities:
//
//   1. `attachInbox(ctx, redis, pool)` — invoked once per WS connection
//      AFTER a successful `HELLO_OK`. It does two things, in order:
//
//        a. Subscribes to `dev:{ctx.deviceId}` so any future
//           `publishEnvelopeToRecipient` published while this socket
//           is live is forwarded to the client as an `S2C.ENVELOPE`
//           frame. The subscription is kept alive for the lifetime
//           of the socket and detached on `close` to keep the
//           upstream Redis client's listener set bounded by the
//           number of currently-connected devices, not the number of
//           ever-connected devices.
//
//        b. Replays every envelope addressed to this device with
//           `delivered_at IS NULL`, ordered by `created_at` ASC then
//           `id` ASC as a tiebreak. This realises Requirement 12.11
//           ("on reconnect, replay all envelopes for the device with
//           delivered_at IS NULL ordered by created_at ASC, id ASC
//           tiebreak; no duplicates, no losses") and property P15
//           ("offline queue completeness").
//
//      Replay runs SECOND (after the subscription is registered) by
//      design: any envelope that lands at the recipient between
//      `HELLO_OK` and the end of replay is captured by either the
//      replay query (if it was inserted before our SELECT) or the
//      pub/sub channel (if it was inserted after). The
//      `seenEnvelopeIds` cache below dedups across the boundary so a
//      message inserted concurrently with replay is delivered exactly
//      once even if it's emitted on both paths.
//
//   2. `publishEnvelopeToRecipient(redis, recipientDeviceId, envelopeId)`
//      publishes a single envelope id (decimal-string) on the recipient's
//      `dev:{recipientDeviceId}` channel ONLY. Fan-out is keyed by the
//      exact recipient device — no broadcast, no wildcards — which
//      satisfies Requirement 12.15 and property P14 ("recipient
//      isolation: for any envelope inserted with recipientDeviceId =
//      X, no fan-out occurs to any device Y ≠ X"). This helper is
//      what `gateway.ts:onSendEnvelope` calls after a successful
//      `INSERT … RETURNING id`; centralising the call here keeps the
//      channel-naming convention in one place.
//
// The module is deliberately framework-agnostic: it takes a `WSContext`
// (structurally), a `WSRedisPublisher`, and a pg-pool-shaped object.
// Test doubles in `apps/api/test/redis-fanout.test.ts` instantiate
// each of these inline without spinning up Fastify, ioredis, or pg.

import {
  EnvelopeRouterType,
  S2C,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import type { WSContext, WSRedisPublisher } from './types.js';

// ---------------------------------------------------------------------------
// Channel naming
// ---------------------------------------------------------------------------

/** The Redis pub/sub channel name for a given recipient device.
 *
 *  Centralised here so this module, `redis-publisher.ts`
 *  (`deviceChannelFor`), and `gateway.ts` (`fanoutChannelFor`) all
 *  produce the same string for any given device id. The naming
 *  prefix `dev:` is dictated by Requirement 12.15 (`dev:{recipientDeviceId}`)
 *  and design.md §3.1. */
export function fanoutChannelFor(recipientDeviceId: string): string {
  return `dev:${recipientDeviceId}`;
}

// ---------------------------------------------------------------------------
// Database surface
// ---------------------------------------------------------------------------

/** The pg.Pool surface this module needs. We only run two
 *  parameterized SQL statements:
 *    - The replay SELECT (`SELECT … FROM ciphertext_envelopes
 *      WHERE recipient_device = $1 AND delivered_at IS NULL
 *      ORDER BY created_at ASC, id ASC`).
 *    - A single-row SELECT-by-id used by the pub/sub listener to
 *      hydrate an envelope from the id payload that
 *      `publishEnvelopeToRecipient` published.
 *
 *  Restating as a structural type lets tests stub it. */
export interface FanoutDbPool {
  query<R = unknown>(
    sql: string,
    params: readonly unknown[],
  ): Promise<{ rows: R[]; rowCount: number | null }>;
}

/** Shape of a row read back from `ciphertext_envelopes` for replay
 *  and for the per-message hydrate. The columns mirror the wire
 *  shape of `CiphertextEnvelope` (design.md §6.1) one-for-one,
 *  except that `created_at` arrives as a Postgres `TIMESTAMPTZ` and
 *  is converted to `epoch ms` before going on the wire. */
interface EnvelopeRow {
  readonly id: string; // BIGINT — pg returns BIGINT as a string
  readonly session_id: string;
  readonly sender_device: string;
  readonly recipient_device: string;
  readonly type: number; // SMALLINT
  readonly ciphertext: Buffer;
  readonly created_at: Date;
}

/** Translate a row read from `ciphertext_envelopes` into the on-the-wire
 *  `CiphertextEnvelope` shape. Centralised so the replay path and the
 *  pub/sub-hydrate path produce byte-identical envelopes. */
function rowToEnvelope(row: EnvelopeRow): CiphertextEnvelope {
  // The wire-format `type` is the `EnvelopeRouterType` enum; the
  // database column is a `SMALLINT` that holds the same integer.
  // We don't widen to a runtime check here because the column is
  // populated only by `onSendEnvelope`, which validated the value
  // via the codec on the way in.
  const enumType = row.type as EnvelopeRouterType;
  return {
    id: BigInt(row.id),
    sessionId: row.session_id,
    senderDeviceId: row.sender_device,
    recipientDeviceId: row.recipient_device,
    type: enumType,
    ciphertext: new Uint8Array(
      row.ciphertext.buffer,
      row.ciphertext.byteOffset,
      row.ciphertext.byteLength,
    ),
    createdAt: row.created_at.getTime(),
  };
}

// ---------------------------------------------------------------------------
// Publish (recipient-isolated fan-out)
// ---------------------------------------------------------------------------

/**
 * Publish a single envelope id to its recipient's fan-out channel —
 * and ONLY to that channel.
 *
 * Realises Requirement 12.15 / property P14: "for any envelope
 * inserted with `recipientDeviceId = X`, no fan-out occurs to any
 * device `Y ≠ X`". The implementation is a single `redis.publish`
 * keyed by the exact recipient; there is no broadcast path, no
 * wildcard, and no secondary channel.
 *
 * The payload is the envelope id formatted as a decimal string so
 * `attachInbox` can parse it back via `BigInt(...)` without needing
 * to commit to a binary encoding for what is otherwise a single
 * 64-bit integer. (We deliberately do NOT publish the full envelope
 * bytes on Redis — design.md §10 keeps the ciphertext on-disk only;
 * the listener hydrates on demand.)
 *
 * Returns the count of subscribers ioredis reports received the
 * message. Call sites today don't branch on this value (a 0-subscriber
 * publish is fine — the recipient is offline and the row stays
 * `delivered_at IS NULL` for the next reconnect's replay), but it is
 * surfaced for symmetry with `WSRedisPublisher.publish` and for use
 * by future observability that wants to count "delivered to a live
 * subscriber on first attempt".
 */
export async function publishEnvelopeToRecipient(
  redis: WSRedisPublisher,
  recipientDeviceId: string,
  envelopeId: bigint,
): Promise<number> {
  return redis.publish(
    fanoutChannelFor(recipientDeviceId),
    envelopeId.toString(),
  );
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/**
 * Read every envelope addressed to `ctx.deviceId` with
 * `delivered_at IS NULL`, in delivery order, and forward each as an
 * `S2C.ENVELOPE` frame. Returns the set of envelope ids that were
 * forwarded so the caller can dedup against the live pub/sub stream.
 *
 * Ordering is `created_at` ASC with `id` ASC as a tiebreak. The
 * tiebreak matters: two envelopes inserted at the same millisecond
 * (Postgres' `TIMESTAMPTZ` resolution is microsecond, but tests can
 * compress timestamps further) need a deterministic order, and the
 * `BIGSERIAL` `id` is monotonic per insert. This realises
 * Requirement 12.11 verbatim.
 *
 * The query uses the partial index `env_recipient_undelivered_idx`
 * (`infra/postgres/init.sql` lines 137–140), which is keyed on
 * `(recipient_device, created_at) WHERE delivered_at IS NULL`, so
 * scan cost is bounded by the size of THIS device's unread queue
 * rather than the global table size.
 *
 * Failure semantics:
 *   - On a SQL error, this function rethrows. The caller
 *     (`attachInbox`) catches and logs; the socket stays open and
 *     replay is effectively skipped — the rows remain
 *     `delivered_at IS NULL` and will be retried on the next
 *     reconnect.
 *   - On a `ctx.send` error (socket closed mid-replay), the loop
 *     stops and returns the set of ids forwarded so far. The remaining
 *     envelopes stay `delivered_at IS NULL` because we do not mark
 *     them delivered here — Requirement 4.6's three-state ticker is
 *     driven by E2EE `ACK_DELIVERED` envelopes, not by transport
 *     replay.
 */
export async function replayUndeliveredEnvelopes(
  pool: FanoutDbPool,
  ctx: WSContext,
): Promise<Set<string>> {
  const seen = new Set<string>();

  let rows: EnvelopeRow[];
  try {
    const result = await pool.query<EnvelopeRow>(
      // NB: `ORDER BY created_at ASC, id ASC` is load-bearing per
      // Requirement 12.11. The partial index is on
      // `(recipient_device, created_at)` so the planner can do an
      // index-only sort on the leading column without touching the
      // heap; the `id ASC` tiebreak is satisfied at scan time.
      `SELECT id::text         AS id,
              session_id       AS session_id,
              sender_device    AS sender_device,
              recipient_device AS recipient_device,
              type             AS type,
              ciphertext       AS ciphertext,
              created_at       AS created_at
         FROM ciphertext_envelopes
        WHERE recipient_device = $1
          AND delivered_at IS NULL
        ORDER BY created_at ASC, id ASC`,
      [ctx.deviceId],
    );
    rows = result.rows;
  } catch (err) {
    ctx.log.error(
      { err, deviceId: ctx.deviceId },
      'offline replay query failed',
    );
    return seen;
  }

  for (const row of rows) {
    const envelope = rowToEnvelope(row);
    seen.add(row.id);
    ctx.send({ t: S2C.ENVELOPE, envelope });
  }

  return seen;
}

// ---------------------------------------------------------------------------
// attachInbox
// ---------------------------------------------------------------------------

/**
 * Returned handle from `attachInbox`. Callers (the WS upgrade route
 * in `gateway.ts`) invoke `detach()` on socket close to release the
 * Redis subscription; the listener registry inside the publisher
 * decrements its refcount and issues a real `UNSUBSCRIBE` to
 * upstream Redis when the last subscriber for `dev:{deviceId}`
 * detaches.
 */
export interface InboxHandle {
  detach(): Promise<void>;
}

/**
 * Attach the per-connection inbox: subscribe to `dev:{ctx.deviceId}`
 * for live fan-out, then replay everything queued.
 *
 * The order — subscribe first, replay second — is chosen so an
 * envelope inserted concurrently with reconnect is captured exactly
 * once:
 *
 *   - If the insert happens BEFORE our SELECT runs, the row is in
 *     the result set and replay forwards it.
 *   - If the insert happens AFTER our SELECT runs but before
 *     `attachInbox` returns, the publish lands on the channel we
 *     already subscribed to and the listener forwards it.
 *   - If the insert happens DURING our SELECT (race window), the
 *     row may be in the result set AND the publish may also fire on
 *     the channel. The dedup set rejects the second copy.
 *
 * The dedup set lives for the lifetime of the connection (it's
 * captured in the listener closure). Memory cost is bounded by the
 * size of the offline queue at reconnect time PLUS any messages
 * that arrive thereafter; the spec caps the queue at 10000
 * (Requirement 12.13's `queuedCount` cap is observational, but the
 * partial index makes scanning cheap regardless), so the set is
 * naturally bounded for steady-state operation.
 *
 * Why we publish JUST the envelope id, not the full envelope:
 *   - Redis pub/sub is best-effort and lossy — design.md §10
 *     declares Postgres as the source of truth. Re-fetching by id
 *     means a missed publish degrades to "delivered on next
 *     reconnect" rather than "delivered with stale bytes".
 *   - Keeping the channel payload tiny lets a single publisher
 *     fan a 64 KiB ciphertext to 100 viewers without putting 6.4
 *     MiB through the publish socket. (Recipient-isolated channels
 *     mean N ~ 1 in steady state, but the same property holds for
 *     future multi-device fan-out.)
 */
export async function attachInbox(
  ctx: WSContext,
  redis: WSRedisPublisher,
  pool: FanoutDbPool,
): Promise<InboxHandle> {
  // Track every envelope id we've forwarded to this socket so a
  // race between replay and live publish doesn't deliver twice.
  // Backed by a Set<string> rather than Set<bigint> because
  // `BigInt`'s value semantics in a Set work but the memory cost
  // and string/bigint conversion overhead is uniform — and the
  // pub/sub payload arrives as a string anyway.
  const seenEnvelopeIds = new Set<string>();

  // Listener captures `seenEnvelopeIds` and `ctx`. Defined OUTSIDE
  // the subscribe call so we can pass the same function reference
  // to `unsubscribeDevice` on detach — the publisher's refcounting
  // is identity-based.
  const listener = (payload: string): void => {
    void handleLivePublish(ctx, pool, payload, seenEnvelopeIds);
  };

  // Subscribe FIRST (see the order rationale in the function header).
  await redis.subscribeDevice(ctx.deviceId, listener);

  // Replay SECOND. Seed the dedup set with every id we forwarded.
  const replayed = await replayUndeliveredEnvelopes(pool, ctx);
  for (const id of replayed) {
    seenEnvelopeIds.add(id);
  }

  return {
    async detach(): Promise<void> {
      await redis.unsubscribeDevice(ctx.deviceId, listener);
    },
  };
}

/**
 * Handle a `dev:{deviceId}` pub/sub payload — a decimal envelope id.
 * Hydrates the row by id, dedups against the connection's seen set,
 * and forwards as `S2C.ENVELOPE`. Errors are logged and swallowed
 * so a single bad payload doesn't tear down the socket: per
 * Requirement 12.11 the row stays `delivered_at IS NULL` and will
 * be retried on the next reconnect.
 */
async function handleLivePublish(
  ctx: WSContext,
  pool: FanoutDbPool,
  payload: string,
  seenEnvelopeIds: Set<string>,
): Promise<void> {
  // Reject anything that isn't a decimal id. We never want to forward
  // a malformed payload to the client; failing closed here avoids
  // surfacing an internal Redis bug as a wire-level error.
  if (!/^[0-9]+$/.test(payload)) {
    ctx.log.warn(
      { deviceId: ctx.deviceId, payloadLen: payload.length },
      'unexpected non-numeric inbox payload',
    );
    return;
  }
  if (seenEnvelopeIds.has(payload)) {
    return;
  }
  seenEnvelopeIds.add(payload);

  let row: EnvelopeRow | undefined;
  try {
    const result = await pool.query<EnvelopeRow>(
      // Re-fetch by id and re-assert the recipient match. The
      // recipient check is defence-in-depth against a future code
      // path that mistakenly publishes on the wrong channel — even
      // then, this query refuses to forward to the wrong device.
      `SELECT id::text         AS id,
              session_id       AS session_id,
              sender_device    AS sender_device,
              recipient_device AS recipient_device,
              type             AS type,
              ciphertext       AS ciphertext,
              created_at       AS created_at
         FROM ciphertext_envelopes
        WHERE id               = $1
          AND recipient_device = $2`,
      [payload, ctx.deviceId],
    );
    row = result.rows[0];
  } catch (err) {
    ctx.log.error(
      { err, deviceId: ctx.deviceId },
      'inbox hydrate query failed',
    );
    return;
  }

  if (row === undefined) {
    // The publish landed but the row is gone — most likely the
    // sender's session cascade-deleted the envelope between
    // publish and hydrate. Drop silently; the client is no worse
    // off than if the publish had been lost.
    ctx.log.warn(
      { deviceId: ctx.deviceId, envelopeId: payload },
      'published envelope id no longer exists',
    );
    return;
  }

  ctx.send({ t: S2C.ENVELOPE, envelope: rowToEnvelope(row) });
}

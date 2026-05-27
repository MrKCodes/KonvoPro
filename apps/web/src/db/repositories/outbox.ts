// apps/web/src/db/repositories/outbox.ts
//
// Dexie-backed repository for the offline-send queue (task 3.7).
//
// Scope:
//   - One `OutboxRow` per pending `SEND_ENVELOPE` frame. Rows live
//     here from the moment the composer enqueues an envelope until
//     the WS layer receives `ENVELOPE_QUEUED` (server has persisted
//     it) and deletes the row by `clientNonce`.
//   - The §11 sketch keys this table by `&clientNonce`; we use an
//     auto-incremented `id` primary key plus a `&clientNonce`
//     unique index so that "FIFO replay-on-reconnect order" maps
//     directly to "primary-key ASC". This eliminates an `orderBy`
//     index lookup in the hot replay loop.
//   - Capacity invariants per requirement 4.8: at most 1000 rows
//     in the table at any moment, and no row older than 7 days.
//     `enqueue` performs both sweeps in a single `readwrite`
//     transaction so the invariants hold even under concurrent
//     enqueues from two tabs.
//
// What this repository does NOT own:
//   - WebSocket transport (`apps/web/src/ws/client.ts`),
//   - replay scheduling (`apps/web/src/ws/outbox.ts` — the
//     higher-level coordinator that watches WS events),
//   - msgpack encoding (`@konvo/protocol`'s codec).

import type { CiphertextEnvelope } from '@konvo/protocol';

import type { KonvoDb, OutboxRow } from '../schema.js';

/** Maximum number of rows retained in the outbox at any time. Per
 *  requirement 4.8. */
export const OUTBOX_MAX_ENTRIES = 1000;

/** Maximum age (in milliseconds) any outbox row may reach before
 *  the next `enqueue` evicts it. 7 days, per requirement 4.8. */
export const OUTBOX_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Public-facing shape returned by repository reads. Mirrors
 *  `OutboxRow` with `id` declared as required (rows always carry
 *  one once persisted). */
export interface OutboxEntry {
  readonly id: number;
  readonly clientNonce: string;
  readonly envelope: CiphertextEnvelope;
  readonly enqueuedAt: number;
  readonly lastTryAt?: number;
  readonly retryCount: number;
}

export class DexieOutboxStore {
  readonly #db: KonvoDb;

  /** Test seam: the eviction sweeps in `enqueue` use the supplied
   *  `now` (defaults to `Date.now`) so age-based eviction can be
   *  asserted without `vi.useFakeTimers`. */
  readonly #now: () => number;

  constructor(db: KonvoDb, now: () => number = () => Date.now()) {
    this.#db = db;
    this.#now = now;
  }

  /**
   * Append an envelope to the outbox.
   *
   * Capacity sweep semantics (requirement 4.8):
   *   1. Drop every existing row whose `enqueuedAt` is older than
   *      `OUTBOX_MAX_AGE_MS` ago.
   *   2. While the row count is at or above `OUTBOX_MAX_ENTRIES`,
   *      drop the row with the smallest primary-key id (FIFO).
   *   3. Insert the new row.
   *
   * Both sweeps run inside the same `readwrite` transaction as
   * the insert, so the table never observes a state where the
   * count exceeds the cap.
   *
   * Idempotency: if a row with the supplied `clientNonce` already
   * exists, the existing row is returned unchanged and no new
   * row is inserted. This protects against duplicate enqueues
   * from a composer retry.
   */
  async enqueue(args: {
    clientNonce: string;
    envelope: CiphertextEnvelope;
    enqueuedAt?: number;
  }): Promise<OutboxEntry> {
    const enqueuedAt = args.enqueuedAt ?? this.#now();
    return this.#db.transaction(
      'rw',
      this.#db.outbox,
      async (): Promise<OutboxEntry> => {
        // 0. Idempotent re-enqueue: same nonce → same row.
        const existing = await this.#db.outbox
          .where('clientNonce')
          .equals(args.clientNonce)
          .first();
        if (existing !== undefined) {
          return rowToEntry(existing);
        }

        // 1. Age-based sweep.
        await this.#sweepAged();

        // 2. FIFO capacity sweep.
        await this.#sweepCapacity(OUTBOX_MAX_ENTRIES - 1);

        // 3. Insert.
        const row: OutboxRow = {
          clientNonce: args.clientNonce,
          envelope: args.envelope,
          enqueuedAt,
          retryCount: 0,
        };
        const id = (await this.#db.outbox.add(row)) as number;
        return rowToEntry({ ...row, id });
      },
    );
  }

  /**
   * Return all pending rows in FIFO (primary-key ASC) order. Used
   * by the higher-level outbox coordinator to drive replay on
   * reconnect.
   */
  async listInOrder(): Promise<OutboxEntry[]> {
    const rows = await this.#db.outbox.orderBy('id').toArray();
    return rows.map(rowToEntry);
  }

  /** Find a pending row by `clientNonce`, or `null`. */
  async findByClientNonce(clientNonce: string): Promise<OutboxEntry | null> {
    const row = await this.#db.outbox
      .where('clientNonce')
      .equals(clientNonce)
      .first();
    return row !== undefined ? rowToEntry(row) : null;
  }

  /**
   * Remove a row by `clientNonce`. Used by the WS layer on
   * `ENVELOPE_QUEUED`. Idempotent.
   */
  async deleteByClientNonce(clientNonce: string): Promise<void> {
    await this.#db.transaction(
      'rw',
      this.#db.outbox,
      async (): Promise<void> => {
        const existing = await this.#db.outbox
          .where('clientNonce')
          .equals(clientNonce)
          .first();
        if (existing !== undefined && existing.id !== undefined) {
          await this.#db.outbox.delete(existing.id);
        }
      },
    );
  }

  /**
   * Bump `retryCount` and stamp `lastTryAt` on a pending row. Used
   * by the replay coordinator each time it (re-)sends a row over
   * the WS without an `ENVELOPE_QUEUED` confirmation in hand. The
   * row's primary-key id is preserved so its FIFO position is
   * unchanged.
   */
  async recordReplayAttempt(
    clientNonce: string,
    at: number = this.#now(),
  ): Promise<void> {
    await this.#db.transaction(
      'rw',
      this.#db.outbox,
      async (): Promise<void> => {
        const existing = await this.#db.outbox
          .where('clientNonce')
          .equals(clientNonce)
          .first();
        if (existing === undefined || existing.id === undefined) {
          return;
        }
        const next: OutboxRow = {
          ...existing,
          lastTryAt: at,
          retryCount: existing.retryCount + 1,
        };
        await this.#db.outbox.put(next);
      },
    );
  }

  /** Current count of pending rows. Useful for diagnostics. */
  async count(): Promise<number> {
    return this.#db.outbox.count();
  }

  /**
   * Drop every row strictly older than `OUTBOX_MAX_AGE_MS` ago.
   * Public so a future scheduled sweep can call it independently
   * of `enqueue`.
   */
  async sweepAged(): Promise<number> {
    return this.#db.transaction(
      'rw',
      this.#db.outbox,
      async (): Promise<number> => this.#sweepAged(),
    );
  }

  // ---------------------------------------------------------------------
  // Private helpers — must run inside an existing `rw` transaction.
  // ---------------------------------------------------------------------

  async #sweepAged(): Promise<number> {
    const cutoff = this.#now() - OUTBOX_MAX_AGE_MS;
    const stale = await this.#db.outbox
      .where('enqueuedAt')
      .below(cutoff)
      .toArray();
    let removed = 0;
    for (const row of stale) {
      if (row.id !== undefined) {
        await this.#db.outbox.delete(row.id);
        removed += 1;
      }
    }
    return removed;
  }

  async #sweepCapacity(maxAfterSweep: number): Promise<void> {
    let count = await this.#db.outbox.count();
    if (count <= maxAfterSweep) {
      return;
    }
    // Walk primary-key ASC (FIFO order) and delete until the
    // residual count fits. `orderBy('id')` is already the natural
    // primary-key order.
    const overflow = count - maxAfterSweep;
    const oldest = await this.#db.outbox.orderBy('id').limit(overflow).toArray();
    for (const row of oldest) {
      if (row.id !== undefined) {
        await this.#db.outbox.delete(row.id);
        count -= 1;
      }
    }
  }
}

function rowToEntry(row: OutboxRow & { id?: number }): OutboxEntry {
  if (row.id === undefined) {
    throw new Error('outbox: row missing primary key id');
  }
  const entry: OutboxEntry = {
    id: row.id,
    clientNonce: row.clientNonce,
    envelope: row.envelope,
    enqueuedAt: row.enqueuedAt,
    retryCount: row.retryCount,
    ...(row.lastTryAt !== undefined ? { lastTryAt: row.lastTryAt } : {}),
  };
  return entry;
}

// apps/web/src/db/repositories/threads.ts
//
// Dexie-backed repository for the local DM thread mirror (task 3.7).
//
// Scope:
//   - One `ThreadRow` per peer user we have (or have ever had) a DM
//     conversation with. The row carries the lightweight metadata
//     the thread-list UI needs (peer handle, last-message timestamp,
//     unread count) and is updated as messages move through the
//     local store.
//   - Threads are NOT the source of truth for fan-out targets; the
//     API's `/users/:handle` response is. See `schema.ts` header
//     for the rationale on omitting `peerDeviceIds` and
//     `safetyNumberVerified` from this slice.
//
// Concurrency:
//   `recordIncoming` / `recordOutgoing` mutate the row inside a
//   `readwrite` transaction so a fast inbound + outbound stream on
//   the same thread cannot race two read-modify-write cycles.

import type { KonvoDb, ThreadRow } from '../schema.js';

/**
 * Public-facing shape returned by repository reads. Identical to
 * `ThreadRow`; re-declared as a non-readonly view so the UI layer
 * can distinguish "row I just read" from "row I want to upsert".
 */
export interface Thread {
  readonly peerUserId: string;
  readonly peerHandle?: string;
  readonly lastMessageAt: number;
  readonly unreadCount: number;
  readonly createdAt: number;
}

export class DexieThreadsStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /**
   * Look up the thread row for a peer, or `null` if none exists.
   *
   * "No row" means we've never sent or received a DM from this peer
   * (or the user explicitly cleared the thread). The caller decides
   * whether to lazily create one via `upsert` or treat the absence
   * as an empty conversation.
   */
  async get(peerUserId: string): Promise<Thread | null> {
    const row = await this.#db.threads.get(peerUserId);
    return row !== undefined ? rowToThread(row) : null;
  }

  /**
   * List all threads, sorted by `lastMessageAt` descending. Suitable
   * for the thread-list panel.
   */
  async list(): Promise<Thread[]> {
    const rows = await this.#db.threads
      .orderBy('lastMessageAt')
      .reverse()
      .toArray();
    return rows.map(rowToThread);
  }

  /**
   * Upsert a thread row, creating it on first sight and refreshing
   * the supplied fields on subsequent calls. `peerHandle` is
   * preserved on update if the caller passes `undefined`.
   *
   * Returns the post-write row so callers can use the canonical
   * `createdAt` value (always set on first creation, preserved on
   * update).
   */
  async upsert(args: {
    peerUserId: string;
    peerHandle?: string;
    lastMessageAt?: number;
    unreadCount?: number;
    now?: number;
  }): Promise<Thread> {
    const now = args.now ?? Date.now();
    return this.#db.transaction(
      'rw',
      this.#db.threads,
      async (): Promise<Thread> => {
        const existing = await this.#db.threads.get(args.peerUserId);
        const peerHandle =
          args.peerHandle !== undefined
            ? args.peerHandle
            : existing?.peerHandle;
        const row: ThreadRow = {
          peerUserId: args.peerUserId,
          ...(peerHandle !== undefined ? { peerHandle } : {}),
          lastMessageAt: args.lastMessageAt ?? existing?.lastMessageAt ?? now,
          unreadCount: args.unreadCount ?? existing?.unreadCount ?? 0,
          createdAt: existing?.createdAt ?? now,
        };
        await this.#db.threads.put(row);
        return rowToThread(row);
      },
    );
  }

  /**
   * Bump `unreadCount` by 1 and refresh `lastMessageAt`. Used by
   * the inbound message path in the WS client.
   *
   * If no row exists yet, one is created with `unreadCount = 1`.
   */
  async recordIncoming(peerUserId: string, at: number): Promise<Thread> {
    return this.#db.transaction(
      'rw',
      this.#db.threads,
      async (): Promise<Thread> => {
        const existing = await this.#db.threads.get(peerUserId);
        const row: ThreadRow = {
          peerUserId,
          ...(existing?.peerHandle !== undefined
            ? { peerHandle: existing.peerHandle }
            : {}),
          lastMessageAt: Math.max(existing?.lastMessageAt ?? 0, at),
          unreadCount: (existing?.unreadCount ?? 0) + 1,
          createdAt: existing?.createdAt ?? at,
        };
        await this.#db.threads.put(row);
        return rowToThread(row);
      },
    );
  }

  /**
   * Refresh `lastMessageAt` without touching `unreadCount`. Used by
   * the outbound message path: sending a message bumps the thread
   * to the top of the list but doesn't add to your own unread
   * count.
   */
  async recordOutgoing(peerUserId: string, at: number): Promise<Thread> {
    return this.#db.transaction(
      'rw',
      this.#db.threads,
      async (): Promise<Thread> => {
        const existing = await this.#db.threads.get(peerUserId);
        const row: ThreadRow = {
          peerUserId,
          ...(existing?.peerHandle !== undefined
            ? { peerHandle: existing.peerHandle }
            : {}),
          lastMessageAt: Math.max(existing?.lastMessageAt ?? 0, at),
          unreadCount: existing?.unreadCount ?? 0,
          createdAt: existing?.createdAt ?? at,
        };
        await this.#db.threads.put(row);
        return rowToThread(row);
      },
    );
  }

  /**
   * Reset `unreadCount` to zero. Called when the user opens (or
   * focuses) a thread; the read receipt to the peer is sent
   * separately by the higher-level DM machinery.
   */
  async markRead(peerUserId: string): Promise<void> {
    await this.#db.transaction(
      'rw',
      this.#db.threads,
      async (): Promise<void> => {
        const existing = await this.#db.threads.get(peerUserId);
        if (existing === undefined || existing.unreadCount === 0) {
          return;
        }
        await this.#db.threads.put({ ...existing, unreadCount: 0 });
      },
    );
  }

  /**
   * Remove a thread row (e.g. user deleted the conversation).
   * Idempotent.
   */
  async delete(peerUserId: string): Promise<void> {
    await this.#db.threads.delete(peerUserId);
  }
}

function rowToThread(row: ThreadRow): Thread {
  return {
    peerUserId: row.peerUserId,
    ...(row.peerHandle !== undefined ? { peerHandle: row.peerHandle } : {}),
    lastMessageAt: row.lastMessageAt,
    unreadCount: row.unreadCount,
    createdAt: row.createdAt,
  };
}

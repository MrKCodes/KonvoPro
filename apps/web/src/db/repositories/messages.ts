// apps/web/src/db/repositories/messages.ts
//
// Dexie-backed repository for the local DM message store (task 3.7).
//
// Scope:
//   - One `MessageRow` per logical message in the local mirror.
//     Outgoing rows are inserted at compose time with `state:
//     'sending'` and transition through `'delivered'` / `'read'` /
//     `'failed'` per requirement 4.6. Inbound rows are inserted at
//     decrypt time directly with `state: 'delivered'`.
//   - The `body` field is plaintext bytes for the Phase-2 slice;
//     task 4.7 swaps it for a libsignal ciphertext payload without
//     requiring any schema changes here.
//   - Queries are bounded: "latest N messages in a thread" uses
//     the compound `[threadId+createdAt]` index defined in
//     `schema.ts`, "find by clientNonce" uses the `clientNonce`
//     index for the `ENVELOPE_QUEUED` state-transition path.
//
// Defensive copying:
//   `body` is a `Uint8Array`. The repository copies on the way in
//   (write) and on the way out (read) so callers can mutate the
//   buffers they pass without affecting the persisted row, and
//   vice versa. The cost is one per-message memcpy; the safety
//   benefit is that the higher-level "scrub plaintext after
//   send" hygiene the encryption layer enforces won't accidentally
//   reach into IndexedDB.

import Dexie from 'dexie';

import type {
  KonvoDb,
  MessageRow,
  MessageState,
} from '../schema.js';

/**
 * Public-facing shape returned by repository reads. Mirrors
 * `MessageRow` with `id` declared as required (rows always carry
 * one once persisted) and a defensive `Uint8Array` copy of
 * `body`.
 */
export interface Message {
  readonly id: number;
  readonly threadId: string;
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly body: Uint8Array;
  readonly state: MessageState;
  readonly clientNonce: string;
  readonly createdAt: number;
}

/** Args for `insertOutgoing`. Mirrors the message-row fields the
 *  composer / send path produces; `state` is forced to `'sending'`
 *  for outbound inserts. */
export interface InsertOutgoingArgs {
  readonly threadId: string;
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly body: Uint8Array;
  readonly clientNonce: string;
  readonly createdAt?: number;
}

/** Args for `insertIncoming`. Inbound messages land with `state:
 *  'delivered'` because the act of decrypting them in this client
 *  is the delivery event. */
export interface InsertIncomingArgs {
  readonly threadId: string;
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly body: Uint8Array;
  readonly clientNonce: string;
  readonly createdAt: number;
}

export class DexieMessagesStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /**
   * Insert an outgoing message in `'sending'` state and return its
   * persisted shape (with the auto-assigned `id`).
   */
  async insertOutgoing(args: InsertOutgoingArgs): Promise<Message> {
    const row: MessageRow = {
      threadId: args.threadId,
      senderDeviceId: args.senderDeviceId,
      recipientDeviceId: args.recipientDeviceId,
      body: new Uint8Array(args.body),
      state: 'sending',
      clientNonce: args.clientNonce,
      createdAt: args.createdAt ?? Date.now(),
    };
    const id = (await this.#db.messages.add(row)) as number;
    return rowToMessage({ ...row, id });
  }

  /**
   * Insert an inbound message in `'delivered'` state and return its
   * persisted shape.
   */
  async insertIncoming(args: InsertIncomingArgs): Promise<Message> {
    const row: MessageRow = {
      threadId: args.threadId,
      senderDeviceId: args.senderDeviceId,
      recipientDeviceId: args.recipientDeviceId,
      body: new Uint8Array(args.body),
      state: 'delivered',
      clientNonce: args.clientNonce,
      createdAt: args.createdAt,
    };
    const id = (await this.#db.messages.add(row)) as number;
    return rowToMessage({ ...row, id });
  }

  /**
   * Find an outgoing message row by its `clientNonce`. Used by the
   * `ENVELOPE_QUEUED` handler to flip a `'sending'` row to
   * `'delivered'`.
   *
   * Returns `null` if no row matches. Returns the first match if
   * multiple rows share the nonce (shouldn't happen at this slice;
   * the outbox enforces uniqueness, and the composer generates a
   * fresh nonce per message).
   */
  async findByClientNonce(clientNonce: string): Promise<Message | null> {
    const row = await this.#db.messages
      .where('clientNonce')
      .equals(clientNonce)
      .first();
    return row !== undefined ? rowToMessage(row) : null;
  }

  /**
   * Update the `state` field of a row by `id`. Returns the updated
   * row or `null` if no row matches.
   */
  async updateState(id: number, state: MessageState): Promise<Message | null> {
    return this.#db.transaction(
      'rw',
      this.#db.messages,
      async (): Promise<Message | null> => {
        const existing = await this.#db.messages.get(id);
        if (existing === undefined) {
          return null;
        }
        const next: MessageRow = { ...existing, state };
        await this.#db.messages.put(next);
        return rowToMessage(next);
      },
    );
  }

  /**
   * Convenience for the `ENVELOPE_QUEUED` path: find by nonce,
   * flip to the supplied state. No-op if no row matches.
   */
  async setStateByClientNonce(
    clientNonce: string,
    state: MessageState,
  ): Promise<Message | null> {
    return this.#db.transaction(
      'rw',
      this.#db.messages,
      async (): Promise<Message | null> => {
        const existing = await this.#db.messages
          .where('clientNonce')
          .equals(clientNonce)
          .first();
        if (existing === undefined) {
          return null;
        }
        const next: MessageRow = { ...existing, state };
        await this.#db.messages.put(next);
        return rowToMessage(next);
      },
    );
  }

  /**
   * Return the most recent `limit` messages in a thread, sorted
   * by `createdAt` ascending (so the UI can append to a
   * scrollable view).
   *
   * Uses the compound `[threadId+createdAt]` index for a bounded
   * range scan rather than a full-table walk.
   */
  async listForThread(threadId: string, limit = 100): Promise<Message[]> {
    const rows = await this.#db.messages
      .where('[threadId+createdAt]')
      .between([threadId, Dexie.minKey], [threadId, Dexie.maxKey])
      .limit(limit)
      .toArray();
    return rows.map(rowToMessage);
  }

  /**
   * Return all rows in a thread (no limit). Useful for tests; the
   * UI should use `listForThread` with an explicit limit.
   */
  async listAllForThread(threadId: string): Promise<Message[]> {
    const rows = await this.#db.messages
      .where('threadId')
      .equals(threadId)
      .toArray();
    rows.sort((a, b) => a.createdAt - b.createdAt);
    return rows.map(rowToMessage);
  }

  /** Remove a message row by `id`. Idempotent. */
  async delete(id: number): Promise<void> {
    await this.#db.messages.delete(id);
  }
}

function rowToMessage(row: MessageRow & { id?: number }): Message {
  if (row.id === undefined) {
    throw new Error('messages: row missing primary key id');
  }
  return {
    id: row.id,
    threadId: row.threadId,
    senderDeviceId: row.senderDeviceId,
    recipientDeviceId: row.recipientDeviceId,
    body: new Uint8Array(row.body),
    state: row.state,
    clientNonce: row.clientNonce,
    createdAt: row.createdAt,
  };
}

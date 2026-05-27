// apps/web/src/db/repositories/rooms.ts
//
// Dexie-backed repository for the local broadcast-room mirror
// (task 7.4).
//
// Scope:
//   - One `RoomRow` per broadcast room the Web_Client has interacted
//     with — fetched via `GET /rooms/:slug`, created via `POST /rooms`,
//     or subscribed via `POST /rooms/:slug/subscribe`. The row carries
//     just enough metadata for the room-list UI to render without a
//     network round-trip (slug, name, ownerHandle, createdAt) plus a
//     local `subscribed` flag so the UI can highlight subscribed rooms.
//   - The server is the source of truth for both the room-id mapping
//     (signature verification depends on the UUID) and the membership
//     role; we do NOT cache role on the row to avoid serving a stale
//     "you are admin" UI after a server-side role change.
//
// Concurrency:
//   `upsert` and `markSubscribed` mutate inside a `'rw'` transaction so
//   two concurrent calls (e.g. the room-list page and a deep-link
//   prefetch) cannot lose-update the row.

import type { KonvoDb, RoomRow } from '../schema.js';

/**
 * Public-facing shape returned by repository reads. Identical to
 * `RoomRow`; re-declared so the UI layer can distinguish "row I just
 * read" from "row I want to upsert".
 */
export interface Room {
  readonly slug: string;
  readonly roomId: string;
  readonly name: string;
  readonly ownerHandle: string;
  readonly subscribed: boolean;
  readonly createdAt: number;
}

export class DexieRoomsStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /** Fetch a single room by slug, or `null` when absent. */
  async get(slug: string): Promise<Room | null> {
    const row = await this.#db.rooms.get(slug);
    return row !== undefined ? rowToRoom(row) : null;
  }

  /** List all locally-mirrored rooms, sorted by `createdAt` DESC. */
  async list(): Promise<Room[]> {
    const rows = await this.#db.rooms.orderBy('createdAt').reverse().toArray();
    return rows.map(rowToRoom);
  }

  /**
   * Upsert a room row. Preserves any existing `subscribed` flag when
   * the caller does not pass one — the API_Gateway's room responses
   * don't surface subscription state, so a refresh of the room
   * metadata mustn't accidentally clear the local subscribed bit.
   */
  async upsert(args: {
    slug: string;
    roomId: string;
    name: string;
    ownerHandle: string;
    subscribed?: boolean;
    createdAt?: number;
  }): Promise<Room> {
    return this.#db.transaction(
      'rw',
      this.#db.rooms,
      async (): Promise<Room> => {
        const existing = await this.#db.rooms.get(args.slug);
        const row: RoomRow = {
          slug: args.slug,
          roomId: args.roomId,
          name: args.name,
          ownerHandle: args.ownerHandle,
          subscribed:
            args.subscribed ?? existing?.subscribed ?? false,
          createdAt: args.createdAt ?? existing?.createdAt ?? Date.now(),
        };
        await this.#db.rooms.put(row);
        return rowToRoom(row);
      },
    );
  }

  /** Flip the `subscribed` flag on an existing row. Idempotent. */
  async markSubscribed(slug: string, subscribed: boolean): Promise<void> {
    await this.#db.transaction(
      'rw',
      this.#db.rooms,
      async (): Promise<void> => {
        const existing = await this.#db.rooms.get(slug);
        if (existing === undefined) {
          return;
        }
        if (existing.subscribed === subscribed) {
          return;
        }
        await this.#db.rooms.put({ ...existing, subscribed });
      },
    );
  }

  /** Remove a room row (e.g. user explicitly cleared local cache). */
  async delete(slug: string): Promise<void> {
    await this.#db.rooms.delete(slug);
  }
}

function rowToRoom(row: RoomRow): Room {
  return {
    slug: row.slug,
    roomId: row.roomId,
    name: row.name,
    ownerHandle: row.ownerHandle,
    subscribed: row.subscribed,
    createdAt: row.createdAt,
  };
}

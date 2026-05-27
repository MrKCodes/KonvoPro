// apps/web/src/db/repositories/roomPosts.ts
//
// Dexie-backed repository for the local broadcast-post cache
// (task 7.4).
//
// Scope:
//   - One `RoomPostRow` per `(roomSlug, postId)` pair the Web_Client
//     has seen, either via paginated `GET /rooms/:slug/messages` or via
//     the `S2C.ROOM_POST` live fan-out. Idempotent on `(roomSlug,
//     postId)` so a post arriving simultaneously over both channels
//     doesn't double-render.
//   - The `verified` boolean is the result of running
//     `verifyBroadcastPost` against the post's body, roomId,
//     createdAt, signature, and authorIdentityPub. Persisting the
//     result lets the UI surface the badge without re-running
//     verification on every render — verification is deterministic
//     on its inputs (Requirement 10.8 / 10.9) so caching the result
//     is safe.
//
// Concurrency:
//   `upsert` opens a single `readwrite` transaction so a fast burst of
//   incoming posts on the same room doesn't lose-update each other.

import type { KonvoDb, RoomPostRow, VerifiedFlag } from '../schema.js';

/** Public-facing shape returned by repository reads. */
export interface RoomPost {
  readonly id: string; // `${roomSlug}:${postId}`
  readonly roomSlug: string;
  readonly postId: string; // decimal-string form of BIGSERIAL
  readonly body: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;
  readonly signature: Uint8Array;
  readonly createdAt: number;
  readonly verified: boolean;
}

/** Synthetic primary-key composite. Centralised here so callers can
 *  never drift on the join character. */
export function roomPostKey(roomSlug: string, postId: string): string {
  return `${roomSlug}:${postId}`;
}

export class DexieRoomPostsStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /** Fetch a single post by `(roomSlug, postId)`, or `null` when
   *  absent. */
  async get(roomSlug: string, postId: string): Promise<RoomPost | null> {
    const row = await this.#db.roomPosts.get(roomPostKey(roomSlug, postId));
    return row !== undefined ? rowToPost(row) : null;
  }

  /**
   * List the most-recent posts in a room, ordered by `createdAt`
   * DESC. `limit` defaults to 50, matching the server's
   * `GET /rooms/:slug/messages` cap.
   */
  async listByRoom(roomSlug: string, limit = 50): Promise<RoomPost[]> {
    const rows = await this.#db.roomPosts
      .where('[roomSlug+createdAt]')
      .between(
        [roomSlug, -Infinity],
        [roomSlug, Infinity],
        true,
        true,
      )
      .reverse()
      .limit(limit)
      .toArray();
    return rows.map(rowToPost);
  }

  /**
   * Upsert a single post. `(roomSlug, postId)` is the natural primary
   * key; re-upserting an existing row (e.g. a REST history page that
   * overlaps a live fan-out) preserves the `verified` flag from the
   * latest write.
   */
  async upsert(args: {
    roomSlug: string;
    postId: string;
    body: string;
    authorHandle: string;
    authorIdentityPub: Uint8Array;
    signature: Uint8Array;
    createdAt: number;
    verified: boolean;
  }): Promise<RoomPost> {
    const id = roomPostKey(args.roomSlug, args.postId);
    const row: RoomPostRow = {
      id,
      roomSlug: args.roomSlug,
      postId: args.postId,
      body: args.body,
      authorHandle: args.authorHandle,
      // Defensive copies — keeps caller-side mutation out of our
      // persisted state.
      authorIdentityPub: new Uint8Array(args.authorIdentityPub),
      signature: new Uint8Array(args.signature),
      createdAt: args.createdAt,
      verified: (args.verified ? 1 : 0) as VerifiedFlag,
    };
    await this.#db.roomPosts.put(row);
    return rowToPost(row);
  }

  /** Bulk-upsert the result of a paginated history page. Wraps the
   *  inserts in a single transaction so an interrupted page doesn't
   *  leave a torn cache. */
  async upsertMany(
    posts: ReadonlyArray<{
      roomSlug: string;
      postId: string;
      body: string;
      authorHandle: string;
      authorIdentityPub: Uint8Array;
      signature: Uint8Array;
      createdAt: number;
      verified: boolean;
    }>,
  ): Promise<void> {
    if (posts.length === 0) return;
    await this.#db.transaction(
      'rw',
      this.#db.roomPosts,
      async (): Promise<void> => {
        for (const p of posts) {
          const row: RoomPostRow = {
            id: roomPostKey(p.roomSlug, p.postId),
            roomSlug: p.roomSlug,
            postId: p.postId,
            body: p.body,
            authorHandle: p.authorHandle,
            authorIdentityPub: new Uint8Array(p.authorIdentityPub),
            signature: new Uint8Array(p.signature),
            createdAt: p.createdAt,
            verified: (p.verified ? 1 : 0) as VerifiedFlag,
          };
          await this.#db.roomPosts.put(row);
        }
      },
    );
  }

  /** Drop every post for a room. Used when the user clears local
   *  cache for a room. */
  async deleteRoom(roomSlug: string): Promise<void> {
    await this.#db.roomPosts.where('roomSlug').equals(roomSlug).delete();
  }
}

function rowToPost(row: RoomPostRow): RoomPost {
  return {
    id: row.id,
    roomSlug: row.roomSlug,
    postId: row.postId,
    body: row.body,
    authorHandle: row.authorHandle,
    authorIdentityPub: new Uint8Array(row.authorIdentityPub),
    signature: new Uint8Array(row.signature),
    createdAt: row.createdAt,
    verified: row.verified === 1,
  };
}

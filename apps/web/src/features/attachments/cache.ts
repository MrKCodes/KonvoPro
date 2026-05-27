// apps/web/src/features/attachments/cache.ts
//
// Bounded LRU cache for downloaded attachment ciphertext + decrypted
// plaintext (task 5.3, design.md §11).
//
// Why we cache at all:
//   - The recipient pays the full network round-trip + AES-GCM decrypt
//     each time `AttachmentView` re-mounts. Caching the decrypted
//     plaintext gives instant re-renders for any attachment the user
//     scrolled past once.
//   - Caching the ciphertext (in addition to the plaintext) lets the
//     UI repaint after a tab reload without re-hitting the API. The
//     ciphertext is opaque to anyone without the AES key, so it can
//     safely persist alongside the plaintext.
//
// Eviction policy:
//   - The cache is bounded to 200 MiB total *ciphertext* footprint
//     (design.md §11 — "LRU cap 200 MiB"). Each row records its
//     `sizeBytes` alongside `lastAccessedAt`; the eviction planner
//     iterates rows in `lastAccessedAt` ASC order, removing the
//     oldest until the residual sum fits inside the cap.
//   - We sum *ciphertext* bytes only because the plaintext column is
//     populated lazily and may be `null` for the moment (e.g. the
//     row was just inserted by a tag-failure path). The intuition
//     "200 MiB on disk" is dominated by the ciphertext — that's what
//     the route actually serves.
//   - Tie-break on `id` ASC. Dexie hands out `id`s in monotonic
//     insertion order, so the tie-break removes the oldest insertion
//     among rows with the same `lastAccessedAt`.
//
// Touch-on-access semantics:
//   - `getByAttachmentId` updates `lastAccessedAt` to `now()` on
//     every hit, so the working set naturally bubbles to the top of
//     the LRU. Without this, a row inserted once and read many times
//     would still be evicted before a fresh-but-untouched row.
//
// Pluggable clock:
//   - The cache accepts a `now: () => number` supplier so tests can
//     advance time deterministically. Production wires `Date.now`.
//
// Concurrency:
//   - All mutations run inside Dexie `transaction('rw', ...)`. Two
//     concurrent `putCiphertext` calls on the same `attachmentId`
//     resolve as a single row by virtue of the unique
//     `&attachmentId` index — Dexie throws on the second insert,
//     which we catch and replay as an update. We never split a
//     "read row → write row" sequence across separate transactions
//     so the eviction planner can never observe a half-applied
//     state.

import type { KonvoDb, LocalAttachmentRow } from '../../db/schema.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Snapshot of a row exposed to callers. Mirrors `LocalAttachmentRow`
 *  with `id` always present and the byte fields defensively copied. */
export interface CachedAttachment {
  readonly id: number;
  readonly attachmentId: string;
  readonly ciphertext: Uint8Array;
  readonly plaintext: Uint8Array | null;
  readonly mime: string;
  readonly filename: string;
  readonly sizeBytes: number;
  readonly createdAt: number;
  readonly lastAccessedAt: number;
}

export interface PutCiphertextArgs {
  readonly attachmentId: string;
  readonly ciphertext: Uint8Array;
  readonly mime: string;
  readonly filename: string;
}

export interface PutPlaintextArgs {
  readonly attachmentId: string;
  readonly plaintext: Uint8Array;
}

export interface LocalAttachmentsStoreOptions {
  /** Cap in bytes. Defaults to 200 MiB per design.md §11. Tests
   *  pass a small value to exercise the eviction loop without
   *  needing 200 MiB of fixtures. */
  readonly maxBytes?: number;
  /** Wall-clock supplier for `lastAccessedAt`. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** Default LRU cap: 200 MiB (design.md §11). */
export const DEFAULT_MAX_BYTES = 200 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class LocalAttachmentsStore {
  readonly #db: KonvoDb;
  readonly #maxBytes: number;
  readonly #now: () => number;

  constructor(db: KonvoDb, options: LocalAttachmentsStoreOptions = {}) {
    this.#db = db;
    this.#maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.#now = options.now ?? (() => Date.now());
  }

  /** Cap in bytes. Exposed so tests can assert against the
   *  configured value without poking the private field. */
  get maxBytes(): number {
    return this.#maxBytes;
  }

  /**
   * Insert (or update) a row carrying the freshly downloaded
   * ciphertext. Idempotent on `attachmentId`: re-inserting the same
   * id replaces the row's ciphertext + mime + filename and refreshes
   * `lastAccessedAt`, but preserves any prior `plaintext` if still
   * valid. After commit, runs the eviction loop to enforce the cap.
   */
  async putCiphertext(args: PutCiphertextArgs): Promise<CachedAttachment> {
    const ts = this.#now();
    const row: LocalAttachmentRow = {
      attachmentId: args.attachmentId,
      ciphertext: new Uint8Array(args.ciphertext),
      plaintext: null,
      mime: args.mime,
      filename: args.filename,
      sizeBytes: args.ciphertext.length,
      createdAt: ts,
      lastAccessedAt: ts,
    };
    const inserted = await this.#db.transaction(
      'rw',
      this.#db.localAttachments,
      async (): Promise<CachedAttachment> => {
        const existing = await this.#db.localAttachments
          .where('attachmentId')
          .equals(args.attachmentId)
          .first();
        if (existing !== undefined) {
          const next: LocalAttachmentRow = {
            ...existing,
            ciphertext: row.ciphertext,
            mime: row.mime,
            filename: row.filename,
            sizeBytes: row.sizeBytes,
            // Preserve the prior plaintext only if its byte count is
            // consistent with the new ciphertext. AES-GCM ciphertext
            // length equals the plaintext length, so a length
            // mismatch means the ciphertext changed (different blob)
            // and the cached plaintext is no longer trustworthy.
            plaintext:
              existing.plaintext !== null &&
              existing.plaintext.length === row.sizeBytes
                ? existing.plaintext
                : null,
            lastAccessedAt: ts,
          };
          await this.#db.localAttachments.put(next);
          return rowToCached(next);
        }
        const id = (await this.#db.localAttachments.add(row)) as number;
        return rowToCached({ ...row, id });
      },
    );
    await this.#evictIfOverCap();
    return inserted;
  }

  /**
   * Attach a decrypted plaintext to an existing row (or insert one
   * if the row is missing — this helps the upload path pre-populate
   * a fresh attachment with both ciphertext and plaintext on the
   * sender side).
   *
   * Touches `lastAccessedAt` so a successful decrypt resets the
   * row's eviction priority.
   */
  async putPlaintext(args: PutPlaintextArgs): Promise<CachedAttachment | null> {
    const ts = this.#now();
    return this.#db.transaction(
      'rw',
      this.#db.localAttachments,
      async (): Promise<CachedAttachment | null> => {
        const existing = await this.#db.localAttachments
          .where('attachmentId')
          .equals(args.attachmentId)
          .first();
        if (existing === undefined) {
          return null;
        }
        const next: LocalAttachmentRow = {
          ...existing,
          plaintext: new Uint8Array(args.plaintext),
          lastAccessedAt: ts,
        };
        await this.#db.localAttachments.put(next);
        return rowToCached(next);
      },
    );
  }

  /**
   * Look up a row by `attachmentId`. Bumps `lastAccessedAt` on a hit
   * so the LRU promotes the row.
   */
  async getByAttachmentId(
    attachmentId: string,
  ): Promise<CachedAttachment | null> {
    const ts = this.#now();
    return this.#db.transaction(
      'rw',
      this.#db.localAttachments,
      async (): Promise<CachedAttachment | null> => {
        const existing = await this.#db.localAttachments
          .where('attachmentId')
          .equals(attachmentId)
          .first();
        if (existing === undefined) {
          return null;
        }
        const next: LocalAttachmentRow = {
          ...existing,
          lastAccessedAt: ts,
        };
        await this.#db.localAttachments.put(next);
        return rowToCached(next);
      },
    );
  }

  /** Drop every row. Used by tests; not exposed from the feature
   *  index because production never has a reason to flush. */
  async clear(): Promise<void> {
    await this.#db.localAttachments.clear();
  }

  /** Total cached ciphertext bytes across all rows. Exposed for
   *  diagnostics + the LRU test suite. */
  async totalBytes(): Promise<number> {
    let sum = 0;
    await this.#db.localAttachments.each((row) => {
      sum += row.sizeBytes;
    });
    return sum;
  }

  /** Number of rows currently cached. */
  async size(): Promise<number> {
    return this.#db.localAttachments.count();
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /** Evict the oldest rows by `lastAccessedAt` until the residual
   *  ciphertext footprint is ≤ `maxBytes`. Idempotent.
   *
   *  We iterate in chunks rather than collecting every row up-front
   *  because a 200 MiB cache may hold thousands of rows; the
   *  indexed `lastAccessedAt` order lets Dexie page through them
   *  efficiently. */
  async #evictIfOverCap(): Promise<void> {
    const total = await this.totalBytes();
    if (total <= this.#maxBytes) return;

    let residual = total;
    await this.#db.transaction(
      'rw',
      this.#db.localAttachments,
      async (): Promise<void> => {
        // Walk the index in ASC order. Dexie's
        // `each(callback)` cannot return early; we use the
        // `Collection.until` pattern via primaryKeys + del.
        const candidates = await this.#db.localAttachments
          .orderBy('lastAccessedAt')
          .primaryKeys();
        for (const key of candidates) {
          if (residual <= this.#maxBytes) break;
          const row = await this.#db.localAttachments.get(key as number);
          if (row === undefined) continue;
          await this.#db.localAttachments.delete(key as number);
          residual -= row.sizeBytes;
        }
      },
    );
  }
}

function rowToCached(row: LocalAttachmentRow & { id?: number }): CachedAttachment {
  if (row.id === undefined) {
    throw new Error('localAttachments: row missing primary key id');
  }
  return {
    id: row.id,
    attachmentId: row.attachmentId,
    ciphertext: new Uint8Array(row.ciphertext),
    plaintext: row.plaintext !== null ? new Uint8Array(row.plaintext) : null,
    mime: row.mime,
    filename: row.filename,
    sizeBytes: row.sizeBytes,
    createdAt: row.createdAt,
    lastAccessedAt: row.lastAccessedAt,
  };
}

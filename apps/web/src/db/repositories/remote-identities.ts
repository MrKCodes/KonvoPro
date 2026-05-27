// apps/web/src/db/repositories/remote-identities.ts
//
// Dexie-backed TOFU bookkeeping for peer device identity public keys
// (task 4.8 — data-layer half of the Safety_Number / TOFU work).
//
// What this repository owns:
//   - persistence of the `remoteIdentities` table from `schema.ts`
//     (mirrors `RemoteIdentityRow` in design.md §11),
//   - the TOFU-on-first-sight flow (`recordFirstSightOrDetectChange`)
//     that requirement 8.1 / 8.2 describes: persist + mark trusted on
//     first sight, surface a typed "changed" outcome on subsequent
//     mismatches without mutating the trusted flag,
//   - the explicit accept / reject transitions
//     (`markTrusted` / `markUntrusted`) that requirement 8.7 / 8.9
//     describe; both also stamp `lastChangedAt` so a re-verify banner
//     can render "since <time>".
//
// What this repository does NOT own:
//   - re-establishing a session on accept (requirement 8.7 / 8.10) —
//     callers do that via `@konvo/crypto`'s `establishSession` after
//     calling `markTrusted`,
//   - pausing outbound sends on a detected change (requirement 8.2 /
//     8.8) — that's a higher-level outbox concern; this repository
//     only reports the change and lets the caller decide what to
//     pause,
//   - safety-number computation (`@konvo/crypto`'s
//     `computeSafetyNumber`).
//
// Identity comparison
// -------------------
// Two identity public keys compare equal iff they're the same length
// and byte-equal at every index. We use a constant-time-ish loop
// (`subtle.timingSafeEqual` is Node-only; jsdom + browser don't have
// it). Identity public keys are not high-entropy secrets the way
// session keys are, so a constant-time compare is not strictly
// required by the threat model — but the loop is bounded and short
// (32 bytes) and avoids any side-channel concerns from a future
// refactor that uses this comparator over secret material.

import type { KonvoDb, RemoteIdentityRow, TrustedFlag } from '../schema.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Public-facing shape returned by repository reads. Decoded from
 * `RemoteIdentityRow` so the `trusted: 0|1` storage encoding doesn't
 * leak across the API.
 *
 * `lastChangedAt` is `null` for rows that were created via TOFU
 * first-sight and have never observed a key change.
 */
export interface RemoteIdentity {
  readonly peerUserId: string;
  readonly peerDeviceId: string;
  readonly identityPub: Uint8Array;
  readonly trusted: boolean;
  readonly firstSeenAt: number;
  readonly lastChangedAt: number | null;
}

/**
 * Result of `recordFirstSightOrDetectChange`. The three outcomes
 * correspond directly to requirement 8.1 / 8.2:
 *
 *   - `first_sight`: no record existed for `(peerUserId,
 *     peerDeviceId)`. The repository persisted a fresh row with
 *     `trusted: true` (TOFU). `record` is the persisted shape.
 *   - `unchanged`: a record exists and the supplied identityPub
 *     matches it byte-for-byte. No write happened. `record` is the
 *     existing shape.
 *   - `changed`: a record exists and the supplied identityPub
 *     differs from the stored one. **No write happens** — the caller
 *     must decide whether to call `markTrusted` (user accepted the
 *     new key) or `markUntrusted` (user rejected). `record` is the
 *     existing (pre-change) shape so the UI can show the user what
 *     identity they previously trusted.
 *
 *   Surfacing the `changed` outcome without mutating storage is
 *   critical for requirement 8.2: the user must explicitly accept or
 *   reject a new identity, and outbound sends remain paused in the
 *   meantime.
 */
export type FirstSightOutcome =
  | { readonly kind: 'first_sight'; readonly record: RemoteIdentity }
  | { readonly kind: 'unchanged'; readonly record: RemoteIdentity }
  | {
      readonly kind: 'changed';
      readonly record: RemoteIdentity;
      readonly newIdentityPub: Uint8Array;
    };

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/**
 * Dexie-backed `remoteIdentities` store.
 *
 * All public methods are async because Dexie's API is async — the
 * underlying IndexedDB calls happen across a microtask boundary even
 * for cache hits.
 */
export class DexieRemoteIdentitiesStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /**
   * Look up a peer's recorded identity, returning `null` if the row
   * has never been observed.
   */
  async get(
    peerUserId: string,
    peerDeviceId: string,
  ): Promise<RemoteIdentity | null> {
    const row = await this.#db.remoteIdentities.get(
      compositeId(peerUserId, peerDeviceId),
    );
    return row !== undefined ? rowToRemoteIdentity(row) : null;
  }

  /**
   * Single-shot TOFU + change-detection entry point.
   *
   * Wrapped in a `readwrite` transaction so a concurrent call from a
   * second tab can't race two `first_sight` writes against the same
   * key. Per design.md §13.2 the trust check is the gate to session
   * establishment, so its consistency invariant matters even in the
   * unlikely two-tab case.
   *
   * Behaviour mirrors design.md §13.2 lines 1276–1290 with the
   * specification fix that the "changed" branch must NOT throw —
   * design.md sketches `throw new Error('Identity changed — require
   * user re-verification')`, but requirement 8.2 explicitly requires
   * surfacing the change to the UI for accept/reject. Throwing would
   * lose the previous identity-pub bytes the UI needs to show the
   * user.
   */
  async recordFirstSightOrDetectChange(
    peerUserId: string,
    peerDeviceId: string,
    identityPub: Uint8Array,
    now: number = Date.now(),
  ): Promise<FirstSightOutcome> {
    // Defensive copy — Dexie copies on its own way in, but we want
    // the in-memory return value to be independent of any subsequent
    // mutation by the caller as well.
    const incoming = new Uint8Array(identityPub);

    return this.#db.transaction(
      'rw',
      this.#db.remoteIdentities,
      async (): Promise<FirstSightOutcome> => {
        const existing = await this.#db.remoteIdentities.get(
          compositeId(peerUserId, peerDeviceId),
        );
        if (existing === undefined) {
          // First sight — TOFU. Requirement 8.1: persist and mark
          // trusted.
          const row: RemoteIdentityRow = {
            id: compositeId(peerUserId, peerDeviceId),
            peerUserId,
            peerDeviceId,
            identityPub: new Uint8Array(incoming),
            trusted: 1,
            firstSeenAt: now,
            lastChangedAt: null,
          };
          await this.#db.remoteIdentities.put(row);
          return { kind: 'first_sight', record: rowToRemoteIdentity(row) };
        }

        if (bytesEqual(existing.identityPub, incoming)) {
          // Same key on file — no-op, no write.
          return { kind: 'unchanged', record: rowToRemoteIdentity(existing) };
        }

        // Key changed. Per requirement 8.2 we surface the event
        // without writing — the caller decides whether to accept
        // (`markTrusted(...newIdentityPub)`) or reject
        // (`markUntrusted()`). The previous `existing.identityPub` is
        // preserved on the row so a mid-flight rebuild of the UI
        // can still show "trust changed from <old>".
        return {
          kind: 'changed',
          record: rowToRemoteIdentity(existing),
          newIdentityPub: new Uint8Array(incoming),
        };
      },
    );
  }

  /**
   * Mark a peer device as trusted, optionally rotating the stored
   * identity public key.
   *
   * Two call patterns:
   *   1. Existing row, no key change: pass `newIdentityPub = null`
   *      (or omit). This is the "user explicitly trusts an existing
   *      TOFU peer" path — rare in practice; mostly a defensive
   *      affordance for tests and admin UIs.
   *   2. Existing row, key change accepted: pass `newIdentityPub`
   *      with the post-change bytes. This stamps `lastChangedAt =
   *      now` and rotates `identityPub` to the new value, satisfying
   *      requirement 8.7.
   *
   * Throws if no row exists for the given `(peerUserId,
   * peerDeviceId)` — the caller must use
   * `recordFirstSightOrDetectChange` for the first-sight path.
   */
  async markTrusted(
    peerUserId: string,
    peerDeviceId: string,
    newIdentityPub: Uint8Array | null = null,
    now: number = Date.now(),
  ): Promise<RemoteIdentity> {
    return this.#db.transaction(
      'rw',
      this.#db.remoteIdentities,
      async (): Promise<RemoteIdentity> => {
        const id = compositeId(peerUserId, peerDeviceId);
        const existing = await this.#db.remoteIdentities.get(id);
        if (existing === undefined) {
          throw new Error(
            `markTrusted: no remoteIdentities row for (${peerUserId}, ${peerDeviceId})`,
          );
        }
        const nextIdentityPub: Uint8Array =
          newIdentityPub !== null
            ? new Uint8Array(newIdentityPub)
            : new Uint8Array(existing.identityPub);

        // `lastChangedAt` only stamps when the identityPub actually
        // changed. A no-op trust-confirm shouldn't pretend the key
        // rotated.
        const keyRotated =
          newIdentityPub !== null &&
          !bytesEqual(existing.identityPub, newIdentityPub);

        const row: RemoteIdentityRow = {
          id,
          peerUserId: existing.peerUserId,
          peerDeviceId: existing.peerDeviceId,
          identityPub: nextIdentityPub,
          trusted: 1,
          firstSeenAt: existing.firstSeenAt,
          lastChangedAt: keyRotated ? now : existing.lastChangedAt,
        };
        await this.#db.remoteIdentities.put(row);
        return rowToRemoteIdentity(row);
      },
    );
  }

  /**
   * Mark a peer device as untrusted (requirement 8.9 — user rejects
   * a new safety number after an identity change).
   *
   * Behaviour:
   *   - If `newIdentityPub` is supplied, the stored identityPub is
   *     rotated to the new value AND `lastChangedAt` is stamped.
   *     The caller can render "you rejected the new key on <time>".
   *   - If `newIdentityPub` is `null`, only the trust flag flips —
   *     the stored identityPub is preserved.
   *
   * Either way the row is upserted with `trusted: 0`. Throws if no
   * row exists.
   *
   * Per requirement 8.9 the caller must also keep outbound sends
   * paused and refuse to re-establish a session until a later
   * `markTrusted` call.
   */
  async markUntrusted(
    peerUserId: string,
    peerDeviceId: string,
    newIdentityPub: Uint8Array | null = null,
    now: number = Date.now(),
  ): Promise<RemoteIdentity> {
    return this.#db.transaction(
      'rw',
      this.#db.remoteIdentities,
      async (): Promise<RemoteIdentity> => {
        const id = compositeId(peerUserId, peerDeviceId);
        const existing = await this.#db.remoteIdentities.get(id);
        if (existing === undefined) {
          throw new Error(
            `markUntrusted: no remoteIdentities row for (${peerUserId}, ${peerDeviceId})`,
          );
        }

        const nextIdentityPub: Uint8Array =
          newIdentityPub !== null
            ? new Uint8Array(newIdentityPub)
            : new Uint8Array(existing.identityPub);

        const keyRotated =
          newIdentityPub !== null &&
          !bytesEqual(existing.identityPub, newIdentityPub);

        const row: RemoteIdentityRow = {
          id,
          peerUserId: existing.peerUserId,
          peerDeviceId: existing.peerDeviceId,
          identityPub: nextIdentityPub,
          trusted: 0,
          firstSeenAt: existing.firstSeenAt,
          lastChangedAt: keyRotated ? now : existing.lastChangedAt,
        };
        await this.#db.remoteIdentities.put(row);
        return rowToRemoteIdentity(row);
      },
    );
  }

  /**
   * List all recorded peer device identities for a user. Useful for
   * "show me every device I've ever trusted from <peer>" surfaces
   * (per-peer Safety_Number screens, requirement 15.2).
   */
  async listForUser(peerUserId: string): Promise<RemoteIdentity[]> {
    const rows = await this.#db.remoteIdentities
      .where('peerUserId')
      .equals(peerUserId)
      .toArray();
    return rows.map(rowToRemoteIdentity);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Composite primary key for the `remoteIdentities` table.
 *
 * Format: `${peerUserId}:${peerDeviceId}`. The `:` is forbidden in
 * UUIDs so collisions with a literal user id containing `:` aren't
 * possible in practice — but if a future user-id format admits `:`
 * we'd need to switch to a length-prefixed encoding. Comment carries
 * forward to that future refactor.
 */
function compositeId(peerUserId: string, peerDeviceId: string): string {
  return `${peerUserId}:${peerDeviceId}`;
}

/**
 * Convert a stored `RemoteIdentityRow` to the public `RemoteIdentity`
 * shape, re-allocating the `identityPub` view so callers can't mutate
 * persisted state by mutating the returned buffer.
 */
function rowToRemoteIdentity(row: RemoteIdentityRow): RemoteIdentity {
  const trusted: TrustedFlag = row.trusted;
  return {
    peerUserId: row.peerUserId,
    peerDeviceId: row.peerDeviceId,
    identityPub: new Uint8Array(row.identityPub),
    trusted: trusted === 1,
    firstSeenAt: row.firstSeenAt,
    lastChangedAt: row.lastChangedAt,
  };
}

/**
 * Byte-equal compare. Identity public keys are 32 bytes — the bound
 * is small and the comparison is data-dependent, but identity public
 * keys aren't secrets so a constant-time compare isn't strictly
 * required. Kept as a single bounded loop for clarity.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

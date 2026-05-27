// apps/web/src/db/repositories/sessions.ts
//
// Dexie-backed implementation of the `SignalProtocolStore` contract
// from `@konvo/crypto` (task 4.4).
//
// What this repository owns:
//   - persistence of the `sessions` table from `schema.ts` (mirror of
//     design.md §11's `SessionRow`),
//   - the four `SignalProtocolStore` operations the Phase-3 ratchet
//     code consumes:
//       * `loadSession(peerUserId, peerDeviceId)`
//       * `saveSession(peerUserId, peerDeviceId, state)`
//       * `deleteSession(peerUserId, peerDeviceId)`
//       * `markOpkUsed(keyId)`
//   - defensive copying on the way in (write) AND on the way out
//     (read), so callers can mutate / scrub byte buffers without
//     affecting the persisted row.
//
// What this repository does NOT own:
//   - the cryptographic state transitions themselves
//     (`@konvo/crypto`'s `ratchet.ts` / `session.ts`),
//   - the prekey-store generator side (`prekeys.ts` repository) — we
//     only reach into the `prekeys` table for the single-row
//     `markOpkUsed` flag flip,
//   - X3DH session establishment (the caller calls
//     `acceptSession(...)` from `@konvo/crypto`, then this repository
//     persists the resulting initial ratchet state via
//     `saveSession`).
//
// Atomicity invariants
// --------------------
// design.md §13.2 requires "on exception, ratchet state is
// unchanged". The pure ratchet functions in `@konvo/crypto` already
// preserve this property in-process; this repository extends it
// across the IndexedDB boundary by:
//
//   1. `saveSession` is a single Dexie `put`. IDB transactions are
//      atomic at the engine level — the row is either fully written
//      or not at all. A throw before the put leaves the prior row
//      intact.
//
//   2. `loadSession` returns the persisted row deserialized into a
//      fresh `SerializedRatchetState`; mutations to the returned
//      state can't reach the persisted row.
//
//   3. `deleteSession` removes the row outright. A subsequent
//      `loadSession` returns `null`, which the ratchet code treats
//      as "no session yet — establish via X3DH".
//
//   4. `markOpkUsed` is intentionally NOT bundled into the same
//      transaction as `saveSession`. The OPK consumption is a
//      one-way fact about prekey lifecycle (requirement 3.5):
//      consuming an OPK is independent of whether the downstream
//      session gets persisted. Bundling them would create a state
//      where a transient `saveSession` failure could leave the OPK
//      reusable, opening a replay path where the same X3DH-init
//      envelope re-derives the same SK twice. The
//      OPK-marked-but-session-not-saved order is the safer failure
//      mode: the next inbound init under the same OPK is rejected
//      because the OPK is gone, so no state divergence can happen.

import type {
  SerializedRatchetState,
  SerializedSkippedKey,
  SignalProtocolStore,
} from '@konvo/crypto';

import {
  type KonvoDb,
  type PreKeyRow,
  type SessionRow,
  type UsedFlag,
} from '../schema.js';

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/**
 * Dexie-backed `SignalProtocolStore`.
 *
 * Construct with the live `KonvoDb` instance at app startup; tests
 * construct a fresh `KonvoDb` per case (see
 * `apps/web/test/db-sessions.test.ts`). The class keeps a private
 * reference rather than a global singleton so a future feature
 * (e.g. multi-account sandboxing) can swap out the underlying DB
 * without touching the repository surface.
 */
export class DexieSessionsStore implements SignalProtocolStore {
  readonly #db: KonvoDb;

  constructor(db: KonvoDb) {
    this.#db = db;
  }

  /**
   * Return the persisted ratchet state for a peer device, or `null`
   * if no session has been established yet.
   *
   * Returned byte buffers are fresh copies — the persisted row is
   * untouched if the caller mutates the returned state. This is the
   * cornerstone of the trial-decrypt atomicity invariant: the
   * ratchet code can clone the loaded state, advance the clone, and
   * either commit (via `saveSession`) or drop the clone on tamper
   * without ever mutating the persisted bytes.
   */
  async loadSession(
    peerUserId: string,
    peerDeviceId: string,
  ): Promise<SerializedRatchetState | null> {
    const row: SessionRow | undefined = await this.#db.sessions.get(
      compositeId(peerUserId, peerDeviceId),
    );
    if (row === undefined) {
      return null;
    }
    // Defensive copy on read. Dexie returns the structured-cloned
    // row, but the typed-array buffers are the same instances as
    // the persisted ones — re-cloning here keeps the persisted row
    // safe from caller-side mutation.
    return cloneSerializedState(row.state);
  }

  /**
   * Upsert the ratchet state for a peer device. Idempotent: re-saving
   * an equivalent state is a no-op semantically.
   *
   * The implementation defensively copies all incoming byte buffers
   * so a caller mutating their source state after `saveSession`
   * resolves cannot retroactively corrupt the persisted row. This
   * matters because `ratchet.ts` scrubs consumed message-key bytes
   * via `.fill(0)` after each successful encrypt / decrypt — without
   * the defensive copy here, those scrubs would zero out the
   * persisted bytes too.
   */
  async saveSession(
    peerUserId: string,
    peerDeviceId: string,
    state: SerializedRatchetState,
  ): Promise<void> {
    const row: SessionRow = {
      id: compositeId(peerUserId, peerDeviceId),
      peerUserId,
      peerDeviceId,
      state: cloneSerializedState(state),
      updatedAt: Date.now(),
    };
    await this.#db.sessions.put(row);
  }

  /**
   * Remove the persisted session for a peer device. Idempotent:
   * deleting a non-existent session resolves successfully with no
   * side effects. Dexie's `Table.delete` is no-op-safe on absent
   * keys.
   *
   * Used when:
   *   - the user explicitly resets a session after rejecting a
   *     TOFU identity change (requirement 8.9 — session is torn
   *     down and outbound sends remain paused),
   *   - a peer device is revoked (the local mirror of the server's
   *     `DELETE /devices/:id` flow, requirement 2.9).
   */
  async deleteSession(
    peerUserId: string,
    peerDeviceId: string,
  ): Promise<void> {
    await this.#db.sessions.delete(compositeId(peerUserId, peerDeviceId));
  }

  /**
   * Flip the `used` flag on the local one-time-prekey row for the
   * given `keyId`. Called by the X3DH-accept side immediately after
   * a successful inbound `SessionInit` so the same OPK isn't reused
   * for a second X3DH (which would let an attacker replay the
   * init-shaped envelope and re-derive the same SK).
   *
   * Idempotent: marking an already-consumed OPK is a no-op (the row
   * already has `used: 1`). If no row matches the `keyId`, the
   * method resolves without error — the state we want to enforce
   * (this OPK is not usable) is already true.
   *
   * The update runs in a `readwrite` transaction so concurrent
   * X3DH-accept calls in two tabs cannot both decide an OPK is
   * still unused at the same instant. The `keyType === 'opk'`
   * filter prevents an accidental flip of the (singleton) signed
   * prekey row, even though signed-prekey ids and OPK ids live in
   * the same table.
   */
  async markOpkUsed(keyId: number): Promise<void> {
    await this.#db.transaction(
      'rw',
      this.#db.prekeys,
      async (): Promise<void> => {
        const matches: PreKeyRow[] = await this.#db.prekeys
          .where('keyId')
          .equals(keyId)
          .toArray();
        // Filter to OPK rows only — see method-level comment on why
        // the type filter matters even though OPK and signed
        // prekey id sequences are independent (they live in the
        // same table and could in principle collide).
        const used: UsedFlag = 1;
        for (const row of matches) {
          if (row.keyType !== 'opk') {
            continue;
          }
          if (row.used === used) {
            // Already consumed — keeping the no-op explicit avoids
            // a needless write and makes the idempotent contract
            // observable in tests.
            continue;
          }
          // The auto-incremented `id` is the primary key on this
          // table; we update by it (rather than by `keyId`) so the
          // single matched row is unambiguous.
          if (row.id === undefined) {
            // Defensive: every persisted row carries an auto-id.
            // A row without one is a programmer error in a future
            // refactor; throw rather than silently skip.
            throw new Error(
              `markOpkUsed: prekey row for keyId=${keyId} missing primary key id`,
            );
          }
          await this.#db.prekeys.update(row.id, { used });
        }
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Composite primary key for the `sessions` table.
 *
 * Format: `${peerUserId}:${peerDeviceId}`. Mirrors the
 * `remoteIdentities` table's keying convention so a future helper
 * that wants to join a session row to its TOFU record can compute
 * the same id from one side.
 *
 * The `:` separator is forbidden in UUIDs (which is what user and
 * device ids are in production), so collisions with a literal id
 * containing `:` aren't possible. If a future user-id format admits
 * `:` we'd need to switch to a length-prefixed encoding — same
 * caveat as `remote-identities.ts`.
 */
function compositeId(peerUserId: string, peerDeviceId: string): string {
  return `${peerUserId}:${peerDeviceId}`;
}

/**
 * Deep-copy a `SerializedRatchetState`. Every byte buffer is
 * re-allocated so the returned state shares no backing memory with
 * the input.
 *
 * Used on both read and write paths:
 *   - read: keep the persisted bytes safe from caller mutation,
 *   - write: keep the persisted bytes safe from caller scrub.
 *
 * The `skippedKeys` array is a plain mutable array on storage (the
 * `readonly` modifier on `SerializedRatchetState.skippedKeys` is
 * TS-only) so we recreate it as such.
 */
function cloneSerializedState(
  state: SerializedRatchetState,
): SerializedRatchetState {
  return {
    rootKey: new Uint8Array(state.rootKey),
    sendingDhPriv: new Uint8Array(state.sendingDhPriv),
    sendingDhPub: new Uint8Array(state.sendingDhPub),
    receivingDhPub:
      state.receivingDhPub === null
        ? null
        : new Uint8Array(state.receivingDhPub),
    sendingChainKey:
      state.sendingChainKey === null
        ? null
        : new Uint8Array(state.sendingChainKey),
    receivingChainKey:
      state.receivingChainKey === null
        ? null
        : new Uint8Array(state.receivingChainKey),
    sendingMessageNumber: state.sendingMessageNumber,
    receivingMessageNumber: state.receivingMessageNumber,
    previousSendingChainLength: state.previousSendingChainLength,
    skippedKeys: state.skippedKeys.map((k: SerializedSkippedKey) => ({
      dhPub: new Uint8Array(k.dhPub),
      messageNumber: k.messageNumber,
      messageKey: new Uint8Array(k.messageKey),
    })),
  };
}

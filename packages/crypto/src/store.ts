// packages/crypto/src/store.ts
//
// Implements task 4.4: Crypto_Module Signal store over Dexie.
//
// What this module owns:
//   - the `SignalProtocolStore` contract — the set of operations the
//     Phase-3 ratchet code (`ratchet.ts`) and X3DH session code
//     (`session.ts`) need against persistent storage to round-trip
//     their state across page reloads,
//   - the `SerializedRatchetState` row shape — a JSON-friendly
//     mirror of `RatchetState` that Dexie can store and re-hydrate,
//   - pure (de)serialization helpers (`serializeRatchetState` /
//     `deserializeRatchetState`) so the store implementation in
//     `apps/web/src/db/repositories/sessions.ts` and any future
//     in-memory test double share the same byte/wire layout.
//
// What this module does NOT own:
//   - the IndexedDB / Dexie binding itself — that lives in
//     `apps/web/src/db/repositories/sessions.ts`, which implements
//     `SignalProtocolStore` against the `sessions` and `prekeys`
//     tables defined in `apps/web/src/db/schema.ts`. Keeping the
//     Dexie code outside `@konvo/crypto` preserves the package's
//     property of being browser-API-only (no `dexie` import in the
//     wrapper, per design.md Appendix A),
//   - the cryptographic state transitions themselves — `ratchet.ts`
//     produces `RatchetState` values, and this module just round-
//     trips them.
//
// Why the store contract lives here, not next to `ratchet.ts`
// ----------------------------------------------------------
// The X3DH (`session.ts`) and Double-Ratchet (`ratchet.ts`) modules
// are intentionally pure functional state transitions: they take a
// state in, return a fresh state out, and never touch storage
// (design.md §13.2 atomicity — the caller is responsible for
// persisting the new state only on a successful return). The Signal
// store contract is thus *adjacent to* the ratchet rather than part
// of it: the wrapper API the rest of the monorepo consumes (a
// future `Crypto_Module.encryptToDevice(peer, plaintext)`) will
// load the prior state via `loadSession`, call into `ratchet.ts`'s
// pure `encryptToDevice`, and then call `saveSession` with the
// returned state. By colocating the contract here, both halves
// (the storage adapter in `apps/web` and any future in-memory
// double for tests) bind to the same symbol.
//
// At-rest protection of ratchet state
// -----------------------------------
// The `SerializedRatchetState` shape carries Phase-3 ratchet bytes
// (root key, sending / receiving chain keys, sending DH private
// key, skipped message keys) in clear within the IndexedDB row.
// These bytes are NOT additionally wrapped under AES-KW the way
// long-term identity / prekey privates are (`identity.ts`,
// `prekeys.ts`). The rationale, mirroring the Signal protocol's
// own design choice:
//
//   - Long-term identity material (the X25519 identity private key,
//     the Ed25519 signing private key, the signed-prekey private
//     bytes, and unused OPK private bytes) is wrapped under a
//     non-extractable WebCrypto AES-KW KEK (the `aesKwKeys` row in
//     Dexie). Compromise of these bytes would let an attacker
//     impersonate the device for new sessions or recover *future*
//     sessions; they MUST be at-rest-protected.
//
//   - Ratchet ephemeral state (root key, chain keys, sending DH
//     private bytes, skipped keys) describes a *single ongoing
//     session*. The Double Ratchet's forward-secrecy property
//     (requirement 9.1, P4) says that the consumed-message-key
//     bytes for any *prior* message are scrubbed by the caller
//     before saveSession — so the persisted state never contains
//     keys for already-consumed messages, only the pending
//     send/receive chain keys and skipped keys for legitimate
//     out-of-order delivery. An attacker who exfiltrates this
//     row CAN read messages from the current point forward until
//     the next DH ratchet step, but cannot retro-decrypt prior
//     messages (the chain keys for those have already been
//     advanced and scrubbed before persistence). This matches
//     Signal's threat model: rotation through DH ratchet steps
//     limits the blast radius of a single state compromise
//     (post-compromise security, requirement 9.2, P5).
//
//   - The Phase-3 implementation lands the ratchet bytes in clear
//     for clarity and testability. When libsignal lands in the
//     Phase-4 swap, the libsignal `SessionRecord` serialization
//     is itself opaque-bytes — the same Dexie row carries the
//     opaque bytes and the same forward-secrecy / post-compromise
//     properties hold. The wire shape stays compatible.
//
// Future hardening (not required by Phase 3): wrap the serialized
// state under the `aesKwKeys` KEK at write time and unwrap at read
// time. The ratchet state would gain at-rest confidentiality at
// the cost of a synchronous WebCrypto round-trip on every
// load/save. That's a defensible Phase 4+ refinement; we leave it
// to a future task rather than complicate the Phase-3 wire shape.
//
// Atomicity invariant
// -------------------
// Per design.md §13.2: "on exception, ratchet state is unchanged".
// The pure ratchet functions (`encryptToDevice` / `decryptFromDevice`
// / `acceptSession`) already guarantee this in-process — they
// return a new `RatchetState` on success and never mutate the input
// on failure. The storage layer extends the guarantee across the
// IndexedDB boundary by:
//
//   1. Saving the *new* state only after a successful ratchet call.
//      A thrown / rejected ratchet call is followed by no
//      `saveSession` call, so the persisted row remains the prior
//      successful state.
//
//   2. The Dexie `put` for `saveSession` is itself atomic at the
//      IDB transaction level: either the row is fully written or
//      it is not.
//
//   3. `markOpkUsed` (the X3DH-accept-side helper) runs in the
//      same Dexie transaction shape: a single update to the
//      `prekeys` row sets `used=1`. We do NOT couple it into the
//      same transaction as the session save, because the OPK
//      consumption is independent of which peer's session a given
//      X3DH-accept produces — the OPK is consumed even if the
//      caller crashes before persisting the session, which matches
//      requirement 3.5 (OPKs are consumed atomically per
//      prekey-bundle request, regardless of downstream success).

import type { RatchetState, SkippedKey } from './ratchet.js';

// ---------------------------------------------------------------------------
// Wire shape — serialized ratchet row
// ---------------------------------------------------------------------------

/**
 * JSON-friendly mirror of `RatchetState` used for persistence in the
 * Dexie `sessions` table. Field names and types match `RatchetState`
 * one-for-one so a future migration to libsignal's opaque
 * `SessionRecord` can swap out the field set without renaming the
 * surrounding row machinery.
 *
 * Why typed arrays survive the IndexedDB round-trip
 * -------------------------------------------------
 * The IndexedDB structured-clone algorithm explicitly preserves
 * `Uint8Array` instances — both byte content and the typed-array
 * shape — across the storage boundary. We rely on that here rather
 * than base64-encoding bytes at the boundary, which would double
 * the row size and require an explicit pre-load decode in
 * `loadSession`. Dexie passes the instances through to IDB
 * unmodified, and reads return fresh `Uint8Array` views over the
 * stored bytes (`identity.ts` / `prekeys.ts` rely on the same
 * behaviour).
 *
 * Why `skippedKeys` is a plain mutable array
 * ------------------------------------------
 * `RatchetState.skippedKeys` is typed `readonly SkippedKey[]` to
 * communicate the immutability invariant at the language level.
 * Once serialized for storage, the readonly modifier is irrelevant
 * (Dexie's row shape is structurally cloned), and a `readonly`
 * marker on a structured-clonable shape adds no runtime guarantee.
 * The serializer copies the array into a plain mutable form so the
 * stored row matches the way IDB will hand it back on read.
 */
export interface SerializedRatchetState {
  readonly rootKey: Uint8Array;
  readonly sendingDhPriv: Uint8Array;
  readonly sendingDhPub: Uint8Array;
  readonly receivingDhPub: Uint8Array | null;
  readonly sendingChainKey: Uint8Array | null;
  readonly receivingChainKey: Uint8Array | null;
  readonly sendingMessageNumber: number;
  readonly receivingMessageNumber: number;
  readonly previousSendingChainLength: number;
  readonly skippedKeys: readonly SerializedSkippedKey[];
}

/**
 * Mirror of `SkippedKey` for storage. Same byte semantics; the
 * `readonly` modifier is a TS-only nicety on the row shape.
 */
export interface SerializedSkippedKey {
  readonly dhPub: Uint8Array;
  readonly messageNumber: number;
  readonly messageKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// Store contract
// ---------------------------------------------------------------------------

/**
 * Persistence contract the Phase-3 ratchet code (and the future
 * libsignal swap) consumes.
 *
 * Method semantics:
 *
 *   - `loadSession(peerUserId, peerDeviceId)` — return the persisted
 *     ratchet state for the peer device, or `null` if no session has
 *     been established yet. Returned byte buffers MUST be defensive
 *     copies — callers may mutate or scrub them (e.g. the ratchet's
 *     trial-decrypt clone path) without affecting the persisted row.
 *
 *   - `saveSession(peerUserId, peerDeviceId, state)` — upsert the
 *     ratchet state for the peer device. Idempotent: re-saving the
 *     same state is a no-op semantically (the row is overwritten with
 *     equivalent bytes). The implementation MUST defensively copy
 *     incoming byte buffers so a caller mutating their source state
 *     after `saveSession` resolves cannot retroactively corrupt the
 *     persisted row.
 *
 *   - `deleteSession(peerUserId, peerDeviceId)` — remove the persisted
 *     state. Used when the user explicitly resets a session (e.g.
 *     after a rejected identity-change in TOFU, requirement 8.9) or
 *     when a device is revoked. Idempotent: deleting a non-existent
 *     session is a no-op (resolves successfully).
 *
 *   - `markOpkUsed(keyId)` — flip the `used` flag on the local
 *     one-time-prekey row matching `keyId`. Called by the X3DH-accept
 *     side (`session.ts:acceptSession` consumer) immediately after a
 *     successful inbound `SessionInit`, so the same OPK isn't re-used
 *     for a second X3DH (which would let an attacker replay the
 *     init-shaped envelope and re-derive the same SK). Idempotent:
 *     marking an already-consumed OPK is a no-op.
 *
 * All methods return Promises because the underlying IndexedDB API is
 * asynchronous; even cache-hit paths cross a microtask boundary.
 *
 * Error contract: implementations SHOULD reject the Promise on any
 * IDB-level failure (quota exceeded, transaction aborted, etc) so
 * callers in the ratchet layer can preserve the design.md §13.2
 * atomicity invariant by NOT using the new state when persistence
 * fails. Implementations MUST NOT swallow such failures into a
 * successful resolve.
 */
export interface SignalProtocolStore {
  loadSession(
    peerUserId: string,
    peerDeviceId: string,
  ): Promise<SerializedRatchetState | null>;

  saveSession(
    peerUserId: string,
    peerDeviceId: string,
    state: SerializedRatchetState,
  ): Promise<void>;

  deleteSession(peerUserId: string, peerDeviceId: string): Promise<void>;

  markOpkUsed(keyId: number): Promise<void>;
}

// ---------------------------------------------------------------------------
// Pure (de)serialization helpers
// ---------------------------------------------------------------------------

/**
 * Convert a `RatchetState` (the in-memory shape `ratchet.ts` works
 * with) to the persistence shape `SerializedRatchetState`. Every
 * byte buffer is copied so the returned row shares no backing
 * memory with the input; the caller may freely scrub the input
 * after this returns.
 *
 * The mapping is field-for-field: the two shapes are intentionally
 * isomorphic in Phase 3. The function exists so callers don't have
 * to reach into the byte-by-byte structure manually and so a future
 * swap to libsignal's opaque `SessionRecord` only has to change
 * one site.
 */
export function serializeRatchetState(
  state: RatchetState,
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
    skippedKeys: state.skippedKeys.map(
      (k: SkippedKey): SerializedSkippedKey => ({
        dhPub: new Uint8Array(k.dhPub),
        messageNumber: k.messageNumber,
        messageKey: new Uint8Array(k.messageKey),
      }),
    ),
  };
}

/**
 * Inverse of `serializeRatchetState`. Returns a fresh `RatchetState`
 * whose byte buffers are owned by the caller — the persisted row is
 * untouched if the caller mutates the returned state.
 *
 * This is the reads-side complement: ratchet code calls
 * `loadSession` (which internally calls `deserializeRatchetState`),
 * runs a state transition on the result, then calls `saveSession`
 * (which internally calls `serializeRatchetState`) to commit.
 */
export function deserializeRatchetState(
  row: SerializedRatchetState,
): RatchetState {
  return {
    rootKey: new Uint8Array(row.rootKey),
    sendingDhPriv: new Uint8Array(row.sendingDhPriv),
    sendingDhPub: new Uint8Array(row.sendingDhPub),
    receivingDhPub:
      row.receivingDhPub === null ? null : new Uint8Array(row.receivingDhPub),
    sendingChainKey:
      row.sendingChainKey === null ? null : new Uint8Array(row.sendingChainKey),
    receivingChainKey:
      row.receivingChainKey === null
        ? null
        : new Uint8Array(row.receivingChainKey),
    sendingMessageNumber: row.sendingMessageNumber,
    receivingMessageNumber: row.receivingMessageNumber,
    previousSendingChainLength: row.previousSendingChainLength,
    skippedKeys: row.skippedKeys.map(
      (k): SkippedKey => ({
        dhPub: new Uint8Array(k.dhPub),
        messageNumber: k.messageNumber,
        messageKey: new Uint8Array(k.messageKey),
      }),
    ),
  };
}

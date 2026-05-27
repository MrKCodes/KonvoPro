// apps/web/src/db/schema.ts
//
// Dexie schema for the Konvo Web_Client. This file is the single source of
// truth for the IndexedDB layout the PWA uses; every persistence-shaped
// interface declared here mirrors a row in `design.md` §11.
//
// Task 2.9 ships a strict *subset* of §11 — only the tables this phase of
// the build actually needs:
//
//   - `identity`  : single-row table holding the wrapped identity keypair
//                   for this Web_Client (key='me'). See requirements 2.1,
//                   2.2, 2.3.
//   - `prekeys`   : signed prekey + one-time prekey storage, indexed for
//                   fast "how many unused OPKs do I have left?" queries
//                   (requirements 3.1, 3.3).
//   - `aesKwKeys` : single-row table holding the non-extractable AES-KW
//                   key-encryption-key (KEK) used to wrap the identity
//                   private key. The CryptoKey lives only here — never as
//                   raw bytes in JS memory.
//
// Task 7.4 adds `rooms` and `roomPosts` — the local mirror for
// broadcast rooms (slug, name, ownerHandle, createdAt) and the per-
// room post cache (id, body, signature, signing identity pub,
// verified flag). See `RoomRow` / `RoomPostRow` below for the
// task-7.4-specific schema deviations from design.md §11.
//
// Task 3.7 adds `threads`, `messages`, and `outbox` — the local DM
// state and offline-send queue. See the row interfaces below for the
// task-3.7-specific schema deviations from design.md §11.
//
// Task 4.8 adds `remoteIdentities` — the TOFU bookkeeping store that
// records, per peer device, the identity public key first observed and
// whether the user has trusted it. See `RemoteIdentityRow` below and
// `repositories/remote-identities.ts` for the access layer.
//
// Task 4.4 adds `sessions` — the Double-Ratchet persistence store the
// `SignalProtocolStore` adapter in `repositories/sessions.ts` writes
// through. The row shape mirrors `SerializedRatchetState` from
// `@konvo/crypto`'s `store.ts` and is keyed by the synthetic
// `${peerUserId}:${peerDeviceId}` composite (same convention used for
// `remoteIdentities`). See the `SessionRow` interface below for
// rationale and the deviation from design.md §11.
//
// Task 5.3 adds `localAttachments` — the bounded LRU cache for
// downloaded attachment ciphertext + decrypted plaintext blobs. The
// row shape mirrors design.md §11's `LocalAttachmentRow` with the
// deviations documented on `LocalAttachmentRow` below; the eviction
// policy (200 MiB cap, oldest-by-`lastAccessedAt` first) lives in
// `apps/web/src/features/attachments/cache.ts`.
//
// Schema deviations from design.md §11 (intentional, per task 2.9 brief):
//   - `prekeys` uses an auto-incremented `id` primary key plus a compound
//     `[keyType+used]` index for cheap unused-OPK count queries. The §11
//     sketch used `[type+keyId]` as the primary key, which makes the
//     unused-count query O(table) rather than O(matching). The design
//     intent (one row per key) is preserved.
//   - `prekeys.keyType` uses values `'signed' | 'opk'` instead of §11's
//     `'signed' | 'one_time'`. `'opk'` matches the requirements.md
//     terminology and is shorter on the wire when this row is later
//     surfaced through diagnostics.
//   - The KEK is broken out into its own `aesKwKeys` table (see comment
//     above the `AesKwKeyRow` interface for why a CryptoKey can't live in
//     the `identity` row).
//   - `remoteIdentities` adds `lastChangedAt: number | null` (not in
//     §11) so the UI can render "identity changed at <time>" alongside
//     the re-verify banner, and `trusted` is encoded as a numeric
//     `0|1` flag for the same compound-index reason `prekeys.used` is.
//     The §11 `peerHandle` field is intentionally omitted — TOFU
//     bookkeeping is keyed by the stable `(peerUserId, peerDeviceId)`
//     tuple per requirement 8.1, and handles are display-name material
//     that can change without a re-verify event.
//   - `sessions` is keyed by the synthetic
//     `${peerUserId}:${peerDeviceId}` composite via primary key `id`
//     rather than §11's bare `peerDeviceId` primary key. The composite
//     matches the `remoteIdentities` keying convention (§11 keys
//     `remoteIdentities` by `peerDeviceId` too, but task 4.8 already
//     deviated to the composite). Two devices belonging to different
//     users could in principle be assigned the same `peerDeviceId` by
//     a future server-side bug; keying by the composite makes the
//     local row layout robust to that. The §11 `peerHandle` field is
//     omitted for the same reason as on `remoteIdentities`.
//   - `sessions.state` carries the full `SerializedRatchetState`
//     object (not the §11 `Uint8Array` `ratchetState`) because the
//     Phase-3 ratchet defines `RatchetState` as a structured shape
//     rather than libsignal's opaque `SessionRecord` byte buffer.
//     IndexedDB structured-clones the nested typed arrays inside the
//     state, so this is wire-compatible. When libsignal lands the
//     field becomes a single opaque `Uint8Array`.
//   - `threads` is keyed by `peerUserId` (the design.md §11 sketch
//     keys by `peerHandle`). User ids are stable identifiers per
//     requirement 8.1; handles are display material that can change
//     without a thread identity change. `peerHandle` survives as an
//     optional display field on the row. The §11 `peerDeviceIds` and
//     `safetyNumberVerified` fields are intentionally omitted from
//     this task's slice: `peerDeviceIds` is computed at fan-out time
//     from the API's `/users/:handle` response (the local mirror is
//     not the source of truth, and a stale per-thread cache would
//     desync against the prekey-bundle path), and verification
//     state lives on `remoteIdentities` keyed per-device per
//     requirement 8.1.
//   - `messages` uses an auto-incremented `id` primary key plus a
//     compound `[threadId+createdAt]` index on the `threadId` (the
//     `peerUserId` of the thread row this message belongs to). The
//     §11 sketch keys by `clientMsgId` (a UUID), but a numeric
//     auto-id keeps the per-thread "latest N" range scan
//     index-friendly without compounding two strings, and a
//     `&clientNonce` unique index gives the WS layer the same
//     "find by nonce on `ENVELOPE_QUEUED`" capability the §11
//     sketch implies. The `state` enum carries `'sending'`,
//     `'delivered'`, `'read'`, and `'failed'` per requirement 4.6.
//     `'queued'` from the §11 sketch is folded into `'sending'`
//     for this slice; the UI does not distinguish "in outbox,
//     waiting for transport" from "in transit". A future task can
//     re-introduce the distinction without a schema change (it's
//     just an enum value).
//   - `messages.body` is plaintext at this slice. Task 4.7 replaces
//     it with the libsignal-encoded ciphertext payload. The schema
//     stays stable; only the producer of the bytes changes.
//   - `outbox` uses an auto-incremented `id` primary key (rather
//     than the §11 sketch's `&clientNonce`) because the FIFO
//     replay-on-reconnect order is best expressed as
//     "primary-key ASC". The `clientNonce` is a `&` unique index
//     so "find pending row by nonce on `ENVELOPE_QUEUED`" remains
//     O(1). `enqueuedAt` is indexed for the 7-day age sweep
//     (requirement 4.8). `retryCount` is incremented every time a
//     row is re-sent without acknowledgement; a future scheduler
//     can use it to surface "permanently failed" messages.

import Dexie, { type Table } from 'dexie';

import type { CiphertextEnvelope } from '@konvo/protocol';

import type { SerializedRatchetState } from '@konvo/crypto';

// ---------------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------------

/**
 * Single-row identity table (primary key always `'me'`).
 *
 * Fields mirror `WrappedIdentityRecord` from `@konvo/crypto` so the
 * `DexieIdentityStore` can `put` / `get` without any field renaming.
 *
 * `createdAt` is local-only metadata — it isn't part of the
 * `WrappedIdentityRecord` contract, but it's useful for diagnostics
 * ("when was this device's identity first generated?") and costs nothing.
 *
 * Phase-1 placeholder: `ed25519PublicKey` and `wrappedEd25519PrivateKey`
 * carry the parallel Ed25519 sub-key used to sign signed prekeys until
 * libsignal/XEdDSA wires the signing flow against the X25519 identity
 * key directly. See `packages/crypto/src/identity.ts` and
 * `packages/crypto/src/prekeys.ts` for the rationale.
 */
export interface IdentityRow {
  readonly id: 'me';
  readonly publicKey: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
  readonly ed25519PublicKey: Uint8Array;
  readonly wrappedEd25519PrivateKey: Uint8Array;
  readonly registrationId: number;
  readonly createdAt: number;
}

/**
 * Discriminator for the `prekeys` table. `'signed'` rows carry an Ed25519
 * `signature` field; `'opk'` rows do not. Per requirements 3.1 we keep
 * exactly one signed prekey active at a time and up to 100 unused OPKs.
 */
export type PreKeyType = 'signed' | 'opk';

/**
 * Numeric encoding of `used`.
 *
 * IndexedDB does NOT accept `boolean` as a valid key type — the spec
 * defines valid keys as `string | number | Date | ArrayBuffer | Array`,
 * and Dexie silently drops boolean-keyed rows from any index that
 * references them. To keep the `[keyType+used]` compound index correct
 * and usable, we encode `used` as a number: `0` for unused, `1` for
 * consumed. The repository layer converts to/from `boolean` at the
 * public API surface so callers continue to think in boolean terms.
 */
export type UsedFlag = 0 | 1;

/**
 * Row shape for both signed prekeys and one-time prekeys.
 *
 * The `id` field is auto-incremented by Dexie (`++id`) and is local-only;
 * the wire `keyId` (uploaded to the API_Gateway) is a separate integer that
 * libsignal/libcrypto generates at key creation time.
 *
 * `wrappedPrivateKey` carries the AES-KW-wrapped private bytes — same KEK
 * as the identity row. Storing only wrapped bytes preserves requirement
 * 2.2's "private key bytes never persisted in cleartext" guarantee for
 * prekey material as well.
 *
 * `used` is a numeric `UsedFlag` (see above) for index compatibility, not a
 * boolean. Logically: `0` = unused (default for OPKs at insert time),
 * `1` = consumed by an X3DH session establishment.
 */
export interface PreKeyRow {
  readonly id?: number; // auto-incremented by Dexie on insert
  readonly keyType: PreKeyType;
  readonly keyId: number;
  readonly publicKey: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
  readonly signature?: Uint8Array; // Ed25519, signed prekeys only
  readonly createdAt: number;
  readonly used: UsedFlag;
}

/**
 * Single-row AES-KW key table.
 *
 * Why this lives in its own table:
 *   - A `CryptoKey` is *not* a typed array, so it can't be stored as
 *     bytes. IndexedDB's structured-clone algorithm explicitly supports
 *     `CryptoKey` and preserves non-extractability across reload, so we
 *     hand the raw CryptoKey to Dexie and let the engine clone it.
 *   - Keeping the KEK separate from the `identity` row means we can
 *     migrate / rotate the wrapping key without touching the identity
 *     record, and a corrupt KEK row doesn't take the identity bytes with
 *     it.
 *
 * The KEK MUST be generated `extractable: false` with usages
 * `['wrapKey', 'unwrapKey']`. The repository enforces both invariants.
 */
export interface AesKwKeyRow {
  readonly id: 'me';
  readonly cryptoKey: CryptoKey;
}

/**
 * TOFU bookkeeping for a peer device's identity public key.
 *
 * Mirrors `RemoteIdentityRow` from design.md §11 with two
 * task-4.8-specific fields appended (see header comment for rationale):
 *   - `trusted` is encoded as a numeric `TrustedFlag` (0 = untrusted,
 *     1 = trusted) so it can participate in compound indices without
 *     hitting the same boolean-key restriction documented on
 *     `PreKeyRow.used`. The repository converts to/from `boolean` at
 *     the public API surface.
 *   - `lastChangedAt` records the timestamp of the most recent
 *     identity-key change observed for this peer device, or `null` if
 *     no change has ever been observed (i.e., the row is still the
 *     original TOFU first-sight record). The UI uses this to render
 *     "identity changed at <time>" alongside the re-verify banner.
 *
 * The `id` field is the primary key — Dexie compound primary keys are
 * supported but make `get(id)` calls noisier. We use the synthetic
 * `${peerUserId}:${peerDeviceId}` composite to keep the lookup API a
 * single string.
 *
 * The §11 `peerHandle` field is intentionally omitted: TOFU
 * bookkeeping is keyed by stable identifiers per requirement 8.1, and
 * a peer handle is display material that can change without
 * triggering a re-verify event. The handle is rendered from a
 * separate users-cache table (added in later phases).
 */
export interface RemoteIdentityRow {
  readonly id: string; // `${peerUserId}:${peerDeviceId}`
  readonly peerUserId: string;
  readonly peerDeviceId: string;
  readonly identityPub: Uint8Array;
  readonly trusted: TrustedFlag;
  readonly firstSeenAt: number;
  readonly lastChangedAt: number | null;
}

/**
 * Numeric encoding of `RemoteIdentityRow.trusted`. See `UsedFlag` for
 * the rationale (IndexedDB rejects boolean compound-index keys).
 *
 * - `0`: untrusted. Either the user explicitly rejected a new
 *   identity key after a change, or a downstream policy has flipped
 *   the flag during a key-rotation event.
 * - `1`: trusted. Either set by TOFU on first sight (requirement
 *   8.1) or after the user explicitly accepts a new key following a
 *   change (requirement 8.7).
 */
export type TrustedFlag = 0 | 1;

/**
 * Persisted Double-Ratchet state for a single peer device, mirroring
 * design.md §11's `SessionRow` with two task-4.4-specific
 * adjustments (see header comment for the full deviation list):
 *
 *   - `id` is the synthetic `${peerUserId}:${peerDeviceId}` composite
 *     used elsewhere in the local DB. The §11 sketch keys by bare
 *     `peerDeviceId`; we use the composite for parity with
 *     `remoteIdentities` and resilience against any future server-side
 *     `peerDeviceId` collision across users.
 *   - `state` carries the structured `SerializedRatchetState` object
 *     (mirror of `RatchetState` from `@konvo/crypto`) rather than a
 *     bare `Uint8Array`. The Phase-3 ratchet defines its state as a
 *     typed shape; IndexedDB's structured-clone preserves nested
 *     `Uint8Array`s so the row round-trips byte-for-byte. When
 *     libsignal lands and the state becomes opaque bytes, this field
 *     simplifies to a single `Uint8Array` without any other row
 *     changes.
 *
 * `updatedAt` is set on every `saveSession` for diagnostics and any
 * future LRU-style eviction policy. It is not currently indexed.
 */
export interface SessionRow {
  readonly id: string; // `${peerUserId}:${peerDeviceId}`
  readonly peerUserId: string;
  readonly peerDeviceId: string;
  readonly state: SerializedRatchetState;
  readonly updatedAt: number;
}

/**
 * Local DM thread mirror, keyed by the peer's stable user id.
 *
 * See the schema header for the deviation rationale. The §11
 * `peerDeviceIds` and `safetyNumberVerified` fields are intentionally
 * omitted: device-id fan-out targets are sourced from the API at send
 * time, and per-device verification lives on `remoteIdentities`.
 *
 * `peerHandle` is optional display material — handles can change
 * without invalidating the thread, so the row stays valid even if it
 * goes briefly stale. `unreadCount` is incremented as inbound
 * messages arrive and reset to zero when the user opens the thread.
 */
export interface ThreadRow {
  readonly peerUserId: string;
  readonly peerHandle?: string;
  readonly lastMessageAt: number;
  readonly unreadCount: number;
  readonly createdAt: number;
}

/**
 * Logical state of an outgoing or inbound DM message.
 *
 * Outbound transitions (requirement 4.6):
 *   `sending` → `delivered` (on `ENVELOPE_QUEUED` plus E2EE
 *   `ACK_DELIVERED`) → `read` (on E2EE `ACK_READ`).
 *   `failed` is a terminal state for outbound messages whose
 *   transport never confirmed within the retry budget.
 *
 * Inbound messages are persisted with `state: 'delivered'`
 * immediately on decrypt, transitioning to `'read'` once the local
 * UI marks the thread read.
 *
 * `tampered` is a terminal state used for inbound envelopes whose
 * libsignal decrypt returned `invalid_message` (Phase-3 / task 4.7).
 * The `body` bytes carry the inert "message couldn't be decrypted
 * (tampered or corrupted)" placeholder text per requirement 4.11;
 * the row is non-actionable in the UI (no retry, no reply).
 * The `tampered` state is intentionally NOT a value Dexie or any
 * existing index keys against, so adding it does not require a
 * schema version bump.
 */
export type MessageState =
  | 'sending'
  | 'delivered'
  | 'read'
  | 'failed'
  | 'tampered';

/**
 * Persisted DM message row.
 *
 * `id` is auto-incremented; the wire-side identity for retry /
 * idempotency is `clientNonce` (matching the `(senderDeviceId,
 * clientNonce)` dedup key on the API per requirement 4.7). The
 * `body` field is plaintext for this slice and becomes the
 * libsignal ciphertext payload after task 4.7 — see the schema
 * header note.
 */
export interface MessageRow {
  readonly id?: number;
  readonly threadId: string; // `peerUserId` of the thread
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly body: Uint8Array; // plaintext bytes (Phase-2 placeholder)
  readonly state: MessageState;
  readonly clientNonce: string;
  readonly createdAt: number;
}

/**
 * Pending-send queue row.
 *
 * The `envelope` field carries the full `CiphertextEnvelope` shape
 * the WS gateway expects on `SEND_ENVELOPE`. The row sits in this
 * table from the moment the composer enqueues it through to the
 * server's `ENVELOPE_QUEUED` confirmation; a successful
 * confirmation deletes the row by `clientNonce`. `enqueuedAt`
 * drives the 7-day age sweep, `retryCount` is bumped on every
 * unacknowledged replay attempt for diagnostics.
 */
export interface OutboxRow {
  readonly id?: number;
  readonly clientNonce: string;
  readonly envelope: CiphertextEnvelope;
  readonly enqueuedAt: number;
  readonly lastTryAt?: number;
  readonly retryCount: number;
}

/**
 * Local mirror of a broadcast room (task 7.4).
 *
 * Sourced from `GET /rooms/:slug` (public read) plus `POST /rooms` /
 * `POST /rooms/:slug/subscribe` admin/subscribe flows. Rows are
 * keyed by `slug` because the slug is the stable user-facing
 * identifier (the public `/r/:slug` route is the entry point) and
 * also the API path component that every room request goes
 * through. The server's `id` UUID is carried alongside as
 * `roomId` because broadcast post signatures cover
 * `(body || roomId || createdAtMs)` — verification therefore
 * requires the UUID, not the slug.
 *
 * Schema deviations from design.md §11:
 *   - The §11 sketch carries `role` (`'owner' | 'admin' | 'subscriber'
 *     | 'viewer'`) and `subscribed: boolean` plus `lastSeenPostId`.
 *     This slice records `ownerHandle` (display material from the
 *     `RoomResponse` DTO) and a separate `subscribed` flag (so the
 *     `RoomList` UI can highlight subscribed rooms without an extra
 *     network round-trip) but omits the per-user `role` and
 *     `lastSeenPostId` fields. The role check is server-authoritative
 *     (Requirement 10.5: `POST /rooms/:slug/messages` returns 403 for
 *     non-admins) and `lastSeenPostId` belongs to the unread-marker
 *     story which is out of scope for task 7.4. A future task can
 *     extend the row without touching the rest of the persisted
 *     state.
 *   - `name` and `ownerHandle` are denormalised from the API
 *     response so the room list can render without a per-row
 *     follow-up fetch; they are best-effort cache, not source of
 *     truth.
 */
export interface RoomRow {
  readonly slug: string;
  readonly roomId: string;
  readonly name: string;
  readonly ownerHandle: string;
  readonly subscribed: boolean;
  readonly createdAt: number;
}

/**
 * Local mirror of a single broadcast post (task 7.4).
 *
 * Rows are keyed by the synthetic `${slug}:${postId}` composite so
 * direct lookups are a single primary-key get. The `roomSlug`,
 * `postId`, and `createdAt` fields are mirrored as their own indexed
 * columns so the `RoomView` UI can range-scan
 * "latest N posts in this room" without a full-table walk.
 *
 * Schema deviations from design.md §11:
 *   - The §11 sketch keys by `&[slug+id]` with secondary indexes on
 *     `slug` and `createdAt`. This implementation matches the index
 *     layout but persists the synthetic primary-key composite in a
 *     dedicated `id` field (`${slug}:${postId}`) instead of relying
 *     on Dexie's compound-key encoding — this keeps `db.roomPosts.get(id)`
 *     a single-string lookup, which mirrors the convention used for
 *     `sessions` and `remoteIdentities` elsewhere in the schema.
 *   - The `verified` flag is encoded as a numeric `0|1` for the same
 *     IndexedDB-rejects-boolean-keys reason documented on
 *     `PreKeyRow.used`; this row is not currently part of any
 *     compound index that depends on `verified`, but we keep the
 *     encoding stable across the schema for any future "list
 *     unverified posts in room" filter. The repository layer
 *     converts to/from `boolean` at the public API surface.
 *   - The §11 sketch stores `id: bigint`. IndexedDB does not accept
 *     bigint as an index key (or as a primary key field when the
 *     row's primary key is a string); we persist `postId` as a
 *     decimal-string form of the BIGSERIAL, which round-trips
 *     losslessly through the API_Gateway's projection (see
 *     `apps/api/src/routes/broadcast.ts` — `id::text AS id` and the
 *     wire shape that already encodes `id` as a string).
 *   - `authorIdentityPub` and `signature` are `Uint8Array`s;
 *     IndexedDB structured-clones nested typed arrays so they
 *     round-trip byte-for-byte without an explicit base64 hop.
 */
export type VerifiedFlag = 0 | 1;

export interface RoomPostRow {
  readonly id: string; // `${roomSlug}:${postId}`
  readonly roomSlug: string;
  readonly postId: string; // decimal-string form of BIGSERIAL
  readonly body: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;
  readonly signature: Uint8Array;
  readonly createdAt: number; // epoch-ms
  readonly verified: VerifiedFlag;
}

/**
 * Local cache row for a downloaded + decrypted attachment (task 5.3).
 *
 * Mirrors the §11 sketch's `LocalAttachmentRow` with the caveats
 * documented in the schema header.
 *
 * What this row caches:
 *   - `ciphertext` is the AES-GCM ciphertext fetched from
 *     `GET /attachments/:id`. We persist the ciphertext (rather than
 *     just the plaintext) so the cache can survive a successful
 *     download even if the matching envelope's AES-GCM key/iv/tag
 *     are not yet available locally (e.g. the user navigated away
 *     before the libsignal decrypt landed).
 *   - `plaintext` is the decrypted blob bytes. Populated only after
 *     a successful `decryptAttachment` call (req 6.5 / 6.9). On a
 *     tag-failure path the row stays present with `plaintext === null`
 *     so subsequent retries can use the persisted ciphertext without
 *     a re-fetch.
 *   - `mime` and `filename` are denormalised from the envelope's
 *     `InnerType.ATTACHMENT` / `InnerType.VOICE_NOTE` payload so
 *     the renderer can display the right element without re-reading
 *     the message row.
 *
 * LRU bookkeeping (req §11 — "LRU cap 200 MiB"):
 *   - `sizeBytes` is the byte length of `ciphertext` (the eviction
 *     planner sums this column to compute the in-cache footprint).
 *   - `lastAccessedAt` is bumped on every successful read; the
 *     cache evicts rows ordered ASC by `lastAccessedAt` until the
 *     summed footprint fits inside the 200 MiB cap.
 *   - `createdAt` records the original insert time; useful for
 *     diagnostics ("how stale is this row?") but does NOT
 *     participate in eviction ordering.
 *
 * Row layout deviations from the §11 sketch:
 *   - The §11 sketch stores `body: Uint8Array` (only the plaintext)
 *     and a separate `key`/`iv`/`tag`. We instead persist the
 *     `ciphertext` plus an optional `plaintext`. The §11 fields
 *     `key`/`iv`/`tag` remain inside the encrypted envelope — they
 *     never live on disk in unwrapped form per req 6.1 (the
 *     `AttachmentRef` carrying them is part of the libsignal-decrypted
 *     `InnerPayload`, which is not persisted). Storing them here would
 *     defeat the purpose of putting the AES key inside the E2EE
 *     envelope in the first place.
 *   - `attachmentId` is indexed unique so we can do a fast O(1)
 *     `getByAttachmentId` lookup without scanning. The synthetic
 *     auto-`id` is the primary key so eviction uses Dexie's monotonic
 *     insertion order as a tie-breaker for rows with the same
 *     `lastAccessedAt`.
 */
export interface LocalAttachmentRow {
  readonly id?: number; // auto-incremented by Dexie
  readonly attachmentId: string; // server-side UUID; unique
  readonly ciphertext: Uint8Array;
  readonly plaintext: Uint8Array | null;
  readonly mime: string;
  readonly filename: string;
  readonly sizeBytes: number;
  readonly createdAt: number;
  readonly lastAccessedAt: number;
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/**
 * Konvo Web_Client IndexedDB binding.
 *
 * The class is exported (rather than only the singleton `db`) so tests
 * can construct a fresh instance per case under `fake-indexeddb`. The
 * production singleton lives at the bottom of this file.
 *
 * Bumping the schema:
 *   - Add a new `this.version(N).stores({ ... })` call (Dexie chains
 *     versions; never mutate an existing one).
 *   - Reflect the new shapes in the `Table<…>` declarations below.
 */
export class KonvoDb extends Dexie {
  readonly identity!: Table<IdentityRow, 'me'>;
  readonly prekeys!: Table<PreKeyRow, number>;
  readonly aesKwKeys!: Table<AesKwKeyRow, 'me'>;
  readonly remoteIdentities!: Table<RemoteIdentityRow, string>;
  readonly sessions!: Table<SessionRow, string>;
  readonly threads!: Table<ThreadRow, string>;
  readonly messages!: Table<MessageRow, number>;
  readonly outbox!: Table<OutboxRow, number>;
  readonly rooms!: Table<RoomRow, string>;
  readonly roomPosts!: Table<RoomPostRow, string>;
  readonly localAttachments!: Table<LocalAttachmentRow, number>;

  constructor(name = 'konvo') {
    super(name);
    // Version 1: identity + prekeys + aesKwKeys (task 2.9).
    //
    // Index notes:
    //   - `identity:  'id'`          single-row, primary key 'id'.
    //   - `prekeys:   '++id, keyType, keyId, used, [keyType+used]'`
    //       The compound `[keyType+used]` index turns
    //       "count unused OPKs" into a bounded range scan rather than a
    //       full-table walk, satisfying the latency expectation for
    //       `listUnusedOneTimePreKeyCount` on devices with many used keys.
    //   - `aesKwKeys: 'id'`          single-row, primary key 'id'.
    this.version(1).stores({
      identity: 'id',
      prekeys: '++id, keyType, keyId, used, [keyType+used]',
      aesKwKeys: 'id',
    });

    // Version 2: add `remoteIdentities` for TOFU bookkeeping (task
    // 4.8). The `peerUserId` index supports "list all peer devices for
    // this user" queries when the UI needs to render a per-peer
    // safety-number screen across a multi-device peer.
    //
    // Bumping rather than mutating v1 is required by Dexie's migration
    // contract: each `version(N).stores({...})` call defines the
    // *delta* from the previous version, and existing v1 databases
    // upgrade by adding the new store with no data loss.
    this.version(2).stores({
      identity: 'id',
      prekeys: '++id, keyType, keyId, used, [keyType+used]',
      aesKwKeys: 'id',
      remoteIdentities: '&id, peerUserId, peerDeviceId',
    });

    // Version 3: add `sessions` for Double-Ratchet persistence (task
    // 4.4). Indices:
    //   - `&id` is the synthetic `${peerUserId}:${peerDeviceId}`
    //     composite primary key.
    //   - `peerUserId` supports "list all sessions for this user"
    //     queries (e.g. revoking every session when a peer device
    //     is removed; or rotating sessions after a TOFU re-accept).
    //   - `peerDeviceId` supports per-device revocation flows that
    //     don't carry the user id (e.g. server-pushed device
    //     deletion notifications).
    //   - `[peerUserId+peerDeviceId]` keeps a compound index for
    //     direct-tuple lookups; functionally equivalent to the
    //     `&id` composite but lets future code that doesn't yet
    //     have the synthetic id pre-computed run an indexed `.where`
    //     instead of a primary-key `.get`. Cheap to maintain and
    //     forward-compatible.
    //
    // Per Dexie's migration contract, this re-declares the prior
    // stores so v1/v2 databases upgrade cleanly to v3 without losing
    // data in the existing tables.
    this.version(3).stores({
      identity: 'id',
      prekeys: '++id, keyType, keyId, used, [keyType+used]',
      aesKwKeys: 'id',
      remoteIdentities: '&id, peerUserId, peerDeviceId',
      sessions: '&id, peerUserId, peerDeviceId, [peerUserId+peerDeviceId]',
    });

    // Version 4: add `threads`, `messages`, and `outbox` for DM
    // state and offline-send queueing (task 3.7). Indices:
    //   - `threads`:  `&peerUserId, lastMessageAt` — `peerUserId`
    //     is the primary key (matches the §11 keying intent of
    //     "one row per peer thread"); `lastMessageAt` supports
    //     "thread list ordered by recency" without a full table
    //     scan.
    //   - `messages`: `++id, threadId, clientNonce, createdAt,
    //     [threadId+createdAt]` — the auto-id keeps inserts
    //     cheap; the compound `[threadId+createdAt]` index makes
    //     "latest N messages in this thread" an indexed range
    //     scan; `clientNonce` is unique-ish per outbound message
    //     (we rely on the outbox's unique `&clientNonce` index
    //     for the dedup invariant; the messages table's own
    //     index is non-unique to allow for future replays of the
    //     same nonce on separate threads, e.g. fan-out to
    //     multiple devices).
    //   - `outbox`:   `++id, &clientNonce, enqueuedAt` — primary
    //     key ASC is the FIFO replay order; `&clientNonce` is a
    //     unique index so `enqueue(envelope)` can detect a
    //     re-enqueue of the same nonce idempotently and the
    //     `ENVELOPE_QUEUED` handler can find-and-delete by
    //     nonce in O(1); `enqueuedAt` is indexed for the 7-day
    //     age sweep.
    //
    // Per Dexie's migration contract, this re-declares the
    // prior stores so v1/v2/v3 databases upgrade cleanly to v4
    // without losing data in the existing tables.
    this.version(4).stores({
      identity: 'id',
      prekeys: '++id, keyType, keyId, used, [keyType+used]',
      aesKwKeys: 'id',
      remoteIdentities: '&id, peerUserId, peerDeviceId',
      sessions: '&id, peerUserId, peerDeviceId, [peerUserId+peerDeviceId]',
      threads: '&peerUserId, lastMessageAt',
      messages: '++id, threadId, clientNonce, createdAt, [threadId+createdAt]',
      outbox: '++id, &clientNonce, enqueuedAt',
    });

    // Version 5: add `rooms` and `roomPosts` for the broadcast-room
    // UI (task 7.4). Indices:
    //   - `rooms`: `&slug, lastSeenAt` — primary key is the slug
    //     (matches the §11 sketch and the public `/r/:slug` route).
    //     `subscribed` is non-indexed because the room list is
    //     small enough to filter in JS; if cardinality grows a
    //     future patch can add `[subscribed+createdAt]`.
    //   - `roomPosts`: `&id, roomSlug, postId, createdAt,
    //     [roomSlug+createdAt]` — `id` is the synthetic
    //     `${roomSlug}:${postId}` composite primary key (so
    //     `put`/`get` is a single-string lookup); `roomSlug` plus
    //     the compound `[roomSlug+createdAt]` index makes "latest
    //     N posts in this room" an indexed range scan; `postId`
    //     is indexed so the WS-fanout handler can detect
    //     "post we already saw via REST history" idempotently.
    //
    // Per Dexie's migration contract this re-declares every
    // prior store so v1..v4 databases upgrade cleanly to v5
    // without losing data in the existing tables.
    this.version(5).stores({
      identity: 'id',
      prekeys: '++id, keyType, keyId, used, [keyType+used]',
      aesKwKeys: 'id',
      remoteIdentities: '&id, peerUserId, peerDeviceId',
      sessions: '&id, peerUserId, peerDeviceId, [peerUserId+peerDeviceId]',
      threads: '&peerUserId, lastMessageAt',
      messages: '++id, threadId, clientNonce, createdAt, [threadId+createdAt]',
      outbox: '++id, &clientNonce, enqueuedAt',
      rooms: '&slug, createdAt',
      roomPosts: '&id, roomSlug, postId, createdAt, [roomSlug+createdAt]',
    });

    // Version 6: add `localAttachments` for the LRU-bounded
    // attachment cache (task 5.3). Indices:
    //   - `++id` is the auto-incremented primary key. Dexie's
    //     monotonic insertion order doubles as a stable tie-breaker
    //     when the eviction planner sees multiple rows sharing the
    //     same `lastAccessedAt`.
    //   - `&attachmentId` is the unique business key. Lookups by
    //     `AttachmentRef.attachmentId` (the routine "do we already
    //     have this download cached?" check) hit this index in
    //     O(log n) without scanning.
    //   - `lastAccessedAt` is indexed because the LRU eviction loop
    //     iterates rows in `lastAccessedAt` ASC order, summing
    //     `sizeBytes` until the residual footprint fits inside the
    //     200 MiB cap. An indexed range scan is cheaper than a
    //     full-table sort.
    //
    // Per Dexie's migration contract this re-declares every prior
    // store so v1..v5 databases upgrade cleanly to v6 without
    // losing data in the existing tables.
    this.version(6).stores({
      identity: 'id',
      prekeys: '++id, keyType, keyId, used, [keyType+used]',
      aesKwKeys: 'id',
      remoteIdentities: '&id, peerUserId, peerDeviceId',
      sessions: '&id, peerUserId, peerDeviceId, [peerUserId+peerDeviceId]',
      threads: '&peerUserId, lastMessageAt',
      messages: '++id, threadId, clientNonce, createdAt, [threadId+createdAt]',
      outbox: '++id, &clientNonce, enqueuedAt',
      rooms: '&slug, createdAt',
      roomPosts: '&id, roomSlug, postId, createdAt, [roomSlug+createdAt]',
      localAttachments: '++id, &attachmentId, lastAccessedAt',
    });
  }
}

/**
 * Process-wide singleton. Tests should construct their own `KonvoDb`
 * instance with a unique name so they don't collide on the shared `'konvo'`
 * IndexedDB database.
 */
export const db: KonvoDb = new KonvoDb();

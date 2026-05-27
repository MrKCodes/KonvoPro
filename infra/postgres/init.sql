-- Konvo Platform — Postgres bootstrap migration
--
-- This script realizes the schema documented in design.md §4 and is the
-- single source of truth for the initial database layout. It is mounted
-- into the postgres container at /docker-entrypoint-initdb.d/init.sql so
-- a fresh volume gets the schema on first boot, AND it is also executed
-- at API_Gateway startup by apps/api/src/db/migrate.ts so reruns,
-- upgrades, and CI environments converge to the same state.
--
-- Idempotency requirements (Requirement 17.2 + 17.8):
--   - Every CREATE uses IF NOT EXISTS so re-running is a no-op.
--   - Migrations run inside a single transaction in migrate.ts; on any
--     error the transaction rolls back and the API refuses to listen.
--
-- Validation rules from design.md §4 are enforced at the application
-- layer (handle regex, identity_pub length, prekey replenish trigger,
-- ciphertext size cap, broadcast body size, push endpoint scheme).
-- Only structural CHECKs land here.

BEGIN;

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
-- citext: case-insensitive handles + room slugs.
-- pgcrypto: gen_random_uuid() for UUID primary keys.
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    handle        CITEXT       UNIQUE NOT NULL,
    password_hash TEXT         NOT NULL,                  -- Argon2id (Phase 1)
    totp_secret   TEXT,                                   -- nullable; encrypted at rest
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- refresh_tokens (Phase 1, task 2.2)
-- ---------------------------------------------------------------------------
-- Authored here as part of the bootstrap so task 2.2 has the table ready.
-- token_hash stores SHA-256 of the opaque 256-bit refresh token; UNIQUE so
-- replay/rotation collisions surface as integrity violations rather than
-- silent overwrites.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  BYTEA        NOT NULL UNIQUE,
    issued_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    rotated_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens(user_id);

-- ---------------------------------------------------------------------------
-- devices
-- ---------------------------------------------------------------------------
-- One row per browser per user. The 5-device cap (design.md §4 / req 2.7)
-- is enforced in the application layer at /devices.
CREATE TABLE IF NOT EXISTS devices (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT         NOT NULL,
    identity_pub    BYTEA        NOT NULL,            -- Curve25519 (32 bytes; checked in app layer)
    signed_prekey   JSONB        NOT NULL,            -- { keyId, publicKey, signature, createdAt }
    registration_id INT          NOT NULL,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices(user_id);

-- Phase-1 placeholder: dual-key identity (see packages/crypto/src/identity.ts
-- header). Each device carries a parallel Ed25519 identity public key
-- alongside its X25519 identity_pub so the API can verify Ed25519
-- signatures (signed-prekey signatures, broadcast post signatures) without
-- XEdDSA derivation. Task 4.x will collapse this back to a single
-- libsignal-managed key. ALTER ... ADD COLUMN IF NOT EXISTS is supported
-- since Postgres 9.6 and keeps this migration idempotent across reruns.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS identity_ed_pub BYTEA;

-- ---------------------------------------------------------------------------
-- one_time_prekeys
-- ---------------------------------------------------------------------------
-- Atomic OPK consumption (design.md §9 / req 3.5) is implemented as a
-- single UPDATE ... WHERE used = FALSE RETURNING ... at the application
-- layer; the partial index below keeps that scan cheap.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id          BIGSERIAL    PRIMARY KEY,
    device_id   UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      INT          NOT NULL,
    public_key  BYTEA        NOT NULL,
    used        BOOLEAN      NOT NULL DEFAULT FALSE,
    UNIQUE (device_id, key_id)
);
CREATE INDEX IF NOT EXISTS prekeys_device_unused_idx
    ON one_time_prekeys(device_id)
    WHERE used = FALSE;

-- ---------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------
-- Abstract DM thread between an unordered pair of users. The CHECK
-- enforces canonical ordering so (a, b) and (b, a) collapse to a single
-- row via the UNIQUE(user_a, user_b) constraint.
CREATE TABLE IF NOT EXISTS sessions (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_a     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (user_a < user_b),
    UNIQUE (user_a, user_b)
);

-- ---------------------------------------------------------------------------
-- ciphertext_envelopes
-- ---------------------------------------------------------------------------
-- Opaque ciphertext only. The server is a blind router (design.md §1.2);
-- no plaintext column ever lands here. The partial index accelerates the
-- offline-replay scan in apps/api/src/ws/redis-fanout.ts (task 3.5).
CREATE TABLE IF NOT EXISTS ciphertext_envelopes (
    id               BIGSERIAL    PRIMARY KEY,
    session_id       UUID         NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    sender_device    UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_device UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ciphertext       BYTEA        NOT NULL,
    type             SMALLINT     NOT NULL,            -- EnvelopeRouterType (1=MESSAGE, 2=ACK, 3=CALL)
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    delivered_at     TIMESTAMPTZ,
    read_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS env_recipient_undelivered_idx
    ON ciphertext_envelopes(recipient_device, created_at)
    WHERE delivered_at IS NULL;

-- Phase-2 task 3.4 — idempotency key for SEND_ENVELOPE retries.
--
-- Requirement 12.9 / property P13: repeated SEND_ENVELOPE requests with
-- the same `(senderDeviceId, clientNonce)` MUST result in exactly one
-- `ciphertext_envelopes` row and exactly one fan-out publish; subsequent
-- attempts return the original envelopeId. We enforce this at the
-- storage layer with a UNIQUE index on `(sender_device, client_nonce)`
-- so the database — not the application — is authoritative for
-- deduplication. The 24h-minimum window from Requirement 12.9 is
-- automatically satisfied because rows are retained indefinitely.
--
-- The column is nullable to remain backwards-compatible with rows
-- inserted before this migration landed (e.g. anything from the
-- pre-task-3.4 plaintext DM dev path). Postgres treats NULLs as
-- distinct in a UNIQUE index by default (NULLS DISTINCT, the only
-- option pre-PG15), so multiple legacy rows with `client_nonce IS
-- NULL` do not collide. Every new insert from `onSendEnvelope` must
-- supply a non-empty nonce.
ALTER TABLE ciphertext_envelopes
    ADD COLUMN IF NOT EXISTS client_nonce TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS env_sender_nonce_uniq
    ON ciphertext_envelopes(sender_device, client_nonce);

-- ---------------------------------------------------------------------------
-- attachments
-- ---------------------------------------------------------------------------
-- Stores ciphertext blob metadata. The AES-GCM key + IV + tag travel
-- inside an E2EE envelope (design.md §3.3 / §6.1 AttachmentRef), so the
-- columns here only hold what's needed for retrieval and integrity.
CREATE TABLE IF NOT EXISTS attachments (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user  UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blob_key    TEXT         NOT NULL,                -- MinIO object key
    content_iv  BYTEA        NOT NULL,
    content_tag BYTEA        NOT NULL,
    size_bytes  BIGINT       NOT NULL,
    mime        TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Phase-4 task 5.2 — owning device + recipient ACL columns.
--
-- Server-side authorization on `GET /attachments/:id` (Requirement 6.7)
-- must reject any caller who is neither the owner nor an envelope
-- recipient. The envelope payloads that reference an attachment are
-- E2EE-encrypted, so the API_Gateway cannot inspect them to discover
-- which devices/users will receive the AttachmentRef. We therefore
-- persist an ACL alongside the attachment at upload time:
--
--   owner_device_id           — the uploading device, used for
--                               correlation in audit logs.
--   allowed_recipient_user_ids — array of user UUIDs the uploader
--                               declares as permitted readers. The
--                               route's authorization check accepts
--                               any caller whose `userId` matches
--                               `owner_user` OR appears in this array.
--
-- Both columns are nullable to remain backwards-compatible with rows
-- inserted before this migration landed. New uploads via
-- apps/api/src/routes/attachments.ts always populate them.
ALTER TABLE attachments
    ADD COLUMN IF NOT EXISTS owner_device_id UUID REFERENCES devices(id) ON DELETE SET NULL;
ALTER TABLE attachments
    ADD COLUMN IF NOT EXISTS allowed_recipient_user_ids UUID[] NOT NULL DEFAULT ARRAY[]::UUID[];

-- ---------------------------------------------------------------------------
-- broadcast_rooms
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS broadcast_rooms (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        CITEXT       UNIQUE NOT NULL,
    name        TEXT         NOT NULL,
    description TEXT,
    owner_user  UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- broadcast_members
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS broadcast_members (
    room_id  UUID  NOT NULL REFERENCES broadcast_rooms(id) ON DELETE CASCADE,
    user_id  UUID  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT  NOT NULL CHECK (role IN ('admin', 'subscriber')),
    PRIMARY KEY (room_id, user_id)
);

-- ---------------------------------------------------------------------------
-- broadcast_messages
-- ---------------------------------------------------------------------------
-- Plaintext bodies are intentional: broadcast rooms are public by design
-- (design.md §1.2). Authenticity is provided by author_signature, an
-- Ed25519 signature over (body || room_id || created_at) by the author's
-- identity key (verified client-side, design.md §3.4).
CREATE TABLE IF NOT EXISTS broadcast_messages (
    id               BIGSERIAL    PRIMARY KEY,
    room_id          UUID         NOT NULL REFERENCES broadcast_rooms(id) ON DELETE CASCADE,
    author_user      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body             TEXT         NOT NULL,
    author_signature BYTEA        NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS bmsg_room_created_idx
    ON broadcast_messages(room_id, created_at DESC);

-- Phase-6 addition (task 7.2): each broadcast post records the AUTHOR'S
-- DEVICE so viewers can verify the Ed25519 signature against the right
-- per-device identity public key. Per packages/crypto/src/identity.ts a
-- user has a per-device Ed25519 keypair; without `author_device` the
-- server cannot disambiguate which key to surface in the BroadcastPost
-- wire shape. ALTER ... ADD COLUMN IF NOT EXISTS keeps this migration
-- idempotent. The column is nullable to remain backwards-compatible with
-- any pre-existing rows; new inserts via apps/api/src/routes/broadcast.ts
-- always populate it (the route looks up the device's Ed25519 pubkey
-- before signature verification and the column receives that device's id).
ALTER TABLE broadcast_messages
    ADD COLUMN IF NOT EXISTS author_device UUID REFERENCES devices(id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- push_subscriptions
-- ---------------------------------------------------------------------------
-- HTTPS endpoint validation lives in the application layer (design.md §4).
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id  UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    endpoint   TEXT         NOT NULL,
    p256dh     TEXT         NOT NULL,
    auth       TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMIT;

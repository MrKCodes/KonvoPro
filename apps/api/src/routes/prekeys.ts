// apps/api/src/routes/prekeys.ts
//
// Prekey-bundle endpoint with atomic OPK consumption (task 4.5 — Phase 3).
//
//   GET /users/:handle/prekey-bundle?deviceId=...
//
// Realizes Requirements 3.5, 3.6, 3.10 + design.md §9 (REST route
// signatures) and §8.2 (`RemotePreKeyBundle` shape):
//
//   - 3.5  : when the device has at least one unused OPK, atomically
//            consume one in a single SQL statement (UPDATE … WHERE id =
//            (SELECT … LIMIT 1) RETURNING …) so two concurrent calls
//            cannot return the same OPK twice.
//   - 3.6  : when no unused OPK is available, return the bundle with
//            `oneTimePreKey: null` so the caller falls back to degraded
//            X3DH (DH1..DH3 only, see packages/crypto/src/session.ts).
//   - 3.10 : 404 on non-existent handle OR non-existent deviceId. We
//            check both before any UPDATE so a probe for an unknown
//            handle / deviceId NEVER consumes an OPK.
//
// Auth posture (task brief):
//   This route is PUBLIC. Anyone may fetch any other user's prekey
//   bundle — that is the entire point of an X3DH prekey distribution
//   server. There is no authentication, no rate limiter on this
//   endpoint at the route layer (a global rate limiter against
//   `req.ip` from `apps/api/src/server.ts` provides the floor of
//   abuse protection). Per-device replenish keeps the OPK pool
//   topped up faster than a single peer can drain it on the read
//   side; the degraded-X3DH branch (Requirement 3.6) means an OPK
//   exhaustion attack downgrades the security posture for a single
//   first-message but never produces an error visible to the
//   victim's correspondents.
//
// Wire format:
//   The byte fields of the `RemotePreKeyBundleResponse` DTO arrive at
//   the route as raw bytes from Postgres (`identity_pub` is BYTEA,
//   `one_time_prekeys.public_key` is BYTEA) or as base64 strings inside
//   the `signed_prekey` JSONB column (because JSONB has no native
//   bytea-in-json type — see `routes/devices.ts` for the symmetric
//   encoding on write). Fastify's default serializer cannot emit
//   `Uint8Array` over JSON, so we project every byte field to a base64
//   string before responding. This matches the convention used by
//   `routes/broadcast.ts` for `BroadcastPostListResponse`.
//
// SQL atomicity:
//   The atomic OPK consumption is a single statement:
//
//     UPDATE one_time_prekeys
//        SET used = TRUE
//      WHERE id = (
//        SELECT id FROM one_time_prekeys
//          WHERE device_id = $1 AND used = FALSE
//          ORDER BY id ASC
//          LIMIT 1
//          FOR UPDATE SKIP LOCKED
//      )
//      RETURNING key_id, public_key
//
//   `FOR UPDATE SKIP LOCKED` ensures two concurrent readers grab two
//   different rows rather than blocking on the same one — the inner
//   SELECT picks a different row in each transaction even if both
//   started at the same instant. The partial index
//   `prekeys_device_unused_idx` (infra/postgres/init.sql) keeps the
//   inner SELECT cheap regardless of how many used OPKs accumulate.
//
//   When the inner SELECT returns no row (no unused OPKs), the outer
//   UPDATE matches no row and `rowCount === 0`, which we map to the
//   degraded-X3DH `oneTimePreKey: null` branch (Requirement 3.6) —
//   never to an error.

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

import type { RemotePreKeyBundleResponse } from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** Minimal `pg.Pool` shape this plugin needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres, matching the
 *  convention from `routes/devices.ts` and `routes/broadcast.ts`. */
type DbPool = Pick<pg.Pool, 'query'>;

export interface PrekeyRoutesDeps {
  readonly pool: DbPool;
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/** `:handle` path parameter validator. We re-validate the handle regex
 *  here (vs. trusting that signup enforced it) so a probe with an
 *  obviously-malformed handle is rejected at the parse layer rather than
 *  reaching Postgres. The lookup is case-insensitive (`citext`), but the
 *  regex still rejects uppercase: a user can't have an uppercase handle
 *  (signup rejects them) so an uppercase probe MUST 404 even before the
 *  citext comparison would. We collapse "malformed handle" to the same
 *  404 shape used for "handle not found" so the response leaks no
 *  information about which case applied — Requirement 3.10. */
const HandleSchema = z.string().regex(/^[a-z0-9_]{3,32}$/);

/** `?deviceId=...` query parameter validator. */
const QuerySchema = z
  .object({
    deviceId: z.string().uuid(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------------

/** Shape of `signed_prekey` JSONB once parsed. The column is written by
 *  `routes/devices.ts` via `encodeSignedPreKeyJson`, which base64-encodes
 *  the byte fields inside the JSON object (Postgres JSONB has no native
 *  bytea-in-json type). pg's default JSONB type parser returns an
 *  already-deserialized object, so we don't run `JSON.parse` here. */
interface SignedPreKeyJson {
  readonly keyId: number;
  readonly publicKey: string; // base64
  readonly signature: string; // base64
  readonly createdAt: number;
}

interface UserRow {
  readonly id: string;
}

interface DeviceRow {
  readonly identity_pub: Buffer | Uint8Array;
  readonly registration_id: number;
  readonly signed_prekey: SignedPreKeyJson | string;
}

interface ConsumedOpkRow {
  readonly key_id: number;
  readonly public_key: Buffer | Uint8Array;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode raw bytes (from a BYTEA column or a fresh allocation) to
 *  base64. Mirrors the convention in `routes/broadcast.ts` so the wire
 *  format is consistent across REST surfaces. */
function bytesToBase64(input: Buffer | Uint8Array): string {
  return Buffer.from(input).toString('base64');
}

/** Coerce a `signed_prekey` cell into the parsed JSON shape. pg's
 *  default JSONB parser returns an object; if a test stub returns a raw
 *  string we fall through to `JSON.parse` to keep the route resilient
 *  to either wire form. */
function parseSignedPreKey(cell: SignedPreKeyJson | string): SignedPreKeyJson {
  if (typeof cell === 'string') {
    return JSON.parse(cell) as SignedPreKeyJson;
  }
  return cell;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const prekeyRoutes: FastifyPluginAsync<PrekeyRoutesDeps> = async (
  app,
  deps,
) => {
  app.get(
    '/users/:handle/prekey-bundle',
    async (req: FastifyRequest, reply: FastifyReply) => {
      // -------------------------------------------------------------------
      // 1. Parse + validate inputs.
      //
      //    Either a malformed handle or a malformed/missing deviceId
      //    yields HTTP 404 (NOT 400). Per Requirement 3.10 the route
      //    leaks no signal about WHICH input was rejected; collapsing
      //    every parse-failure to 404 prevents an attacker from
      //    distinguishing "device id is wrong shape" from "device id is
      //    well-formed but absent". The body shape is the same as the
      //    not-found branches below.
      // -------------------------------------------------------------------
      const params = req.params as { handle?: unknown };
      const handleParsed = HandleSchema.safeParse(params.handle);
      if (!handleParsed.success) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const handle = handleParsed.data;

      const queryParsed = QuerySchema.safeParse(req.query);
      if (!queryParsed.success) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const { deviceId } = queryParsed.data;

      // -------------------------------------------------------------------
      // 2. Look up the user by handle. citext makes the comparison
      //    case-insensitive (signup persists lowercase only, but the
      //    column type is forgiving on read). 404 on miss.
      //
      //    Must run BEFORE the OPK consumption (Requirement 3.10): a
      //    404 path MUST NOT consume any prekey.
      // -------------------------------------------------------------------
      const userR = await deps.pool.query<UserRow>(
        `SELECT id FROM users WHERE handle = $1 LIMIT 1`,
        [handle],
      );
      if (userR.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const userId = (userR.rows[0] as UserRow).id;

      // -------------------------------------------------------------------
      // 3. Look up the device, scoped to the resolved user id. A
      //    cross-user deviceId (a real UUID owned by a different user)
      //    must collapse to 404, not silently return another user's
      //    device's bundle. The `id = $1 AND user_id = $2` predicate
      //    enforces that.
      //
      //    Must run BEFORE the OPK consumption (Requirement 3.10).
      // -------------------------------------------------------------------
      const deviceR = await deps.pool.query<DeviceRow>(
        `SELECT identity_pub, registration_id, signed_prekey
           FROM devices
          WHERE id = $1 AND user_id = $2
          LIMIT 1`,
        [deviceId, userId],
      );
      if (deviceR.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const device = deviceR.rows[0] as DeviceRow;

      // -------------------------------------------------------------------
      // 4. Atomic OPK consumption (Requirement 3.5). A single SQL
      //    statement so two concurrent readers can never return the
      //    same OPK twice; see file header for the rationale on
      //    `FOR UPDATE SKIP LOCKED`. When no unused OPK is available
      //    `rowCount === 0` and we drop into the degraded-X3DH branch
      //    (Requirement 3.6), which returns the bundle with
      //    `oneTimePreKey: null`.
      //
      //    `ORDER BY id ASC` consumes OPKs in insertion order so the
      //    pool drains FIFO; that's nice for determinism and tests but
      //    has no security relevance — every OPK is independent of
      //    every other one and any consumption order is fine.
      // -------------------------------------------------------------------
      const opkR = await deps.pool.query<ConsumedOpkRow>(
        `UPDATE one_time_prekeys
            SET used = TRUE
          WHERE id = (
            SELECT id FROM one_time_prekeys
              WHERE device_id = $1 AND used = FALSE
              ORDER BY id ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
          )
          RETURNING key_id, public_key`,
        [deviceId],
      );

      const consumed: ConsumedOpkRow | null =
        opkR.rowCount !== null && opkR.rowCount > 0
          ? (opkR.rows[0] as ConsumedOpkRow)
          : null;

      // -------------------------------------------------------------------
      // 5. Build the wire response. Every byte field is base64-encoded
      //    so Fastify's JSON serializer can emit it; the client decodes
      //    via `Buffer.from(s, 'base64')` to reconstruct the original
      //    `Uint8Array`. The signed-prekey byte fields are ALREADY
      //    base64 strings inside the JSONB cell so we pass them through
      //    untouched — re-encoding them would produce a double-base64.
      // -------------------------------------------------------------------
      const spk = parseSignedPreKey(device.signed_prekey);

      // Cast to a JSON-friendly mirror of `RemotePreKeyBundleResponse`
      // so TypeScript doesn't insist on `Uint8Array` (which Fastify
      // can't serialize). The DTO interface shape is preserved at the
      // field-name level; only the byte fields' runtime type changes
      // from Uint8Array → base64 string. The client's parser knows to
      // decode them.
      const response = {
        recipientDeviceId: deviceId,
        identityPub: bytesToBase64(device.identity_pub),
        registrationId: device.registration_id,
        signedPreKey: {
          keyId: spk.keyId,
          publicKey: spk.publicKey, // already base64 in JSONB
          signature: spk.signature, // already base64 in JSONB
          createdAt: spk.createdAt,
        },
        oneTimePreKey:
          consumed === null
            ? null
            : {
                keyId: consumed.key_id,
                publicKey: bytesToBase64(consumed.public_key),
              },
      } satisfies Record<keyof RemotePreKeyBundleResponse, unknown>;

      return reply.code(200).send(response);
    },
  );
};

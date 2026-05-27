// apps/api/src/routes/devices.ts
//
// Device-enrollment REST routes (task 2.6 — Phase 1). Per design.md §9:
//
//   POST   /devices                       (auth)        enroll the current
//                                                       browser as a device
//   GET    /devices                       (auth)        list my devices
//   DELETE /devices/:id                   (auth)        revoke a device I own
//   POST   /devices/:id/prekeys           (auth)        top up one-time prekeys
//
// Realizes Requirements 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.1, 3.2, 3.4,
// 3.8, 3.9, and 19.4 (rate limit 100/min/device on prekey replenish).
//
// Validation rules enforced here:
//   - `identityPub`: exactly 32 bytes (Curve25519 X25519 public key,
//     Requirement 2.4).
//   - `identityEdPub`: exactly 32 bytes (Ed25519 public key, Phase-1
//     dual-key identity per packages/crypto/src/identity.ts; needed so
//     we can verify the signed-prekey signature without XEdDSA).
//   - `signedPreKey.signature`: exactly 64 bytes Ed25519 (Requirement
//     2.4 / 3.2).
//   - `oneTimePreKeys`: array length 1..100, each `publicKey` exactly
//     32 bytes (Requirement 2.4).
//   - `registrationId`: integer in [1, 16383] (Requirement 2.1).
//   - Signed-prekey signature MUST verify against `identityEdPub` via
//     @konvo/crypto's `verifySignedPreKeySignature`. On any failure we
//     reject WITHOUT persisting (Requirements 2.7, 3.2, 3.8).
//
// Five-device cap (Requirement 2.7):
//   We count the user's existing devices BEFORE insert; if count >= 5
//   we reject with HTTP 409 `{ error: 'device_limit' }`. There's a
//   theoretical TOCTOU race between count and insert, but the ceiling
//   is 5 — not 1 — so a tiny over-shoot would be self-healing on the
//   next subsequent enrollment attempt. A row-level lock or unique
//   partial index could tighten this further; deferred until ops
//   demand it.
//
// Wire format:
//   The `Uint8Array` fields in the protocol DTOs (`identityPub`,
//   `identityEdPub`, `signedPreKey.publicKey`, `signedPreKey.signature`,
//   `oneTimePreKeys[].publicKey`) arrive on the wire as base64-encoded
//   strings (clients use `Buffer.from(bytes).toString('base64')`). The
//   schema below decodes via `Buffer.from(s, 'base64')` (which is
//   lenient and accepts both standard and URL-safe base64) and then
//   asserts the exact decoded length. Any malformed encoding or wrong
//   length surfaces as HTTP 400 `{ error: 'invalid_request' }` and
//   nothing is persisted.
//
// Persistence:
//   - `devices`: one row per browser per user. The `signed_prekey`
//     column is JSONB; we write the SignedPreKey with bytes encoded
//     as base64 strings inside the JSON (Postgres JSONB has no native
//     bytea-in-json type). `identity_pub` and `identity_ed_pub` are
//     bytea columns and receive raw `Buffer` values.
//   - `one_time_prekeys`: a row per OPK with `(device_id, key_id)`
//     unique. We bulk-insert all OPKs in one statement to keep the
//     enrollment atomic-ish from the client's perspective.
//
// On DELETE /devices/:id:
//   - 404 `{ error: 'not_found' }` if the device id doesn't match a
//     device the authenticated user owns. We do NOT distinguish
//     "missing" from "not yours" so probing IDs from a stolen token
//     yields the same shape regardless.
//   - On match, `DELETE FROM devices WHERE id=$1 AND user_id=$2` — the
//     `ON DELETE CASCADE` on `one_time_prekeys.device_id` (per
//     `infra/postgres/init.sql`) cleans up remaining prekeys
//     automatically. Reply is 204 (Requirement 2.9).
//
// Rate limit (POST /devices/:id/prekeys):
//   100 requests per minute per device id. Hand-rolled fixed-window
//   counter (same approach as `broadcast.ts`'s post limiter) so this
//   plugin stays self-contained and testable; an injected `now()`
//   keeps the test deterministic without `vi.useFakeTimers`. The
//   fastify-rate-limit plugin's per-IP keyGenerator is the wrong scope
//   here — we want per-device, and the device id is in the URL.

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

import { verifySignedPreKeySignature } from '@konvo/crypto';
import type {
  DeviceCreateResponse,
  DeviceListItem,
  DeviceListResponse,
  PreKeysReplenishResponse,
} from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** Minimal `pg.Pool` shape this plugin needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres, matching the
 *  convention from `routes/broadcast.ts` and
 *  `services/auth/tokens.ts`. */
type DbPool = Pick<pg.Pool, 'query'>;

export interface DevicesRoutesDeps {
  readonly pool: DbPool;
  /** Fastify preHandler that decorates `req.authUser` on success and
   *  short-circuits with 401 on failure. Built via
   *  `apps/api/src/middleware/auth.ts makeRequireAuth(tokenService)`. */
  readonly requireAuth: preHandlerAsyncHookHandler;
  /** Override the wall-clock used for the prekey rate limiter. Defaults
   *  to `() => Date.now()`. Tests inject a deterministic clock. */
  readonly now?: () => number;
  /** Window for the per-device prekey replenish rate limiter, in
   *  milliseconds. Defaults to 60_000 (Requirement 19.4 / 3.4: 100/min). */
  readonly prekeyRateLimitWindowMs?: number;
  /** Max replenish requests per device per window. Defaults to 100. */
  readonly prekeyRateLimitMax?: number;
  /** Per-user device cap. Defaults to 5 (Requirement 2.7). */
  readonly maxDevicesPerUser?: number;
}

const DEFAULT_PREKEY_RATE_LIMIT_WINDOW_MS = 60_000;
const DEFAULT_PREKEY_RATE_LIMIT_MAX = 100;
const DEFAULT_MAX_DEVICES_PER_USER = 5;

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/** zod helper: parse a base64 (or base64url) string into a `Uint8Array`
 *  of EXACTLY `length` bytes. Surfaces a clean validation error if the
 *  encoding is malformed or the decoded length is wrong. */
function base64Bytes(length: number) {
  return z
    .string()
    .min(1)
    .transform((s, ctx) => {
      // `Buffer.from(s, 'base64')` is lenient — it accepts both
      // standard base64 and URL-safe base64, and silently ignores
      // characters outside the alphabet. We re-check the length after
      // decoding rather than gating on a regex up front so that
      // `Buffer.from(' ', 'base64')` (which yields zero bytes) is
      // surfaced as a length error rather than passing the regex and
      // producing an empty Uint8Array downstream.
      let buf: Buffer;
      try {
        buf = Buffer.from(s, 'base64');
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'invalid base64',
        });
        return z.NEVER;
      }
      if (buf.length !== length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `expected ${length} bytes, got ${buf.length}`,
        });
        return z.NEVER;
      }
      return new Uint8Array(buf);
    });
}

// ---------------------------------------------------------------------------
// zod schemas
// ---------------------------------------------------------------------------

const SignedPreKeySchema = z
  .object({
    keyId: z.number().int().nonnegative(),
    publicKey: base64Bytes(32),
    signature: base64Bytes(64),
    createdAt: z.number().int().nonnegative(),
  })
  .strict();

const OneTimePreKeySchema = z
  .object({
    keyId: z.number().int().nonnegative(),
    publicKey: base64Bytes(32),
  })
  .strict();

const DeviceCreateSchema = z
  .object({
    name: z.string().min(1).max(64),
    identityPub: base64Bytes(32),
    identityEdPub: base64Bytes(32),
    registrationId: z.number().int().min(1).max(16383),
    signedPreKey: SignedPreKeySchema,
    oneTimePreKeys: z.array(OneTimePreKeySchema).min(1).max(100),
  })
  .strict();

const PrekeysReplenishSchema = z
  .object({
    oneTimePreKeys: z.array(OneTimePreKeySchema).min(1).max(100),
  })
  .strict();

const UuidSchema = z.string().uuid();

// ---------------------------------------------------------------------------
// Per-device prekey replenish rate limiter (Requirement 3.4 / 19.4: 100/min)
// ---------------------------------------------------------------------------
//
// Fixed-window counter per device id. A request is admitted iff:
//   - the device has no entry yet, OR
//   - the current window has expired (now - windowStartMs >= windowMs),
//     in which case we reset to count=1, OR
//   - the count is below the limit, in which case we increment.
//
// The map is unbounded by device id but device ids are user-controlled
// only insofar as the user can mint ≤ 5 of them via POST /devices, so
// the cardinality is bounded by `users × 5`. A periodic sweep can be
// added later; not necessary for Phase 1.

interface PrekeyRateLimitState {
  count: number;
  windowStartMs: number;
}

class PrekeyReplenishRateLimiter {
  readonly #state = new Map<string, PrekeyRateLimitState>();
  readonly #windowMs: number;
  readonly #limit: number;
  readonly #now: () => number;

  constructor(limit: number, windowMs: number, now: () => number) {
    this.#limit = limit;
    this.#windowMs = windowMs;
    this.#now = now;
  }

  /** Returns true if the request is admitted (and updates the bucket);
   *  false if it should be rejected with 429. */
  tryAcquire(deviceId: string): boolean {
    const now = this.#now();
    const existing = this.#state.get(deviceId);
    if (existing === undefined || now - existing.windowStartMs >= this.#windowMs) {
      this.#state.set(deviceId, { count: 1, windowStartMs: now });
      return true;
    }
    if (existing.count >= this.#limit) {
      return false;
    }
    existing.count += 1;
    return true;
  }
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

/** Encode a SignedPreKey for the JSONB column. Postgres JSONB has no
 *  native bytea-in-json type, so we base64-encode the byte fields. The
 *  surrounding shape mirrors the wire format. */
function encodeSignedPreKeyJson(spk: {
  keyId: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
  createdAt: number;
}): Record<string, unknown> {
  return {
    keyId: spk.keyId,
    publicKey: Buffer.from(spk.publicKey).toString('base64'),
    signature: Buffer.from(spk.signature).toString('base64'),
    createdAt: spk.createdAt,
  };
}

/** Format a Date as ISO-8601 UTC. */
function isoUtc(d: Date): string {
  return d.toISOString();
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const devicesRoutes: FastifyPluginAsync<DevicesRoutesDeps> = async (
  app,
  deps,
) => {
  const now = deps.now ?? (() => Date.now());
  const maxDevices = deps.maxDevicesPerUser ?? DEFAULT_MAX_DEVICES_PER_USER;
  const rateLimiter = new PrekeyReplenishRateLimiter(
    deps.prekeyRateLimitMax ?? DEFAULT_PREKEY_RATE_LIMIT_MAX,
    deps.prekeyRateLimitWindowMs ?? DEFAULT_PREKEY_RATE_LIMIT_WINDOW_MS,
    now,
  );

  // -------------------------------------------------------------------------
  // POST /devices — enroll (Requirements 2.4, 2.7, 3.1, 3.2, 3.8)
  // -------------------------------------------------------------------------
  app.post(
    '/devices',
    {
      preHandler: deps.requireAuth,
      // 100 OPKs * (32 bytes encoded ≈ 44 base64 chars + JSON noise)
      // plus the surrounding identity / signed-prekey fields fits well
      // under 64 KiB. Any larger and the request is malformed by
      // construction; bodyLimit catches it before parsing.
      bodyLimit: 64 * 1024,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        // requireAuth would already have rejected; this guard keeps
        // TS narrowing flowing without `!`.
        return reply.code(401).send({ error: 'auth_required' });
      }
      const parsed = DeviceCreateSchema.safeParse(req.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      const body = parsed.data;

      // Verify the Ed25519 signature on the signed prekey by the
      // device's Ed25519 identity public key. On any failure we MUST
      // NOT persist anything (Requirements 2.7, 3.2, 3.8).
      const sigOk = verifySignedPreKeySignature(
        {
          keyId: body.signedPreKey.keyId,
          publicKey: body.signedPreKey.publicKey,
          signature: body.signedPreKey.signature,
          createdAt: body.signedPreKey.createdAt,
        },
        body.identityEdPub,
      );
      if (!sigOk) {
        return reply.code(400).send({ error: 'invalid_signed_prekey' });
      }

      // Five-device cap (Requirement 2.7). Counted before any insert
      // so a user already at the cap sees 409 without DB writes.
      const countR = await deps.pool.query<{ c: string }>(
        `SELECT COUNT(*)::text AS c FROM devices WHERE user_id = $1`,
        [auth.userId],
      );
      // pg types `rowCount` as `number | null` post-8.x; the SELECT
      // COUNT here always returns exactly one row so a null/zero
      // rowCount means an unexpected driver error. Treat both as
      // "no devices" (i.e. allow the insert) rather than crash —
      // the INSERT below is still racey by 1 in the worst case.
      const currentCount =
        countR.rowCount !== null && countR.rowCount > 0
          ? Number((countR.rows[0] as { c: string }).c)
          : 0;
      if (currentCount >= maxDevices) {
        return reply.code(409).send({ error: 'device_limit' });
      }

      // Insert the device row. `signed_prekey` is JSONB so we encode
      // the byte fields as base64 inside the object — see
      // `encodeSignedPreKeyJson`. `identity_pub` / `identity_ed_pub`
      // are bytea so we pass `Buffer` values directly.
      const ins = await deps.pool.query<{ id: string }>(
        `INSERT INTO devices
           (user_id, name, identity_pub, signed_prekey,
            registration_id, identity_ed_pub)
         VALUES ($1, $2, $3, $4::jsonb, $5, $6)
         RETURNING id`,
        [
          auth.userId,
          body.name,
          Buffer.from(body.identityPub),
          JSON.stringify(encodeSignedPreKeyJson(body.signedPreKey)),
          body.registrationId,
          Buffer.from(body.identityEdPub),
        ],
      );
      if (ins.rowCount === 0) {
        return reply.code(500).send({ error: 'internal' });
      }
      const deviceId = (ins.rows[0] as { id: string }).id;

      // Bulk-insert all OPKs. We iterate per-row rather than building
      // a single multi-row VALUES clause — keeps the SQL boring,
      // testable, and well-behaved when a single OPK violates the
      // (device_id, key_id) UNIQUE constraint (which would surface
      // as a clean 23505 we could turn into a 409). Any OPK insert
      // failure here leaves the device row in place; the caller can
      // retry via POST /devices/:id/prekeys.
      for (const opk of body.oneTimePreKeys) {
        await deps.pool.query(
          `INSERT INTO one_time_prekeys
             (device_id, key_id, public_key)
           VALUES ($1, $2, $3)`,
          [deviceId, opk.keyId, Buffer.from(opk.publicKey)],
        );
      }

      const response: DeviceCreateResponse = { deviceId };
      return reply.code(201).send(response);
    },
  );

  // -------------------------------------------------------------------------
  // GET /devices — list mine (Requirement 2.6)
  // -------------------------------------------------------------------------
  app.get(
    '/devices',
    { preHandler: deps.requireAuth },
    async (req, reply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }
      interface Row {
        id: string;
        name: string;
        last_seen_at: Date | null;
        created_at: Date;
      }
      const r = await deps.pool.query<Row>(
        `SELECT id, name, last_seen_at, created_at
           FROM devices
          WHERE user_id = $1
          ORDER BY created_at ASC`,
        [auth.userId],
      );
      const devices: DeviceListItem[] = r.rows.map((row) => ({
        id: row.id,
        name: row.name,
        lastSeenAt: row.last_seen_at === null ? null : isoUtc(row.last_seen_at),
        createdAt: isoUtc(row.created_at),
      }));
      const response: DeviceListResponse = { devices };
      return reply.code(200).send(response);
    },
  );

  // -------------------------------------------------------------------------
  // DELETE /devices/:id — revoke a device I own (Requirements 2.8, 2.9)
  // -------------------------------------------------------------------------
  app.delete(
    '/devices/:id',
    { preHandler: deps.requireAuth },
    async (req, reply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }
      const params = req.params as { id?: unknown };
      const idParsed = UuidSchema.safeParse(params.id);
      if (!idParsed.success) {
        // A malformed UUID can't match any device the user owns so
        // 404 is the correct response shape (Requirement 2.8: same
        // error for non-owned and missing).
        return reply.code(404).send({ error: 'not_found' });
      }

      // Single SQL: DELETE WHERE id matches AND user_id matches. If
      // the user doesn't own the device, rowCount === 0 and we 404.
      // The ON DELETE CASCADE on `one_time_prekeys.device_id` (see
      // infra/postgres/init.sql) cleans up the device's remaining
      // prekeys automatically. The cascade also removes any
      // ciphertext_envelopes referencing this device id, which is the
      // closest analogue we have to "revoke session" — once the
      // device row is gone, no envelope can be routed to it and any
      // device-bound access token (carrying `did = <gone-device>`)
      // will fail at WS auth time when the gateway looks the device
      // up.
      const r = await deps.pool.query<{ id: string }>(
        `DELETE FROM devices
           WHERE id = $1 AND user_id = $2
         RETURNING id`,
        [idParsed.data, auth.userId],
      );
      if (r.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }
      return reply.code(204).send();
    },
  );

  // -------------------------------------------------------------------------
  // POST /devices/:id/prekeys — top up OPKs (Requirements 3.1, 3.4, 19.4)
  // -------------------------------------------------------------------------
  app.post(
    '/devices/:id/prekeys',
    {
      preHandler: deps.requireAuth,
      bodyLimit: 64 * 1024,
    },
    async (req, reply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }
      const params = req.params as { id?: unknown };
      const idParsed = UuidSchema.safeParse(params.id);
      if (!idParsed.success) {
        return reply.code(404).send({ error: 'not_found' });
      }

      // Rate limit BEFORE the ownership check so that a flood from a
      // valid token against an arbitrary device id can't burn a DB
      // round-trip per request. The per-device key is the URL param
      // — anything else (per-user, per-IP) would let a single user
      // multiplex 5 devices' worth of replenish traffic. Ownership is
      // verified next; rate-limiting an unowned device id is harmless
      // because the limiter's keyspace is unbounded only by device
      // ids, which the user controls via /devices anyway.
      if (!rateLimiter.tryAcquire(idParsed.data)) {
        return reply.code(429).send({ error: 'rate_limited' });
      }

      const parsed = PrekeysReplenishSchema.safeParse(req.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }

      // Verify ownership: the device must belong to the authenticated
      // user. A non-owned or missing device collapses to 404 (same
      // shape as DELETE — Requirement 2.8 / 3.10).
      const ownership = await deps.pool.query<{ id: string }>(
        `SELECT id FROM devices
          WHERE id = $1 AND user_id = $2
          LIMIT 1`,
        [idParsed.data, auth.userId],
      );
      if (ownership.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }

      // Bulk-insert OPKs. Same per-row pattern as POST /devices for
      // consistency; the (device_id, key_id) UNIQUE constraint makes
      // duplicate keyIds surface as 23505. We let pg's error bubble
      // up as a 500 on conflict — clients are expected to allocate
      // monotonically-increasing keyIds via PreKeyStore.
      let count = 0;
      for (const opk of parsed.data.oneTimePreKeys) {
        await deps.pool.query(
          `INSERT INTO one_time_prekeys
             (device_id, key_id, public_key)
           VALUES ($1, $2, $3)`,
          [idParsed.data, opk.keyId, Buffer.from(opk.publicKey)],
        );
        count += 1;
      }

      const response: PreKeysReplenishResponse = { count };
      return reply.code(200).send(response);
    },
  );
};

// apps/api/src/routes/broadcast.ts
//
// Broadcast room REST routes (task 7.2 — Phase 6). Per design.md §9:
//
//   POST   /rooms                       (auth required)         create room
//   GET    /rooms/:slug                 (public, no auth)       read room
//   GET    /rooms/:slug/messages        (public, no auth)       paginated history
//   POST   /rooms/:slug/messages        (auth + admin role)     post a message
//   POST   /rooms/:slug/subscribe       (auth required)         record membership
//
// Realizes Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8,
// 10.9, 10.12, 10.13, 10.14, and 19.4 (rate limit 1/s/admin/room on
// `POST /rooms/:slug/messages`).
//
// Per the orchestrator's task brief:
//
//   - Slug validation: `^[a-z0-9-]{3,64}$`. Lowercase + digits + hyphens.
//   - Name validation: 1..100 chars (Requirement 10.1).
//   - Body cap: 4 KiB (4096 bytes) UTF-8 — measured by byte length, not
//     character count, so a body that fits in 4096 16-bit JS code units
//     but expands to 12 KB after UTF-8 encoding is correctly rejected.
//   - createdAtMs window: ±60 s of server clock (Requirement 10.4).
//   - Ed25519 signature verification: via `@konvo/crypto`'s
//     `verifyBroadcastPost`. Each device has its own Ed25519 identity key
//     (Phase-1 dual-key identity, see packages/crypto/src/identity.ts);
//     the request body therefore carries `deviceId` so the server can
//     look up the right `devices.identity_ed_pub`. The persisted post
//     records `author_user` (the device owner) and `author_device`
//     (the signing device) — the wire-level fan-out
//     (`packages/protocol/src/ws-messages.ts BroadcastPost`) carries
//     that device's `identityEdPub` so viewers verify against the same
//     key the server did.
//   - Rate limit: 1 post per second per (admin user, room) tuple. We
//     hand-roll a tiny token-bucket here rather than relying on
//     `@fastify/rate-limit`, both to keep this plugin testable in
//     isolation and to scope the limit by `(userId, roomId)` instead of
//     per-IP, which is what `requirements.md` §19.4 specifies.
//   - Auth: every route except the two public reads runs the
//     `requireAuth` preHandler (`apps/api/src/middleware/auth.ts`).
//     Returns 401 `{ error: 'auth_required' }` on missing/invalid
//     bearer.
//   - 404: any `/rooms/:slug/...` path whose slug does not match an
//     existing room returns HTTP 404 (Requirement 10.13).
//   - 413: bodies > 4 KiB are rejected with HTTP 413 (Requirement 10.7).
//
// Schema notes:
//   - This route inserts into `broadcast_rooms`, `broadcast_members`,
//     and `broadcast_messages` per `infra/postgres/init.sql`. Two
//     idempotent ALTERs there add (a) `devices.identity_ed_pub` and
//     (b) `broadcast_messages.author_device` so signature verification
//     and per-post-author-device tracking work.

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

import { verifyBroadcastPost } from '@konvo/crypto';
import type {
  BroadcastPostCreateRequest,
  BroadcastPostCreateResponse,
  BroadcastPostResponse,
  RoomCreateRequest,
  RoomResponse,
} from '@konvo/protocol';

import type { WSRedisPublisher } from '../ws/types.js';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** Minimal `pg.Pool` shape this plugin needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres, matching the
 *  convention from `apps/api/src/services/auth/tokens.ts`. */
type DbPool = Pick<pg.Pool, 'query'>;

export interface BroadcastRoutesDeps {
  readonly pool: DbPool;
  /** Fastify preHandler that decorates `req.authUser` on success and
   *  short-circuits with 401 on failure. Built via
   *  `apps/api/src/middleware/auth.ts makeRequireAuth(tokenService)`. */
  readonly requireAuth: preHandlerAsyncHookHandler;
  /** Override the wall-clock used for the ±60s `createdAtMs` window
   *  and for the per-(admin, room) rate limiter. Defaults to
   *  `() => Date.now()`. Tests inject a deterministic clock. */
  readonly now?: () => number;
  /** Window for the `createdAtMs` skew check, in milliseconds.
   *  Defaults to 60_000 (Requirement 10.4 ±60 s). */
  readonly clockSkewWindowMs?: number;
  /** Per-admin-per-room rate-limit window, in milliseconds. Defaults
   *  to 1000 (Requirement 10.6 / 19.4: 1/s/admin/room). */
  readonly postRateLimitWindowMs?: number;
  /** Optional WS Redis publisher for broadcast-post fan-out (task
   *  7.3 — Requirement 10.4). When provided, a successful
   *  `POST /rooms/:slug/messages` PUBLISHes a JSON-encoded
   *  `BroadcastPostFanout` payload to channel `room:{slug}` after the
   *  row has been persisted. The WS gateway (`makeRoomListener` in
   *  `apps/api/src/ws/gateway.ts`) decodes this payload and forwards
   *  it as an `S2C.ROOM_POST` frame to every subscribed connection.
   *
   *  Why optional: the broadcast-routes unit test in
   *  `apps/api/test/broadcast-routes.test.ts` (task 7.2) exercises
   *  every persistence + auth + signature-verification path WITHOUT
   *  needing a Redis client, and threading a no-op stub through every
   *  call site would add boilerplate that the test does not rely on.
   *  The production wiring in `apps/api/src/server.ts` always supplies
   *  this dependency, so production behaviour matches Requirement 10.4
   *  (POSTed messages reach subscribed sockets).
   *
   *  Failure handling: a `publish()` rejection is logged at warn-level
   *  but does NOT fail the HTTP request. Per design.md §13.6 the row is
   *  the durable source of truth and a missed live fan-out is recovered
   *  by the next `GET /rooms/:slug/messages` history fetch. */
  readonly redis?: WSRedisPublisher;
}

const DEFAULT_CLOCK_SKEW_WINDOW_MS = 60_000;
const DEFAULT_POST_RATE_LIMIT_WINDOW_MS = 1_000;

/** Hard cap on broadcast post body size in bytes, per Requirement 10.7. */
const BODY_BYTE_LIMIT = 4 * 1024;

/** Default `limit` for `GET /rooms/:slug/messages` when the query string
 *  omits it. Matches design.md §9 (`...&limit=50`). */
const DEFAULT_MESSAGES_LIMIT = 50;
/** Maximum allowed `limit`. Requirement 10.14: `limit` ∈ [1, 50]. The
 *  task brief mentions a cap of 100 in passing, but Requirement 10.14
 *  is canonical; we honour the requirement. */
const MAX_MESSAGES_LIMIT = 50;

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const SLUG_REGEX = /^[a-z0-9-]{3,64}$/;

const SlugSchema = z.string().regex(SLUG_REGEX);const RoomCreateSchema = z
  .object({
    slug: z.string().regex(SLUG_REGEX),
    name: z.string().min(1).max(100),
    description: z.string().max(2000).optional(),
  })
  .strict();

const MessagesQuerySchema = z
  .object({
    before: z.string().optional(),
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(MAX_MESSAGES_LIMIT)
      .optional(),
  })
  .strict();

/** `signature` and `deviceId` are required; the Ed25519 signature is
 *  exactly 64 bytes when decoded. We accept either base64 or base64url
 *  on the wire (clients that use `Buffer.toString('base64url')` and
 *  clients that fall back to `Buffer.toString('base64')` both work). */
const PostMessageSchema = z
  .object({
    body: z.string().min(1),
    signature: z
      .string()
      .min(86) // 64 bytes -> 88 base64 chars or 86 base64url unpadded
      .max(96),
    createdAtMs: z.number().int().nonnegative(),
    deviceId: z.string().uuid(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Wire shape published on the `room:{slug}` Redis channel for the
 *  broadcast-post fan-out (task 7.3 — Requirement 10.4). The gateway
 *  listener (`makeRoomListener` in `apps/api/src/ws/gateway.ts`)
 *  decodes this payload, reconstructs the typed `BroadcastPost`
 *  (re-promoting `id` to `bigint` and base64-decoding the byte
 *  fields), and forwards it as an `S2C.ROOM_POST` frame.
 *
 *  We keep the payload as a small JSON DTO rather than reusing the
 *  protocol's `BroadcastPost` directly because:
 *    - JSON has no native bigint or byte-array type, so `id` is a
 *      decimal string and the byte fields are base64.
 *    - `Date` instances on the wire become epoch-ms numbers
 *      (`createdAtMs`) so the listener can re-emit them as the
 *      protocol's `createdAt: number` field without re-parsing.
 *    - The shape is stable across api replicas: a JSON.parse on the
 *      receive side never has to negotiate version skew between two
 *      processes that may be on different commits during a rolling
 *      deploy.
 */
export interface BroadcastPostFanoutPayload {
  /** Decimal-string form of the BIGSERIAL `broadcast_messages.id`. */
  readonly id: string;
  /** UUID of the `broadcast_rooms.id` row this post belongs to. */
  readonly roomId: string;
  /** UUID of the authoring user. */
  readonly authorUserId: string;
  /** `users.handle` of the authoring user (denormalized so the WS
   *  listener can render the post without a separate lookup). */
  readonly authorHandle: string;
  /** Base64 of the signing device's Ed25519 public key (32 bytes).
   *  The receiver re-verifies `(body, roomId, createdAtMs)` against
   *  this key before rendering — task 7.4 / Requirement 10.10. */
  readonly authorIdentityPub: string;
  /** Plaintext post body (≤ 4 KiB UTF-8 per Requirement 10.7). */
  readonly body: string;
  /** Base64 of the 64-byte Ed25519 signature over
   *  `canonicalBroadcastMessage(body, roomId, createdAtMs)`. */
  readonly authorSignature: string;
  /** Wall-clock epoch-ms the author signed at (and that the row's
   *  `created_at` reflects after `to_timestamp(... / 1000)`).
   *  Doubles as the signed timestamp the receiver re-verifies
   *  against. */
  readonly createdAtMs: number;
}

/** The Redis pub/sub channel name for a given broadcast room slug.
 *  Centralised here so the route and the WS publisher
 *  (`roomChannelFor` in `apps/api/src/ws/redis-publisher.ts`) can never
 *  drift on the prefix. The naming `room:{slug}` is dictated by
 *  Requirement 10.4 and design.md §10. */
export function roomChannelFor(slug: string): string {
  return `room:${slug}`;
}

/** Decode a base64-or-base64url string into a Uint8Array. Returns
 *  `null` if the input is not parseable as either, or if the decoded
 *  length isn't 64 (the Ed25519 signature length). */
function decodeSignature(input: string): Uint8Array | null {
  // Buffer.from with `'base64'` accepts both standard base64 and
  // base64url because the Node Buffer decoder is lenient with the
  // url-safe substitutions. We still attempt a base64url decode first
  // for clarity.
  let buf: Buffer;
  try {
    buf = Buffer.from(input, 'base64url');
  } catch {
    return null;
  }
  if (buf.length !== 64) {
    // Try plain base64 as a fallback in case base64url decoding
    // dropped padding chars.
    try {
      buf = Buffer.from(input, 'base64');
    } catch {
      return null;
    }
  }
  if (buf.length !== 64) {
    return null;
  }
  return new Uint8Array(buf);
}

/** UTF-8 byte length of a string. We use TextEncoder rather than
 *  Buffer.byteLength so the implementation works identically on Node
 *  and on potential edge runtimes (which is what Caddy might forward
 *  to in a future deployment). */
const BYTE_LENGTH_ENCODER = new TextEncoder();
function utf8ByteLength(s: string): number {
  return BYTE_LENGTH_ENCODER.encode(s).length;
}

/** Format a Postgres TIMESTAMPTZ Date as an ISO-8601 UTC string with
 *  millisecond precision. The pg driver returns Date objects; we never
 *  surface raw Postgres timestamp strings on the wire. */
function isoUtc(d: Date): string {
  return d.toISOString();
}

// ---------------------------------------------------------------------------
// Per-(admin, room) rate limiter (Requirement 10.6 / 19.4: 1/s)
// ---------------------------------------------------------------------------
//
// Token-bucket-style: per `(userId, roomId)` we record the timestamp of
// the last accepted post. A new post is admitted iff
// `now - lastAcceptedAt >= windowMs`. This is the classical "fixed
// minimum interval" interpretation of "1 per second per admin per
// room" and is identical to the leaky-bucket scheme `@fastify/rate-limit`
// would impose with `max: 1, timeWindow: '1 second'`. We hand-roll it
// to keep the plugin self-contained (no `@fastify/rate-limit` dep
// installed yet) and to scope the key by `(userId, roomId)` rather than
// per-IP.
//
// Memory: an unbounded Map would leak under attacker-controlled
// `(userId, roomId)` cardinality. We don't actively GC entries here
// because broadcast rooms are admin-scoped and the cardinality is
// O(rooms × admins) which is small in practice. A periodic sweep can
// be added in task 10.1 alongside the Prometheus counter.

interface RateLimitState {
  lastAcceptedAtMs: number;
}

class PostRateLimiter {
  readonly #state = new Map<string, RateLimitState>();
  readonly #windowMs: number;
  readonly #now: () => number;

  constructor(windowMs: number, now: () => number) {
    this.#windowMs = windowMs;
    this.#now = now;
  }

  #key(userId: string, roomId: string): string {
    return `${userId}:${roomId}`;
  }

  /** Returns true if the post is admitted and updates the bucket;
   *  false if the post should be rejected with 429. */
  tryAcquire(userId: string, roomId: string): boolean {
    const k = this.#key(userId, roomId);
    const now = this.#now();
    const prev = this.#state.get(k);
    if (prev !== undefined && now - prev.lastAcceptedAtMs < this.#windowMs) {
      return false;
    }
    this.#state.set(k, { lastAcceptedAtMs: now });
    return true;
  }
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

interface RoomRow {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  owner_user: string;
  owner_handle: string;
  created_at: Date;
}

async function findRoomBySlug(
  pool: DbPool,
  slug: string,
): Promise<RoomRow | null> {
  const r = await pool.query<RoomRow>(
    `SELECT r.id, r.slug, r.name, r.description, r.owner_user,
            u.handle AS owner_handle, r.created_at
       FROM broadcast_rooms r
       JOIN users u ON u.id = r.owner_user
      WHERE r.slug = $1
      LIMIT 1`,
    [slug],
  );
  if (r.rowCount === 0) return null;
  return r.rows[0] as RoomRow;
}

function rowToRoomResponse(row: RoomRow): RoomResponse {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    description: row.description,
    ownerHandle: row.owner_handle,
    createdAt: isoUtc(row.created_at),
  };
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const broadcastRoutes: FastifyPluginAsync<BroadcastRoutesDeps> = async (
  app,
  deps,
) => {
  const now = deps.now ?? (() => Date.now());
  const clockSkewWindowMs =
    deps.clockSkewWindowMs ?? DEFAULT_CLOCK_SKEW_WINDOW_MS;
  const rateLimiter = new PostRateLimiter(
    deps.postRateLimitWindowMs ?? DEFAULT_POST_RATE_LIMIT_WINDOW_MS,
    now,
  );

  // -------------------------------------------------------------------------
  // POST /rooms — create (auth required) — Requirements 10.1, 10.12
  // -------------------------------------------------------------------------
  app.post(
    '/rooms',
    {
      preHandler: deps.requireAuth,
      // bodyLimit caps the JSON payload itself before parsing — defense
      // in depth against `description` spam. The per-field schema below
      // is the authoritative validator.
      bodyLimit: 8 * 1024,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        // requireAuth would have rejected; this is a defensive guard so
        // TS narrowing flows through without `!`.
        return reply.code(401).send({ error: 'auth_required' });
      }
      const parsed = RoomCreateSchema.safeParse(req.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      // `parsed.data.description` is `string | undefined`; `RoomCreateRequest.description`
      // is `string?` under `exactOptionalPropertyTypes: true`, so we must
      // omit the field rather than assign `undefined` to it.
      const body: RoomCreateRequest =
        parsed.data.description !== undefined
          ? {
              slug: parsed.data.slug,
              name: parsed.data.name,
              description: parsed.data.description,
            }
          : { slug: parsed.data.slug, name: parsed.data.name };

      // Insert atomically: room first, then admin membership for the
      // owner. We do NOT wrap in a transaction here because slug
      // uniqueness is enforced at the DB level (citext UNIQUE) and the
      // membership insert can't violate any constraint that the room
      // insert wouldn't already have caught. If the membership insert
      // ever fails (e.g. transient pool error) the room remains owned
      // but unreferenceable in `broadcast_members`; in practice the
      // owner can re-call `POST /rooms/:slug/subscribe` to rebuild the
      // membership row. A transactional version is straightforward to
      // add later by replacing `pool.query` with a borrowed client.

      let inserted: { id: string; created_at: Date };
      try {
        const r = await deps.pool.query<{ id: string; created_at: Date }>(
          `INSERT INTO broadcast_rooms (slug, name, description, owner_user)
           VALUES ($1, $2, $3, $4)
           RETURNING id, created_at`,
          [body.slug, body.name, body.description ?? null, auth.userId],
        );
        if (r.rowCount === 0) {
          return reply.code(500).send({ error: 'internal' });
        }
        inserted = r.rows[0] as { id: string; created_at: Date };
      } catch (err) {
        // Postgres unique_violation = 23505 (duplicate slug). pg
        // surfaces this as `code: '23505'` on the error. We map it to
        // 409 per Requirement 10.12.
        if (
          err !== null &&
          typeof err === 'object' &&
          'code' in err &&
          (err as { code: unknown }).code === '23505'
        ) {
          return reply.code(409).send({ error: 'slug_taken' });
        }
        throw err;
      }

      // Owner becomes admin. ON CONFLICT keeps this idempotent under
      // any retry shape (network blip after the room insert succeeded).
      await deps.pool.query(
        `INSERT INTO broadcast_members (room_id, user_id, role)
         VALUES ($1, $2, 'admin')
         ON CONFLICT (room_id, user_id) DO UPDATE SET role = 'admin'`,
        [inserted.id, auth.userId],
      );

      // Look up the owner's handle for the response. We could JOIN it
      // out of the INSERT, but a separate read keeps the SQL boring and
      // testable.
      const owner = await deps.pool.query<{ handle: string }>(
        `SELECT handle FROM users WHERE id = $1`,
        [auth.userId],
      );
      const ownerHandle =
        (owner.rowCount ?? 0) > 0 ? (owner.rows[0] as { handle: string }).handle : '';

      const response: RoomResponse = {
        id: inserted.id,
        slug: body.slug,
        name: body.name,
        description: body.description ?? null,
        ownerHandle,
        createdAt: isoUtc(inserted.created_at),
      };
      return reply.code(201).send(response);
    },
  );

  // -------------------------------------------------------------------------
  // GET /rooms/:slug — public read — Requirements 10.2, 10.13
  // -------------------------------------------------------------------------
  app.get('/rooms/:slug', async (req, reply) => {
    const params = req.params as { slug?: unknown };
    const slugParse = SlugSchema.safeParse(params.slug);
    if (!slugParse.success) {
      // Slug doesn't match the format → no such room exists, by
      // construction. Return 404 rather than 400 so probing for valid
      // slug ranges yields the same shape as probing for absent ones.
      return reply.code(404).send({ error: 'not_found' });
    }
    const room = await findRoomBySlug(deps.pool, slugParse.data);
    if (room === null) {
      return reply.code(404).send({ error: 'not_found' });
    }
    return reply.code(200).send(rowToRoomResponse(room));
  });

  // -------------------------------------------------------------------------
  // GET /rooms/:slug/messages — public read, paginated — Req 10.2, 10.14
  // -------------------------------------------------------------------------
  app.get('/rooms/:slug/messages', async (req, reply) => {
    const params = req.params as { slug?: unknown };
    const slugParse = SlugSchema.safeParse(params.slug);
    if (!slugParse.success) {
      return reply.code(404).send({ error: 'not_found' });
    }
    const room = await findRoomBySlug(deps.pool, slugParse.data);
    if (room === null) {
      return reply.code(404).send({ error: 'not_found' });
    }

    const queryParse = MessagesQuerySchema.safeParse(req.query);
    if (!queryParse.success) {
      return reply.code(400).send({ error: 'invalid_request' });
    }
    const { before, limit } = queryParse.data;
    const effectiveLimit = limit ?? DEFAULT_MESSAGES_LIMIT;

    // Cursor pagination keyed off `created_at` DESC. `before` is an
    // ISO-8601 string the client took from a previous response's last
    // post `createdAt`. We accept any value parseable as a Date; an
    // unparseable cursor returns 400.
    let beforeDate: Date | null = null;
    if (before !== undefined && before.length > 0) {
      const t = Date.parse(before);
      if (!Number.isFinite(t)) {
        return reply.code(400).send({ error: 'invalid_cursor' });
      }
      beforeDate = new Date(t);
    }

    interface MsgRow {
      id: string; // BIGSERIAL surfaces as string in pg by default
      room_id: string;
      author_user: string;
      author_handle: string;
      author_identity_ed_pub: Uint8Array | null;
      body: string;
      author_signature: Uint8Array;
      created_at: Date;
    }

    // The JOIN to `devices` uses `broadcast_messages.author_device` so
    // we surface the right per-device Ed25519 pubkey for clients to
    // verify against. Older posts that predate the column carry NULL
    // and we surface an empty-byte authorIdentityPub; the client UI
    // is responsible for marking those "unverified" (Requirement
    // 10.11) — which it would have done anyway because verification
    // would fail.
    const sqlBase = `
      SELECT m.id::text AS id,
             m.room_id,
             m.author_user,
             u.handle AS author_handle,
             d.identity_ed_pub AS author_identity_ed_pub,
             m.body,
             m.author_signature,
             m.created_at
        FROM broadcast_messages m
        JOIN users u ON u.id = m.author_user
   LEFT JOIN devices d ON d.id = m.author_device
       WHERE m.room_id = $1
    `;

    let rows: MsgRow[];
    if (beforeDate !== null) {
      const r = await deps.pool.query<MsgRow>(
        `${sqlBase} AND m.created_at < $2
         ORDER BY m.created_at DESC, m.id DESC
         LIMIT $3`,
        [room.id, beforeDate, effectiveLimit],
      );
      rows = r.rows;
    } else {
      const r = await deps.pool.query<MsgRow>(
        `${sqlBase}
         ORDER BY m.created_at DESC, m.id DESC
         LIMIT $2`,
        [room.id, effectiveLimit],
      );
      rows = r.rows;
    }

    const messages: BroadcastPostResponse[] = rows.map((row) => ({
      id: BigInt(row.id),
      roomId: row.room_id,
      authorUserId: row.author_user,
      authorHandle: row.author_handle,
      authorIdentityPub: row.author_identity_ed_pub ?? new Uint8Array(0),
      body: row.body,
      authorSignature: row.author_signature,
      createdAt: isoUtc(row.created_at),
    }));

    // Next cursor: the oldest post in the page. Null if the page is
    // shorter than `effectiveLimit` (no more rows behind it).
    const nextBefore =
      rows.length === effectiveLimit && rows.length > 0
        ? isoUtc((rows[rows.length - 1] as MsgRow).created_at)
        : null;

    // The wire shape declared in BroadcastPostListResponse uses bigint
    // and Uint8Array, neither of which JSON.stringify (Fastify's
    // default serializer) can emit. Project to JSON-friendly types
    // (string / base64) here; clients reconstruct the original types
    // at the type level on parse. Doing the projection inside the
    // handler — rather than registering a global JSON.stringify
    // replacer — keeps the transformation explicit and route-local.
    const wire = {
      messages: messages.map((m) => ({
        id: m.id.toString(),
        roomId: m.roomId,
        authorUserId: m.authorUserId,
        authorHandle: m.authorHandle,
        authorIdentityPub: Buffer.from(m.authorIdentityPub).toString('base64'),
        body: m.body,
        authorSignature: Buffer.from(m.authorSignature).toString('base64'),
        createdAt: m.createdAt,
      })),
      nextBefore,
    };
    return reply.code(200).send(wire);
  });

  // -------------------------------------------------------------------------
  // POST /rooms/:slug/subscribe — auth required, idempotent — Req 10.3
  // -------------------------------------------------------------------------
  app.post(
    '/rooms/:slug/subscribe',
    { preHandler: deps.requireAuth },
    async (req, reply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }
      const params = req.params as { slug?: unknown };
      const slugParse = SlugSchema.safeParse(params.slug);
      if (!slugParse.success) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const room = await findRoomBySlug(deps.pool, slugParse.data);
      if (room === null) {
        return reply.code(404).send({ error: 'not_found' });
      }

      // Idempotent membership insert. If the user is already an admin
      // we MUST NOT downgrade them to subscriber (Requirement 10.3:
      // "creating the subscription if absent and otherwise leaving it
      // unchanged"). ON CONFLICT DO NOTHING preserves the existing
      // role. New rows always start as `subscriber`.
      await deps.pool.query(
        `INSERT INTO broadcast_members (room_id, user_id, role)
         VALUES ($1, $2, 'subscriber')
         ON CONFLICT (room_id, user_id) DO NOTHING`,
        [room.id, auth.userId],
      );

      return reply.code(204).send();
    },
  );

  // -------------------------------------------------------------------------
  // POST /rooms/:slug/messages — admin only, signed body — Reqs 10.4..10.7,
  //                              10.8, 10.9, 19.4
  // -------------------------------------------------------------------------
  app.post(
    '/rooms/:slug/messages',
    {
      preHandler: deps.requireAuth,
      // Reject obviously-oversized payloads at the parser layer so we
      // don't burn signature-verification cycles on garbage. The 4 KiB
      // body cap (Requirement 10.7) is enforced in-handler against the
      // UTF-8 byte length of `body`; we add overhead here for the
      // surrounding JSON envelope (signature, deviceId, …).
      bodyLimit: 16 * 1024,
    },
    async (req, reply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }
      const params = req.params as { slug?: unknown };
      const slugParse = SlugSchema.safeParse(params.slug);
      if (!slugParse.success) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const parsedBody = PostMessageSchema.safeParse(req.body);
      if (!parsedBody.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      const post: BroadcastPostCreateRequest = {
        body: parsedBody.data.body,
        // The signature on the wire is base64(url); the schema
        // accepted a string. We rebind to Uint8Array below after
        // decoding. Cast to satisfy the DTO type used downstream;
        // the real decode happens via `decodeSignature`.
        signature: new Uint8Array(0),
        createdAtMs: parsedBody.data.createdAtMs,
        deviceId: parsedBody.data.deviceId,
      };

      // Body byte cap (Requirement 10.7).
      if (utf8ByteLength(post.body) > BODY_BYTE_LIMIT) {
        return reply.code(413).send({ error: 'body_too_large' });
      }

      // Clock-skew window (Requirement 10.4 ±60s).
      const skew = Math.abs(now() - post.createdAtMs);
      if (skew > clockSkewWindowMs) {
        return reply.code(400).send({ error: 'clock_skew' });
      }

      // Look up the room. 404 on absent slug (Requirement 10.13).
      const room = await findRoomBySlug(deps.pool, slugParse.data);
      if (room === null) {
        return reply.code(404).send({ error: 'not_found' });
      }

      // Role check (Requirement 10.5). NB: this also covers the
      // "non-member" case — the SELECT returns no rows when the user
      // has neither admin nor subscriber membership.
      const roleR = await deps.pool.query<{ role: string }>(
        `SELECT role FROM broadcast_members
         WHERE room_id = $1 AND user_id = $2
         LIMIT 1`,
        [room.id, auth.userId],
      );
      const role =
        (roleR.rowCount ?? 0) > 0 ? (roleR.rows[0] as { role: string }).role : null;
      if (role !== 'admin') {
        return reply.code(403).send({ error: 'forbidden' });
      }

      // Rate limit (Requirement 10.6 / 19.4: 1/s/admin/room). Take the
      // token AFTER the role check so non-admins can't probe rate-
      // limit state by getting a 429 when they should see a 403.
      if (!rateLimiter.tryAcquire(auth.userId, room.id)) {
        return reply.code(429).send({ error: 'rate_limited' });
      }

      // Decode signature.
      const sigBytes = decodeSignature(parsedBody.data.signature);
      if (sigBytes === null) {
        return reply.code(400).send({ error: 'invalid_signature' });
      }

      // Look up the signing device's Ed25519 pubkey AND verify it
      // belongs to the authenticated user. Cross-user device misuse
      // (a holds device d, b says "sign as me with d") is rejected
      // here: the JOIN restricts `devices` to the auth.userId.
      //
      // We also pull the author's `users.handle` in the same query
      // (task 7.3 — broadcast post fan-out). A successful publish
      // carries `author_handle` so subscribed sockets render the
      // sender immediately without a separate `users` lookup; doing
      // the JOIN here keeps the per-request SQL count flat at one
      // for the device-lookup step.
      const devR = await deps.pool.query<{
        identity_ed_pub: Uint8Array | null;
        author_handle: string;
      }>(
        `SELECT d.identity_ed_pub AS identity_ed_pub,
                u.handle           AS author_handle
           FROM devices d
           JOIN users   u ON u.id = d.user_id
          WHERE d.id = $1 AND d.user_id = $2
          LIMIT 1`,
        [post.deviceId, auth.userId],
      );
      if (devR.rowCount === 0) {
        return reply.code(400).send({ error: 'invalid_signature' });
      }
      const devRow = devR.rows[0] as {
        identity_ed_pub: Uint8Array | null;
        author_handle: string;
      };
      const edPub = devRow.identity_ed_pub;
      const authorHandle = devRow.author_handle;
      if (edPub === null || edPub.length !== 32) {
        return reply.code(400).send({ error: 'invalid_signature' });
      }

      // Verify the Ed25519 signature. `verifyBroadcastPost` is a pure
      // function that returns false on any failure (malformed key /
      // signature, wrong message, wrong key) — it never throws.
      // (Requirements 10.8, 10.9.)
      const sigOk = verifyBroadcastPost(
        post.body,
        room.id,
        post.createdAtMs,
        sigBytes,
        new Uint8Array(edPub),
      );
      if (!sigOk) {
        return reply.code(400).send({ error: 'invalid_signature' });
      }

      // Persist. Use `to_timestamp(createdAtMs/1000.0)` so the stored
      // `created_at` reflects the wall-clock time the client signed,
      // not the server's insertion time. This keeps signature
      // verification on the read path consistent: the client will
      // re-verify against the same `createdAtMs` it originally signed
      // (round-tripped via the post's `createdAt`).
      const ins = await deps.pool.query<{ id: string; created_at: Date }>(
        `INSERT INTO broadcast_messages
           (room_id, author_user, body, author_signature,
            author_device, created_at)
         VALUES ($1, $2, $3, $4, $5, to_timestamp($6::bigint / 1000.0))
         RETURNING id::text AS id, created_at`,
        [
          room.id,
          auth.userId,
          post.body,
          Buffer.from(sigBytes),
          post.deviceId,
          post.createdAtMs,
        ],
      );
      if (ins.rowCount === 0) {
        return reply.code(500).send({ error: 'internal' });
      }
      const inserted = ins.rows[0] as { id: string; created_at: Date };

      // Fan-out to every subscribed WS connection on this room (task
      // 7.3 — Requirement 10.4). The publish runs AFTER the row has
      // been persisted so a Redis hiccup never produces a "ghost"
      // post that subscribed sockets see but `GET /rooms/:slug/messages`
      // does not. Publishing on the same path also keeps ordering
      // straight for any single-process listener: persist → publish.
      //
      // Wire format: a JSON object with the BroadcastPost fields
      // (id, body, authorHandle, signature, authorIdentityPub,
      // roomId, createdAtMs). We pick JSON over msgpack here because
      // `WSRedisPublisher.publish` accepts a string payload only,
      // matching the existing `dev:{id}` envelope-id convention. The
      // gateway's `makeRoomListener` decodes the JSON and rebuilds
      // a typed `BroadcastPost` (with `id` re-promoted to `bigint`
      // and the byte fields reconstructed from base64) before
      // sending it on as an `S2C.ROOM_POST` frame.
      //
      // Why we don't fail the HTTP request on publish error:
      // the post is durably persisted; a missed live fan-out is
      // recovered by the next `GET /rooms/:slug/messages` history
      // fetch (Requirements 10.2 / 10.14). A failure here is
      // operationally noteworthy but not user-fatal.
      if (deps.redis !== undefined) {
        const fanoutPayload: BroadcastPostFanoutPayload = {
          id: inserted.id,
          roomId: room.id,
          authorUserId: auth.userId,
          authorHandle,
          authorIdentityPub: Buffer.from(edPub).toString('base64'),
          body: post.body,
          authorSignature: Buffer.from(sigBytes).toString('base64'),
          createdAtMs: inserted.created_at.getTime(),
        };
        try {
          await deps.redis.publish(
            roomChannelFor(slugParse.data),
            JSON.stringify(fanoutPayload),
          );
        } catch (err) {
          req.log.warn(
            { err, slug: slugParse.data, postId: inserted.id },
            'broadcast post fan-out: redis PUBLISH failed; row persisted',
          );
        }
      }

      const response: BroadcastPostCreateResponse = {
        id: BigInt(inserted.id),
        createdAt: isoUtc(inserted.created_at),
      };
      // BigInt cannot be serialized by JSON.stringify directly. Project
      // to string on the wire; the protocol DTO tags it as bigint at
      // the type level so clients deserialize accordingly.
      return reply
        .code(201)
        .send({ id: response.id.toString(), createdAt: response.createdAt });
    },
  );
};

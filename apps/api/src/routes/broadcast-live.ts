// apps/api/src/routes/broadcast-live.ts
//
// Broadcast-room LiveKit token issuance routes (task 8.1 — Phase 7).
//
//   POST  /rooms/:slug/live              (auth + admin role) → publisher token
//   GET   /rooms/:slug/live/viewer-token (auth)              → viewer token
//
// Realizes Requirements 11.1, 11.2 (the broadcast-only LiveKit posture
// from 11.7 / 11.8 is enforced by where this plugin is mounted: it only
// looks up rooms in `broadcast_rooms` and never receives a 1:1 DM call
// id from any caller).
//
//   - 11.1 : `POST /rooms/:slug/live`. The handler verifies the caller
//            is an admin via `broadcast_members.role = 'admin'`. On
//            non-admin → HTTP 403, no token minted. On unknown slug →
//            HTTP 404. Mints a LiveKit publisher JWT (TTL 3600 s) keyed
//            to `(userId, roomId)` and returns
//            `LiveKitTokenResponse { token, url, role: 'publisher' }`
//            with `url = config.LIVEKIT_URL`.
//   - 11.2 : `GET /rooms/:slug/live/viewer-token`. Auth required;
//            otherwise unrestricted (any logged-in user may view a
//            broadcast). Returns
//            `LiveKitTokenResponse { token, url, role: 'subscriber' }`.
//            On unknown slug → HTTP 404.
//
// Wire shape:
//   The protocol DTO `LiveKitTokenResponse` is defined in
//   `packages/protocol/src/rest-dto.ts`:
//
//     interface LiveKitTokenResponse {
//       token: string;
//       url: string;
//       role: 'publisher' | 'subscriber';
//     }
//
//   The task 8.1 brief (and Requirement 11.x) supersedes the older
//   `{ livekitUrl, publisherToken }` shape mentioned in design.md §9.
//   Web clients consume the protocol DTO; we honour it.
//
// Auth posture:
//   - Both routes require a valid Bearer access token (via the shared
//     `requireAuth` preHandler from `middleware/auth.ts`).
//   - `POST /rooms/:slug/live` additionally requires the caller's user
//     to be an admin of the room (`broadcast_members.role = 'admin'`).
//   - 404 on missing slug supersedes the auth check ordering only at
//     the handler level — Fastify still rejects the request with 401
//     first if there is no Bearer header. This matches Requirement
//     11.2's "404 for missing slug" applied to AUTHENTICATED callers.
//
// Logger redaction: the response body contains a JWT in `token`. The
// pino redaction layer added in task 4.9 strips top-level `token`
// fields recursively, so a future `app.log.info({ body }, ...)` would
// not leak this token into Loki. This route plugin emits no logs of
// its own beyond Fastify's request-log line (method, path, status,
// duration only — no body).

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

import type { LiveKitTokenResponse } from '@konvo/protocol';

import type { LiveKitTokenSigner } from '../services/livekit.js';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** Minimal `pg.Pool` shape this plugin needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres — same pattern
 *  the broadcast plugin uses. */
type DbPool = Pick<pg.Pool, 'query'>;

export interface BroadcastLiveRoutesDeps {
  readonly pool: DbPool;
  /** Shared `requireAuth` preHandler. Built via
   *  `apps/api/src/middleware/auth.ts makeRequireAuth(tokenService)`. */
  readonly requireAuth: preHandlerAsyncHookHandler;
  /** LiveKit token signer (publisher and viewer JWT mints). */
  readonly livekitSigner: LiveKitTokenSigner;
  /** Public LiveKit URL the web client connects to. Mirrors
   *  `config.LIVEKIT_URL` (e.g. `wss://livekit.konvo.local`). */
  readonly livekitUrl: string;
}

// ---------------------------------------------------------------------------
// Slug validation (mirrors `routes/broadcast.ts`)
// ---------------------------------------------------------------------------

const SLUG_REGEX = /^[a-z0-9-]{3,64}$/;
const SlugSchema = z.string().regex(SLUG_REGEX);

interface RoomRow {
  id: string;
  slug: string;
}

/** Look up `broadcast_rooms.id` by `slug`. Returns null when no row
 *  matches. Restricted to (id, slug) — these routes don't need the
 *  surrounding metadata. */
async function findRoomBySlug(
  pool: DbPool,
  slug: string,
): Promise<RoomRow | null> {
  const r = await pool.query<RoomRow>(
    `SELECT id, slug
       FROM broadcast_rooms
      WHERE slug = $1
      LIMIT 1`,
    [slug],
  );
  if (r.rowCount === 0) return null;
  return r.rows[0] as RoomRow;
}

/** Returns true iff (userId, roomId) is an admin in `broadcast_members`. */
async function isRoomAdmin(
  pool: DbPool,
  roomId: string,
  userId: string,
): Promise<boolean> {
  const r = await pool.query<{ role: string }>(
    `SELECT role FROM broadcast_members
      WHERE room_id = $1 AND user_id = $2
      LIMIT 1`,
    [roomId, userId],
  );
  if (r.rowCount === 0) return false;
  const row = r.rows[0] as { role: string };
  return row.role === 'admin';
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const broadcastLiveRoutes: FastifyPluginAsync<
  BroadcastLiveRoutesDeps
> = async (app, deps) => {
  // -------------------------------------------------------------------------
  // POST /rooms/:slug/live — admin only, publisher token (Req 11.1)
  // -------------------------------------------------------------------------
  app.post(
    '/rooms/:slug/live',
    { preHandler: deps.requireAuth },
    async (req: FastifyRequest, reply: FastifyReply) => {
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
      const admin = await isRoomAdmin(deps.pool, room.id, auth.userId);
      if (!admin) {
        // Requirement 11.1: non-admin → 403 without provisioning a
        // LiveKit room. Token minting is downstream of this branch.
        return reply.code(403).send({ error: 'forbidden' });
      }
      // The LiveKit `roomId` (i.e. the `video.room` JWT grant) is the
      // broadcast SLUG, never the `broadcast_rooms.id` UUID. The slug
      // satisfies the runtime guard `assertBroadcastRoomId` in
      // `services/livekit.ts` (which rejects UUID-shaped ids that
      // could otherwise be 1:1 DM call ids — Requirements 7.10,
      // 11.7, 11.8, 22.7).
      const token = await deps.livekitSigner.signPublisher({
        userId: auth.userId,
        roomId: room.slug,
      });
      const response: LiveKitTokenResponse = {
        token,
        url: deps.livekitUrl,
        role: 'publisher',
      };
      return reply.code(200).send(response);
    },
  );

  // -------------------------------------------------------------------------
  // GET /rooms/:slug/live/viewer-token — any authed user (Req 11.2)
  // -------------------------------------------------------------------------
  app.get(
    '/rooms/:slug/live/viewer-token',
    { preHandler: deps.requireAuth },
    async (req: FastifyRequest, reply: FastifyReply) => {
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
      // See the matching comment on the publisher path above: LiveKit's
      // `video.room` grant is bound to the broadcast SLUG so the
      // runtime guard in `services/livekit.ts` can reject any DM call
      // id (UUID) before a JWT is constructed.
      const token = await deps.livekitSigner.signViewer({
        userId: auth.userId,
        roomId: room.slug,
      });
      const response: LiveKitTokenResponse = {
        token,
        url: deps.livekitUrl,
        role: 'subscriber',
      };
      return reply.code(200).send(response);
    },
  );
};

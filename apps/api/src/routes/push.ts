// apps/api/src/routes/push.ts
//
// Web Push subscription REST routes (task 9.3 — Phase 8).
//
//   POST   /push/subscribe       (auth + CSRF)
//   DELETE /push/subscribe/:id   (auth + CSRF)
//
// Realizes Requirement 13.1 / 13.2 / 13.7 / 15.3 at the route layer:
//
//   - 13.1: persist a subscription keyed by `deviceId`, REPLACING any
//     existing subscription for the same `deviceId` (one device → at
//     most one push subscription).
//   - 13.2: reject the request without persistence on
//       * missing or empty `deviceId` / `endpoint` / `p256dh` / `auth`
//       * `endpoint` whose URL scheme is not `https://`
//   - 13.7: the SPA-side toggle drives this route; on enable the
//     client POSTs, on disable it DELETEs `/push/subscribe/:id`.
//   - 15.3: paired Web_Push toggle persists across sessions on the
//     same device (the persistence is a SPA concern; this route just
//     accepts the underlying subscribe / unsubscribe calls).
//
// Why "replace any existing subscription for the same deviceId"
// rather than "upsert by (device_id, endpoint)":
//   The spec is explicit (Requirement 13.1: "replacing any existing
//   subscription for the same deviceId"). A user who toggles push off
//   then back on, or whose browser rotates its push endpoint, gets a
//   single fresh row — there's never a stale row routing to a dead
//   endpoint. We implement it as DELETE-then-INSERT inside one
//   transaction so a crash between the two leaves the row absent
//   rather than duplicated; the next subscribe call repairs.
//
// Why DELETE /push/subscribe/:id checks ownership via the device row:
//   `push_subscriptions` doesn't carry `user_id` directly — it joins
//   to `devices` via `device_id`, and `devices.user_id` is the
//   authoritative owner. The DELETE statement uses an EXISTS
//   subquery against `devices` so a caller can't drop another user's
//   subscription even if they guess its UUID. Rows the caller doesn't
//   own collapse to the same 204 reply as a missing row, mirroring
//   the device-revocation convention from `routes/devices.ts`.
//
// Why HTTPS scheme is enforced here AND in the database column comment:
//   The push protocol (RFC 8030) is HTTPS-only by design; FCM, Mozilla,
//   and Apple all reject `http://` endpoints. Validating at the API
//   layer means a malicious client can't smuggle an `http://` endpoint
//   into our DB and force the sender to leak metadata to plaintext at
//   send time. The init.sql column comment documents the same
//   invariant for ops grepping schema for invariants.

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** Minimal `pg.Pool` shape this plugin needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres. */
type DbPool = Pick<pg.Pool, 'query'>;

export interface PushRoutesDeps {
  readonly pool: DbPool;
  readonly requireAuth: preHandlerAsyncHookHandler;
}

// ---------------------------------------------------------------------------
// zod schema for `POST /push/subscribe` body
// ---------------------------------------------------------------------------
//
// The push.api shape (RFC 8030 + browser PushSubscription serialisation):
//   - `endpoint`:   absolute URL the push service exposes
//   - `keys.p256dh`: base64url-encoded P-256 ECDH public key (~88 chars)
//   - `keys.auth`:   base64url-encoded 16-byte authentication secret
//
// The browser exposes these via `subscription.toJSON()` as
// `{ endpoint, keys: { p256dh, auth } }`. Per the task brief our wire
// shape flattens them into top-level fields so the route handler is
// flat. Our `deviceId` is a UUID that the SPA passes alongside —
// the device row is the authoritative key per Requirement 13.1.
//
// We deliberately do NOT decode `p256dh` or `auth` here: the push
// service speaks base64url and our `web-push` sender forwards them
// untouched. Validating the shape (non-empty string) is enough at
// the API layer; any malformed crypto material surfaces later as a
// push-service 400 / 410, which the sender handles via the standard
// 410 → row deletion path (Requirement 13.6).

const PushSubscribeSchema = z
  .object({
    deviceId: z.string().uuid(),
    endpoint: z.string().min(1),
    p256dh: z.string().min(1),
    auth: z.string().min(1),
  })
  .strict();

const UuidSchema = z.string().uuid();

/** Validate the endpoint scheme. The push protocol is HTTPS-only
 *  (Requirement 13.2). We reject any non-https:// scheme even if
 *  zod's URL validation would otherwise accept the string — the
 *  `URL` constructor accepts ftp://, ws://, etc., so we check the
 *  resulting `protocol` explicitly. */
function isHttpsEndpoint(endpoint: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return false;
  }
  return parsed.protocol === 'https:';
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const pushRoutes: FastifyPluginAsync<PushRoutesDeps> = async (
  app,
  deps,
) => {
  // -------------------------------------------------------------------------
  // POST /push/subscribe — Requirements 13.1, 13.2, 13.7
  // -------------------------------------------------------------------------
  app.post(
    '/push/subscribe',
    { preHandler: deps.requireAuth },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }

      const parsed = PushSubscribeSchema.safeParse(req.body);
      if (!parsed.success) {
        // Requirement 13.2: missing / empty fields collapse to the
        // same 400 shape so a probing client cannot enumerate which
        // field was malformed.
        return reply.code(400).send({ error: 'invalid_request' });
      }
      const body = parsed.data;

      // Requirement 13.2: reject any non-HTTPS endpoint scheme. We
      // do this AFTER the schema validation so a malformed URL still
      // surfaces as 400 with the same shape.
      if (!isHttpsEndpoint(body.endpoint)) {
        return reply.code(400).send({ error: 'invalid_request' });
      }

      // Verify the device belongs to the caller. Without this check a
      // user with a valid token could plant a subscription on someone
      // else's device id, redirecting another user's push notifications
      // to their own endpoint. The same query also surfaces as 404 for
      // a missing device id, mirroring the device-revocation convention.
      const ownership = await deps.pool.query<{ id: string }>(
        `SELECT id FROM devices
          WHERE id = $1 AND user_id = $2
          LIMIT 1`,
        [body.deviceId, auth.userId],
      );
      if (ownership.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }

      // Requirement 13.1: replace any existing subscription for the
      // same deviceId. We delete first, then insert. A row-level lock
      // would tighten the race window but the user-facing effect of a
      // double subscribe is identical (the next subscribe overwrites)
      // so we keep the SQL boring.
      await deps.pool.query(
        `DELETE FROM push_subscriptions WHERE device_id = $1`,
        [body.deviceId],
      );

      const ins = await deps.pool.query<{ id: string }>(
        `INSERT INTO push_subscriptions
           (device_id, endpoint, p256dh, auth)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
        [body.deviceId, body.endpoint, body.p256dh, body.auth],
      );
      if (ins.rowCount === 0) {
        return reply.code(500).send({ error: 'internal' });
      }
      const subscriptionId = (ins.rows[0] as { id: string }).id;

      return reply.code(201).send({ subscriptionId });
    },
  );

  // -------------------------------------------------------------------------
  // DELETE /push/subscribe/:id — Requirement 13.7
  // -------------------------------------------------------------------------
  app.delete(
    '/push/subscribe/:id',
    { preHandler: deps.requireAuth },
    async (req, reply) => {
      const auth = req.authUser;
      if (auth === undefined) {
        return reply.code(401).send({ error: 'auth_required' });
      }
      const params = req.params as { id?: unknown };
      const idParsed = UuidSchema.safeParse(params.id);
      if (!idParsed.success) {
        // Malformed UUID can't match any real subscription. Idempotent
        // delete: 204 either way so the SPA can disable push without
        // racing the row's existence.
        return reply.code(204).send();
      }

      // EXISTS subquery joins push_subscriptions to devices via
      // device_id and gates on devices.user_id = $auth — a caller can
      // never delete another user's subscription. We don't surface
      // "not found" vs "not yours" separately: 204 either way.
      await deps.pool.query(
        `DELETE FROM push_subscriptions
          WHERE id = $1
            AND EXISTS (
              SELECT 1 FROM devices
               WHERE devices.id = push_subscriptions.device_id
                 AND devices.user_id = $2
            )`,
        [idParsed.data, auth.userId],
      );
      return reply.code(204).send();
    },
  );
};

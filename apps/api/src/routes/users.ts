// apps/api/src/routes/users.ts
//
// Minimal directory routes used by the SPA to bootstrap a DM thread
// from a handle the user types into the composer.
//
//   GET /users/:handle           (auth required) → { userId, handle, devices: [{ deviceId, name, lastSeenTime }] }
//
// The endpoint requires auth so anonymous handle harvesting is not a
// trivial drive-by. It is intentionally narrow: only the fields the
// SPA needs to (a) route to /dm/:peerUserId and (b) open ratchet
// sessions to every enrolled device of the peer.
//
// Consumes the same handle regex as `/auth/signup` (`^[a-z0-9_]{3,32}$`)
// and collapses every parse failure / not-found case to HTTP 404 with
// `{ error: 'not_found' }` so an attacker cannot distinguish "shape
// is wrong" from "handle is unknown" (Requirement 3.10 spirit applied
// to directory lookups).

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

type DbPool = Pick<pg.Pool, 'query'>;

const HandleSchema = z.string().regex(/^[a-z0-9_]{3,32}$/);

export interface UsersRoutesDeps {
  readonly pool: DbPool;
  /** Built via `apps/api/src/middleware/auth.ts:makeRequireAuth(...)`. */
  readonly requireAuth: preHandlerAsyncHookHandler;
}

export interface UserDirectoryDevice {
  readonly deviceId: string;
  readonly name: string;
  readonly lastSeenTime: string | null;
}

export interface UserDirectoryResponse {
  readonly userId: string;
  readonly handle: string;
  readonly devices: readonly UserDirectoryDevice[];
}

interface UserRow {
  id: string;
  handle: string;
}

interface DeviceRow {
  id: string;
  name: string;
  last_seen_at: Date | null;
}

export const usersRoutes: FastifyPluginAsync<UsersRoutesDeps> = async (
  app,
  deps,
) => {
  app.get(
    '/users/:handle',
    {
      preHandler: deps.requireAuth,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const params = req.params as { handle?: unknown };
      const parsed = HandleSchema.safeParse(params.handle);
      if (!parsed.success) {
        return reply.code(404).send({ error: 'not_found' });
      }

      const userR = await deps.pool.query<UserRow>(
        `SELECT id, handle FROM users WHERE handle = $1 LIMIT 1`,
        [parsed.data],
      );
      if (userR.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const user = userR.rows[0] as UserRow;

      // A peer with zero enrolled devices is unreachable; the SPA still
      // wants to know that distinction so it can render "@handle exists
      // but has no active devices" rather than "@handle not found".
      const devR = await deps.pool.query<DeviceRow>(
        `SELECT id, name, last_seen_at
           FROM devices
          WHERE user_id = $1
          ORDER BY created_at ASC`,
        [user.id],
      );

      const response: UserDirectoryResponse = {
        userId: user.id,
        handle: user.handle,
        devices: devR.rows.map((row) => ({
          deviceId: row.id,
          name: row.name,
          lastSeenTime:
            row.last_seen_at !== null ? row.last_seen_at.toISOString() : null,
        })),
      };
      return reply.code(200).send(response);
    },
  );

  // GET /devices/:id/owner — auth-gated reverse lookup used by the
  // SPA to map an inbound envelope's `senderDeviceId` back to its
  // owning user (needed so the plaintext-DM controller can land
  // the inbound row in the correct thread). Anti-harvest posture
  // matches `/users/:handle`: every parse / not-found path is
  // collapsed to HTTP 404 with `{ error: 'not_found' }`.
  app.get(
    '/devices/:id/owner',
    {
      preHandler: deps.requireAuth,
    },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const params = req.params as { id?: unknown };
      const idParsed = z.string().uuid().safeParse(params.id);
      if (!idParsed.success) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const r = await deps.pool.query<{ user_id: string; handle: string }>(
        `SELECT d.user_id, u.handle
           FROM devices d
           JOIN users u ON u.id = d.user_id
          WHERE d.id = $1
          LIMIT 1`,
        [idParsed.data],
      );
      if (r.rowCount === 0) {
        return reply.code(404).send({ error: 'not_found' });
      }
      const row = r.rows[0]!;
      return reply.code(200).send({
        deviceId: idParsed.data,
        userId: row.user_id,
        handle: row.handle,
      });
    },
  );
};

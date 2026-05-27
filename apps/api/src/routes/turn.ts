// apps/api/src/routes/turn.ts
//
// Ephemeral coturn TURN credential endpoint (task 6.1 — Phase 5).
//
// Realizes Requirement 7.12: the API_Gateway issues short-lived,
// REST-auth-secret-derived TURN_Credentials with a 1-hour TTL, used by
// `RTCPeerConnection` for NAT traversal on 1:1 calls. The shared secret
// (`config.COTURN_REST_SECRET`) MUST match the `static-auth-secret`
// configured on the coturn server (`infra/coturn/turnserver.conf`); any
// drift between the two values will cause coturn to reject every
// allocation with `401 Unauthorized` and the call will fail to relay.
//
// Wire format (RFC 7635 §2.2 — "Time-limited TURN credentials"):
//
//   username   = `${expirationUnixTimestamp}:${userId}`
//                 where expirationUnixTimestamp = floor((Date.now() + ttlMs)/1000)
//   credential = base64(HMAC-SHA1(coturnRestSecret, username))
//   ttlSec     = 3600 (1 hour, fixed by Requirement 7.12)
//
// Notes on cryptographic primitives:
//
//   - HMAC-SHA1 is mandated by the RFC 7635 / coturn REST auth model.
//     This is NOT a content-confidentiality boundary: it's a MAC over a
//     username so coturn can verify the credential came from the api
//     without sharing per-user state. SHA-1 is acceptable here because
//     the security property required is HMAC pseudorandomness, which
//     SHA-1 still provides; coturn does not accept any other hash for
//     this construction.
//
//   - The credential is base64 (NOT base64url) because that is what
//     coturn's `static-auth-secret` mechanism expects on the wire.
//     Switching to base64url would silently break authentication.
//
// Auth posture:
//
//   - GET /turn/credentials requires a valid 15-min access token
//     (`makeRequireAuth` from middleware/auth.ts). Without auth we
//     would be handing every drive-by visitor an hour of TURN relay
//     bandwidth.
//   - We bind the credential to the authenticated user id (`sub` claim)
//     by embedding it in the username. coturn does not inspect the
//     userId — it only verifies the HMAC — but stamping the userId
//     gives us an audit trail in coturn's logs and lets a future
//     per-user rate limit slot in here without changing the wire shape.

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import { createHmac } from 'node:crypto';

import type { TurnCredentialsResponse } from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

export interface TurnRoutesDeps {
  /** Fastify preHandler that decorates `req.authUser` on success and
   *  short-circuits with 401 on failure. Built via
   *  `apps/api/src/middleware/auth.ts makeRequireAuth(tokenService)`. */
  readonly requireAuth: preHandlerAsyncHookHandler;
  /** The shared secret coturn validates HMACs against. MUST match the
   *  `static-auth-secret` line in the coturn config. Loaded from
   *  `config.COTURN_REST_SECRET` in production (≥32 chars enforced by
   *  the zod schema). */
  readonly coturnRestSecret: string;
  /** TURN realm and host. Loaded from `config.COTURN_REALM` (default
   *  `konvo.local`). Used both as the SDP `realm` (coturn already
   *  enforces this server-side) and as the host portion of the
   *  `turn:`/`turns:`/`stun:` URLs returned to the client. */
  readonly coturnRealm: string;
  /** Credential lifetime in seconds. Defaults to 3600 (Requirement
   *  7.12). Tests override to a tiny window so they can assert the
   *  expiration math without waiting an hour. */
  readonly ttlSec?: number;
  /** Wall-clock injection. Defaults to `Date.now`. Tests override to
   *  produce deterministic timestamps for HMAC equality checks. */
  readonly now?: () => number;
  /** UDP/TCP TURN port (default 3478) and TLS TURN port (default 5349).
   *  Exposed for tests; production deployments use the coturn defaults. */
  readonly turnPort?: number;
  readonly turnsPort?: number;
}

const DEFAULT_TTL_SEC = 3600;
const DEFAULT_TURN_PORT = 3478;
const DEFAULT_TURNS_PORT = 5349;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build the `urls` array per the design.md §3.2 ICE-server hint:
 *
 *    turn:<host>:<turnPort>?transport=udp     ← preferred relay path
 *    turn:<host>:<turnPort>?transport=tcp     ← TCP fallback for hostile NATs
 *    turns:<host>:<turnsPort>?transport=tcp   ← TLS-TURN, opaque to MITMs
 *    stun:<host>:<turnPort>                   ← srflx candidate gathering
 *
 *  The order matters: WebRTC's ICE agent will try entries in the order
 *  presented, so we put the cheapest UDP relay first and the most
 *  expensive TLS relay third. STUN goes last because it's only used for
 *  candidate gathering, not media relay.
 */
function buildTurnUrls(
  host: string,
  turnPort: number,
  turnsPort: number,
): readonly string[] {
  return [
    `turn:${host}:${turnPort}?transport=udp`,
    `turn:${host}:${turnPort}?transport=tcp`,
    `turns:${host}:${turnsPort}?transport=tcp`,
    `stun:${host}:${turnPort}`,
  ];
}

/** Compute the RFC 7635 / coturn REST credential.
 *
 *  Returned credential is the base64 (not base64url) encoding of the
 *  HMAC-SHA1 digest of `username` keyed by `secret`. coturn validates
 *  the credential by recomputing this same HMAC and timing-safe-equal
 *  comparing the digests; any drift in algorithm, encoding, or input
 *  composition will cause every TURN allocation to fail.
 */
function computeTurnCredential(secret: string, username: string): string {
  return createHmac('sha1', secret).update(username).digest('base64');
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const turnRoutes: FastifyPluginAsync<TurnRoutesDeps> = async (
  app,
  deps,
) => {
  const ttlSec = deps.ttlSec ?? DEFAULT_TTL_SEC;
  const now = deps.now ?? (() => Date.now());
  const turnPort = deps.turnPort ?? DEFAULT_TURN_PORT;
  const turnsPort = deps.turnsPort ?? DEFAULT_TURNS_PORT;

  app.get(
    '/turn/credentials',
    { preHandler: deps.requireAuth },
    async (
      req: FastifyRequest,
      reply: FastifyReply,
    ): Promise<TurnCredentialsResponse | undefined> => {
      const auth = req.authUser;
      if (auth === undefined) {
        // requireAuth would have rejected; this is a defensive guard so
        // TypeScript narrows `auth` without a non-null assertion.
        await reply.code(401).send({ error: 'auth_required' });
        return undefined;
      }

      // Expiration is `floor((nowMs + ttlMs) / 1000)` — a Unix-epoch
      // second count that coturn parses out of the username and uses to
      // reject expired credentials. We compute it once here so the
      // value embedded in the username is identical to the one we
      // imply via `ttlSec` in the response body.
      const expirationUnixTimestamp = Math.floor(
        (now() + ttlSec * 1000) / 1000,
      );
      const username = `${expirationUnixTimestamp}:${auth.userId}`;
      const credential = computeTurnCredential(deps.coturnRestSecret, username);

      const response: TurnCredentialsResponse = {
        urls: buildTurnUrls(deps.coturnRealm, turnPort, turnsPort),
        username,
        credential,
        ttlSec,
      };
      // Returning the object lets Fastify serialize via its default
      // JSON path. We do NOT set Cache-Control: public — the credential
      // is per-user and short-lived; caching would be a security bug.
      // Setting `no-store` keeps Caddy and any CDN from accidentally
      // memoizing the response.
      await reply
        .code(200)
        .header('cache-control', 'no-store')
        .send(response);
      return undefined;
    },
  );
};

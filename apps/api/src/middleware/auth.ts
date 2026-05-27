// apps/api/src/middleware/auth.ts
//
// Shared `requireAuth` Fastify preHandler used by every authenticated
// REST route (broadcast, devices, prekeys, attachments, push, livekit
// tokens, …). Reads a 15-min HS256 access token from the
// `Authorization: Bearer <token>` header, verifies it via the supplied
// `AccessTokenService`, and attaches `{ userId, deviceId }` to
// `req.authUser` for downstream handlers to consume.
//
// Why a preHandler (not onRequest):
//   - We want body parsing and route matching to have happened before
//     auth runs, so that route-specific schemas can decide whether the
//     request shape is valid in the first place. Using preHandler also
//     means a single shared instance plays nicely with per-route
//     `config.rateLimit` keyGenerators that read `req.authUser` (which
//     wouldn't exist yet at onRequest time).
//
// Why a factory rather than a plugin:
//   - Different routes need different token services in tests. The
//     factory takes the dependency once and returns a closure that
//     downstream routes can drop into their `preHandler` array.
//
// Decoration:
//   - We attach the user payload as `req.authUser` rather than
//     `req.user` because Fastify v5 reserves `request.user` for the
//     `@fastify/jwt` ecosystem. Using a Konvo-specific name avoids the
//     `Decorator already exists` runtime error if both are loaded in
//     the same instance later. Routes consume the augmented type via
//     the module augmentation at the bottom of this file.
//
// Auth posture:
//   - Missing header / malformed scheme / invalid token → 401 with
//     body `{ error: 'auth_required' }`. We do NOT distinguish between
//     "no token" and "expired token" in the response shape; that
//     prevents an unauthenticated probe from learning whether a
//     particular bearer string was ever a valid Konvo token.
//   - The token is parsed and verified BEFORE the route handler runs;
//     a failed verify short-circuits the request lifecycle so no DB
//     writes, Redis publishes, or other side effects can occur on the
//     failure path (Requirement 19.9 spirit, applied to auth).

import type {
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';

import type { AccessTokenService } from '../services/auth/tokens.js';

/** What downstream handlers see on `req.authUser`. */
export interface AuthenticatedUser {
  /** Authenticated user UUID (`sub` claim of the access token). */
  readonly userId: string;
  /** Authenticated device UUID (`did` claim). May be the empty string
   *  for tokens issued before device enrollment (Phase-1 caveat in
   *  `routes/auth.ts`); routes that require a real device id MUST
   *  reject the empty-string case explicitly. */
  readonly deviceId: string;
}

/** Construct a `requireAuth` preHandler bound to the given access-token
 *  service. The returned handler is shared (no per-request construction
 *  cost) and safe to attach to multiple routes. */
export function makeRequireAuth(
  tokenService: AccessTokenService,
): preHandlerAsyncHookHandler {
  return async function requireAuth(
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const header = req.headers.authorization;
    if (typeof header !== 'string' || header.length === 0) {
      await reply.code(401).send({ error: 'auth_required' });
      return;
    }

    // RFC 6750 §2.1: `Authorization: Bearer <token>`. We accept any
    // case for the scheme (RFC 7235 says scheme matching is case-
    // insensitive) and reject any non-Bearer scheme.
    const space = header.indexOf(' ');
    if (space < 0) {
      await reply.code(401).send({ error: 'auth_required' });
      return;
    }
    const scheme = header.slice(0, space);
    const tokenRaw = header.slice(space + 1).trim();
    if (scheme.toLowerCase() !== 'bearer' || tokenRaw.length === 0) {
      await reply.code(401).send({ error: 'auth_required' });
      return;
    }

    let claims;
    try {
      claims = await tokenService.verify(tokenRaw);
    } catch {
      // Any verify failure (signature, expired, malformed, missing
      // claim) collapses to the same generic 401 to avoid disclosing
      // which check rejected the token.
      await reply.code(401).send({ error: 'auth_required' });
      return;
    }

    // Attach the validated principal. Routes that require a non-empty
    // device id (e.g. WS auth, anything that ties to a physical
    // browser) must check `deviceId !== ''` themselves.
    req.authUser = {
      userId: claims.sub,
      deviceId: claims.did,
    };
  };
}

// ---------------------------------------------------------------------------
// Module augmentation
// ---------------------------------------------------------------------------
//
// Fastify v5 expects request decorators to be declared via module
// augmentation so route handlers see the typed property. We also
// `decorateRequest` at runtime in the plugin below so the property
// exists with `undefined` default before `requireAuth` populates it.

declare module 'fastify' {
  interface FastifyRequest {
    /** Populated by `requireAuth`. Undefined on routes that don't run
     *  the preHandler (public routes like `GET /rooms/:slug`). */
    authUser?: AuthenticatedUser;
  }
}

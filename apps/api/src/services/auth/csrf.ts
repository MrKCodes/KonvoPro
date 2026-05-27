// CSRF middleware (task 2.5).
//
// Realizes Requirements 19.3 and 19.9:
//   - 19.3: every state-changing REST endpoint (POST/PUT/PATCH/DELETE)
//           requires a double-submit CSRF token.
//   - 19.9: a request that is missing the token, or whose submitted
//           token does not match the value in the corresponding cookie,
//           SHALL be rejected without applying any server-side state
//           change. We enforce this in `onRequest` so the rejection
//           happens BEFORE preHandler / preValidation / handler ever
//           run, guaranteeing no DB write, Redis publish, or other
//           side effect can occur on the failure path.
//
// Design notes:
//   - Pattern: classic double-submit cookie.
//
//     The server sets a fresh, random 256-bit token in a cookie that is
//     readable by JavaScript (NOT httpOnly). On state-changing requests
//     the SPA copies that cookie value into the `X-CSRF-Token` request
//     header. The server checks that the header value byte-for-byte
//     matches the cookie value. A cross-origin attacker cannot read the
//     cookie (same-origin policy), so they cannot forge a matching
//     header — the SameSite=Lax attribute is the primary defense for
//     top-level navigations, and this check is defense-in-depth for
//     same-site fetch() exfiltration vectors.
//
//   - We deliberately implement the plugin from scratch rather than
//     depending on `@fastify/csrf-protection`. The protocol is ~50 LoC,
//     the design.md note for §18.2 is unambiguous, and bringing in a new
//     dependency would require a `pnpm install` which is out of scope
//     for this task. Task 2.4 (which would have introduced
//     `@fastify/cookie`) is also not landed yet, so we parse cookies
//     ourselves; the parser is intentionally minimal (no quoted-string
//     handling, no support for multiple cookies of the same name) since
//     we own both producer and consumer.
//
//   - Token generation uses `crypto.randomBytes(32)` (CSPRNG, 256 bits
//     of entropy) base64url-encoded — 43 characters, URL-safe, cookie-safe.
//
//   - Token comparison uses `crypto.timingSafeEqual` after a length
//     check. timingSafeEqual requires equal-length buffers, so a length
//     mismatch is short-circuited explicitly without leaking timing.
//
//   - The cookie is issued lazily: on any non-OPTIONS request that
//     arrives without a `konvo_csrf` cookie we generate a token in
//     `onRequest` and stash it in a per-request WeakMap; an `onSend`
//     hook then writes the `Set-Cookie` header. This means the very
//     first GET response carries a fresh token, and the next POST from
//     that session can already include the matching header.
//
//   - OPTIONS preflights are skipped for cookie-issuance because they
//     never carry credentials in browsers' default CORS mode and
//     because issuing a Set-Cookie on a preflight response is silently
//     dropped by some user agents.
//
//   - Routes like `/health` and `/metrics` should be opted out via the
//     `skipPaths` option so unauthenticated probes never receive a
//     csrf cookie. Wiring lives in `apps/api/src/server.ts`.

import { randomBytes, timingSafeEqual } from 'node:crypto';

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

export interface CsrfOptions {
  /** Cookie name carrying the CSRF token. Default: `konvo_csrf`. */
  readonly cookieName?: string;
  /** Header name carrying the submitted token. Default: `x-csrf-token`.
   *  Compared case-insensitively against `req.headers`, which Node
   *  lowercases automatically. */
  readonly headerName?: string;
  /** Cookie `Path` attribute. Default: `/`. */
  readonly cookiePath?: string;
  /** HTTP methods (uppercase) that bypass the double-submit check.
   *  Default: `['GET', 'HEAD', 'OPTIONS']`. */
  readonly skipMethods?: readonly string[];
  /** Path patterns that bypass the double-submit check AND skip cookie
   *  issuance entirely. Used to exempt `/health` and `/metrics`.
   *  Matched against the path component of `req.url`, with the query
   *  string stripped. Default: `[]`. */
  readonly skipPaths?: readonly RegExp[];
  /** Whether the issued cookie carries the `Secure` attribute. Defaults
   *  to `true`. Set to `false` only in non-production tests over plain
   *  HTTP — the test suite injects requests directly into Fastify and
   *  doesn't observe the `Secure` flag for its assertions. */
  readonly cookieSecure?: boolean;
}

/** Number of random bytes per token. 32 bytes = 256 bits of entropy. */
const TOKEN_BYTES = 32;

const DEFAULT_COOKIE_NAME = 'konvo_csrf';
const DEFAULT_HEADER_NAME = 'x-csrf-token';
const DEFAULT_COOKIE_PATH = '/';
const DEFAULT_SKIP_METHODS: readonly string[] = ['GET', 'HEAD', 'OPTIONS'];
const DEFAULT_SKIP_PATHS: readonly RegExp[] = [];

/** Per-request stash of a freshly minted token that needs to be written
 *  back as a `Set-Cookie` header during `onSend`. A WeakMap keyed by the
 *  FastifyRequest object avoids polluting the request type and is cleaned
 *  up when the request is garbage-collected. */
const pendingTokens = new WeakMap<FastifyRequest, string>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a fresh 256-bit token, base64url-encoded (43 chars). */
function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url');
}

/** Minimal `Cookie:` header parser. Returns `undefined` for the named
 *  cookie if it is absent OR if the cookie's value is empty.
 *
 *  Intentionally simple: we own both producer and consumer, the producer
 *  emits base64url tokens with no special characters that need quoting,
 *  and we never set multiple cookies of the same name at the same path. */
function readCookie(header: string | undefined, name: string): string | undefined {
  if (typeof header !== 'string' || header.length === 0) {
    return undefined;
  }
  const parts = header.split(';');
  for (const raw of parts) {
    const eq = raw.indexOf('=');
    if (eq < 0) continue;
    const k = raw.slice(0, eq).trim();
    if (k !== name) continue;
    const v = raw.slice(eq + 1).trim();
    if (v.length === 0) return undefined;
    return v;
  }
  return undefined;
}

/** Constant-time comparison guarded by an explicit length check.
 *  `timingSafeEqual` throws on length mismatch, so we short-circuit
 *  on length first; a length difference is not a secret. */
function tokensEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  // Buffer.from on equal-length strings yields equal-length buffers as
  // long as both inputs are valid UTF-8; base64url tokens are pure ASCII
  // so byte length === character length.
  if (ab.length !== bb.length) {
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/** Build the `Set-Cookie` header value for the CSRF token.
 *
 *  Cookie attributes:
 *    - `Path`     : configurable (default `/`)
 *    - `SameSite` : `Lax` — primary CSRF defense for top-level navigations.
 *    - `Secure`   : present in production; omitted only in HTTP test mode.
 *    - `HttpOnly` : INTENTIONALLY OMITTED. The SPA must read this cookie
 *                   from `document.cookie` to populate the `X-CSRF-Token`
 *                   header on fetch() calls. This is safe because the
 *                   token is a per-session anti-CSRF nonce, not an auth
 *                   credential — the auth credential lives in the
 *                   refresh-token cookie which IS `HttpOnly`. */
function buildSetCookie(
  name: string,
  value: string,
  opts: { readonly path: string; readonly secure: boolean },
): string {
  const parts: string[] = [`${name}=${value}`, `Path=${opts.path}`, 'SameSite=Lax'];
  if (opts.secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/** Append a `Set-Cookie` header without clobbering any cookies the
 *  route handler may already have set (e.g. the refresh-token cookie
 *  on `/auth/login`). `reply.header` would replace; we always append. */
function appendSetCookie(reply: FastifyReply, cookieValue: string): void {
  const existing = reply.getHeader('set-cookie');
  if (Array.isArray(existing)) {
    const merged: string[] = [];
    for (const item of existing) {
      if (typeof item === 'string') merged.push(item);
    }
    merged.push(cookieValue);
    reply.header('set-cookie', merged);
    return;
  }
  if (typeof existing === 'string') {
    reply.header('set-cookie', [existing, cookieValue]);
    return;
  }
  reply.header('set-cookie', cookieValue);
}

/** Strip the query string from `req.url` to get the path component for
 *  `skipPaths` matching. Avoids constructing a URL object on the hot
 *  path. */
function pathOf(url: string): string {
  const q = url.indexOf('?');
  return q < 0 ? url : url.slice(0, q);
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const csrfPlugin: FastifyPluginAsync<CsrfOptions> = async (app, opts) => {
  // Hooks installed below must apply to routes registered on the parent
  // instance (the actual application), not just routes nested inside this
  // plugin. Without breaking encapsulation, `app.register(csrfPlugin)`
  // followed by `app.post('/foo', ...)` would NOT run the CSRF check on
  // `/foo` because the hook lives in the plugin's child context.
  //
  // The canonical way to break encapsulation is `fastify-plugin`, which
  // marks the function with `Symbol.for('skip-override')`. We avoid the
  // extra dependency by setting that symbol directly on the exported
  // function below — same effect, zero install footprint.
  const cookieName = opts.cookieName ?? DEFAULT_COOKIE_NAME;
  // Header lookup against `req.headers` is always lowercase (Node lowercases
  // incoming header names), so normalize once at registration.
  const headerName = (opts.headerName ?? DEFAULT_HEADER_NAME).toLowerCase();
  const cookiePath = opts.cookiePath ?? DEFAULT_COOKIE_PATH;
  const skipMethods = (opts.skipMethods ?? DEFAULT_SKIP_METHODS).map((m) =>
    m.toUpperCase(),
  );
  const skipPaths = opts.skipPaths ?? DEFAULT_SKIP_PATHS;
  const cookieSecure = opts.cookieSecure ?? true;

  app.addHook('onRequest', async (req, reply) => {
    const method = req.method.toUpperCase();
    const path = pathOf(req.url);
    const isSkippedPath = skipPaths.some((re) => re.test(path));

    // Always skip every CSRF behaviour on opted-out paths so unauthenticated
    // probes (`/health`, `/metrics`) never get a csrf cookie.
    if (isSkippedPath) {
      return;
    }

    const cookieValue = readCookie(req.headers.cookie, cookieName);
    const isStateChanging = !skipMethods.includes(method);

    if (isStateChanging) {
      // ---- Requirement 19.9 enforcement -----------------------------------
      // Reject BEFORE any handler runs so no DB write, Redis publish, etc.
      // can occur on the failure path. `reply.code(403).send(...)` ends the
      // request lifecycle; subsequent hooks on the failure path will not
      // run (Fastify short-circuits when the reply is already sent).
      const headerRaw = req.headers[headerName];
      const headerValue: string | undefined = Array.isArray(headerRaw)
        ? headerRaw[0]
        : headerRaw;

      if (
        typeof cookieValue !== 'string' ||
        cookieValue.length === 0 ||
        typeof headerValue !== 'string' ||
        headerValue.length === 0 ||
        !tokensEqual(cookieValue, headerValue)
      ) {
        await reply.code(403).send({ error: 'csrf_invalid' });
        return;
      }
      // Match — fall through. Do NOT mint a new token: rotating on every
      // state-changing request would invalidate any other tab the user
      // has open against the same origin.
      return;
    }

    // Non-state-changing request. Issue a token if the client doesn't
    // already have one. OPTIONS is handled by the skipPaths/skipMethods
    // logic above; we still want to skip cookie issuance on OPTIONS even
    // if some operator overrides skipMethods, because OPTIONS responses
    // are preflights and Set-Cookie on preflights is undefined behaviour.
    if (method === 'OPTIONS') {
      return;
    }
    if (typeof cookieValue !== 'string' || cookieValue.length === 0) {
      pendingTokens.set(req, generateToken());
    }
  });

  app.addHook('onSend', async (req, reply, payload) => {
    const pending = pendingTokens.get(req);
    if (typeof pending === 'string' && pending.length > 0) {
      appendSetCookie(
        reply,
        buildSetCookie(cookieName, pending, {
          path: cookiePath,
          secure: cookieSecure,
        }),
      );
      // Free the entry eagerly. The WeakMap would clean itself up when the
      // request is GC'd, but explicit deletion makes the lifetime obvious.
      pendingTokens.delete(req);
    }
    return payload;
  });
};

// Mark the plugin to skip Fastify's encapsulation override so that
// `addHook` inside the plugin attaches to the parent instance (the real
// application). This is the same symbol `fastify-plugin` sets internally;
// we set it directly to avoid pulling in another dependency for a
// one-symbol affordance. See the Fastify plugins guide for the contract:
// https://fastify.dev/docs/latest/Reference/Plugins/#handle-the-scope.
//
// We also declare the plugin's metadata fields so Fastify's plugin
// registry can identify us in error messages and in `printPlugins()`.
interface FastifyPluginMeta {
  default?: { name?: string; fastify?: string };
}
const skipOverride = Symbol.for('skip-override');
(csrfPlugin as unknown as Record<symbol, boolean>)[skipOverride] = true;
(csrfPlugin as unknown as FastifyPluginMeta).default = {
  name: 'konvo-csrf',
  fastify: '5.x',
};

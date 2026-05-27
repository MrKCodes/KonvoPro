// apps/api/src/routes/auth.ts
//
// `/auth/*` routes. Tasks 2.3 (signup) and 2.4 (login, refresh, logout).
//
// Realizes Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.13,
// 1.15, 19.2, 19.4 + design.md §9 (route signatures), §17.3 (HSTS-only),
// §18.2 (auth):
//
//   - 1.1  : signup persists `password_hash = argon2id(password)` with
//            production params (m=64 MiB, t=3, p=4 — set by the bootstrap
//            in server.ts and embedded in the PHC string by argon2.hash).
//   - 1.2  : duplicate handle is rejected via the Postgres unique
//            violation on `users.handle` (citext UNIQUE) translated to
//            HTTP 409 + `{ error: 'handle_unavailable' }`.
//   - 1.13 : passwords outside the 12..128 char window are rejected at
//            the zod layer with HTTP 400 + `{ error: 'invalid_request' }`.
//            The same body is used for an invalid handle so the error
//            response shape is uniform across input-validation failures.
//   - 1.3  : login issues a 15-min HS256 access token + 30-day refresh
//            token; the refresh token is also placed in an httpOnly,
//            Secure, SameSite=Lax cookie.
//   - 1.4  : if the user has TOTP enabled (`users.totp_secret IS NOT
//            NULL`), require a valid RFC 6238 6-digit TOTP with a 30-second
//            window. We allow ±1 step (±30s) of clock skew via otplib's
//            `window: 1` setting.
//   - 1.5  : on either-factor failure return a NON-DISCLOSING error. We
//            return HTTP 401 with body `{ error: 'invalid_credentials' }`
//            for ALL of: unknown handle, wrong password, missing TOTP when
//            required, wrong TOTP. The route does NOT reveal which factor
//            failed (the body is the same string in every case).
//   - 1.6  : `/auth/refresh` exchanges the cookie-borne refresh token for
//            a fresh 15-min access token.
//   - 1.7  : every refresh-token use rotates the underlying token; the
//            cookie is overwritten with the new raw value before the
//            response is sent. (Rotation itself is implemented in
//            `services/auth/tokens.ts` — this route only consumes it.)
//   - 1.8  : logout revokes the refresh token (idempotent) and clears
//            the cookie; reply is 204 even if no cookie was present.
//   - 1.9  : 5/min/IP on signup, 5/min/IP on login, 30/min/IP on refresh.
//   - 1.15 : exceeding either rate limit returns HTTP 429 (handled by
//            `@fastify/rate-limit` once registered).
//   - 19.2 : refresh-token cookie always carries `Secure; HttpOnly;
//            SameSite=Lax`. We unconditionally set `secure: true` because
//            local development runs behind Caddy with auto-TLS at
//            `https://konvo.local`; if you ever run the api over plain
//            http://localhost the browser will simply not send the cookie
//            back, which is the correct fail-closed behaviour.
//   - 19.4 : rate limits are scoped per-IP via `keyGenerator: req.ip`,
//            which respects `app.proxyTrust` (configured in server.ts so
//            Caddy's `X-Forwarded-For` is honoured).
//
// Phase-1 device-id binding caveat (Requirement 1.3 + design.md §6.2):
//   Access tokens carry `{sub, did, iat, exp}`. At login time we don't
//   yet know which enrolled device this browser is — the device-enrollment
//   flow (`POST /devices`, task 2.6) hasn't run for first-time logins on
//   a new browser. To unblock Phase 1 without violating the claim shape:
//
//     - The login body accepts an optional `deviceId` field. If the client
//       has previously enrolled a device on this browser (i.e. its Dexie
//       store has a deviceId), it passes it through. The access token then
//       carries `did = <deviceId>` and is immediately useful for WS auth.
//     - If the client omits `deviceId` (first login on a new browser), we
//       sign the token with `did = ''` (empty-string sentinel). The web
//       client then runs device enrollment, calls `POST /auth/refresh?
//       deviceId=...`, and replaces the access token. The WS gateway
//       (task 3.3) MUST reject `did === ''` to prevent any envelope
//       traffic before enrollment.
//
//   The same caveat applies to `/auth/refresh`, which accepts an optional
//   `deviceId` query param.

import { z } from 'zod';
import type { FastifyPluginAsync, FastifyReply } from 'fastify';
import type pg from 'pg';
import { authenticator } from 'otplib';
import { HashAlgorithms } from '@otplib/core';

import type { Argon2Service } from '../services/auth/argon2.js';
import {
  type AccessTokenService,
  type RefreshTokenStore,
  InvalidRefreshTokenError,
  RefreshTokenExpiredError,
} from '../services/auth/tokens.js';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** The minimal `pg.Pool` surface this plugin needs. Restated as a
 *  structural type so tests can stub it without instantiating a real
 *  Pool, matching the convention from `services/auth/tokens.ts`. */
type DbPool = Pick<pg.Pool, 'query'>;

/** Dependencies handed to the auth-routes plugin. The bootstrap in
 *  `server.ts` constructs these once and passes them through; tests
 *  pass mocks to exercise route behaviour without Postgres / argon2 / jose. */
export interface AuthRoutesDeps {
  readonly pool: DbPool;
  readonly argon2: Argon2Service;
  readonly accessTokenService: AccessTokenService;
  readonly refreshTokenStore: RefreshTokenStore;
  /** Cookie name. Default `'konvo_rt'`. */
  readonly refreshCookieName?: string;
  /** Cookie path. Default `'/auth'` so it's only sent to the auth routes
   *  (refresh + logout) and never leaks to other endpoints. */
  readonly refreshCookiePath?: string;
  /** Refresh-token TTL in milliseconds. Default 30 days; mirrors the
   *  default in `services/auth/tokens.ts`. The cookie's `max-age` is
   *  derived as `Math.floor(refreshTokenTtlMs / 1000)`. */
  readonly refreshTokenTtlMs?: number;
}

const DEFAULT_REFRESH_COOKIE_NAME = 'konvo_rt';
const DEFAULT_REFRESH_COOKIE_PATH = '/auth';
const DEFAULT_REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** A rate-limit configuration that the auth plugin asks Fastify to apply
 *  per-route. We don't construct it here; the plugin pulls
 *  `fastify.rateLimit` (registered globally in server.ts) and attaches
 *  per-route configs via the `config.rateLimit` route option. */
const SIGNUP_RATE_LIMIT = { max: 5, timeWindow: '1 minute' } as const;
const LOGIN_RATE_LIMIT = { max: 5, timeWindow: '1 minute' } as const;
const REFRESH_RATE_LIMIT = { max: 30, timeWindow: '1 minute' } as const;

// ---------------------------------------------------------------------------
// Body schemas (zod)
// ---------------------------------------------------------------------------

/** `POST /auth/signup` body validator. Mirrors `SignupRequest` in
 *  `packages/protocol/src/rest-dto.ts` and Requirements 1.1 / 1.13:
 *
 *  - `handle`: `^[a-z0-9_]{3,32}$`. Citext on the database side makes
 *    later lookups case-insensitive, but we still REJECT uppercase at
 *    write time so two users can't enroll handles that visually differ
 *    by case. Without that defense, `Alice` would be valid input but
 *    would collide with an existing `alice` row, surfacing as a 409 that
 *    the user can't fix without retrying with a different (lowercased)
 *    string. Failing fast at validation gives a clearer 400.
 *  - `password`: 12..128 chars (Requirement 1.13). Argon2id is invoked
 *    with the production params from config; PHC string embeds them so
 *    a future param upgrade still validates legacy hashes.
 *  - `.strict()` rejects unknown keys so a misspelt field surfaces as a
 *    400 instead of being silently ignored. */
const SignupBodySchema = z
  .object({
    handle: z.string().regex(/^[a-z0-9_]{3,32}$/),
    password: z.string().min(12).max(128),
  })
  .strict();

/** `POST /auth/login` body validator. Mirrors `LoginRequest` in
 *  `packages/protocol/src/rest-dto.ts` plus the optional `deviceId`
 *  pass-through described in the file header.
 *
 *  - `handle`: 3..32 chars (citext lookup). The full `^[a-z0-9_]{3,32}$`
 *    regex from Requirement 1.1 is enforced at SIGNUP time (task 2.3),
 *    not here — we want login to fail with a uniform `invalid_credentials`
 *    error rather than a 400 if a user happens to have a handle from a
 *    legacy migration that doesn't match the regex.
 *  - `password`: 12..128 chars. The same length rules from signup
 *    (Requirement 1.13) apply here defensively; sending a password
 *    outside that range cannot be valid by construction so we reject
 *    it as a 400 to avoid burning Argon2 cycles.
 *  - `totp`: optional, exactly 6 digits when present. `min(6).max(6)`
 *    keeps the schema strict; the regex `^[0-9]{6}$` is applied via
 *    `.regex(...)` so a 6-char alpha string is rejected.
 *  - `deviceId`: optional UUID. See file header for Phase-1 caveat. */
const LoginBodySchema = z
  .object({
    handle: z.string().min(3).max(32),
    password: z.string().min(12).max(128),
    totp: z
      .string()
      .regex(/^[0-9]{6}$/, 'totp must be exactly 6 digits')
      .optional(),
    deviceId: z.string().uuid().optional(),
  })
  .strict();

/** `POST /auth/refresh` query-string validator. The refresh token itself
 *  is read from the cookie, not the body. */
const RefreshQuerySchema = z
  .object({
    deviceId: z.string().uuid().optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Argon2 timing-attack defense
// ---------------------------------------------------------------------------

/** A pre-computed Argon2id hash used to keep login timing constant when the
 *  presented handle doesn't exist. Without this an attacker could enumerate
 *  valid handles by measuring the response time difference between "no row
 *  found" (fast) and "row found, password verify" (slow). On the unknown-
 *  handle path we run `argon2.verify(SENTINEL_HASH, presentedPassword)`
 *  which always returns false but takes the same wall-clock time as a real
 *  verify against a real hash.
 *
 *  The sentinel is a real Argon2id hash of an arbitrary string produced
 *  with the test parameters from `argon2.test.ts` (m=16384, t=1, p=1).
 *  That choice matters: production hashes are produced with m=64 MiB,
 *  t=3, p=4. Using a sentinel with weaker parameters keeps the unknown-
 *  handle path FASTER than the real path, which still leaks timing.
 *
 *  Resolution: the bootstrap in `server.ts` produces the sentinel ONCE at
 *  startup using the SAME parameters as production, then injects it via
 *  `argon2.verify(sentinel, presentedPassword)`. We expose the helper
 *  through a closure rather than a module-level constant so the sentinel
 *  is bound to the specific `Argon2Service` instance the route uses.
 *
 *  This module owns the closure construction; the bootstrap calls
 *  `prepareTimingDefense(argon2)` and passes the resulting function in
 *  via the plugin deps. (We don't fold the closure into `AuthRoutesDeps`
 *  because tests want to bypass it — they pass `() => false` to skip the
 *  fake verify.) */
export interface TimingDefense {
  /** Run a fake Argon2id verify so the unknown-handle path takes the
   *  same wall-clock time as a real verify. Always returns false. */
  fakeVerify(presentedPassword: string): Promise<false>;
}

/** Construct a `TimingDefense` bound to the given `Argon2Service`. Hashes
 *  a sentinel password ONCE at construction so the per-request `verify`
 *  call doesn't pay the hash cost. */
export async function prepareTimingDefense(
  argon2: Argon2Service,
): Promise<TimingDefense> {
  // The sentinel password is irrelevant — Argon2's work factor is dictated
  // by parameters, not input. We just need *some* hash produced with the
  // production params so verify() does the same amount of work as on the
  // real path.
  const sentinelHash = await argon2.hash('konvo-timing-defense-sentinel');
  return {
    async fakeVerify(presentedPassword: string): Promise<false> {
      // Run verify with a deliberately-wrong password so the result is
      // always false. We don't care about the boolean here; we only care
      // about the time spent.
      await argon2.verify(sentinelHash, presentedPassword);
      return false;
    },
  };
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

/** Set the refresh-token cookie on `reply`. Always uses `Secure;
 *  HttpOnly; SameSite=Lax` per Requirement 19.2.
 *
 *  Note on `secure: true` in development: local dev runs behind Caddy
 *  with auto-TLS at `https://konvo.local`, so the browser DOES send the
 *  cookie. If you bypass Caddy and hit the api directly over
 *  `http://localhost:3000`, the browser will reject the Set-Cookie
 *  silently — that's the intended fail-closed behaviour. We do NOT
 *  conditionally weaken `secure` based on `NODE_ENV` because a forgotten
 *  toggle in production would silently downgrade the security posture. */
function setRefreshCookie(
  reply: FastifyReply,
  cookieName: string,
  cookiePath: string,
  rawToken: string,
  ttlMs: number,
): void {
  reply.setCookie(cookieName, rawToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: cookiePath,
    maxAge: Math.floor(ttlMs / 1000),
  });
}

/** Clear the refresh-token cookie. Used on logout and on
 *  invalid/expired refresh-token branches in /auth/refresh. */
function clearRefreshCookie(
  reply: FastifyReply,
  cookieName: string,
  cookiePath: string,
): void {
  reply.clearCookie(cookieName, { path: cookiePath });
}

// ---------------------------------------------------------------------------
// Route plugin
// ---------------------------------------------------------------------------

/** Configure RFC 6238 TOTP verification. Mirrors `requirements.md` §1.4:
 *  - 6 digits
 *  - 30-second step
 *  - HMAC-SHA1 (the RFC 6238 default; otplib also supports SHA256/512
 *    but Signal-style apps universally use SHA1, and changing it would
 *    break existing authenticator app enrolments)
 *  - window: 1 → accept the previous and next 30-second step (±30s of
 *    clock skew). This matches the Authy / Google Authenticator default
 *    and avoids spurious failures on phones whose clock has drifted.
 *
 *  We construct a fresh `authenticator` instance per plugin so test
 *  isolation is preserved (otplib's default singleton mutates global
 *  options). */
function buildTotpVerifier(): (totp: string, secret: string) => boolean {
  const inst = authenticator.create({
    digits: 6,
    step: 30,
    window: 1,
    algorithm: HashAlgorithms.SHA1,
  });
  return (totp, secret) => inst.check(totp, secret);
}

export const authRoutes: FastifyPluginAsync<AuthRoutesDeps> = async (
  app,
  deps,
) => {
  const cookieName = deps.refreshCookieName ?? DEFAULT_REFRESH_COOKIE_NAME;
  const cookiePath = deps.refreshCookiePath ?? DEFAULT_REFRESH_COOKIE_PATH;
  const ttlMs = deps.refreshTokenTtlMs ?? DEFAULT_REFRESH_TOKEN_TTL_MS;
  const verifyTotp = buildTotpVerifier();
  const timingDefense = await prepareTimingDefense(deps.argon2);

  // -------------------------------------------------------------------------
  // POST /auth/signup (Requirements 1.1, 1.2, 1.13, 1.9, 1.15, 19.4)
  // -------------------------------------------------------------------------
  app.post(
    '/auth/signup',
    {
      config: {
        rateLimit: SIGNUP_RATE_LIMIT,
      },
    },
    async (req, reply) => {
      // 1. Parse + validate body. Either an invalid handle (regex miss,
      //    wrong length, uppercase) or an out-of-range password length
      //    yields HTTP 400 + `{ error: 'invalid_request' }` per
      //    Requirement 1.13. The body shape is the same for both
      //    failure modes so a malformed request can't be used to probe
      //    which field tripped — consistent with Requirement 1.5's
      //    non-disclosing stance on auth errors.
      const parsed = SignupBodySchema.safeParse(req.body);
      if (!parsed.success) {
        return reply.status(400).send({ error: 'invalid_request' });
      }
      const { handle, password } = parsed.data;

      // 2. Hash the password BEFORE the INSERT so a duplicate-handle
      //    rejection still pays the Argon2 cost — otherwise an attacker
      //    can probe handle availability via the difference between a
      //    fast 409 (no hash) and a slow 201 (hash + insert). Spending
      //    the hash unconditionally collapses both paths to the same
      //    wall-clock cost class, mirroring the timing defense on the
      //    login path.
      const passwordHash = await deps.argon2.hash(password);

      // 3. INSERT into `users`. The `handle` column is `CITEXT UNIQUE`
      //    (infra/postgres/init.sql), so a duplicate surfaces as a
      //    Postgres `unique_violation` (SQLSTATE 23505). pg's typed
      //    error carries that code on `error.code`. We translate it to
      //    HTTP 409 per the task brief.
      try {
        const insert = await deps.pool.query<{ id: string }>(
          `INSERT INTO users (handle, password_hash)
           VALUES ($1, $2)
           RETURNING id`,
          [handle, passwordHash],
        );

        // RETURNING guarantees rowCount === 1 on success; if the driver
        // returned an empty result for any reason, fail closed rather
        // than emit a malformed response.
        if (insert.rowCount !== 1 || insert.rows[0] === undefined) {
          throw new Error('signup INSERT returned no rows');
        }

        return reply.status(201).send({ userId: insert.rows[0].id });
      } catch (err: unknown) {
        // pg's runtime errors expose SQLSTATE on `.code`. We narrow via
        // a property check rather than `instanceof pg.DatabaseError`
        // because that constructor isn't part of pg's public surface
        // and tests stub the pool with plain objects that throw an
        // `Error` carrying a `code` field.
        const code =
          typeof err === 'object' && err !== null && 'code' in err
            ? (err as { code?: unknown }).code
            : undefined;

        if (code === '23505') {
          return reply
            .status(409)
            .send({ error: 'handle_unavailable' });
        }

        // Any other failure is a 500 — bubble up so the framework's
        // error handler logs it (with redaction) without leaking the
        // underlying SQL error string to the client.
        throw err;
      }
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/login (Requirement 1.3, 1.4, 1.5, 1.9, 1.13)
  // -------------------------------------------------------------------------
  app.post(
    '/auth/login',
    {
      config: {
        rateLimit: LOGIN_RATE_LIMIT,
      },
    },
    async (req, reply) => {
      // 1. Parse + validate body. zod.safeParse keeps the response shape
      //    consistent regardless of which field failed; we never echo the
      //    rejected payload back so a malformed body doesn't reveal what
      //    we expected.
      const parsed = LoginBodySchema.safeParse(req.body);
      if (!parsed.success) {
        return reply.status(400).send({ error: 'invalid_request' });
      }
      const { handle, password, totp, deviceId } = parsed.data;

      // 2. Look up the user. citext makes the comparison case-insensitive
      //    so `Alice` and `alice` collapse to the same row.
      const lookup = await deps.pool.query<{
        id: string;
        handle: string;
        password_hash: string;
        totp_secret: string | null;
      }>(
        `SELECT id, handle, password_hash, totp_secret
           FROM users
          WHERE handle = $1
          LIMIT 1`,
        [handle],
      );

      // 3. Unknown handle. Run the timing-defense fake verify so this
      //    branch takes the same wall-clock time as the real path, then
      //    return the SAME error body as wrong-password. Per Requirement
      //    1.5 the error MUST NOT disclose which factor failed.
      if (lookup.rowCount === 0) {
        await timingDefense.fakeVerify(password);
        return reply.status(401).send({ error: 'invalid_credentials' });
      }

      // `rowCount > 0` → `rows[0]` defined under noUncheckedIndexedAccess.
      const row = lookup.rows[0] as {
        id: string;
        handle: string;
        password_hash: string;
        totp_secret: string | null;
      };

      // 4. Verify password. Argon2 verify takes the params from the stored
      //    hash, so a future param upgrade still validates legacy users.
      const passwordOk = await deps.argon2.verify(row.password_hash, password);
      if (!passwordOk) {
        return reply.status(401).send({ error: 'invalid_credentials' });
      }

      // 5. TOTP. Per Requirement 1.4 it's required ONLY when the user
      //    has enrolled (totp_secret is non-null). When required:
      //      - missing → invalid_credentials (NOT a separate "totp_required"
      //        error; that would let an attacker enumerate which accounts
      //        have 2FA enabled).
      //      - wrong → invalid_credentials.
      if (row.totp_secret !== null) {
        if (totp === undefined) {
          return reply.status(401).send({ error: 'invalid_credentials' });
        }
        const totpOk = verifyTotp(totp, row.totp_secret);
        if (!totpOk) {
          return reply.status(401).send({ error: 'invalid_credentials' });
        }
      }

      // 6. Issue tokens. See Phase-1 device-id caveat in the file header
      //    for why `did` may be the empty string here.
      const accessToken = await deps.accessTokenService.sign({
        sub: row.id,
        did: deviceId ?? '',
      });
      const refresh = await deps.refreshTokenStore.issue(row.id);

      // 7. Set the cookie AND echo the raw token in the body. Per design.md
      //    §9 LoginResponse, native clients (mobile WebView wrappers) can't
      //    rely on cookies, so we include `refreshToken` in the body too.
      //    Web clients should ignore the body field and rely on the cookie.
      setRefreshCookie(reply, cookieName, cookiePath, refresh.raw, ttlMs);

      return reply.status(200).send({
        accessToken,
        refreshToken: refresh.raw,
        user: { id: row.id, handle: row.handle },
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/refresh (Requirements 1.6, 1.7, 1.14, 1.15)
  // -------------------------------------------------------------------------
  app.post(
    '/auth/refresh',
    {
      config: {
        rateLimit: REFRESH_RATE_LIMIT,
      },
    },
    async (req, reply) => {
      // 1. Validate query (just deviceId). A malformed deviceId (non-UUID)
      //    is treated as a 400 — this is a programmer error from the client,
      //    not an auth failure.
      const parsedQuery = RefreshQuerySchema.safeParse(req.query);
      if (!parsedQuery.success) {
        return reply.status(400).send({ error: 'invalid_request' });
      }
      const { deviceId } = parsedQuery.data;

      // 2. Read the refresh token from the cookie. `req.cookies` is
      //    populated by `@fastify/cookie` (registered globally in
      //    server.ts). Missing cookie → 401 generic.
      const rawToken = req.cookies[cookieName];
      if (typeof rawToken !== 'string' || rawToken.length === 0) {
        return reply.status(401).send({ error: 'invalid_credentials' });
      }

      // 3. Rotate. The store throws:
      //      - InvalidRefreshTokenError on unknown / replay (1.14 family
      //        revoke happens inside rotate()).
      //      - RefreshTokenExpiredError on expired-but-otherwise-valid.
      //    Either way we clear the cookie before responding.
      let rotated;
      try {
        rotated = await deps.refreshTokenStore.rotate(rawToken);
      } catch (err) {
        clearRefreshCookie(reply, cookieName, cookiePath);
        if (err instanceof RefreshTokenExpiredError) {
          return reply.status(401).send({ error: 'session_expired' });
        }
        if (err instanceof InvalidRefreshTokenError) {
          return reply.status(401).send({ error: 'invalid_credentials' });
        }
        // Unknown error — surface as 500 (the route layer's error handler
        // will redact details before logging).
        throw err;
      }

      // 4. Issue a new access token. Same Phase-1 device-id caveat as
      //    /auth/login.
      const accessToken = await deps.accessTokenService.sign({
        sub: rotated.userId,
        did: deviceId ?? '',
      });

      // 5. Replace the cookie with the new raw token.
      setRefreshCookie(reply, cookieName, cookiePath, rotated.raw, ttlMs);

      return reply.status(200).send({ accessToken });
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/logout (Requirement 1.8)
  // -------------------------------------------------------------------------
  app.post('/auth/logout', async (req, reply) => {
    // Logout is idempotent: revoke the cookie-borne token if present, then
    // clear the cookie regardless. Reply is always 204 (no body) so a
    // missing cookie can't be distinguished from a successful revoke —
    // this prevents an attacker from probing for stale sessions by
    // observing response shape.
    const rawToken = req.cookies[cookieName];
    if (typeof rawToken === 'string' && rawToken.length > 0) {
      // The store's revoke() is itself idempotent — it's a no-op on
      // unknown / already-revoked tokens.
      await deps.refreshTokenStore.revoke(rawToken);
    }
    clearRefreshCookie(reply, cookieName, cookiePath);
    return reply.status(204).send();
  });
};

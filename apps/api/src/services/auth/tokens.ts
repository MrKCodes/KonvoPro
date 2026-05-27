// JWT access tokens + opaque refresh-token store (task 2.2).
//
// Realizes Requirements 1.3, 1.6, 1.7, 1.14 and design.md §18.2:
//   - 1.3  : login issues a 15-minute access token (HS256 JWT) and a
//            30-day refresh token; refresh token is httpOnly/Secure/SameSite=Lax.
//   - 1.6  : `/auth/refresh` exchanges a valid refresh token for a new
//            15-min access token (this module exposes the primitives the
//            route uses; route wiring lands in task 2.4).
//   - 1.7  : every refresh-token use rotates the token; the prior token
//            becomes invalid.
//   - 1.14 : if a refresh token that has already been rotated/revoked
//            is presented, ALL active refresh tokens for the owning user
//            are revoked and the request is rejected.
//   - 18.2 : access-token claims are exactly `{sub, did, iat, exp}`,
//            HS256, 15-min TTL.
//
// Design notes:
//   - We use `jose` rather than `jsonwebtoken` for first-class ESM support
//     under apps/api's `"type": "module"` configuration.
//   - The access token is symmetric (HS256). The signing key is a single
//     secret loaded from `JWT_ACCESS_SECRET` via the config layer; rotation
//     is operator-driven (env change + rolling restart).
//   - Refresh tokens are opaque random 256-bit values. Only their
//     SHA-256 hash (peppered with `REFRESH_TOKEN_PEPPER`) is persisted, so
//     a database snapshot leak does not yield usable tokens.
//   - Rotation is implemented as a SQL transaction over a `FOR UPDATE`
//     row lock. The replay-detection branch (req 1.14) revokes all of the
//     user's active tokens inside the same transaction.
//   - Database access is delegated to a `pg.Pool`-shaped object so tests
//     can mock the surface without bringing up Postgres. Real integration
//     tests against a live Postgres land in
//     `apps/api/test/tokens.integration.spec.ts` (CI; not authored here).

import { createHash, randomBytes } from 'node:crypto';

import { jwtVerify, SignJWT } from 'jose';
import type pg from 'pg';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Thrown by `RefreshTokenStore.rotate` / `revoke` when the presented raw
 *  token does not match an active row, OR when it matches a row that was
 *  previously rotated/revoked (replay). The route layer maps this to
 *  HTTP 401 with a non-disclosing body per Requirement 1.14. */
export class InvalidRefreshTokenError extends Error {
  constructor(message = 'invalid refresh token') {
    super(message);
    this.name = 'InvalidRefreshTokenError';
  }
}

/** Thrown by `RefreshTokenStore.rotate` when the presented row is valid
 *  but past `expires_at`. Distinct from InvalidRefreshTokenError so the
 *  route layer can surface a "session expired" UX without conflating it
 *  with replay/tamper. Per Requirement 1.14 this branch does NOT trigger
 *  the family-revoke; an honest expired token is not a sign of compromise. */
export class RefreshTokenExpiredError extends Error {
  constructor(message = 'refresh token expired') {
    super(message);
    this.name = 'RefreshTokenExpiredError';
  }
}

// ---------------------------------------------------------------------------
// Access token service (HS256 JWT, 15-min TTL)
// ---------------------------------------------------------------------------

/** The exact claim set required by Requirement 1.3 and design.md §18.2.
 *  - `sub` : user UUID
 *  - `did` : device UUID (custom claim — JWT WS auth in task 3.3 keys
 *            envelope ownership off this)
 *  - `iat` : issued-at, epoch seconds (set by jose via setIssuedAt)
 *  - `exp` : expires-at, epoch seconds (set by jose via setExpirationTime) */
export interface AccessTokenClaims {
  readonly sub: string;
  readonly did: string;
  readonly iat: number;
  readonly exp: number;
}

export interface AccessTokenService {
  /** Sign a fresh access token for `(userId, deviceId)`. Returns the
   *  compact-serialized JWT string. The TTL is fixed at construction. */
  sign(claims: { sub: string; did: string }): Promise<string>;

  /** Verify a presented JWT, asserting HS256 + the configured secret +
   *  exp not in the past. Returns the validated claim set. Throws on
   *  any verification failure (signature mismatch, wrong alg, expired). */
  verify(token: string): Promise<AccessTokenClaims>;
}

const DEFAULT_ACCESS_TOKEN_TTL_SEC = 15 * 60;

/** Construct an `AccessTokenService` bound to the given symmetric secret
 *  and TTL (in seconds). The secret MUST be the value loaded from
 *  `config.JWT_ACCESS_SECRET`; passing anything shorter than the schema's
 *  32-char minimum will still work here but undermines the auth posture. */
export function createAccessTokenService(
  secret: string,
  ttlSec: number = DEFAULT_ACCESS_TOKEN_TTL_SEC,
): AccessTokenService {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('createAccessTokenService: secret must be a non-empty string');
  }
  if (!Number.isInteger(ttlSec) || ttlSec < 1) {
    throw new Error(
      `createAccessTokenService: ttlSec must be a positive integer, got ${String(ttlSec)}`,
    );
  }

  // jose accepts a Uint8Array for HS* algorithms. Encode once at
  // construction so we don't allocate on every sign/verify.
  const key = new TextEncoder().encode(secret);

  return {
    async sign(claims: { sub: string; did: string }): Promise<string> {
      // setSubject populates `sub`; the custom `did` claim is set via
      // the constructor payload. setIssuedAt + setExpirationTime fill
      // `iat` and `exp` per design.md §18.2.
      return new SignJWT({ did: claims.did })
        .setProtectedHeader({ alg: 'HS256' })
        .setSubject(claims.sub)
        .setIssuedAt()
        .setExpirationTime(`${ttlSec}s`)
        .sign(key);
    },

    async verify(token: string): Promise<AccessTokenClaims> {
      // `algorithms` lock forces HS256; an attacker swapping in `none`
      // or `RS256` is rejected at the algorithm-selection step rather
      // than after the signature check, eliminating the alg-confusion
      // class of attacks.
      const result = await jwtVerify(token, key, { algorithms: ['HS256'] });
      const payload = result.payload;

      // jose validates `exp` against the current clock automatically and
      // throws JWTExpired if it's in the past. We still need to project
      // the dynamic payload back into our typed claim shape.
      const sub = payload.sub;
      const did = payload['did'];
      const iat = payload.iat;
      const exp = payload.exp;

      if (typeof sub !== 'string' || sub.length === 0) {
        throw new Error('access token missing required claim: sub');
      }
      if (typeof did !== 'string' || did.length === 0) {
        throw new Error('access token missing required claim: did');
      }
      if (typeof iat !== 'number') {
        throw new Error('access token missing required claim: iat');
      }
      if (typeof exp !== 'number') {
        throw new Error('access token missing required claim: exp');
      }

      return { sub, did, iat, exp };
    },
  };
}

// ---------------------------------------------------------------------------
// Refresh token store (opaque 256-bit, sha256+pepper, rotation w/ replay defense)
// ---------------------------------------------------------------------------

/** The minimal `pg.Pool` surface we depend on. Restated as a structural
 *  type so tests can stub it without instantiating a real Pool. */
type DbPool = Pick<pg.Pool, 'connect'>;

export interface RefreshTokenStore {
  /** Issue a fresh opaque 256-bit refresh token for `userId`. Persists
   *  only the sha256-peppered hash; returns the raw token + absolute
   *  expiry so the route layer can set the cookie. */
  issue(userId: string): Promise<{ raw: string; expiresAt: Date }>;

  /** Validate the presented raw token, mark it rotated, and issue a
   *  fresh one — atomically, in a single transaction.
   *
   *  Throws:
   *    - InvalidRefreshTokenError if the token is unknown OR if it has
   *      already been rotated/revoked. In the latter case ALL active
   *      refresh tokens for the owning user are revoked before throwing
   *      (Requirement 1.14).
   *    - RefreshTokenExpiredError if the row is otherwise valid but past
   *      its `expires_at`.
   */
  rotate(presentedRaw: string): Promise<{
    userId: string;
    raw: string;
    expiresAt: Date;
  }>;

  /** Revoke a single token (e.g. logout). Idempotent: revoking a token
   *  that is already revoked or unknown is a silent no-op so the route
   *  layer can return 204 without leaking which case occurred. */
  revoke(presentedRaw: string): Promise<void>;

  /** Revoke every active refresh token for `userId`. Used by the route
   *  layer when an admin disables an account or after device revocation;
   *  also invoked internally by `rotate` on replay detection. */
  revokeAllForUser(userId: string): Promise<void>;
}

/** 30 days, in milliseconds. Matches design.md §18.2. */
const DEFAULT_REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Number of random bytes per opaque refresh token. 32 bytes = 256 bits
 *  of entropy, encoded as base64url for cookie transport. */
const REFRESH_TOKEN_BYTES = 32;

/** Generate a fresh opaque 256-bit token, base64url-encoded. */
function generateRawRefreshToken(): string {
  // Node's crypto.randomBytes is a CSPRNG (libcrypto / OpenSSL) and is the
  // appropriate primitive here per design.md §18.2 ("opaque random 256-bit").
  // We avoid `crypto.getRandomValues` because we want the Buffer form's
  // base64url encoder rather than re-implementing it for Uint8Array.
  return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
}

/** Hash the raw token with sha256, peppered by the global secret.
 *  Pepper is updated via `update()` after the raw value so a hash
 *  cannot be replayed against a different deployment that happens to
 *  share the same DB snapshot. Returns a Buffer suitable for direct
 *  use as a `BYTEA` parameter in pg. */
function hashRefreshToken(raw: string, pepper: string): Buffer {
  return createHash('sha256').update(raw).update(pepper).digest();
}

/** Construct a `RefreshTokenStore` against the given `pg.Pool`. The
 *  pool is owned by the caller (apps/api/src/server.ts in task 2.3+
 *  will create a single shared pool); this factory simply borrows it.
 *  `pepper` MUST be the value loaded from `config.REFRESH_TOKEN_PEPPER`. */
export function createRefreshTokenStore(
  pool: DbPool,
  pepper: string,
  ttlMs: number = DEFAULT_REFRESH_TOKEN_TTL_MS,
): RefreshTokenStore {
  if (typeof pepper !== 'string' || pepper.length === 0) {
    throw new Error('createRefreshTokenStore: pepper must be a non-empty string');
  }
  if (!Number.isInteger(ttlMs) || ttlMs < 1) {
    throw new Error(
      `createRefreshTokenStore: ttlMs must be a positive integer, got ${String(ttlMs)}`,
    );
  }

  return {
    async issue(userId: string): Promise<{ raw: string; expiresAt: Date }> {
      const raw = generateRawRefreshToken();
      const tokenHash = hashRefreshToken(raw, pepper);
      const expiresAt = new Date(Date.now() + ttlMs);

      const client = await pool.connect();
      try {
        await client.query(
          `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
           VALUES ($1, $2, $3)
           RETURNING id`,
          [userId, tokenHash, expiresAt],
        );
      } finally {
        client.release();
      }

      return { raw, expiresAt };
    },

    async rotate(
      presentedRaw: string,
    ): Promise<{ userId: string; raw: string; expiresAt: Date }> {
      const presentedHash = hashRefreshToken(presentedRaw, pepper);

      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Step 1: lock the row matching the presented hash. FOR UPDATE
        // serializes concurrent rotations of the same token so two
        // simultaneous /auth/refresh calls can't both succeed.
        const lookup = await client.query<{
          id: string;
          user_id: string;
          expires_at: Date;
          rotated_at: Date | null;
          revoked_at: Date | null;
        }>(
          `SELECT id, user_id, expires_at, rotated_at, revoked_at
           FROM refresh_tokens
           WHERE token_hash = $1
           FOR UPDATE`,
          [presentedHash],
        );

        // Step 2: unknown token. We have no associated user, so we
        // cannot do a family-revoke — bail immediately. The COMMIT here
        // is harmless (no writes) but keeps the connection clean.
        if (lookup.rowCount === 0) {
          await client.query('COMMIT');
          throw new InvalidRefreshTokenError('refresh token not recognized');
        }

        // `rowCount > 0` guarantees `rows[0]` is defined; the cast
        // narrows under `noUncheckedIndexedAccess`.
        const row = lookup.rows[0] as {
          id: string;
          user_id: string;
          expires_at: Date;
          rotated_at: Date | null;
          revoked_at: Date | null;
        };

        // Step 3: replay or revoked. Per Requirement 1.14, revoke
        // EVERY active refresh token for this user inside the same
        // transaction, then refuse this rotation.
        if (row.rotated_at !== null || row.revoked_at !== null) {
          await client.query(
            `UPDATE refresh_tokens
             SET revoked_at = now()
             WHERE user_id = $1 AND revoked_at IS NULL`,
            [row.user_id],
          );
          await client.query('COMMIT');
          throw new InvalidRefreshTokenError(
            'refresh token reuse detected; all sessions revoked',
          );
        }

        // Step 4: expired-but-otherwise-valid. Distinct error class so
        // the route layer can surface a "session expired" UX. We do
        // NOT family-revoke here — an honest expired token isn't a
        // compromise signal — and we deliberately do NOT mark this row
        // revoked either. If we set revoked_at on expiry, a second
        // presentation of the same expired token would fall into the
        // step-3 replay branch above and incorrectly trigger a
        // family-revoke. Leaving the row untouched keeps "expired"
        // distinct from "rotated/revoked" on subsequent presentations.
        if (row.expires_at.getTime() <= Date.now()) {
          await client.query('COMMIT');
          throw new RefreshTokenExpiredError();
        }

        // Step 5: mark the presented row rotated. Subsequent presentations
        // of this raw value will hit the replay branch above.
        await client.query(
          `UPDATE refresh_tokens
           SET rotated_at = now()
           WHERE id = $1`,
          [row.id],
        );

        // Step 6: issue the successor token and persist its hash.
        const newRaw = generateRawRefreshToken();
        const newHash = hashRefreshToken(newRaw, pepper);
        const newExpiresAt = new Date(Date.now() + ttlMs);

        await client.query(
          `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
           VALUES ($1, $2, $3)`,
          [row.user_id, newHash, newExpiresAt],
        );

        await client.query('COMMIT');

        return {
          userId: row.user_id,
          raw: newRaw,
          expiresAt: newExpiresAt,
        };
      } catch (err) {
        // Best-effort rollback. If the COMMIT in the replay/expired
        // branches already ran we'll get a "no transaction in progress"
        // error here, which we swallow — the original error is what
        // the route layer needs to see.
        try {
          await client.query('ROLLBACK');
        } catch {
          // intentionally swallowed
        }
        throw err;
      } finally {
        client.release();
      }
    },

    async revoke(presentedRaw: string): Promise<void> {
      const presentedHash = hashRefreshToken(presentedRaw, pepper);

      const client = await pool.connect();
      try {
        // Idempotent revoke — UPDATE matches at most one row (UNIQUE
        // on token_hash) and is a no-op if already revoked.
        await client.query(
          `UPDATE refresh_tokens
           SET revoked_at = now()
           WHERE token_hash = $1 AND revoked_at IS NULL`,
          [presentedHash],
        );
      } finally {
        client.release();
      }
    },

    async revokeAllForUser(userId: string): Promise<void> {
      const client = await pool.connect();
      try {
        await client.query(
          `UPDATE refresh_tokens
           SET revoked_at = now()
           WHERE user_id = $1 AND revoked_at IS NULL`,
          [userId],
        );
      } finally {
        client.release();
      }
    },
  };
}

// apps/api/test/auth-routes.test.ts
//
// Unit tests for the `/auth/{login,refresh,logout}` routes (task 2.4).
//
// Validates Requirements 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.14 and design.md §9.
//
// Strategy: we exercise the route plugin in isolation by registering it
// against a fresh Fastify instance per test, with mocked dependencies for
// argon2, the pg pool, the access-token service, and the refresh-token
// store. This is a UNIT test of route behaviour — it does not exercise
// Postgres, Argon2 native bindings, or jose's signature math. Those are
// covered by `argon2.test.ts` and `tokens.test.ts` (and a future
// `auth-routes.integration.spec.ts` against a real stack).
//
// Per the task brief, rate-limit testing is deferred to the integration
// spec; we register `@fastify/rate-limit` with permissive config here so
// the `config.rateLimit` route options resolve without surprises.

import { describe, expect, it, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyRateLimit from '@fastify/rate-limit';

import {
  authRoutes,
  type AuthRoutesDeps,
} from '../src/routes/auth.js';
import {
  InvalidRefreshTokenError,
  RefreshTokenExpiredError,
  type AccessTokenService,
  type RefreshTokenStore,
} from '../src/services/auth/tokens.js';
import { type Argon2Service } from '../src/services/auth/argon2.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

interface FakeUserRow {
  id: string;
  handle: string;
  password_hash: string;
  totp_secret: string | null;
}

/** A pg.Pool stub that returns a fixed row when the SELECT runs. The
 *  match is by handle (case-insensitive) so we mirror citext semantics. */
function makePool(rows: FakeUserRow[]) {
  return {
    async query<T>(_sql: string, params?: readonly unknown[]) {
      const handle = String(params?.[0] ?? '').toLowerCase();
      const found = rows.find((r) => r.handle.toLowerCase() === handle);
      if (found === undefined) {
        return { rows: [] as T[], rowCount: 0 };
      }
      return { rows: [found as unknown as T], rowCount: 1 };
    },
  };
}

/** A fast Argon2Service stub. We avoid real Argon2 for speed; the timing-
 *  defense path still exercises hash() + verify() on a sentinel, so we
 *  don't need to gate behaviour on real cryptographic work. */
function makeArgon2(passwords: Record<string, string>): Argon2Service {
  // `passwords` maps password-hash → plaintext that should validate.
  return {
    async hash(p: string): Promise<string> {
      return `mock$${p}`;
    },
    async verify(passwordHash: string, password: string): Promise<boolean> {
      return passwords[passwordHash] === password;
    },
  };
}

function makeAccessTokenService(): AccessTokenService {
  return {
    async sign(claims: { sub: string; did: string }): Promise<string> {
      return `access.${claims.sub}.${claims.did}`;
    },
    async verify(): Promise<never> {
      throw new Error('not used in route tests');
    },
  };
}

interface RefreshStoreStub extends RefreshTokenStore {
  readonly issuedFor: string[];
  readonly rotated: string[];
  readonly revoked: string[];
}

function makeRefreshStore(opts: {
  rotateThrows?: Error;
  rotateUserId?: string;
} = {}): RefreshStoreStub {
  const issuedFor: string[] = [];
  const rotated: string[] = [];
  const revoked: string[] = [];
  return {
    issuedFor,
    rotated,
    revoked,
    async issue(userId: string) {
      issuedFor.push(userId);
      return {
        raw: `rt-issued-${issuedFor.length}`,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      };
    },
    async rotate(presented: string) {
      rotated.push(presented);
      if (opts.rotateThrows !== undefined) {
        throw opts.rotateThrows;
      }
      return {
        userId: opts.rotateUserId ?? 'user-1',
        raw: `rt-rotated-${rotated.length}`,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      };
    },
    async revoke(presented: string) {
      revoked.push(presented);
    },
    async revokeAllForUser() {
      // unused by these tests
    },
  };
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

async function buildApp(deps: AuthRoutesDeps): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(fastifyCookie);
  // Permissive rate limit so the per-route configs in the auth plugin
  // resolve without 429-ing test traffic.
  await app.register(fastifyRateLimit, {
    global: false,
    max: 1000,
    timeWindow: '1 minute',
  });
  await app.register(authRoutes, deps);
  await app.ready();
  return app;
}

// Shared user row used across login tests. The password "correct horse battery"
// is 21 chars (passes the 12..128 minLength); the hash is the sentinel format
// produced by `makeArgon2`.
const ALICE: FakeUserRow = {
  id: '11111111-1111-1111-1111-111111111111',
  handle: 'alice',
  password_hash: 'mock$correct horse battery',
  totp_secret: null,
};

// ---------------------------------------------------------------------------
// /auth/signup
// ---------------------------------------------------------------------------

/** A pg.Pool stub for signup tests. Routes the SELECT path to the rows
 *  list (so the timing-defense doesn't blow up if it runs by accident),
 *  and routes the INSERT path through `onInsert(handle, passwordHash)`
 *  which returns either a `{ id }` row, throws a Postgres-shaped error
 *  with `code = '23505'`, or throws a generic error for the 500 branch. */
function makeSignupPool(opts: {
  onInsert: (
    handle: string,
    passwordHash: string,
  ) => Promise<{ id: string }> | { id: string };
}) {
  const inserts: Array<{ handle: string; passwordHash: string }> = [];
  return {
    inserts,
    async query<T>(sql: string, params?: readonly unknown[]) {
      const isInsert = sql.includes('INSERT INTO users');
      if (!isInsert) {
        // Login-style SELECT — return empty so signup tests never
        // accidentally exercise the login-handle-lookup path.
        return { rows: [] as T[], rowCount: 0 };
      }
      const handle = String(params?.[0] ?? '');
      const passwordHash = String(params?.[1] ?? '');
      inserts.push({ handle, passwordHash });
      const row = await opts.onInsert(handle, passwordHash);
      return {
        rows: [row as unknown as T],
        rowCount: 1,
      };
    },
  };
}

/** Build a Postgres-shaped unique-violation error matching what `pg`
 *  throws on a `users_handle_key` collision. We only set `code` because
 *  the route narrows on that exact field. */
function pgUniqueViolation(): Error & { code: string } {
  const err = new Error(
    'duplicate key value violates unique constraint "users_handle_key"',
  ) as Error & { code: string };
  err.code = '23505';
  return err;
}

describe('POST /auth/signup', () => {
  it('returns 201 with userId on valid handle + password', async () => {
    const NEW_USER_ID = '99999999-9999-9999-9999-999999999999';
    const pool = makeSignupPool({
      onInsert: () => ({ id: NEW_USER_ID }),
    });
    const app = await buildApp({
      pool,
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: makeRefreshStore(),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: { handle: 'alice_99', password: 'correct horse battery' },
    });

    expect(res.statusCode).toBe(201);
    expect(res.json()).toEqual({ userId: NEW_USER_ID });

    // The INSERT must have run with the lowercased handle and a hashed
    // (not plaintext) password.
    expect(pool.inserts).toHaveLength(1);
    expect(pool.inserts[0]?.handle).toBe('alice_99');
    expect(pool.inserts[0]?.passwordHash).toBe('mock$correct horse battery');
    // Sanity: the hash format is what argon2.hash returns, never the
    // raw password — confirms we hashed before the INSERT.
    expect(pool.inserts[0]?.passwordHash.startsWith('mock$')).toBe(true);
  });

  it('returns 409 handle_unavailable on duplicate handle (Postgres 23505)', async () => {
    const pool = makeSignupPool({
      onInsert: () => {
        throw pgUniqueViolation();
      },
    });
    const app = await buildApp({
      pool,
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: makeRefreshStore(),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: { handle: 'taken_user', password: 'correct horse battery' },
    });

    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ error: 'handle_unavailable' });
  });

  it.each([
    { label: 'uppercase letters', handle: 'Alice' },
    { label: 'too short (2 chars)', handle: 'al' },
    { label: 'too long (33 chars)', handle: 'a'.repeat(33) },
    { label: 'invalid char (dash)', handle: 'alice-99' },
    { label: 'invalid char (dot)', handle: 'alice.99' },
    { label: 'invalid char (space)', handle: 'alice 99' },
  ])(
    'returns 400 invalid_request on invalid handle: $label',
    async ({ handle }) => {
      const pool = makeSignupPool({
        onInsert: () => {
          throw new Error(
            'INSERT must not run on invalid handle',
          );
        },
      });
      const app = await buildApp({
        pool,
        argon2: makeArgon2({}),
        accessTokenService: makeAccessTokenService(),
        refreshTokenStore: makeRefreshStore(),
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        payload: { handle, password: 'correct horse battery' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ error: 'invalid_request' });
      expect(pool.inserts).toHaveLength(0);
    },
  );

  it.each([
    { label: 'empty', password: '' },
    { label: '11 chars (one below minimum)', password: 'a'.repeat(11) },
    { label: '129 chars (one above maximum)', password: 'a'.repeat(129) },
  ])(
    'returns 400 invalid_request on invalid password length: $label',
    async ({ password }) => {
      const pool = makeSignupPool({
        onInsert: () => {
          throw new Error(
            'INSERT must not run on invalid password length',
          );
        },
      });
      const app = await buildApp({
        pool,
        argon2: makeArgon2({}),
        accessTokenService: makeAccessTokenService(),
        refreshTokenStore: makeRefreshStore(),
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        payload: { handle: 'alice_99', password },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ error: 'invalid_request' });
      expect(pool.inserts).toHaveLength(0);
    },
  );

  it('accepts boundary password lengths (12 and 128 chars)', async () => {
    const pool = makeSignupPool({
      onInsert: () => ({ id: 'id-boundary' }),
    });
    const app = await buildApp({
      pool,
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: makeRefreshStore(),
    });

    for (const password of ['a'.repeat(12), 'b'.repeat(128)]) {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        payload: { handle: 'alice_99', password },
      });
      expect(res.statusCode).toBe(201);
    }
  });

  it('rejects unknown body keys with 400 invalid_request', async () => {
    const pool = makeSignupPool({
      onInsert: () => {
        throw new Error('INSERT must not run on extra body keys');
      },
    });
    const app = await buildApp({
      pool,
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: makeRefreshStore(),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/signup',
      payload: {
        handle: 'alice_99',
        password: 'correct horse battery',
        extra: 'should-be-rejected',
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'invalid_request' });
    expect(pool.inserts).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// /auth/login
// ---------------------------------------------------------------------------

describe('POST /auth/login', () => {
  let app: FastifyInstance;
  let store: RefreshStoreStub;

  beforeEach(async () => {
    store = makeRefreshStore();
    app = await buildApp({
      pool: makePool([ALICE]),
      argon2: makeArgon2({ 'mock$correct horse battery': 'correct horse battery' }),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: store,
    });
  });

  it('returns 200 with accessToken + cookie on valid credentials (no TOTP)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { handle: 'alice', password: 'correct horse battery' },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      accessToken: string;
      refreshToken: string;
      user: { id: string; handle: string };
    };
    expect(body.accessToken).toBe('access.11111111-1111-1111-1111-111111111111.');
    expect(body.refreshToken).toBe('rt-issued-1');
    expect(body.user).toEqual({ id: ALICE.id, handle: ALICE.handle });

    // Cookie must carry Secure; HttpOnly; SameSite=Lax (Requirement 19.2).
    const setCookie = res.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie);
    expect(cookieHeader).toContain('konvo_rt=rt-issued-1');
    expect(cookieHeader).toContain('HttpOnly');
    expect(cookieHeader).toContain('Secure');
    expect(cookieHeader).toMatch(/SameSite=Lax/i);
    expect(cookieHeader).toContain('Path=/auth');

    expect(store.issuedFor).toEqual([ALICE.id]);
  });

  it('issues access token with did=deviceId when deviceId provided', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        handle: 'alice',
        password: 'correct horse battery',
        deviceId: '22222222-2222-2222-2222-222222222222',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { accessToken: string };
    expect(body.accessToken).toBe(
      'access.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222',
    );
  });

  it('returns 401 invalid_credentials on unknown handle (no cookie)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { handle: 'nobody', password: 'some password 123' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'invalid_credentials' });
    expect(res.headers['set-cookie']).toBeUndefined();
    expect(store.issuedFor).toEqual([]);
  });

  it('returns 401 invalid_credentials on wrong password (no cookie)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { handle: 'alice', password: 'wrong password 123' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'invalid_credentials' });
    expect(res.headers['set-cookie']).toBeUndefined();
    expect(store.issuedFor).toEqual([]);
  });

  it('returns 400 invalid_request when password is shorter than 12 chars', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { handle: 'alice', password: 'short' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'invalid_request' });
  });

  it('returns 400 invalid_request when totp is not 6 digits', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        handle: 'alice',
        password: 'correct horse battery',
        totp: 'abc123',
      },
    });

    expect(res.statusCode).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// /auth/login with TOTP
// ---------------------------------------------------------------------------

describe('POST /auth/login (TOTP enrolled)', () => {
  // We use otplib's `authenticator` to produce a fresh code so the route's
  // verifier (also otplib) accepts it. This is the only place we exercise
  // real otplib in the unit suite.
  it.each([
    {
      label: 'missing TOTP when required → 401 invalid_credentials',
      provideTotp: false,
      tamperTotp: false,
      expectStatus: 401,
    },
    {
      label: 'invalid TOTP → 401 invalid_credentials',
      provideTotp: true,
      tamperTotp: true,
      expectStatus: 401,
    },
    {
      label: 'valid TOTP → 200',
      provideTotp: true,
      tamperTotp: false,
      expectStatus: 200,
    },
  ])('$label', async ({ provideTotp, tamperTotp, expectStatus }) => {
    const { authenticator } = await import('otplib');
    // base32 secret as expected by RFC 6238 / otplib. 16 chars is the
    // length authenticator.generateSecret() emits at default.
    const secret = 'JBSWY3DPEHPK3PXP';
    const aliceWithTotp: FakeUserRow = { ...ALICE, totp_secret: secret };

    const app = await buildApp({
      pool: makePool([aliceWithTotp]),
      argon2: makeArgon2({ 'mock$correct horse battery': 'correct horse battery' }),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: makeRefreshStore(),
    });

    let totpCode: string | undefined;
    if (provideTotp) {
      const code = authenticator.generate(secret);
      totpCode = tamperTotp
        ? // Bump the last digit so the code is structurally valid (6
          // digits) but semantically wrong.
          code.slice(0, 5) + (code[5] === '0' ? '1' : '0')
        : code;
    }

    const payload: Record<string, unknown> = {
      handle: 'alice',
      password: 'correct horse battery',
    };
    if (totpCode !== undefined) payload['totp'] = totpCode;

    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload,
    });

    expect(res.statusCode).toBe(expectStatus);
    if (expectStatus === 401) {
      expect(res.json()).toEqual({ error: 'invalid_credentials' });
      expect(res.headers['set-cookie']).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// /auth/refresh
// ---------------------------------------------------------------------------

describe('POST /auth/refresh', () => {
  it('returns 401 invalid_credentials when no cookie present', async () => {
    const app = await buildApp({
      pool: makePool([]),
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: makeRefreshStore(),
    });

    const res = await app.inject({ method: 'POST', url: '/auth/refresh' });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'invalid_credentials' });
  });

  it('returns 200 + new accessToken + replaced cookie on valid refresh', async () => {
    const store = makeRefreshStore({ rotateUserId: 'user-7' });
    const app = await buildApp({
      pool: makePool([]),
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: store,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: { konvo_rt: 'rt-presented' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ accessToken: 'access.user-7.' });
    expect(store.rotated).toEqual(['rt-presented']);

    const setCookie = res.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie);
    expect(cookieHeader).toContain('konvo_rt=rt-rotated-1');
    expect(cookieHeader).toContain('HttpOnly');
    expect(cookieHeader).toContain('Secure');
    expect(cookieHeader).toMatch(/SameSite=Lax/i);
    expect(cookieHeader).toContain('Path=/auth');
  });

  it('returns 401 invalid_credentials + clears cookie on rotated/replayed token', async () => {
    const store = makeRefreshStore({
      rotateThrows: new InvalidRefreshTokenError('replay'),
    });
    const app = await buildApp({
      pool: makePool([]),
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: store,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: { konvo_rt: 'rt-stale' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'invalid_credentials' });
    expect(store.rotated).toEqual(['rt-stale']);

    const setCookie = res.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie);
    // clearCookie sets Max-Age=0 / Expires in the past
    expect(cookieHeader).toContain('konvo_rt=');
    expect(cookieHeader).toContain('Path=/auth');
  });

  it('returns 401 session_expired + clears cookie on expired refresh token', async () => {
    const store = makeRefreshStore({
      rotateThrows: new RefreshTokenExpiredError(),
    });
    const app = await buildApp({
      pool: makePool([]),
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: store,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      cookies: { konvo_rt: 'rt-expired' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'session_expired' });

    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// /auth/logout
// ---------------------------------------------------------------------------

describe('POST /auth/logout', () => {
  it('returns 204 + revokes token + clears cookie when cookie is present', async () => {
    const store = makeRefreshStore();
    const app = await buildApp({
      pool: makePool([]),
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: store,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      cookies: { konvo_rt: 'rt-present' },
    });

    expect(res.statusCode).toBe(204);
    expect(res.body).toBe('');
    expect(store.revoked).toEqual(['rt-present']);

    const setCookie = res.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie);
    expect(cookieHeader).toContain('konvo_rt=');
    expect(cookieHeader).toContain('Path=/auth');
  });

  it('returns 204 + clears cookie when no cookie present (idempotent)', async () => {
    const store = makeRefreshStore();
    const app = await buildApp({
      pool: makePool([]),
      argon2: makeArgon2({}),
      accessTokenService: makeAccessTokenService(),
      refreshTokenStore: store,
    });

    const res = await app.inject({ method: 'POST', url: '/auth/logout' });

    expect(res.statusCode).toBe(204);
    expect(store.revoked).toEqual([]);
  });
});

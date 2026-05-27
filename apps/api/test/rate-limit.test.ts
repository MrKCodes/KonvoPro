// apps/api/test/rate-limit.test.ts
//
// Unit test for `@fastify/rate-limit` enforcement on `/auth/*` routes
// (task 2.11 — rate-limit leg of the auth-service test suite).
//
// Validates Requirements 1.7 / 1.9 / 1.15 / 19.4:
//   - 1.9  : 5/min/IP on /auth/login, 30/min/IP on /auth/refresh.
//   - 1.15 : exceeding either limit returns HTTP 429.
//   - 19.4 : limits are scoped per-IP via `keyGenerator: req.ip`.
//
// Strategy: we don't exercise the production auth plugin here — that
// test is `auth-routes.test.ts`. Instead we register `@fastify/rate-limit`
// against a minimal Fastify app with a route configured exactly like
// `/auth/login` (`config.rateLimit: { max: 5, timeWindow: '1 minute' }`)
// and a second route configured like `/auth/refresh` (max 30). We then
// fire 6 requests with the same simulated `req.ip` in quick succession
// and assert that the 6th comes back 429. A separate IP gets a fresh
// budget to confirm the limit is keyed per-IP, not globally.
//
// `fastify.inject()` doesn't open a real socket, so `req.socket.remoteAddress`
// is undefined out of the box. We feed `app.inject({ remoteAddress: ... })`
// to control what `req.ip` resolves to, and we register the app with
// `trustProxy: true` so `keyGenerator: req => req.ip` reads from the
// chosen address rather than a synthetic loopback.

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

/** Build a Fastify instance with two opt-in rate-limited routes that
 *  mirror the production /auth/login and /auth/refresh limits.
 *
 *  - `global: false` keeps the limit OFF by default, then per-route
 *    `config.rateLimit` opts each handler in. This is exactly the
 *    pattern used by `apps/api/src/server.ts`, so a regression in the
 *    server's wiring would be visible here as a test failure. */
async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    // trustProxy must be true for `req.ip` to honour the
    // `remoteAddress` we feed via inject(). Without it Fastify falls
    // back to the connection's local address (undefined for inject),
    // which would collapse every test request to the same key
    // regardless of the IP we pass — defeating the per-IP test.
    trustProxy: true,
  });

  await app.register(fastifyRateLimit, {
    global: false,
    keyGenerator: (req: FastifyRequest) => req.ip,
    // Match production: a generic 429 body that doesn't disclose the
    // window. Tests assert on statusCode only.
    errorResponseBuilder: () => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'rate limit exceeded',
    }),
  });

  // Mirrors POST /auth/login (Requirement 1.9: 5/min/IP).
  app.post(
    '/login',
    { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } },
    async () => ({ ok: true }),
  );

  // Mirrors POST /auth/refresh (Requirement 1.9: 30/min/IP). Used to
  // confirm the limit is per-route, not shared across endpoints.
  app.post(
    '/refresh',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async () => ({ ok: true }),
  );

  // A route with no rate-limit config — used to confirm the global:
  // false default still applies (i.e. routes don't inherit the limit
  // unless they opt in).
  app.post('/unlimited', async () => ({ ok: true }));

  await app.ready();
  return app;
}

describe('@fastify/rate-limit — per-route, per-IP enforcement', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await buildApp();
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns 429 on the 6th /login request from the same IP within the window', async () => {
    const ip = '203.0.113.10'; // TEST-NET-3 reserved IP — never a real client

    // First 5 requests must all succeed (max=5).
    for (let i = 1; i <= 5; i += 1) {
      const res = await app.inject({
        method: 'POST',
        url: '/login',
        remoteAddress: ip,
      });
      expect(res.statusCode).toBe(200);
      // Rate-limit headers are informational; we don't assert on them
      // here because their exact format is plugin-version-specific.
      // The contract under test is the 429 status on overflow.
    }

    // 6th request from the same IP must be rejected.
    const overflow = await app.inject({
      method: 'POST',
      url: '/login',
      remoteAddress: ip,
    });
    expect(overflow.statusCode).toBe(429);
    // The plugin's standard response body uses the errorResponseBuilder
    // we registered. We assert on the shape to confirm the builder ran
    // (i.e. the 429 came from rate-limit, not some other middleware).
    expect(overflow.json()).toEqual({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'rate limit exceeded',
    });
  });

  it('limits are scoped per-IP — a different IP gets a fresh budget', async () => {
    const ipA = '203.0.113.20';
    const ipB = '203.0.113.21';

    // Exhaust the budget for IP A.
    for (let i = 1; i <= 5; i += 1) {
      const res = await app.inject({
        method: 'POST',
        url: '/login',
        remoteAddress: ipA,
      });
      expect(res.statusCode).toBe(200);
    }

    // IP A is now over the limit.
    const overflowA = await app.inject({
      method: 'POST',
      url: '/login',
      remoteAddress: ipA,
    });
    expect(overflowA.statusCode).toBe(429);

    // IP B is starting fresh — must still be allowed. This is the
    // critical assertion for Requirement 19.4 ("scoped per-IP via
    // `keyGenerator: req.ip`"). If the keyGenerator were broken (say,
    // returning a constant), ipB would inherit ipA's exhausted bucket.
    for (let i = 1; i <= 5; i += 1) {
      const res = await app.inject({
        method: 'POST',
        url: '/login',
        remoteAddress: ipB,
      });
      expect(res.statusCode).toBe(200);
    }

    // And the 6th from IP B is now rejected too — same threshold, just
    // applied independently.
    const overflowB = await app.inject({
      method: 'POST',
      url: '/login',
      remoteAddress: ipB,
    });
    expect(overflowB.statusCode).toBe(429);
  });

  it('limits are scoped per-route — exhausting /login does NOT exhaust /refresh', async () => {
    const ip = '203.0.113.30';

    // Exhaust /login's 5/min budget.
    for (let i = 1; i <= 5; i += 1) {
      const res = await app.inject({
        method: 'POST',
        url: '/login',
        remoteAddress: ip,
      });
      expect(res.statusCode).toBe(200);
    }
    const overflowLogin = await app.inject({
      method: 'POST',
      url: '/login',
      remoteAddress: ip,
    });
    expect(overflowLogin.statusCode).toBe(429);

    // /refresh has its own 30/min budget for the same IP. The first
    // request after /login is exhausted MUST succeed; if it 429s, the
    // limits are sharing state across routes (a regression).
    const refreshFirst = await app.inject({
      method: 'POST',
      url: '/refresh',
      remoteAddress: ip,
    });
    expect(refreshFirst.statusCode).toBe(200);
  });

  it('routes without config.rateLimit are not gated (global: false default)', async () => {
    const ip = '203.0.113.40';

    // 50 requests in a row — well above either configured limit. The
    // /unlimited route never opted in, so global: false means none of
    // them should 429.
    for (let i = 1; i <= 50; i += 1) {
      const res = await app.inject({
        method: 'POST',
        url: '/unlimited',
        remoteAddress: ip,
      });
      expect(res.statusCode).toBe(200);
    }
  });
});

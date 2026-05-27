// apps/api/test/security-headers.test.ts
//
// Integration-style tests that exercise the full
// `buildServer({...})` pipeline as wired in `src/server.ts` task
// 10.3, validating Requirements 17.4, 19.1, 19.3, 19.9, 19.10:
//
//   - 17.4 / 19.1 : helmet emits CSP + HSTS + sniff/frame/referrer
//                   protections on every response, including
//                   skipPaths that bypass CSRF.
//   - 19.3 / 19.9 : every state-changing route (POST/PUT/PATCH/DELETE)
//                   that is NOT in `skipPaths` requires a double-submit
//                   CSRF token; missing/mismatched tokens are rejected
//                   with HTTP 403 BEFORE the handler runs (no DB write,
//                   no Redis publish, no side effect).
//
// We don't bring up a real Postgres or Redis here: the goal is to
// observe headers and the CSRF/headers wiring around the real route
// handlers, not the route-handler logic itself (which has its own unit
// suites in `auth-routes.test.ts`, `broadcast-routes.test.ts`, etc.).
// To keep the harness self-contained we register the same plugins
// `buildServer` registers, with stub deps for the database and a
// trivial route shaped like a real state-changing endpoint
// (`POST /devices`-equivalent) that we can prove was NOT entered when
// the CSRF check fails.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyHelmet from '@fastify/helmet';
import fastifyRateLimit from '@fastify/rate-limit';

import { csrfPlugin } from '../src/services/auth/csrf.js';
import { healthRoutes } from '../src/routes/health.js';

/** Build a Fastify app that mirrors the security-relevant slice of
 *  `buildServer({...})`: cookie → helmet → rate-limit → csrf → routes.
 *  We register healthRoutes and a synthetic `/devices` endpoint whose
 *  handler increments an in-memory counter so we can assert the
 *  CSRF-failure path never enters the handler. */
async function buildHardenedApp(counter: { value: number }): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });

  await app.register(fastifyCookie);

  // Same options as production. `cookieSecure: false` is NOT set here
  // because helmet doesn't set cookies; the `csrfPlugin` registration
  // below carries its own override.
  await app.register(fastifyHelmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'wasm-unsafe-eval'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:', 'blob:'],
        'media-src': ["'self'", 'blob:', 'wss:'],
        'connect-src': ["'self'", 'wss:', 'turns:'],
        'font-src': ["'self'", 'data:'],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"],
      },
    },
    strictTransportSecurity: {
      maxAge: 63_072_000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    frameguard: { action: 'deny' },
    noSniff: true,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    xssFilter: false,
  });

  await app.register(fastifyRateLimit, {
    global: false,
    max: 1000,
    timeWindow: '1 minute',
  });

  await app.register(csrfPlugin, {
    // Tests run over plain HTTP via app.inject; turning Secure off
    // lets us read back the cookie value without the test harness
    // dropping it. The double-submit semantics under test do not
    // depend on the Secure attribute.
    cookieSecure: false,
    skipPaths: [
      /^\/health$/,
      /^\/metrics$/,
      /^\/auth\/login$/,
      /^\/auth\/signup$/,
      /^\/ws/,
      /^\/livekit\//,
    ],
  });

  await app.register(healthRoutes);

  // Synthetic state-changing endpoint shaped like POST /devices. We
  // assert the counter remains 0 on the CSRF-failure path so the
  // "without applying any server-side state change" half of 19.9 is
  // observable.
  app.post('/devices', async () => {
    counter.value += 1;
    return { ok: true, count: counter.value };
  });
  app.get('/devices', async () => ({ devices: [], count: counter.value }));

  // A second state-changing endpoint that exercises the same
  // wiring on PUT/PATCH/DELETE.
  app.put('/devices', async () => {
    counter.value += 1;
    return { ok: true };
  });
  app.patch('/devices', async () => {
    counter.value += 1;
    return { ok: true };
  });
  app.delete('/devices', async () => {
    counter.value += 1;
    return { ok: true };
  });

  await app.ready();
  return app;
}

/** Pull a named cookie value out of one or more `Set-Cookie` strings. */
function getCookie(
  setCookie: string | string[] | undefined,
  name: string,
): string | undefined {
  if (typeof setCookie === 'undefined') return undefined;
  const items = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const item of items) {
    const m = new RegExp(`^${name}=([^;]+)`).exec(item);
    if (m && typeof m[1] === 'string') return m[1];
  }
  return undefined;
}

describe('security headers (helmet) — task 10.3', () => {
  let counter: { value: number };
  let app: FastifyInstance;

  beforeEach(async () => {
    counter = { value: 0 };
    app = await buildHardenedApp(counter);
  });

  afterEach(async () => {
    await app.close();
  });

  it('GET /health includes the standard helmet hardening headers', async () => {
    const res = await app.inject({ method: 'GET', url: '/health' });

    expect(res.statusCode).toBe(200);
    // Defense-in-depth headers (Caddy also emits these; helmet
    // restates them so direct-to-api access is hardened too).
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    // HSTS — Requirement 17.4.
    const hsts = res.headers['strict-transport-security'];
    expect(typeof hsts).toBe('string');
    expect(hsts).toMatch(/max-age=63072000/);
    expect(hsts).toMatch(/includeSubDomains/);
    expect(hsts).toMatch(/preload/);
  });

  it('GET /devices includes a Content-Security-Policy header with a per-request nonce', async () => {
    const r1 = await app.inject({ method: 'GET', url: '/devices' });
    expect(r1.statusCode).toBe(200);

    const csp1 = r1.headers['content-security-policy'];
    expect(typeof csp1).toBe('string');
    if (typeof csp1 !== 'string') throw new Error('unreachable');

    // Critical directives — these match the production policy in
    // server.ts. We don't assert exact equality on the whole CSP
    // string because helmet reorders directives based on internal
    // serialization; we just check each substring is present.
    expect(csp1).toMatch(/default-src 'self'/);
    expect(csp1).toMatch(/script-src 'self' 'wasm-unsafe-eval' 'nonce-[a-f0-9]+'/);
    expect(csp1).toMatch(/style-src 'self' 'nonce-[a-f0-9]+'/);
    expect(csp1).toMatch(/img-src 'self' data: blob:/);
    expect(csp1).toMatch(/connect-src 'self' wss: turns:/);
    expect(csp1).toMatch(/frame-ancestors 'none'/);
    expect(csp1).toMatch(/object-src 'none'/);
    // Critically, NO `'unsafe-inline'` for either scripts or styles —
    // the nonce strategy replaces it.
    expect(csp1).not.toMatch(/unsafe-inline/);

    // The nonce must be regenerated per-request (this is what
    // protects inline tags from a static-CSP-bypass attacker).
    const r2 = await app.inject({ method: 'GET', url: '/devices' });
    const csp2 = r2.headers['content-security-policy'];
    expect(typeof csp2).toBe('string');
    if (typeof csp2 !== 'string') throw new Error('unreachable');

    const nonce1 = /style-src 'self' 'nonce-([a-f0-9]+)'/.exec(csp1)?.[1];
    const nonce2 = /style-src 'self' 'nonce-([a-f0-9]+)'/.exec(csp2)?.[1];
    expect(typeof nonce1).toBe('string');
    expect(typeof nonce2).toBe('string');
    expect(nonce1).not.toBe(nonce2);
  });

  it('CSP and the hardening headers also apply to skipPaths like /health', async () => {
    // skipPaths affects ONLY CSRF cookie-issuance and double-submit;
    // it does NOT bypass helmet. /health must still carry CSP + HSTS.
    const res = await app.inject({ method: 'GET', url: '/health' });

    expect(res.statusCode).toBe(200);
    expect(typeof res.headers['content-security-policy']).toBe('string');
    expect(typeof res.headers['strict-transport-security']).toBe('string');
  });
});

describe('CSRF double-submit on state-changing routes — task 10.3', () => {
  let counter: { value: number };
  let app: FastifyInstance;

  beforeEach(async () => {
    counter = { value: 0 };
    app = await buildHardenedApp(counter);
  });

  afterEach(async () => {
    await app.close();
  });

  it('POST /devices without csrf header is rejected with 403 and handler does not run', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: { cookie: 'konvo_csrf=some-existing-token' },
      payload: { foo: 'bar' },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'csrf_invalid' });
    // Critical: the synthetic handler MUST NOT have advanced the
    // counter. This is the "without applying any server-side state
    // change" half of 19.9.
    expect(counter.value).toBe(0);

    // Even on the failure path, helmet still emits the security
    // headers (helmet runs in onRequest before the CSRF hook
    // short-circuits the reply).
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(typeof res.headers['content-security-policy']).toBe('string');
  });

  it('POST /devices with matching csrf cookie + header succeeds and handler runs', async () => {
    // First, GET /devices to receive a fresh csrf cookie.
    const seed = await app.inject({ method: 'GET', url: '/devices' });
    expect(seed.statusCode).toBe(200);
    const token = getCookie(seed.headers['set-cookie'], 'konvo_csrf');
    expect(typeof token).toBe('string');
    if (typeof token !== 'string') throw new Error('unreachable');

    const res = await app.inject({
      method: 'POST',
      url: '/devices',
      headers: {
        cookie: `konvo_csrf=${token}`,
        'x-csrf-token': token,
      },
      payload: { foo: 'bar' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, count: 1 });
    expect(counter.value).toBe(1);
    // Headers continue to flow on the success path.
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('every state-changing method (POST/PUT/PATCH/DELETE) requires the double-submit token', async () => {
    // Failure path: missing token on each method → 403.
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
      const res = await app.inject({ method, url: '/devices' });
      expect(res.statusCode, `${method} without token`).toBe(403);
    }
    expect(counter.value).toBe(0);

    // Success path: matching token on each method → handler runs.
    const seed = await app.inject({ method: 'GET', url: '/devices' });
    const token = getCookie(seed.headers['set-cookie'], 'konvo_csrf');
    if (typeof token !== 'string') throw new Error('expected csrf cookie');

    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
      const res = await app.inject({
        method,
        url: '/devices',
        headers: {
          cookie: `konvo_csrf=${token}`,
          'x-csrf-token': token,
        },
      });
      expect(res.statusCode, `${method} with token`).toBe(200);
    }
    expect(counter.value).toBe(4);
  });

  it('skipPaths (/health) bypass CSRF entirely — no cookie issued, no token required', async () => {
    // /health doesn't need cookie issuance because /health is in skipPaths.
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(getCookie(res.headers['set-cookie'], 'konvo_csrf')).toBeUndefined();
  });
});

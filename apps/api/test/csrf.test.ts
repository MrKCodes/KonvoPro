// Unit tests for the CSRF middleware (task 2.5).
//
// Validates Requirements 19.3 and 19.9:
//   - 19.3: state-changing methods (POST/PUT/PATCH/DELETE) require a
//           double-submit token.
//   - 19.9: missing or mismatched tokens are rejected without applying
//           any server-side state change.
//
// Strategy: register the plugin against a fresh Fastify instance per
// test, attach a tiny stateful route (`POST /counter` increments an
// in-memory counter, `GET /counter` returns it) so we can directly
// observe whether the failure path actually short-circuits the handler.
// All HTTP traffic flows through `app.inject` — no real network sockets,
// no `pnpm install`, no flakiness around port binding.

import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { csrfPlugin } from '../src/services/auth/csrf.js';

interface Counter {
  value: number;
}

/** Build a Fastify app wired to the CSRF plugin, exposing:
 *    - GET  /counter   → returns the counter (no state change)
 *    - POST /counter   → increments and returns the counter
 *    - PUT/PATCH/DELETE /counter → also increment, used for method coverage
 *    - GET /health     → never receives a CSRF cookie (skipPaths)
 *
 *  The `cookieSecure: false` override is mandatory: `app.inject` simulates
 *  HTTP, not HTTPS, so a `Secure` cookie would still be issued by the
 *  server but the test would have no easy way to introspect the flag.
 *  The semantics under test (token equality, rejection-before-handler)
 *  are independent of the `Secure` attribute. */
async function buildApp(counter: Counter) {
  const app = Fastify();
  await app.register(csrfPlugin, {
    cookieSecure: false,
    skipPaths: [/^\/health$/],
  });

  app.get('/counter', async () => ({ value: counter.value }));
  app.post('/counter', async () => {
    counter.value += 1;
    return { value: counter.value };
  });
  app.put('/counter', async () => {
    counter.value += 1;
    return { value: counter.value };
  });
  app.patch('/counter', async () => {
    counter.value += 1;
    return { value: counter.value };
  });
  app.delete('/counter', async () => {
    counter.value += 1;
    return { value: counter.value };
  });

  app.get('/health', async () => ({ status: 'ok' }));

  return app;
}

/** Pull the value of the `konvo_csrf` cookie from the response.
 *  Fastify normalizes `set-cookie` to a string when there's exactly one
 *  cookie, and to a string[] when there's more than one; handle both. */
function extractCsrfCookie(setCookie: string | string[] | undefined): string | undefined {
  if (typeof setCookie === 'undefined') return undefined;
  const items = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const item of items) {
    const m = /^konvo_csrf=([^;]+)/.exec(item);
    if (m && typeof m[1] === 'string') return m[1];
  }
  return undefined;
}

describe('csrfPlugin — double-submit token', () => {
  let counter: Counter;
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    counter = { value: 0 };
    app = await buildApp(counter);
  });

  afterEach(async () => {
    await app.close();
  });

  it('GET sets a fresh csrf cookie when none is present and returns the route output', async () => {
    const res = await app.inject({ method: 'GET', url: '/counter' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ value: 0 });

    const token = extractCsrfCookie(res.headers['set-cookie']);
    expect(typeof token).toBe('string');
    // 32 random bytes base64url-encoded → 43 chars.
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('GET does not re-issue a cookie when the client already has one', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/counter',
      headers: { cookie: 'konvo_csrf=existing-token-value' },
    });

    expect(res.statusCode).toBe(200);
    // No Set-Cookie header for konvo_csrf when the client already has one.
    const token = extractCsrfCookie(res.headers['set-cookie']);
    expect(token).toBeUndefined();
  });

  it('GET on a skipPath (/health) never issues a csrf cookie', async () => {
    const res = await app.inject({ method: 'GET', url: '/health' });

    expect(res.statusCode).toBe(200);
    expect(extractCsrfCookie(res.headers['set-cookie'])).toBeUndefined();
  });

  it('POST without csrf header is rejected with 403 and the handler does not run', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/counter',
      headers: { cookie: 'konvo_csrf=some-cookie-value' },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'csrf_invalid' });
    // Critical: the counter MUST NOT have advanced. This is the
    // "without applying any server-side state change" half of 19.9.
    expect(counter.value).toBe(0);
  });

  it('POST without cookie is rejected with 403 even if a header is present', async () => {
    // Header alone is not enough — double-submit requires both sides.
    const res = await app.inject({
      method: 'POST',
      url: '/counter',
      headers: { 'x-csrf-token': 'header-only-no-cookie' },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'csrf_invalid' });
    expect(counter.value).toBe(0);
  });

  it('POST with header that does not match the cookie is rejected with 403', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/counter',
      headers: {
        cookie: 'konvo_csrf=cookie-value-here',
        'x-csrf-token': 'different-header-value',
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'csrf_invalid' });
    expect(counter.value).toBe(0);
  });

  it('POST with header that matches the cookie passes through and applies the state change', async () => {
    const token = 'matching-token-value-12345';
    const res = await app.inject({
      method: 'POST',
      url: '/counter',
      headers: {
        cookie: `konvo_csrf=${token}`,
        'x-csrf-token': token,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ value: 1 });
    expect(counter.value).toBe(1);
  });

  it('PUT, PATCH, and DELETE are all subject to the same check', async () => {
    // Missing-token attempts on each method.
    for (const method of ['PUT', 'PATCH', 'DELETE'] as const) {
      const res = await app.inject({ method, url: '/counter' });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({ error: 'csrf_invalid' });
    }
    expect(counter.value).toBe(0);

    // Matching attempts on each method.
    const token = 'shared-token-for-all-methods-x';
    for (const method of ['PUT', 'PATCH', 'DELETE'] as const) {
      const res = await app.inject({
        method,
        url: '/counter',
        headers: {
          cookie: `konvo_csrf=${token}`,
          'x-csrf-token': token,
        },
      });
      expect(res.statusCode).toBe(200);
    }
    expect(counter.value).toBe(3);
  });

  it('does not enforce the check on HEAD or OPTIONS', async () => {
    // HEAD on a route that supports GET — Fastify auto-handles HEAD.
    const head = await app.inject({ method: 'HEAD', url: '/counter' });
    // HEAD returns 200 with empty body when the underlying GET succeeds.
    expect(head.statusCode).toBe(200);

    const opts = await app.inject({ method: 'OPTIONS', url: '/counter' });
    // Fastify replies to OPTIONS with 404 by default (no route registered),
    // but importantly it doesn't 403 from CSRF. The point of the test is
    // that the CSRF middleware doesn't gate the request.
    expect(opts.statusCode).not.toBe(403);
    // OPTIONS must not issue a csrf cookie either.
    expect(extractCsrfCookie(opts.headers['set-cookie'])).toBeUndefined();
  });

  it('rejects with constant-time comparison even when token lengths differ', async () => {
    // Sanity check — different lengths should still be a clean 403, not
    // a thrown error from `timingSafeEqual` (which throws on length
    // mismatch when called directly).
    const res = await app.inject({
      method: 'POST',
      url: '/counter',
      headers: {
        cookie: 'konvo_csrf=short',
        'x-csrf-token': 'much-longer-header-value-here',
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'csrf_invalid' });
    expect(counter.value).toBe(0);
  });

  it('header lookup is case-insensitive (Node lowercases incoming header names)', async () => {
    const token = 'case-insensitive-test-token-x';
    const res = await app.inject({
      method: 'POST',
      url: '/counter',
      headers: {
        cookie: `konvo_csrf=${token}`,
        // Mixed case — Node will lowercase this before our hook sees it.
        'X-CSRF-Token': token,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(counter.value).toBe(1);
  });

  it('issued cookie carries SameSite=Lax and Path=/', async () => {
    const res = await app.inject({ method: 'GET', url: '/counter' });
    const setCookie = res.headers['set-cookie'];
    const items = Array.isArray(setCookie) ? setCookie : [setCookie];
    const csrf = items.find((s) => typeof s === 'string' && s.startsWith('konvo_csrf='));
    expect(csrf).toBeDefined();
    if (typeof csrf !== 'string') throw new Error('unreachable');
    expect(csrf).toMatch(/Path=\//);
    expect(csrf).toMatch(/SameSite=Lax/);
    // cookieSecure was overridden to false in the test app, so Secure
    // should NOT be present here. (In production the default is true.)
    expect(csrf).not.toMatch(/Secure/);
  });
});

describe('csrfPlugin — custom options', () => {
  it('honours custom cookieName, headerName, and cookiePath', async () => {
    const counter: Counter = { value: 0 };
    const app = Fastify();
    await app.register(csrfPlugin, {
      cookieName: 'custom_csrf',
      headerName: 'x-custom-csrf',
      cookiePath: '/api',
      cookieSecure: false,
    });
    app.post('/counter', async () => {
      counter.value += 1;
      return { value: counter.value };
    });
    app.get('/counter', async () => ({ value: counter.value }));

    try {
      // GET issues a cookie under the custom name with the custom path.
      const getRes = await app.inject({ method: 'GET', url: '/counter' });
      const setCookie = getRes.headers['set-cookie'];
      const items = Array.isArray(setCookie) ? setCookie : [setCookie];
      const cookieLine = items.find(
        (s) => typeof s === 'string' && s.startsWith('custom_csrf='),
      );
      expect(cookieLine).toBeDefined();
      if (typeof cookieLine !== 'string') throw new Error('unreachable');
      expect(cookieLine).toMatch(/Path=\/api/);

      // POST with the matching header name + cookie passes; default
      // header name (x-csrf-token) is no longer accepted.
      const tokenMatch = /^custom_csrf=([^;]+)/.exec(cookieLine);
      const token = tokenMatch?.[1];
      expect(typeof token).toBe('string');
      if (typeof token !== 'string') throw new Error('unreachable');

      const okRes = await app.inject({
        method: 'POST',
        url: '/counter',
        headers: {
          cookie: `custom_csrf=${token}`,
          'x-custom-csrf': token,
        },
      });
      expect(okRes.statusCode).toBe(200);
      expect(counter.value).toBe(1);

      const wrongHeaderRes = await app.inject({
        method: 'POST',
        url: '/counter',
        headers: {
          cookie: `custom_csrf=${token}`,
          // Default header name — should not satisfy the custom config.
          'x-csrf-token': token,
        },
      });
      expect(wrongHeaderRes.statusCode).toBe(403);
      expect(counter.value).toBe(1);
    } finally {
      await app.close();
    }
  });

  it('honours custom skipMethods to also bypass POST when configured (defense check)', async () => {
    // This test exists to assert the option flows through, NOT to suggest
    // that POST should ever actually be in skipMethods in production.
    // Requirement 19.3 mandates POST is checked.
    const counter: Counter = { value: 0 };
    const app = Fastify();
    await app.register(csrfPlugin, {
      cookieSecure: false,
      skipMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
    });
    app.post('/counter', async () => {
      counter.value += 1;
      return { value: counter.value };
    });

    try {
      const res = await app.inject({ method: 'POST', url: '/counter' });
      // No cookie, no header — but POST is opted out by config, so this
      // succeeds. Confirms options are wired end-to-end.
      expect(res.statusCode).toBe(200);
      expect(counter.value).toBe(1);
    } finally {
      await app.close();
    }
  });
});

// apps/api/test/turn-routes.test.ts
//
// Unit tests for the coturn ephemeral credential route (task 6.1 — Phase 5).
//
// Validates Requirement 7.12: GET /turn/credentials returns a
// `TurnCredentialsResponse { urls, username, credential, ttlSec }` whose
// fields encode an RFC 7635 / coturn REST credential:
//
//   - username   = `${expirationUnixTimestamp}:${userId}`
//   - credential = base64(HMAC-SHA1(secret, username))
//   - ttlSec     = 3600 (1 hour, fixed by Requirement 7.12)
//   - urls       = `turn:host:3478?transport=udp`,
//                  `turn:host:3478?transport=tcp`,
//                  `turns:host:5349?transport=tcp`,
//                  `stun:host:3478`
//
// Strategy: register `turnRoutes` against a fresh Fastify instance with a
// trivial `requireAuth` preHandler that decorates `req.authUser` from a
// `Bearer test:<userId>:<deviceId>` header. We do NOT exercise the real
// JWT machinery here — that's covered by `auth-routes.test.ts`. The unit
// under test is the credential math + response shape, which is independent
// of how `req.authUser` was populated.

import { afterEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHmac } from 'node:crypto';

import {
  turnRoutes,
  type TurnRoutesDeps,
} from '../src/routes/turn.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const ALICE_DEVICE = '22222222-2222-2222-2222-222222222222';

/** Trivial preHandler that reads `Authorization: Bearer test:<uid>:<did>`
 *  and decorates `req.authUser`. Anything else → 401 with the same body
 *  the real `requireAuth` returns, so callers can assert the wire shape
 *  identically against either. */
const fakeRequireAuth = async (
  req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
): Promise<void> => {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer test:')) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const payload = header.slice('Bearer test:'.length);
  const parts = payload.split(':');
  const userId = parts[0];
  const deviceId = parts[1];
  if (
    typeof userId !== 'string' ||
    typeof deviceId !== 'string' ||
    userId.length === 0
  ) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const principal: AuthenticatedUser = { userId, deviceId };
  req.authUser = principal;
};

interface Harness {
  app: FastifyInstance;
  setNow: (ms: number) => void;
  secret: string;
  realm: string;
}

async function buildHarness(opts?: {
  ttlSec?: number;
  nowMs?: number;
  secret?: string;
  realm?: string;
}): Promise<Harness> {
  // 32-char minimum mirrors the production zod constraint on
  // COTURN_REST_SECRET. Tests use a fixed value so HMAC outputs are
  // reproducible across runs.
  const secret =
    opts?.secret ?? 'test-secret-do-not-use-in-prod-32+characters-long';
  const realm = opts?.realm ?? 'konvo.local';
  let nowMs = opts?.nowMs ?? Date.now();
  const setNow = (ms: number): void => {
    nowMs = ms;
  };

  const app = Fastify({ logger: false });
  const deps: TurnRoutesDeps = {
    requireAuth: fakeRequireAuth,
    coturnRestSecret: secret,
    coturnRealm: realm,
    now: () => nowMs,
    ...(opts?.ttlSec !== undefined ? { ttlSec: opts.ttlSec } : {}),
  };
  await app.register(turnRoutes, deps);
  await app.ready();
  return { app, setNow, secret, realm };
}

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
}

let activeApp: FastifyInstance | null = null;
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
});

// ---------------------------------------------------------------------------
// Wire-shape type the tests assert against. Mirrors the protocol DTO but
// declared inline so the test stays decoupled from the package barrel.
// ---------------------------------------------------------------------------

interface TurnCredentialsBody {
  urls: string[];
  username: string;
  credential: string;
  ttlSec: number;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GET /turn/credentials', () => {
  it('returns 401 without an Authorization header', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
    });

    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'auth_required' });
  });

  it('returns 200 with the TurnCredentialsResponse shape on auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as TurnCredentialsBody;

    // Shape — all four required keys present, no extras that would
    // surprise the client.
    expect(Object.keys(body).sort()).toEqual(
      ['credential', 'ttlSec', 'urls', 'username'].sort(),
    );

    // Default TTL (Requirement 7.12).
    expect(body.ttlSec).toBe(3600);

    // urls — exact order and content per design.md §3.2 / route comments.
    expect(body.urls).toEqual([
      'turn:konvo.local:3478?transport=udp',
      'turn:konvo.local:3478?transport=tcp',
      'turns:konvo.local:5349?transport=tcp',
      'stun:konvo.local:3478',
    ]);

    // Cache control — credentials are per-user and must never be cached.
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('embeds the expiration unix timestamp and userId in the username', async () => {
    // Pin `now` so the embedded timestamp is deterministic.
    const fixedNowMs = 1_700_000_000_000; // 2023-11-14T22:13:20Z
    const h = await buildHarness({ nowMs: fixedNowMs });
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    const body = res.json() as TurnCredentialsBody;
    const expectedExpUnix = Math.floor(
      (fixedNowMs + body.ttlSec * 1000) / 1000,
    );
    expect(body.username).toBe(`${expectedExpUnix}:${ALICE_ID}`);

    // The embedded expiration MUST be in the future relative to "now".
    const [tsStr, uid] = body.username.split(':');
    expect(Number(tsStr)).toBeGreaterThan(Math.floor(fixedNowMs / 1000));
    expect(uid).toBe(ALICE_ID);
  });

  it('signs the username with HMAC-SHA1 using the configured secret', async () => {
    const h = await buildHarness({ nowMs: 1_700_000_000_000 });
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    const body = res.json() as TurnCredentialsBody;
    // Recompute the HMAC server-side and compare. This is exactly what
    // coturn does on every Allocate request, so a passing test here
    // guarantees the credential is valid against a correctly-configured
    // coturn server.
    const expected = createHmac('sha1', h.secret)
      .update(body.username)
      .digest('base64');
    expect(body.credential).toBe(expected);
  });

  it('honours a custom ttlSec and reflects it in both the response and the username', async () => {
    const fixedNowMs = 1_700_000_000_000;
    const customTtl = 60; // 1 minute
    const h = await buildHarness({ nowMs: fixedNowMs, ttlSec: customTtl });
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    const body = res.json() as TurnCredentialsBody;
    expect(body.ttlSec).toBe(customTtl);
    const expectedExpUnix = Math.floor(
      (fixedNowMs + customTtl * 1000) / 1000,
    );
    expect(body.username).toBe(`${expectedExpUnix}:${ALICE_ID}`);

    // Credential must still verify against the same secret and the new
    // username.
    const expected = createHmac('sha1', h.secret)
      .update(body.username)
      .digest('base64');
    expect(body.credential).toBe(expected);
  });

  it('uses the configured realm as the host portion of all urls', async () => {
    const h = await buildHarness({ realm: 'turn.example.com' });
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    const body = res.json() as TurnCredentialsBody;
    expect(body.urls).toEqual([
      'turn:turn.example.com:3478?transport=udp',
      'turn:turn.example.com:3478?transport=tcp',
      'turns:turn.example.com:5349?transport=tcp',
      'stun:turn.example.com:3478',
    ]);
  });

  it('returns a base64 (not base64url) credential', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/turn/credentials',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    const body = res.json() as TurnCredentialsBody;
    // base64 alphabet: A–Z a–z 0–9 + / =. base64url replaces +/ with -_,
    // so the presence of `-` or `_` in a credential would indicate the
    // wrong encoding. We don't assert presence of `+` or `/` because
    // some HMACs happen to land on alphabetics, but we DO assert the
    // url-safe variants are absent.
    expect(body.credential).not.toMatch(/[-_]/);
    // Length: HMAC-SHA1 → 20 bytes → 28 base64 chars (with padding).
    expect(body.credential.length).toBe(28);
  });
});

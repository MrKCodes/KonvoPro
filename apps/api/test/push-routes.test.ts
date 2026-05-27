// apps/api/test/push-routes.test.ts
//
// Unit tests for the Web Push subscription REST routes (task 9.3).
//
// Validates Requirements 13.1, 13.2, and 13.7 at the route layer:
//   - 13.1: POST /push/subscribe persists a subscription keyed by
//           deviceId, REPLACING any existing subscription for the
//           same deviceId.
//   - 13.2: rejects missing/empty deviceId/endpoint/p256dh/auth and
//           rejects non-https endpoint schemes without persistence.
//   - 13.7: DELETE /push/subscribe/:id removes the row owned by the
//           authenticated user.
//
// Strategy mirrors `devices-routes.test.ts`:
//   - Fastify instance per test with the route registered against an
//     in-memory pg.Pool stub.
//   - `requireAuth` is replaced by a test stub that reads
//     `Authorization: Bearer test:<userId>:<deviceId>`.

import { afterEach, describe, expect, it } from 'vitest';
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from 'fastify';

import {
  pushRoutes,
  type PushRoutesDeps,
} from '../src/routes/push.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------

interface DeviceRow {
  id: string;
  user_id: string;
}

interface SubscriptionRow {
  id: string;
  device_id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  created_at: Date;
}

class FakeDb {
  devices: DeviceRow[] = [];
  subscriptions: SubscriptionRow[] = [];
  #nextSubSeq = 1;

  newSubscriptionId(): string {
    const seq = String(this.#nextSubSeq++).padStart(12, '0');
    return `cccccccc-dddd-4eee-8fff-${seq}`;
  }

  addDevice(userId: string, id: string): void {
    this.devices.push({ id, user_id: userId });
  }

  addSubscription(deviceId: string, endpoint = 'https://push.example/x'): string {
    const id = this.newSubscriptionId();
    this.subscriptions.push({
      id,
      device_id: deviceId,
      endpoint,
      p256dh: 'p256dh-bytes',
      auth: 'auth-bytes',
      created_at: new Date(),
    });
    return id;
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase().trim();

      // SELECT id FROM devices WHERE id = $1 AND user_id = $2 LIMIT 1
      if (
        lower.startsWith('select id from devices') &&
        lower.includes('where id =')
      ) {
        const id = String(params[0]);
        const userId = String(params[1]);
        const found = db.devices.find(
          (d) => d.id === id && d.user_id === userId,
        );
        if (found === undefined) return { rows: [], rowCount: 0 };
        return { rows: [{ id: found.id } as unknown as T], rowCount: 1 };
      }

      // DELETE FROM push_subscriptions WHERE device_id = $1
      if (
        lower.startsWith('delete from push_subscriptions') &&
        lower.includes('where device_id')
      ) {
        const deviceId = String(params[0]);
        const before = db.subscriptions.length;
        db.subscriptions = db.subscriptions.filter(
          (s) => s.device_id !== deviceId,
        );
        return { rows: [], rowCount: before - db.subscriptions.length };
      }

      // INSERT INTO push_subscriptions ... RETURNING id
      if (lower.startsWith('insert into push_subscriptions')) {
        const [deviceId, endpoint, p256dh, auth] = params as [
          string,
          string,
          string,
          string,
        ];
        const id = db.newSubscriptionId();
        db.subscriptions.push({
          id,
          device_id: deviceId,
          endpoint,
          p256dh,
          auth,
          created_at: new Date(),
        });
        return { rows: [{ id } as unknown as T], rowCount: 1 };
      }

      // DELETE FROM push_subscriptions WHERE id = $1 AND EXISTS (...)
      if (
        lower.startsWith('delete from push_subscriptions') &&
        lower.includes('where id = $1') &&
        lower.includes('exists')
      ) {
        const subId = String(params[0]);
        const userId = String(params[1]);
        const idx = db.subscriptions.findIndex((s) => s.id === subId);
        if (idx === -1) return { rows: [], rowCount: 0 };
        const sub = db.subscriptions[idx]!;
        const ownerOk = db.devices.some(
          (d) => d.id === sub.device_id && d.user_id === userId,
        );
        if (!ownerOk) return { rows: [], rowCount: 0 };
        db.subscriptions.splice(idx, 1);
        return { rows: [], rowCount: 1 };
      }

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const ALICE_DEVICE = '33333333-3333-3333-3333-333333333333';
const ALICE_DEVICE_2 = '44444444-4444-4444-4444-444444444444';
const BOB_ID = '22222222-2222-2222-2222-222222222222';
const BOB_DEVICE = '55555555-5555-5555-5555-555555555555';
const NONEXISTENT_ID = '99999999-9999-9999-9999-999999999999';

const fakeRequireAuth = async (
  req: FastifyRequest,
  reply: FastifyReply,
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
    userId.length === 0 ||
    typeof deviceId !== 'string'
  ) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const principal: AuthenticatedUser = { userId, deviceId };
  req.authUser = principal;
};

interface Harness {
  app: FastifyInstance;
  db: FakeDb;
}

async function buildHarness(): Promise<Harness> {
  const db = new FakeDb();
  // Pre-populate Alice's two devices and Bob's device for ownership
  // tests below.
  db.addDevice(ALICE_ID, ALICE_DEVICE);
  db.addDevice(ALICE_ID, ALICE_DEVICE_2);
  db.addDevice(BOB_ID, BOB_DEVICE);

  const app = Fastify({ logger: false });
  const deps: PushRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
  };
  await app.register(pushRoutes, deps);
  await app.ready();
  return { app, db };
}

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
}

function happyBody(deviceId: string): Record<string, unknown> {
  return {
    deviceId,
    endpoint: 'https://push.example.com/abc/123',
    p256dh: 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCC=',
    auth: 'tBHItJI5svbpez7KI4CCXg==',
  };
}

let activeApp: FastifyInstance | null = null;
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
});

// ---------------------------------------------------------------------------
// POST /push/subscribe — happy path + validation
// ---------------------------------------------------------------------------

describe('POST /push/subscribe', () => {
  it('happy path: persists subscription and returns 201 { subscriptionId }', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: happyBody(ALICE_DEVICE),
    });

    expect(res.statusCode).toBe(201);
    const body = res.json() as { subscriptionId: string };
    expect(typeof body.subscriptionId).toBe('string');
    expect(body.subscriptionId.length).toBeGreaterThan(0);

    expect(h.db.subscriptions).toHaveLength(1);
    const row = h.db.subscriptions[0]!;
    expect(row.device_id).toBe(ALICE_DEVICE);
    expect(row.endpoint).toBe('https://push.example.com/abc/123');
  });

  it('Requirement 13.1: REPLACES any existing subscription for the same deviceId', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Pre-existing subscription for this device.
    h.db.addSubscription(ALICE_DEVICE, 'https://push.old/x');
    expect(h.db.subscriptions).toHaveLength(1);

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: happyBody(ALICE_DEVICE),
    });

    expect(res.statusCode).toBe(201);
    // Exactly one row remains, pointing at the new endpoint. The
    // pre-existing row has been replaced, not added next to.
    expect(h.db.subscriptions).toHaveLength(1);
    const row = h.db.subscriptions[0]!;
    expect(row.device_id).toBe(ALICE_DEVICE);
    expect(row.endpoint).toBe('https://push.example.com/abc/123');
    expect(row.endpoint).not.toBe('https://push.old/x');
  });

  it('Requirement 13.1: replacing one device does NOT affect another device of the same user', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    h.db.addSubscription(ALICE_DEVICE_2, 'https://push.other/x');

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: happyBody(ALICE_DEVICE),
    });

    expect(res.statusCode).toBe(201);
    // Both subscriptions exist: ALICE_DEVICE_2's untouched, ALICE_DEVICE's fresh.
    expect(h.db.subscriptions).toHaveLength(2);
    const other = h.db.subscriptions.find((s) => s.device_id === ALICE_DEVICE_2);
    expect(other).toBeDefined();
    expect(other!.endpoint).toBe('https://push.other/x');
  });

  it('Requirement 13.2: rejects missing deviceId with 400 and persists nothing', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const body = happyBody(ALICE_DEVICE);
    delete body['deviceId'];

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('Requirement 13.2: rejects empty endpoint with 400', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const body = happyBody(ALICE_DEVICE);
    body['endpoint'] = '';

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('Requirement 13.2: rejects empty p256dh with 400', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const body = happyBody(ALICE_DEVICE);
    body['p256dh'] = '';

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('Requirement 13.2: rejects empty auth with 400', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const body = happyBody(ALICE_DEVICE);
    body['auth'] = '';

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('Requirement 13.2: rejects http:// endpoint scheme with 400 and persists nothing', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const body = happyBody(ALICE_DEVICE);
    body['endpoint'] = 'http://push.example/abc';

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('Requirement 13.2: rejects ws:// endpoint scheme with 400', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const body = happyBody(ALICE_DEVICE);
    body['endpoint'] = 'ws://push.example/abc';

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: body,
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('rejects subscribing to a device the caller does not own with 404', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: happyBody(BOB_DEVICE),
    });

    expect(res.statusCode).toBe(404);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('rejects subscribing to a non-existent deviceId with 404', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
      payload: happyBody(NONEXISTENT_ID),
    });

    expect(res.statusCode).toBe(404);
    expect(h.db.subscriptions).toHaveLength(0);
  });

  it('returns 401 when the request has no Authorization header', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'POST',
      url: '/push/subscribe',
      payload: happyBody(ALICE_DEVICE),
    });

    expect(res.statusCode).toBe(401);
    expect(h.db.subscriptions).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DELETE /push/subscribe/:id
// ---------------------------------------------------------------------------

describe('DELETE /push/subscribe/:id', () => {
  it('204 + drops the row owned by the caller', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const subId = h.db.addSubscription(ALICE_DEVICE);

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/push/subscribe/${subId}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(204);
    expect(h.db.subscriptions.find((s) => s.id === subId)).toBeUndefined();
  });

  it('does NOT delete a subscription owned by another user', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const bobSubId = h.db.addSubscription(BOB_DEVICE);

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/push/subscribe/${bobSubId}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    // Idempotent delete: still 204 from the caller's perspective so a
    // probing token cannot enumerate subscription ids by status code.
    expect(res.statusCode).toBe(204);
    // But the row is intact.
    expect(h.db.subscriptions.find((s) => s.id === bobSubId)).toBeDefined();
  });

  it('returns 204 for a non-existent subscription id (idempotent)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/push/subscribe/${NONEXISTENT_ID}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(204);
  });

  it('returns 204 for a malformed UUID (idempotent)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'DELETE',
      url: '/push/subscribe/not-a-uuid',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(204);
  });

  it('returns 401 without auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const subId = h.db.addSubscription(ALICE_DEVICE);

    const res = await h.app.inject({
      method: 'DELETE',
      url: `/push/subscribe/${subId}`,
    });
    expect(res.statusCode).toBe(401);
    // Row still present.
    expect(h.db.subscriptions.find((s) => s.id === subId)).toBeDefined();
  });
});

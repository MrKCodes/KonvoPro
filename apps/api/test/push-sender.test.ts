// apps/api/test/push-sender.test.ts
//
// Unit tests for the Web Push sender (task 9.3).
//
// Validates Requirements 13.3 and 13.6:
//   - 13.3: payload schema is STRICTLY `{ type, senderHandle,
//           conversationId }`. Any other shape (extra key, missing
//           key, wrong type) is refused before sending.
//           PLAINTEXT body / ciphertext / key material MUST NOT
//           appear in the encoded payload bytes.
//   - 13.6: on HTTP 410 from the push service, the corresponding
//           push_subscriptions row is deleted.

import { describe, expect, it, vi } from 'vitest';

import {
  PushPayloadSchema,
  sendPushToDevice,
  type PushSenderDeps,
  type WebPushClient,
} from '../src/push/sender.js';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

interface SubscriptionRow {
  id: string;
  device_id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  created_at: Date;
}

class FakeDb {
  subscriptions: SubscriptionRow[] = [];
  #nextSeq = 1;

  newId(): string {
    const seq = String(this.#nextSeq++).padStart(12, '0');
    return `eeeeeeee-ffff-4aaa-8bbb-${seq}`;
  }

  addSubscription(deviceId: string): SubscriptionRow {
    const row: SubscriptionRow = {
      id: this.newId(),
      device_id: deviceId,
      endpoint: 'https://push.example/abc',
      p256dh: 'p256dh-bytes',
      auth: 'auth-bytes',
      created_at: new Date(),
    };
    this.subscriptions.push(row);
    return row;
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase().trim();

      // SELECT id, endpoint, p256dh, auth FROM push_subscriptions
      //   WHERE device_id = $1 ORDER BY created_at DESC LIMIT 1
      if (
        lower.startsWith('select id, endpoint, p256dh, auth') &&
        lower.includes('from push_subscriptions')
      ) {
        const deviceId = String(params[0]);
        const matches = db.subscriptions
          .filter((s) => s.device_id === deviceId)
          .sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
        if (matches.length === 0) return { rows: [], rowCount: 0 };
        const top = matches[0]!;
        return {
          rows: [
            {
              id: top.id,
              endpoint: top.endpoint,
              p256dh: top.p256dh,
              auth: top.auth,
            } as unknown as T,
          ],
          rowCount: 1,
        };
      }

      // DELETE FROM push_subscriptions WHERE id = $1
      if (
        lower.startsWith('delete from push_subscriptions') &&
        lower.includes('where id = $1') &&
        !lower.includes('exists')
      ) {
        const id = String(params[0]);
        const before = db.subscriptions.length;
        db.subscriptions = db.subscriptions.filter((s) => s.id !== id);
        return { rows: [], rowCount: before - db.subscriptions.length };
      }

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

const DEVICE = '33333333-3333-3333-3333-333333333333';

// ---------------------------------------------------------------------------
// Payload schema (Requirement 13.3)
// ---------------------------------------------------------------------------

describe('PushPayloadSchema (Requirement 13.3)', () => {
  it('accepts the exact { type, senderHandle, conversationId } shape', () => {
    const r = PushPayloadSchema.safeParse({
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
    });
    expect(r.success).toBe(true);
  });

  it('REJECTS any extra top-level field (strict)', () => {
    const r = PushPayloadSchema.safeParse({
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
      body: 'hello secret world', // <- forbidden plaintext field
    });
    expect(r.success).toBe(false);
  });

  it('REJECTS a payload missing conversationId', () => {
    const r = PushPayloadSchema.safeParse({
      type: 'dm.message',
      senderHandle: 'alice',
    });
    expect(r.success).toBe(false);
  });

  it('REJECTS a payload missing senderHandle', () => {
    const r = PushPayloadSchema.safeParse({
      type: 'dm.message',
      conversationId: 'conv-1',
    });
    expect(r.success).toBe(false);
  });

  it('REJECTS a payload missing type', () => {
    const r = PushPayloadSchema.safeParse({
      senderHandle: 'alice',
      conversationId: 'conv-1',
    });
    expect(r.success).toBe(false);
  });

  it('REJECTS a ciphertext field', () => {
    const r = PushPayloadSchema.safeParse({
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
      ciphertext: new Uint8Array([1, 2, 3]),
    });
    expect(r.success).toBe(false);
  });

  it('REJECTS a key field', () => {
    const r = PushPayloadSchema.safeParse({
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
      key: 'secret',
    });
    expect(r.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sendPushToDevice
// ---------------------------------------------------------------------------

describe('sendPushToDevice', () => {
  it('happy path: serializes the validated payload as JSON and calls webPush.sendNotification', async () => {
    const db = new FakeDb();
    const sub = db.addSubscription(DEVICE);

    const sendNotification = vi.fn(async () => undefined);
    const webPush: WebPushClient = { sendNotification };
    const deps: PushSenderDeps = { pool: makePool(db), webPush };

    const result = await sendPushToDevice(deps, DEVICE, {
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
    });

    expect(result.ok).toBe(true);
    expect(sendNotification).toHaveBeenCalledTimes(1);
    const [subscription, body] = sendNotification.mock.calls[0]!;
    expect(subscription).toEqual({
      endpoint: sub.endpoint,
      keys: { p256dh: sub.p256dh, auth: sub.auth },
    });
    // The serialized payload contains ONLY the three whitelisted fields.
    const parsed = JSON.parse(body as string) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(
      ['conversationId', 'senderHandle', 'type'].sort(),
    );
    expect(parsed['type']).toBe('dm.message');
    expect(parsed['senderHandle']).toBe('alice');
    expect(parsed['conversationId']).toBe('conv-1');
  });

  it('Requirement 13.3: refuses to send when payload has extra fields, NEVER calls webPush', async () => {
    const db = new FakeDb();
    db.addSubscription(DEVICE);

    const sendNotification = vi.fn(async () => undefined);
    const webPush: WebPushClient = { sendNotification };
    const deps: PushSenderDeps = { pool: makePool(db), webPush };

    // TypeScript wouldn't normally allow this shape; the cast simulates
    // a runtime call site that smuggles extra fields (e.g. via spread).
    const result = await sendPushToDevice(
      deps,
      DEVICE,
      {
        type: 'dm.message',
        senderHandle: 'alice',
        conversationId: 'conv-1',
        body: 'plaintext-leak',
      } as unknown as {
        type: string;
        senderHandle: string;
        conversationId: string;
      },
    );

    expect(result).toEqual({ ok: false, reason: 'invalid_payload' });
    expect(sendNotification).not.toHaveBeenCalled();
  });

  it('returns no_subscription when no row exists for the device', async () => {
    const db = new FakeDb();
    // No subscription added.

    const sendNotification = vi.fn(async () => undefined);
    const webPush: WebPushClient = { sendNotification };
    const deps: PushSenderDeps = { pool: makePool(db), webPush };

    const result = await sendPushToDevice(deps, DEVICE, {
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
    });

    expect(result).toEqual({ ok: false, reason: 'no_subscription' });
    expect(sendNotification).not.toHaveBeenCalled();
  });

  it('Requirement 13.6: on HTTP 410 deletes the corresponding push_subscriptions row', async () => {
    const db = new FakeDb();
    const sub = db.addSubscription(DEVICE);

    const sendNotification = vi.fn(async () => {
      const err: Error & { statusCode?: number } = new Error('Gone');
      err.statusCode = 410;
      throw err;
    });
    const webPush: WebPushClient = { sendNotification };
    const deps: PushSenderDeps = { pool: makePool(db), webPush };

    const result = await sendPushToDevice(deps, DEVICE, {
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
    });

    expect(result).toEqual({ ok: false, reason: 'gone' });
    expect(sendNotification).toHaveBeenCalledTimes(1);
    // The row is gone.
    expect(db.subscriptions.find((s) => s.id === sub.id)).toBeUndefined();
    expect(db.subscriptions).toHaveLength(0);
  });

  it('non-410 send failures DO NOT delete the row', async () => {
    const db = new FakeDb();
    const sub = db.addSubscription(DEVICE);

    const sendNotification = vi.fn(async () => {
      const err: Error & { statusCode?: number } = new Error('Boom');
      err.statusCode = 500;
      throw err;
    });
    const webPush: WebPushClient = { sendNotification };
    const deps: PushSenderDeps = { pool: makePool(db), webPush };

    const result = await sendPushToDevice(deps, DEVICE, {
      type: 'dm.message',
      senderHandle: 'alice',
      conversationId: 'conv-1',
    });

    expect(result).toEqual({ ok: false, reason: 'send_failed' });
    expect(db.subscriptions.find((s) => s.id === sub.id)).toBeDefined();
  });
});

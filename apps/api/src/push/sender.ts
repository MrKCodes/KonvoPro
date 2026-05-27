// apps/api/src/push/sender.ts
//
// Web Push sender (task 9.3 — Phase 8). Sends VAPID-signed notifications
// to subscribed devices via the standard Web Push protocol.
//
// Realizes Requirements 13.3 and 13.6:
//
//   - 13.3: payload contents are the EXACT three fields
//             { type, senderHandle, conversationId }
//           and ONLY those fields. The `web-push` library happily ships
//           whatever bytes we hand it; the strict zod schema below is
//           the canonical guard. We re-validate at every send call so a
//           future caller cannot accidentally smuggle extra keys (e.g.
//           a debug `body` field) into the payload.
//   - 13.6: on HTTP 410 from the push service, the corresponding
//           `push_subscriptions` row is deleted. 410 means the
//           subscription is permanently dead (user revoked, browser
//           uninstalled, endpoint expired) — keeping the row would
//           burn 410s on every subsequent send.
//
// Why a distinct module rather than co-locating with `routes/push.ts`:
//   The route module is the SPA-facing subscribe/unsubscribe surface;
//   this module is the "send a push" pipeline used by the WS gateway
//   (when a recipient device is offline) and by the broadcast post
//   fan-out. Keeping them separate keeps the SPA-facing code free of
//   the `web-push` dependency and lets tests mock the sender without
//   touching the routes.
//
// Why the zod schema is `strict()`:
//   `z.object(...).strict()` rejects unknown keys at parse time. This
//   is the load-bearing guarantee for Requirement 13.3 — even if a
//   future call site builds the payload from an existing object via
//   spread (`{ ...something }`), zod refuses to encode it unless the
//   shape is exactly `{ type, senderHandle, conversationId }`.

import type pg from 'pg';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/** Push payload schema — STRICTLY `{ type, senderHandle, conversationId }`.
 *
 *  Any additional field at the top level causes `safeParse` to fail with
 *  `unrecognized_keys`. This is the load-bearing schema for Requirement
 *  13.3: the sender refuses to ship anything else. */
export const PushPayloadSchema = z
  .object({
    type: z.string().min(1),
    senderHandle: z.string().min(1),
    conversationId: z.string().min(1),
  })
  .strict();

export type PushPayload = z.infer<typeof PushPayloadSchema>;

/** A push subscription row as stored in `push_subscriptions`. */
export interface PushSubscriptionRow {
  readonly id: string;
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}

/** Minimal `pg.Pool` shape this module needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres. */
type DbPool = Pick<pg.Pool, 'query'>;

/** The bits of the `web-push` API we depend on. Restated as an interface
 *  so unit tests can substitute a stub without resolving the SDK. */
export interface WebPushClient {
  sendNotification(
    subscription: { endpoint: string; keys: { p256dh: string; auth: string } },
    payload: string,
  ): Promise<unknown>;
}

/** Result of a single `sendPushToDevice` call. Discriminated so callers
 *  can branch on the explicit outcome rather than parsing exception
 *  messages. */
export type SendPushResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason:
        | 'no_subscription'
        | 'invalid_payload'
        | 'gone'
        | 'send_failed';
    };

export interface PushSenderDeps {
  readonly pool: DbPool;
  readonly webPush: WebPushClient;
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/** Send a Web Push notification to the subscription registered for the
 *  given device. Returns a typed result rather than throwing so callers
 *  (the WS gateway, broadcast fan-out) can handle the no-subscription
 *  case without try/catch.
 *
 *  Requirement 13.3: the payload schema is enforced at the top of the
 *  call. Anything that doesn't match
 *  `{ type, senderHandle, conversationId }` exactly is rejected before
 *  any network I/O happens.
 *
 *  Requirement 13.6: on HTTP 410 from the push service the
 *  `push_subscriptions` row is deleted. Other failures are logged at
 *  the call site and surfaced as `'send_failed'`. */
export async function sendPushToDevice(
  deps: PushSenderDeps,
  deviceId: string,
  payload: PushPayload,
): Promise<SendPushResult> {
  // Validate the payload shape FIRST, before we touch the DB or the
  // push service. A misconstructed payload can never leak — we refuse
  // to send it.
  const parsed = PushPayloadSchema.safeParse(payload);
  if (!parsed.success) {
    return { ok: false, reason: 'invalid_payload' };
  }

  // Look up the subscription. Subscriptions are 1-1 with devices per
  // Requirement 13.1; if more than one row matches we take the most
  // recently inserted via ORDER BY created_at DESC LIMIT 1. The
  // typical case has exactly one row.
  const r = await deps.pool.query<PushSubscriptionRow>(
    `SELECT id, endpoint, p256dh, auth
       FROM push_subscriptions
      WHERE device_id = $1
      ORDER BY created_at DESC
      LIMIT 1`,
    [deviceId],
  );
  if (r.rowCount === 0) {
    return { ok: false, reason: 'no_subscription' };
  }
  const sub = r.rows[0] as PushSubscriptionRow;

  // Encode the validated payload exactly. We use the parsed value
  // (rather than the caller's input) so any TypeScript type-level
  // looseness gets sanitized to the exact three-field shape.
  const body = JSON.stringify(parsed.data);

  try {
    await deps.webPush.sendNotification(
      {
        endpoint: sub.endpoint,
        keys: { p256dh: sub.p256dh, auth: sub.auth },
      },
      body,
    );
    return { ok: true };
  } catch (err) {
    // Requirement 13.6: HTTP 410 means the subscription is gone — we
    // delete the row so subsequent sends don't burn the same 410
    // forever. The `web-push` library surfaces the upstream HTTP
    // status as `err.statusCode`; we accept both `statusCode` and
    // `status` to remain robust against minor SDK API drift.
    if (isGoneError(err)) {
      await deps.pool.query(
        `DELETE FROM push_subscriptions WHERE id = $1`,
        [sub.id],
      );
      return { ok: false, reason: 'gone' };
    }
    return { ok: false, reason: 'send_failed' };
  }
}

// ---------------------------------------------------------------------------
// Convenience wrapper used by the WS gateway's offline push fallback
// ---------------------------------------------------------------------------

/** Arguments for `sendPushNotification` — flat shape matching the
 *  gateway's offline-fallback call site (task 10.4). The four fields
 *  are split apart from the strict `PushPayload` so the caller never
 *  has to construct the payload object manually (which historically
 *  was a recurring source of "extra field" leaks).
 *
 *  `deviceId` selects the recipient subscription row; the remaining
 *  three fields are forwarded verbatim into the `PushPayload` and
 *  validated by `PushPayloadSchema.strict()` inside
 *  `sendPushToDevice`. The argument shape is therefore the SAME shape
 *  that ends up on the wire: there is no place for `body`,
 *  `ciphertext`, or any key material to slip in between this call
 *  site and `JSON.stringify`. */
export interface SendPushNotificationArgs {
  readonly deviceId: string;
  readonly type: string;
  readonly senderHandle: string;
  readonly conversationId: string;
}

/** Send a metadata-only Web Push notification keyed by `deviceId`.
 *
 *  This is the call site used by `apps/api/src/ws/gateway.ts` when a
 *  recipient device is offline at envelope insertion time
 *  (Requirement 12.10 — task 10.4). It exists as a thin convenience
 *  wrapper around `sendPushToDevice` so the gateway never has to
 *  construct a `PushPayload` literal in-line — the argument shape is
 *  flat (one named param per field) which makes it impossible to
 *  spread an unrelated object into the payload.
 *
 *  The strict payload schema (`PushPayloadSchema`) is enforced inside
 *  `sendPushToDevice`; any forbidden field would already have to come
 *  through one of the four explicit string parameters here, which
 *  TypeScript and the schema reject at the call boundary. */
export async function sendPushNotification(
  deps: PushSenderDeps,
  args: SendPushNotificationArgs,
): Promise<SendPushResult> {
  return sendPushToDevice(deps, args.deviceId, {
    type: args.type,
    senderHandle: args.senderHandle,
    conversationId: args.conversationId,
  });
}

/** Detect an HTTP 410 from the push service. The web-push library
 *  surfaces these as a thrown `WebPushError` with a numeric
 *  `statusCode`. We compare structurally to avoid depending on the
 *  library's class for the runtime check. */
function isGoneError(err: unknown): boolean {
  if (err === null || err === undefined || typeof err !== 'object') {
    return false;
  }
  const e = err as { statusCode?: unknown; status?: unknown };
  if (typeof e.statusCode === 'number' && e.statusCode === 410) return true;
  if (typeof e.status === 'number' && e.status === 410) return true;
  return false;
}

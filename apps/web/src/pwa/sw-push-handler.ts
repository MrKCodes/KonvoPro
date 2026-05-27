// apps/web/src/pwa/sw-push-handler.ts
//
// Service-worker push + notification-click handlers (task 9.4).
//
// Realizes Requirements 13.4 and 13.5:
//
//   - 13.4: on a Web_Push event, the Service_Worker fetches the
//           latest envelope for the carried `conversationId`,
//           decrypts it locally, and renders a notification whose
//           body is the decrypted plaintext.
//   - 13.5: if the fetch or the decrypt fails, the Service_Worker
//           renders a generic notification that identifies only
//           `senderHandle` and `type` and never displays
//           plaintext, ciphertext, or any key material.
//
// Why this lives in its own module rather than inline in `sw.ts`:
//   `sw.ts` calls Workbox routing / precaching at module load
//   time. Importing it from a unit test (which runs under
//   jsdom, not a real `ServiceWorkerGlobalScope`) would either
//   register stray fetch handlers on the test runtime or — with
//   stricter Workbox versions — throw because the runtime isn't
//   a SW. By keeping the handler logic here as PURE async
//   functions parameterised on injectable dependencies
//   (`registration`, `clients`, `fetchLatestEnvelope`,
//   `decryptEnvelope`), the tests can exercise every branch
//   without ever touching Workbox.
//
// Layering contract:
//   - This module owns the *decision* logic: parse the push
//     payload, attempt decrypt, fall back to a generic body,
//     route a click to the correct thread.
//   - `sw.ts` owns the *binding*: read `event.data`, call into
//     this module, wrap the call in `event.waitUntil`, supply
//     the production `fetchLatestEnvelope` / `decryptEnvelope`
//     strategies.
//   - The production strategies are documented `TODO`s today —
//     no `GET /envelopes?conversationId=...` REST route exists
//     yet (the existing routes only stream attachments and
//     prekey bundles), and the libsignal Signal store from
//     task 4.4 is keyed by Dexie which is reachable from a SW
//     context but requires deferred wiring. Until both exist
//     the production path always falls through to the generic
//     notification, which is exactly the safe behaviour
//     mandated by Requirement 13.5.

import { pwaLog } from './logger.js';

// ---------------------------------------------------------------------------
// Push payload (must mirror `apps/api/src/push/sender.ts` exactly)
// ---------------------------------------------------------------------------

/** Push payload shape carried in the encrypted Web_Push body.
 *  Mirrors the strict zod schema in
 *  `apps/api/src/push/sender.ts` — the API_Gateway refuses to
 *  ship anything else (Requirement 13.3) and this module
 *  refuses to render anything else for the same reason. */
export interface PushPayload {
  readonly type: string;
  readonly senderHandle: string;
  readonly conversationId: string;
}

/** Parse + validate an incoming push body. Returns `null` for
 *  every shape that doesn't match the strict three-field
 *  contract — we silently drop those. The API will never send
 *  a malformed payload (the schema is `.strict()`); a malformed
 *  payload reaching us means either a bug, an attacker-injected
 *  push, or a future-protocol field we don't yet understand. In
 *  every case the right move is to swallow it rather than
 *  render a notification with attacker-controlled bytes. */
export function parsePushPayload(raw: string | null): PushPayload | null {
  if (raw === null || raw.length === 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object') return null;
  const o = parsed as Record<string, unknown>;
  const type = o['type'];
  const senderHandle = o['senderHandle'];
  const conversationId = o['conversationId'];
  if (typeof type !== 'string' || type.length === 0) return null;
  if (typeof senderHandle !== 'string' || senderHandle.length === 0) {
    return null;
  }
  if (typeof conversationId !== 'string' || conversationId.length === 0) {
    return null;
  }
  return { type, senderHandle, conversationId };
}

// ---------------------------------------------------------------------------
// Envelope fetch + decrypt strategies (injectable)
// ---------------------------------------------------------------------------

/** The minimum envelope shape the decrypt path needs. We restate
 *  it here rather than importing `CiphertextEnvelope` directly so
 *  the SW push handler can be tested without pulling in the
 *  protocol package, AND so we can swap the on-the-wire shape
 *  without touching the handler. */
export interface EnvelopeForNotification {
  readonly ciphertext: Uint8Array;
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly sessionId: string;
}

/** Result of a `fetchLatestEnvelope` call. Discriminated so
 *  callers don't have to grep exception strings. */
export type FetchLatestEnvelopeResult =
  | { readonly ok: true; readonly envelope: EnvelopeForNotification }
  | { readonly ok: false };

/** Strategy: fetch the latest unread envelope for a
 *  `conversationId` (Requirement 13.4). Returns `{ ok: false }`
 *  on any failure (network error, 4xx/5xx, parse error). */
export type FetchLatestEnvelope = (
  conversationId: string,
) => Promise<FetchLatestEnvelopeResult>;

/** Result of a `decryptEnvelope` call. The `plaintext` field is
 *  the **already-formatted** display string for the
 *  notification body — the decrypt strategy is responsible for
 *  any InnerType-specific formatting (e.g. "🎤 Voice note" for
 *  `InnerType.VOICE_NOTE`). We never put the raw decrypted
 *  bytes into a string field that could surface keying
 *  material. */
export type DecryptEnvelopeResult =
  | { readonly ok: true; readonly plaintext: string }
  | { readonly ok: false };

/** Strategy: decrypt an envelope locally and return the
 *  display string. Returns `{ ok: false }` on any failure
 *  (no session, ratchet rejection, store error). */
export type DecryptEnvelopeForNotification = (
  envelope: EnvelopeForNotification,
) => Promise<DecryptEnvelopeResult>;

// ---------------------------------------------------------------------------
// Notification rendering
// ---------------------------------------------------------------------------

/** Generic notification body table for the `type` field.
 *  Requirement 13.5: identifies only `senderHandle` and
 *  `type`; never plaintext / ciphertext / key material. */
export const GENERIC_BODIES: Readonly<Record<string, string>> = {
  'dm.message': 'New message',
  'dm.voice_note': 'New voice note',
  'dm.attachment': 'New attachment',
  'broadcast.post': 'New broadcast post',
};

/** Fallback body for any `type` not in `GENERIC_BODIES`. We
 *  prefer "New notification" over the raw `type` string because
 *  the type string is attacker-influenceable (the API server
 *  picks it, but a malformed routing path could include
 *  arbitrary characters). Showing a constant English string
 *  prevents that surface from rendering anything user-visible
 *  derived from message data. */
export const FALLBACK_GENERIC_BODY = 'New notification' as const;

/** Look up the generic display body for a push `type`. Pure +
 *  total; never throws. */
export function genericBodyFor(type: string): string {
  if (Object.prototype.hasOwnProperty.call(GENERIC_BODIES, type)) {
    const body = GENERIC_BODIES[type];
    if (typeof body === 'string') return body;
  }
  return FALLBACK_GENERIC_BODY;
}

/** Default thread-URL builder. The SPA handles routing in-app;
 *  this URL is what the SW navigates a freshly-opened tab to,
 *  AND what existing tabs match against to decide whether to
 *  re-focus or open a new window. */
export function defaultThreadUrlFor(conversationId: string): string {
  return `/thread/${encodeURIComponent(conversationId)}`;
}

/** Subset of `ServiceWorkerRegistration` we depend on. Restated
 *  structurally so tests can stub it without instantiating a
 *  full SW registration. */
export interface ShowNotificationLike {
  showNotification(
    title: string,
    options?: NotificationOptions,
  ): Promise<void>;
}

/** Notification `data` payload we attach so the click handler
 *  can navigate without re-parsing the body. Plain strings —
 *  no plaintext content, no envelope ids, no key material. */
export interface NotificationData {
  readonly conversationId: string;
  readonly threadUrl: string;
}

export interface PushHandlerDeps {
  readonly registration: ShowNotificationLike;
  readonly fetchLatestEnvelope: FetchLatestEnvelope;
  readonly decryptEnvelope: DecryptEnvelopeForNotification;
  readonly threadUrlFor: (conversationId: string) => string;
}

/**
 * Top-level push event handler. Wired in `sw.ts` as:
 *
 *   self.addEventListener('push', (event) => {
 *     event.waitUntil(handlePushEvent(event.data?.text() ?? null, deps));
 *   });
 *
 * Behaviour:
 *   1. Parse + validate the payload. On invalid payload, return
 *      WITHOUT showing a notification — we'd rather drop a bogus
 *      push than render an attacker-controlled string.
 *   2. Compute the thread URL up-front so it's always present in
 *      `data` regardless of which body branch we land on.
 *   3. Try the fetch + decrypt path. Any failure (rejected
 *      Promise, `{ ok: false }`, exception thrown by either
 *      strategy) collapses to `bodyText = null` and we fall
 *      through to the generic body for the type.
 *   4. Render the notification with `senderHandle` as the title
 *      and either the decrypted plaintext (Requirement 13.4) or
 *      the generic body (Requirement 13.5) as the body.
 *
 * The notification title is `senderHandle` in both branches —
 * Requirement 13.5 explicitly permits the handle in the
 * fallback, and rendering it consistently means the user can't
 * tell from the title whether decrypt succeeded or not (a small
 * but real privacy gain — an observer watching notifications
 * over the user's shoulder learns less).
 */
export async function handlePushEvent(
  rawData: string | null,
  deps: PushHandlerDeps,
): Promise<void> {
  const payload = parsePushPayload(rawData);
  if (payload === null) {
    pwaLog('warn', 'sw.push.invalid_payload');
    return;
  }

  const threadUrl = deps.threadUrlFor(payload.conversationId);
  const data: NotificationData = {
    conversationId: payload.conversationId,
    threadUrl,
  };

  let bodyText: string | null = null;
  try {
    const fetched = await deps.fetchLatestEnvelope(payload.conversationId);
    if (fetched.ok) {
      const decrypted = await deps.decryptEnvelope(fetched.envelope);
      if (decrypted.ok) {
        bodyText = decrypted.plaintext;
      }
    }
  } catch (err) {
    // Strategy threw rather than returning `{ ok: false }`. Same
    // outcome — fall through to generic. Log once so a recurring
    // failure surfaces in DevTools.
    pwaLog('warn', 'sw.push.fetch_or_decrypt_threw', { error: err });
  }

  if (bodyText === null) {
    bodyText = genericBodyFor(payload.type);
  }

  try {
    await deps.registration.showNotification(payload.senderHandle, {
      body: bodyText,
      data,
    });
  } catch (err) {
    // Notification rendering itself failed (permission revoked
    // mid-flight, browser-internal error). Nothing to fall back
    // to — log and return.
    pwaLog('warn', 'sw.push.show_notification_failed', { error: err });
  }
}

// ---------------------------------------------------------------------------
// Notification click → focus existing tab or open a new one
// ---------------------------------------------------------------------------

/** Subset of `WindowClient` we depend on. */
export interface ClientLike {
  readonly url: string;
  focus(): Promise<unknown>;
  postMessage(data: unknown): void;
}

/** Subset of `Clients` we depend on. */
export interface ClientsLike {
  matchAll(opts: {
    type: 'window';
    includeUncontrolled: boolean;
  }): Promise<readonly ClientLike[]>;
  openWindow(url: string): Promise<unknown>;
}

export interface NotificationClickDeps {
  readonly clients: ClientsLike;
  readonly threadUrlFor: (conversationId: string) => string;
  /** Origin used to resolve the thread URL into an absolute
   *  URL for `WindowClient.url` comparisons and for
   *  `clients.openWindow`. The SW reads this from
   *  `self.registration.scope` or `self.location.origin`; tests
   *  pass a synthetic origin. */
  readonly origin: string;
}

/** Message posted to a focused tab so the SPA router can
 *  navigate without a full reload. The SPA installs a
 *  `navigator.serviceWorker.addEventListener('message', ...)`
 *  handler that pattern-matches on `kind === 'konvo.navigate'`. */
export interface NavigateMessage {
  readonly kind: 'konvo.navigate';
  readonly conversationId: string;
  readonly threadUrl: string;
}

/**
 * Notification-click handler. Wired in `sw.ts` as:
 *
 *   self.addEventListener('notificationclick', (event) => {
 *     event.notification.close();
 *     event.waitUntil(handleNotificationClick(event.notification.data, deps));
 *   });
 *
 * Behaviour:
 *   1. Pull `conversationId` out of the notification's `data`
 *      object. If missing or malformed, return — clicking a
 *      malformed notification is a no-op rather than an error.
 *   2. Build the absolute thread URL.
 *   3. Walk the open windows for this origin. If any window's
 *      URL matches the thread URL, focus it and post a
 *      `konvo.navigate` message so the SPA can route in-app.
 *      We also try a relative-suffix match so a window currently
 *      on `/threads` (the thread list) gets focused even though
 *      its URL doesn't equal the per-thread URL exactly.
 *   4. Otherwise, open a new window at the thread URL.
 */
export async function handleNotificationClick(
  notificationData: unknown,
  deps: NotificationClickDeps,
): Promise<void> {
  const conversationId = extractConversationId(notificationData);
  if (conversationId === null) {
    pwaLog('warn', 'sw.click.missing_conversation_id');
    return;
  }
  const path = deps.threadUrlFor(conversationId);
  const absolute = new URL(path, deps.origin).toString();

  let openClients: readonly ClientLike[];
  try {
    openClients = await deps.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    });
  } catch (err) {
    pwaLog('warn', 'sw.click.match_all_failed', { error: err });
    openClients = [];
  }

  // Prefer an exact-URL match; fall back to a same-origin client
  // (any open Konvo tab can in-app-navigate to the thread).
  const exact = openClients.find((c) => c.url === absolute);
  const sameOrigin =
    exact ?? openClients.find((c) => sameOriginAs(c.url, deps.origin));

  if (sameOrigin !== undefined) {
    try {
      await sameOrigin.focus();
    } catch (err) {
      // Some browsers reject focus() if the user gesture has
      // already been consumed. Best-effort — fall through to
      // posting the navigate message so the existing tab still
      // routes.
      pwaLog('warn', 'sw.click.focus_failed', { error: err });
    }
    const message: NavigateMessage = {
      kind: 'konvo.navigate',
      conversationId,
      threadUrl: path,
    };
    try {
      sameOrigin.postMessage(message);
    } catch (err) {
      pwaLog('warn', 'sw.click.post_message_failed', { error: err });
    }
    return;
  }

  try {
    await deps.clients.openWindow(absolute);
  } catch (err) {
    pwaLog('warn', 'sw.click.open_window_failed', { error: err });
  }
}

/** Pull the `conversationId` out of an unknown `notification.data`
 *  payload. Returns `null` if the field is missing or not a
 *  non-empty string. */
function extractConversationId(d: unknown): string | null {
  if (d === null || d === undefined || typeof d !== 'object') return null;
  const obj = d as Record<string, unknown>;
  const cid = obj['conversationId'];
  return typeof cid === 'string' && cid.length > 0 ? cid : null;
}

/** Best-effort same-origin check. We compare the parsed URL's
 *  origin to the supplied origin string. On parse failure we
 *  default to `false` — better to open a fresh window than to
 *  focus an unrelated tab. */
function sameOriginAs(url: string, origin: string): boolean {
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

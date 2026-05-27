// apps/web/src/features/settings/PushToggle.tsx
//
// Web_Push enable/disable toggle for the Settings screen
// (task 9.3 — Phase 8).
//
// Realizes Requirements 13.7 and 15.3:
//
//   - 13.7: when the user enables the toggle, the Web_Client submits
//           POST /push/subscribe for the current device. When the user
//           disables the toggle, the Web_Client submits DELETE
//           /push/subscribe/:id so the API_Gateway no longer sends
//           Web_Push notifications to that device.
//   - 15.3: the toggle's value persists across browser sessions on
//           the same device. We persist the boolean enable/disable
//           preference in `localStorage` under the key
//           `konvo:webpush:enabled` AND the server-issued subscription
//           id under `konvo:webpush:subscriptionId`. The actual push
//           subscription itself lives inside the browser's
//           `PushManager` (browser-managed); we re-derive its identity
//           from the browser on demand via `pushManager.getSubscription()`.
//
// What we INTENTIONALLY do NOT persist:
//   - The access token (Requirement 1.11): the auth API client reads
//     it from the in-memory `authStore` per request.
//   - The push subscription's `endpoint` / `keys.p256dh` / `keys.auth`
//     bytes — those are owned by the browser and re-derivable from
//     `pushManager.getSubscription()`. Storing them in localStorage
//     would create a redundant copy that could drift.
//
// State model:
//
//   The toggle is a 5-state machine driven by the persisted flag and
//   any in-flight async work:
//
//     'unsupported' — the browser lacks Notification API or
//                     PushManager support; the toggle is disabled and
//                     reads "Push not available in this browser".
//     'idle-off'    — toggle off, no pending work.
//     'enabling'    — user clicked enable; we're requesting
//                     permission, subscribing via PushManager, and
//                     POSTing /push/subscribe.
//     'idle-on'     — toggle on, persisted; backend subscription id
//                     is in localStorage.
//     'disabling'   — user clicked disable; we're unsubscribing from
//                     PushManager and DELETEing /push/subscribe/:id.
//
//   Errors during 'enabling' or 'disabling' surface inline via an
//   `error` property on the model rather than throwing — the toggle
//   reverts to the prior idle state so the user can retry.
//
// PushSubscriber abstraction:
//
//   Tests do not have a real browser PushManager. We isolate every
//   permission/subscribe/unsubscribe call behind a `PushSubscriber`
//   interface so tests can substitute an in-memory implementation
//   without monkey-patching `navigator.serviceWorker` or
//   `Notification`. Production wires `defaultPushSubscriber()` which
//   reads from `navigator` directly.

import { useEffect, useMemo, useState } from 'react';

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

/** Persists the user's preferred toggle state across browser sessions
 *  (Requirement 15.3). Value is `'1'` for enabled, `'0'` for disabled,
 *  absent for "never been touched". */
export const TOGGLE_STORAGE_KEY = 'konvo:webpush:enabled';

/** Persists the server-issued subscription id so disable can DELETE
 *  the right row even after a page reload. The browser-side
 *  PushSubscription identity (endpoint + keys) is owned by the
 *  PushManager and re-derivable; only the server's row id needs to
 *  travel. */
export const SUBSCRIPTION_ID_KEY = 'konvo:webpush:subscriptionId';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A single Web_Push subscription as the browser exposes it. Mirrors
 *  the shape of `PushSubscription.toJSON()` and the
 *  `PushSubscriptionRequest` REST DTO. */
export interface PushSubscriptionShape {
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}

/** Pluggable push subscriber. Production wires `defaultPushSubscriber()`;
 *  tests inject a stub. */
export interface PushSubscriber {
  /** Whether this browser supports Web Push at all. */
  isSupported(): boolean;
  /** Current notification permission. We treat any value other than
   *  `'granted'` as not-yet-enabled. */
  permission(): NotificationPermission | 'unsupported';
  /** Prompt the user for notification permission. Returns the new
   *  permission value. */
  requestPermission(): Promise<NotificationPermission>;
  /** Read the active PushSubscription, if any. Returns `null` when
   *  there's no active subscription. */
  getSubscription(): Promise<PushSubscriptionShape | null>;
  /** Subscribe via the PushManager. The application server key is
   *  the VAPID public key from the API_Gateway. */
  subscribe(applicationServerKey: string): Promise<PushSubscriptionShape>;
  /** Unsubscribe the current PushSubscription. Idempotent. */
  unsubscribe(): Promise<void>;
}

/** REST API client for the push subscribe / unsubscribe routes.
 *  Production wires the same `AuthApiClient` shape used elsewhere in
 *  the Web_Client; tests inject a stub. */
export interface PushApiClient {
  /** POST /push/subscribe. Returns the server-issued subscription id. */
  subscribe(req: {
    deviceId: string;
    endpoint: string;
    p256dh: string;
    auth: string;
  }): Promise<{ subscriptionId: string }>;
  /** DELETE /push/subscribe/:id. */
  unsubscribe(subscriptionId: string): Promise<void>;
}

export interface PushToggleProps {
  /** UUID of the current browser device (the device row this toggle
   *  manages a subscription for). The Web_Client knows its own device
   *  id from the auth store / device-enrollment flow. */
  readonly deviceId: string;
  /** VAPID public key the browser passes as `applicationServerKey`. */
  readonly vapidPublicKey: string;
  /** Pluggable subscriber + REST client. Tests substitute these; in
   *  production callers pass `defaultPushSubscriber()` and the shared
   *  `AuthApiClient`. */
  readonly subscriber: PushSubscriber;
  readonly api: PushApiClient;
  /** Override the storage backend for tests. Defaults to
   *  `window.localStorage`. */
  readonly storage?: Storage;
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

type ToggleState =
  | { readonly kind: 'unsupported' }
  | { readonly kind: 'idle-off'; readonly error?: string }
  | { readonly kind: 'enabling' }
  | { readonly kind: 'idle-on'; readonly error?: string }
  | { readonly kind: 'disabling' };

function readPersistedFlag(storage: Storage): boolean {
  return storage.getItem(TOGGLE_STORAGE_KEY) === '1';
}

function writePersistedFlag(storage: Storage, enabled: boolean): void {
  if (enabled) {
    storage.setItem(TOGGLE_STORAGE_KEY, '1');
  } else {
    // `removeItem` rather than setting `'0'` so a never-touched
    // browser and a deliberately-disabled browser both observe as
    // "no preference". Subsequent reads use `=== '1'` so '0' would
    // also be "off"; we use removeItem for cleanliness.
    storage.removeItem(TOGGLE_STORAGE_KEY);
  }
}

function readSubscriptionId(storage: Storage): string | null {
  return storage.getItem(SUBSCRIPTION_ID_KEY);
}

function writeSubscriptionId(storage: Storage, id: string | null): void {
  if (id === null) {
    storage.removeItem(SUBSCRIPTION_ID_KEY);
  } else {
    storage.setItem(SUBSCRIPTION_ID_KEY, id);
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function PushToggle(props: PushToggleProps): JSX.Element {
  const storage = props.storage ?? globalThis.localStorage;

  // Initial state is derived synchronously from the supported check
  // and the persisted flag so the toggle reflects the user's last
  // session immediately on render (Requirement 15.3).
  const initial = useMemo<ToggleState>(() => {
    if (!props.subscriber.isSupported()) {
      return { kind: 'unsupported' };
    }
    return readPersistedFlag(storage) ? { kind: 'idle-on' } : { kind: 'idle-off' };
  }, [props.subscriber, storage]);

  const [state, setState] = useState<ToggleState>(initial);

  // On mount, if the persisted flag says "on" but the browser has no
  // active PushSubscription (e.g. user cleared site data, browser
  // garbage-collected the subscription), reconcile by flipping the
  // visible state to "off". We don't auto-resubscribe — the user has
  // to explicitly opt back in so a hostile site can't regenerate
  // notification access through a stale flag.
  useEffect(() => {
    if (state.kind !== 'idle-on') return;
    let cancelled = false;
    (async () => {
      const sub = await props.subscriber.getSubscription();
      if (cancelled) return;
      if (sub === null) {
        writePersistedFlag(storage, false);
        writeSubscriptionId(storage, null);
        setState({ kind: 'idle-off' });
      }
    })();
    return () => {
      cancelled = true;
    };
    // Run once after the initial state is established.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function enable(): Promise<void> {
    setState({ kind: 'enabling' });
    try {
      const perm = await props.subscriber.requestPermission();
      if (perm !== 'granted') {
        setState({
          kind: 'idle-off',
          error: 'Notifications permission denied. Enable it in your browser to receive push.',
        });
        return;
      }
      const subscription = await props.subscriber.subscribe(props.vapidPublicKey);
      const result = await props.api.subscribe({
        deviceId: props.deviceId,
        endpoint: subscription.endpoint,
        p256dh: subscription.p256dh,
        auth: subscription.auth,
      });
      // Persist BOTH the toggle flag and the subscription id so a
      // reload finds them and a later disable can target the right
      // row.
      writePersistedFlag(storage, true);
      writeSubscriptionId(storage, result.subscriptionId);
      setState({ kind: 'idle-on' });
    } catch (err) {
      // On any failure roll back to "off" so the UI matches reality.
      // We attempt a best-effort browser unsubscribe so a half-
      // completed flow doesn't leave a stranded PushSubscription
      // that the server doesn't know about.
      try {
        await props.subscriber.unsubscribe();
      } catch {
        // Ignore — best effort.
      }
      writePersistedFlag(storage, false);
      writeSubscriptionId(storage, null);
      const msg = err instanceof Error ? err.message : 'Failed to enable push notifications.';
      setState({ kind: 'idle-off', error: msg });
    }
  }

  async function disable(): Promise<void> {
    setState({ kind: 'disabling' });
    const subscriptionId = readSubscriptionId(storage);
    try {
      // Best-effort browser unsubscribe first. Even if the server
      // DELETE fails the user's local PushManager should be inert.
      await props.subscriber.unsubscribe();
      if (subscriptionId !== null) {
        await props.api.unsubscribe(subscriptionId);
      }
      writePersistedFlag(storage, false);
      writeSubscriptionId(storage, null);
      setState({ kind: 'idle-off' });
    } catch (err) {
      // Mark off locally regardless: the user wants it off, and the
      // server-side row is one DELETE retry away. We surface the
      // error so the user knows the server may still hold the row.
      writePersistedFlag(storage, false);
      writeSubscriptionId(storage, null);
      const msg = err instanceof Error ? err.message : 'Failed to disable push notifications.';
      setState({ kind: 'idle-off', error: msg });
    }
  }

  if (state.kind === 'unsupported') {
    return (
      <section aria-labelledby="webpush-toggle-heading" data-testid="webpush-toggle-section">
        <h3 id="webpush-toggle-heading">Push notifications</h3>
        <p data-testid="webpush-unsupported">
          Push notifications are not available in this browser.
        </p>
      </section>
    );
  }

  const busy = state.kind === 'enabling' || state.kind === 'disabling';
  const checked = state.kind === 'idle-on' || state.kind === 'disabling';
  const errorMessage =
    (state.kind === 'idle-off' || state.kind === 'idle-on') && state.error !== undefined
      ? state.error
      : null;

  return (
    <section aria-labelledby="webpush-toggle-heading" data-testid="webpush-toggle-section">
      <h3 id="webpush-toggle-heading">Push notifications</h3>
      <p>
        Receive notifications when you have new messages even if Konvo is closed. Notification
        contents stay private — only the sender handle and conversation id are sent through
        the push service; the message body is fetched and decrypted on this device.
      </p>
      <label>
        <input
          type="checkbox"
          checked={checked}
          disabled={busy}
          onChange={(e) => {
            if (e.currentTarget.checked) {
              void enable();
            } else {
              void disable();
            }
          }}
          data-testid="webpush-toggle-input"
        />
        <span>{checked ? 'Push notifications on' : 'Push notifications off'}</span>
      </label>
      {busy ? (
        <p data-testid="webpush-toggle-busy">
          {state.kind === 'enabling' ? 'Enabling…' : 'Disabling…'}
        </p>
      ) : null}
      {errorMessage !== null ? (
        <p role="alert" data-testid="webpush-toggle-error">
          {errorMessage}
        </p>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Default browser-backed PushSubscriber
// ---------------------------------------------------------------------------

/** Construct a `PushSubscriber` backed by the browser's
 *  `Notification` and `navigator.serviceWorker` APIs. Returns
 *  `unsupported`-flavoured behaviour on environments without those
 *  globals (e.g. SSR build).
 *
 *  We reach into the active service worker registration's
 *  `pushManager` rather than `navigator.serviceWorker.pushManager`
 *  because the latter doesn't exist as a public API; the registration
 *  object owns the manager. Callers must register the SW before
 *  mounting `PushToggle`. */
export function defaultPushSubscriber(): PushSubscriber {
  return {
    isSupported(): boolean {
      return (
        typeof globalThis.Notification !== 'undefined' &&
        typeof navigator !== 'undefined' &&
        'serviceWorker' in navigator &&
        typeof PushManager !== 'undefined'
      );
    },
    permission(): NotificationPermission | 'unsupported' {
      if (typeof globalThis.Notification === 'undefined') return 'unsupported';
      return globalThis.Notification.permission;
    },
    async requestPermission(): Promise<NotificationPermission> {
      return globalThis.Notification.requestPermission();
    },
    async getSubscription(): Promise<PushSubscriptionShape | null> {
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg === undefined) return null;
      const sub = await reg.pushManager.getSubscription();
      if (sub === null) return null;
      return serializeSubscription(sub);
    },
    async subscribe(applicationServerKey: string): Promise<PushSubscriptionShape> {
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg === undefined) {
        throw new Error('service worker is not registered');
      }
      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(applicationServerKey),
      });
      return serializeSubscription(sub);
    },
    async unsubscribe(): Promise<void> {
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg === undefined) return;
      const sub = await reg.pushManager.getSubscription();
      if (sub === null) return;
      await sub.unsubscribe();
    },
  };
}

/** Read the `endpoint`, `p256dh`, and `auth` fields from a browser
 *  `PushSubscription` and surface them in the wire shape the API
 *  expects. */
function serializeSubscription(sub: PushSubscription): PushSubscriptionShape {
  const json = sub.toJSON() as {
    endpoint?: string;
    keys?: { p256dh?: string; auth?: string };
  };
  const endpoint = json.endpoint ?? sub.endpoint;
  const p256dh = json.keys?.p256dh ?? '';
  const auth = json.keys?.auth ?? '';
  return { endpoint, p256dh, auth };
}

/** Convert a base64url-encoded VAPID key (as the API_Gateway exposes
 *  it) into the `Uint8Array` the PushManager wants. The push spec
 *  requires base64url; we handle both standard and URL-safe variants. */
function urlBase64ToUint8Array(b64: string): Uint8Array {
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

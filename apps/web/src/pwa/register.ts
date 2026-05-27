// apps/web/src/pwa/register.ts
//
// Page-side service-worker registration + offline/online
// reconciliation hooks (task 9.1).
//
// Responsibilities:
//   1. Register `/sw.js` once at page load. If `navigator.serviceWorker`
//      is unavailable (older browser, file:// origin) OR registration
//      throws, log via the structured logger and continue running in
//      online-only mode. Requirement 14.8.
//   2. Wire offline → online reconciliation. When `navigator.onLine`
//      flips from `false` to `true`, dispatch a `konvo:reconnect`
//      CustomEvent on `globalThis`. Listeners (the DM controller,
//      the broadcast feature, the WS client wrapper) re-fetch
//      authoritative state from the server and overwrite any
//      divergent optimistic state. Requirement 14.9 — "treat the
//      server as authoritative".
//
// Why a CustomEvent and not a direct module dependency:
//   `register.ts` is loaded synchronously from `main.tsx` to keep
//   the SW install path off the critical render path. Pulling in
//   the DM controller / WS client modules here would force the
//   PWA bundle to load all of them up front, which defeats Vite's
//   route-level code-split. The CustomEvent decouples
//   registration from the consumers; each feature subscribes
//   on mount. The event name lives in this module so callers
//   import a constant rather than copy-pasting a magic string.
//
// Reconciliation contract for listeners (Requirement 14.9):
//   When a listener receives `konvo:reconnect`, it should:
//     - Re-fetch authoritative state from the server (or wait for
//       the WS to re-establish and replay queued envelopes).
//     - Overwrite any in-memory optimistic state that diverges.
//     - NEVER promote a still-pending optimistic state to
//       "delivered" without a server acknowledgement — the spec
//       explicitly mandates server authority on divergence.

import { pwaLog } from './logger.js';

/** Custom-event name dispatched on `globalThis` when the browser
 *  transitions from offline to online. Subscribers reconcile
 *  optimistic state against the server. */
export const RECONNECT_EVENT_NAME = 'konvo:reconnect' as const;

/** Default URL the SW is registered against. Vite emits the SW
 *  bundle to `/sw.js` at build time. Production code does not
 *  override this; tests pass a different URL to assert the
 *  registration call shape. */
export const DEFAULT_SW_URL = '/sw.js' as const;

/** Result of `registerServiceWorker`. Returned for tests + future
 *  callers that want to surface registration state in the UI
 *  (e.g. "offline mode unavailable" badge). */
export type RegisterResult =
  | { readonly kind: 'registered'; readonly registration: ServiceWorkerRegistration }
  | { readonly kind: 'unsupported' }
  | { readonly kind: 'failed'; readonly error: unknown };

export interface RegisterOptions {
  /** SW URL. Defaults to `/sw.js`. */
  readonly url?: string;
  /** Override the navigator instance (tests). Defaults to the
   *  global `navigator`. */
  readonly navigator?: Navigator;
}

/**
 * Register `/sw.js`. Never throws — every failure path resolves
 * to a typed `RegisterResult` and emits a structured log.
 *
 * Requirement 14.8: "IF Service Worker registration or precache
 * fails, THEN THE Web_Client SHALL log the failure to the existing
 * structured logger and SHALL continue to function in online-only
 * mode." This implementation honors that by:
 *   - swallowing the rejection from `register()` rather than
 *     propagating, AND
 *   - returning `{ kind: 'failed' }` so a caller that DOES want
 *     to surface a UI affordance has the failure available.
 *
 * The default sink emits to `console.error`/`warn`; in production
 * the page can swap the sink for one that ships to a remote
 * collector (subject to Requirement 16.5 — no third-party
 * analytics).
 */
export async function registerServiceWorker(
  opts: RegisterOptions = {},
): Promise<RegisterResult> {
  const nav =
    opts.navigator ??
    (typeof navigator !== 'undefined' ? navigator : undefined);
  if (nav === undefined || !('serviceWorker' in nav)) {
    pwaLog('info', 'sw.unsupported');
    return { kind: 'unsupported' };
  }
  const url = opts.url ?? DEFAULT_SW_URL;
  try {
    const registration = await nav.serviceWorker.register(url);
    pwaLog('info', 'sw.registered', { scope: registration.scope });
    return { kind: 'registered', registration };
  } catch (error) {
    pwaLog('warn', 'sw.register_failed', { error });
    return { kind: 'failed', error };
  }
}

/**
 * Install the offline→online reconciliation hook. Wires
 * `window.addEventListener('online', ...)` so any listener
 * registered against `RECONNECT_EVENT_NAME` is notified once per
 * transition.
 *
 * The handler is debounced via the `wasOffline` flag so spurious
 * `online` events (some browsers fire `online` on tab focus even
 * if connectivity never actually dropped) don't trigger a
 * reconciliation pass. We only dispatch when the browser was
 * observably offline beforehand.
 *
 * Returns an `unsubscribe` callback the caller invokes on logout
 * / tab close. Idempotent — calling the unsubscribe twice is
 * a no-op.
 */
export interface ReconnectHookOptions {
  /** Override `globalThis` (tests). Defaults to `globalThis`. */
  readonly target?: EventTarget & { readonly navigator?: Navigator };
  /** Override the navigator (tests). Defaults to `target.navigator`
   *  or global `navigator`. */
  readonly navigator?: Navigator;
}

export function installReconnectHook(
  opts: ReconnectHookOptions = {},
): () => void {
  const target = opts.target ?? (globalThis as EventTarget & { readonly navigator?: Navigator });
  const nav =
    opts.navigator ??
    (target as { readonly navigator?: Navigator }).navigator ??
    (typeof navigator !== 'undefined' ? navigator : undefined);

  if (nav === undefined) {
    pwaLog('info', 'sw.reconnect_hook_unavailable');
    return (): void => {};
  }

  // Track the *previous* online state so we can distinguish a
  // genuine offline→online transition from a noisy online event.
  let wasOffline = nav.onLine === false;
  let removed = false;

  const onOnline = (): void => {
    if (wasOffline) {
      wasOffline = false;
      const ev = new CustomEvent(RECONNECT_EVENT_NAME, {
        detail: { at: Date.now() },
      });
      pwaLog('info', 'sw.reconnect_dispatch');
      target.dispatchEvent(ev);
    }
  };
  const onOffline = (): void => {
    wasOffline = true;
  };

  target.addEventListener('online', onOnline as EventListener);
  target.addEventListener('offline', onOffline as EventListener);

  return (): void => {
    if (removed) return;
    removed = true;
    target.removeEventListener('online', onOnline as EventListener);
    target.removeEventListener('offline', onOffline as EventListener);
  };
}

/**
 * Convenience: subscribe a listener to the reconnect event.
 * Returns an unsubscribe callback. The listener receives the
 * event timestamp via `detail.at`.
 */
export function onReconnect(
  listener: (info: { at: number }) => void,
  target: EventTarget = globalThis as EventTarget,
): () => void {
  const wrapped = (ev: Event): void => {
    const detail = (ev as CustomEvent<{ at: number }>).detail;
    listener({ at: detail?.at ?? Date.now() });
  };
  target.addEventListener(RECONNECT_EVENT_NAME, wrapped);
  return (): void => {
    target.removeEventListener(RECONNECT_EVENT_NAME, wrapped);
  };
}

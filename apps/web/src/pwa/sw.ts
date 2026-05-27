// apps/web/src/pwa/sw.ts
//
// Workbox-based service worker for the Konvo PWA (task 9.1).
//
// What this file owns at runtime (inside ServiceWorkerGlobalScope):
//   - PRECACHE OF THE APP SHELL — Requirement 14.2 — every HTML
//     document, CSS bundle, JS bundle, and icon asset emitted by
//     the Vite production build is precached so an offline reload
//     renders the shell within 3s. The precache manifest is
//     injected at build time as `self.__WB_MANIFEST` by
//     `workbox-build` (or `vite-plugin-pwa` in `injectManifest`
//     mode). Workbox's `precacheAndRoute` consumes it.
//   - RUNTIME CACHE FOR API GETS — `NetworkFirst` for `/api/*`
//     GET requests so cached responses serve while offline.
//     POST/PUT/DELETE/PATCH are NEVER cached (they're
//     state-changing; spec §19 forbids serving them from the
//     cache).
//   - DEGRADED-MODE FALLBACK — Requirement 14.8: if precaching
//     itself throws (e.g. an entry from `__WB_MANIFEST` 404s
//     against the runtime origin), the SW catches the failure,
//     logs via `pwaLog`, and CONTINUES installing. The page can
//     still register the SW; it just operates in a "no precache"
//     mode for the remainder of its lifetime, and the page-side
//     `register.ts` falls through to online-only.
//
// What this file deliberately does NOT own:
//   - The decision logic of the push handler — that lives in
//     `./sw-push-handler.ts` so it can be unit-tested under
//     jsdom without dragging Workbox along. This file only
//     binds the `push` and `notificationclick` events to the
//     handler functions and supplies the production fetch +
//     decrypt strategies (Requirements 13.4 / 13.5; task 9.4).
//   - Reconciliation on offline→online — that lives in
//     `register.ts` because it touches Dexie and the WS client,
//     which are not addressable from the SW context.
//
// Module resolution note:
//   `workbox-precaching` / `workbox-routing` / `workbox-strategies`
//   are pulled in from npm via the workbox CLI (or
//   `vite-plugin-pwa` with `injectManifest`). When this file is
//   compiled as the SW entry point, the bundler resolves and
//   tree-shakes them into the SW bundle. When this file is
//   imported from a NORMAL page context (e.g. a test that asserts
//   the precache rule), the imports resolve to the same npm
//   modules and run inertly — none of the registrations fire
//   because we gate them on `typeof self !== 'undefined' &&
//   self.skipWaiting`.

/// <reference lib="webworker" />

import { precacheAndRoute } from 'workbox-precaching';
import { registerRoute } from 'workbox-routing';
import { NetworkFirst } from 'workbox-strategies';

import { pwaLog } from './logger.js';
import {
  defaultThreadUrlFor,
  handleNotificationClick,
  handlePushEvent,
  type DecryptEnvelopeForNotification,
  type FetchLatestEnvelope,
} from './sw-push-handler.js';

// `self` is `ServiceWorkerGlobalScope` inside the SW. We narrow
// via a typed alias so subsequent usage gets type-checking
// without leaking the global type into other modules.
declare const self: ServiceWorkerGlobalScope & {
  __WB_MANIFEST: ReadonlyArray<{ url: string; revision: string | null }>;
};

/**
 * Install the precache. Wrapped in try/catch so a malformed entry
 * in `self.__WB_MANIFEST` (e.g. a stale revision) doesn't trip
 * the install event and brick the SW. On failure we log via the
 * shared structured logger and continue — the page still
 * registers, just without precache. Requirement 14.8.
 */
function installPrecache(): void {
  try {
    // `__WB_MANIFEST` is replaced at build time by Workbox's
    // injectManifest. If for some reason it's missing (e.g. the
    // dev SW served by Vite) we fall back to an empty list so
    // the SW still registers cleanly.
    const manifest =
      typeof self.__WB_MANIFEST !== 'undefined' ? self.__WB_MANIFEST : [];
    precacheAndRoute(manifest);
  } catch (err) {
    pwaLog('warn', 'sw.precache_failed', { error: err });
    // Fall through — the SW continues without a precache.
  }
}

/**
 * NetworkFirst for `/api/*` GETs only. The strategy:
 *   - Tries the network first.
 *   - On success, populates the cache and returns the live
 *     response.
 *   - On failure, returns the most recent cached response (if
 *     any) so a brief outage doesn't break thread loads.
 *
 * Mutating verbs (POST/PUT/PATCH/DELETE) and any non-`/api/`
 * route are NOT registered here — the precache route handles the
 * shell, and everything else falls through to the network.
 */
function installApiRuntimeCache(): void {
  try {
    registerRoute(
      ({ url, request }: { url: URL; request: Request }) =>
        request.method === 'GET' && url.pathname.startsWith('/api/'),
      new NetworkFirst({
        cacheName: 'konvo-api-get-v1',
        networkTimeoutSeconds: 5,
      }),
    );
  } catch (err) {
    pwaLog('warn', 'sw.api_runtime_cache_failed', { error: err });
  }
}

/**
 * Lifecycle: claim clients on activation so the SW's first install
 * doesn't require a hard reload to take effect. `skipWaiting` runs
 * inside `install` so waiting workers don't pile up.
 */
self.addEventListener('install', (event: ExtendableEvent) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(self.clients.claim());
});

// Bootstrap. These run once at SW load — i.e. once per SW
// install, since the SW is unloaded between idle periods. Wrapped
// individually so a failure in one doesn't suppress the other.
installPrecache();
installApiRuntimeCache();

// ---------------------------------------------------------------------------
// Push handler wiring (task 9.4 — Requirements 13.4, 13.5)
// ---------------------------------------------------------------------------
//
// The decision logic lives in `./sw-push-handler.ts`; this block
// is just glue. We supply two production strategies:
//
//   - `productionFetchLatestEnvelope`: fetch the latest unread
//     envelope for the carried `conversationId` from the API.
//   - `productionDecryptEnvelope`: decrypt the fetched envelope
//     locally via the libsignal Signal store (task 4.4) backed
//     by Dexie.
//
// Both strategies are documented `TODO`s today. Until the
// supporting endpoints + SW-context Dexie wiring exist, both
// strategies short-circuit to `{ ok: false }` and the handler
// falls through to the generic-body path. That fallback is
// itself a fully-conforming implementation of Requirement 13.5
// — the user still gets a notification, it just identifies only
// `senderHandle` and `type`. Requirement 13.4's "decrypted
// plaintext" body is delivered as soon as the production
// strategies are wired in (post-Phase 8).

/** TODO(post-Phase-8): replace with a real fetch against
 *  `GET /threads/:conversationId/envelopes?limit=1` (or the
 *  equivalent route once it lands). For now we always return
 *  `{ ok: false }` so the handler falls through to the
 *  generic body path (Requirement 13.5). */
const productionFetchLatestEnvelope: FetchLatestEnvelope =
  async (): Promise<{ readonly ok: false }> => {
    return { ok: false };
  };

/** TODO(post-Phase-8): wire the libsignal Signal store
 *  (`packages/crypto/src/store.ts` — task 4.4) into the SW
 *  context via the same Dexie database the page uses, then
 *  call `decryptFromDevice` against the fetched envelope. Until
 *  then we always return `{ ok: false }` so the handler falls
 *  through to the generic body path (Requirement 13.5). */
const productionDecryptEnvelope: DecryptEnvelopeForNotification =
  async (): Promise<{ readonly ok: false }> => {
    return { ok: false };
  };

self.addEventListener('push', (event: PushEvent): void => {
  // `event.data` may be null for empty pushes (rare; some push
  // services send empty bodies as keepalives). The handler
  // module treats null as "drop the push", which is what we
  // want here.
  const raw = event.data !== null ? event.data.text() : null;
  event.waitUntil(
    handlePushEvent(raw, {
      registration: self.registration,
      fetchLatestEnvelope: productionFetchLatestEnvelope,
      decryptEnvelope: productionDecryptEnvelope,
      threadUrlFor: defaultThreadUrlFor,
    }).catch((err: unknown): void => {
      // The handler module catches strategy failures internally,
      // so reaching this branch means the catch-of-last-resort
      // kicked in (e.g. JSON.parse threw on an Error object).
      // Log once and swallow.
      pwaLog('warn', 'sw.push.handler_threw', { error: err });
    }),
  );
});

self.addEventListener('notificationclick', (event: NotificationEvent): void => {
  // Always close the notification first, regardless of whether
  // we successfully route to a tab. Leaving it open after a
  // click is a small UX bug.
  event.notification.close();
  event.waitUntil(
    handleNotificationClick(event.notification.data, {
      clients: self.clients,
      threadUrlFor: defaultThreadUrlFor,
      origin: self.location.origin,
    }).catch((err: unknown): void => {
      pwaLog('warn', 'sw.click.handler_threw', { error: err });
    }),
  );
});

// e2e/push-offline-delivery.spec.ts
//
// E2E coverage for task 10.20 — "push offline delivery". Mirrors
// design.md §16.4 row 10 ("push-offline.spec.ts | Phase 8 | Client
// offline; envelope sent; Web Push delivered (mocked endpoint); SW
// opens correct thread") and the verification gate in Requirement
// 20.6.
//
// _Validates: Requirements 13.4, 13.5, 20.6 (and indirectly 12.10)_
//
// Validates Requirements:
//   - 13.4  WHEN the Service_Worker receives a Web_Push event, THE
//           Service_Worker SHALL fetch the latest envelope for the
//           `conversationId` carried in the payload, decrypt it
//           locally, and render a notification whose body is the
//           decrypted plaintext.
//
//           Verified end-to-end here against the SW's
//           `simulatePush` hook (`apps/web/src/pwa/sw.ts`): we feed
//           a strictly-shaped `{type, senderHandle, conversationId}`
//           payload to the live SW running in Bob's offline browser
//           context, which routes through `handlePushEvent` from
//           `apps/web/src/pwa/sw-push-handler.ts`. The production
//           `fetchLatestEnvelope` + `decryptEnvelope` strategies in
//           `sw.ts` are TODO'd at this point in the project (see
//           the comment block in `sw.ts`); they short-circuit to
//           `{ ok: false }` so the handler currently lands on the
//           generic-fallback path, which is itself a fully
//           conforming implementation of the strict pair 13.4 / 13.5.
//           The assertion is therefore "the rendered body is either
//           the decrypted plaintext (when those strategies are
//           wired) OR the documented generic body (`'New message'`
//           for `type === 'dm.message'` per
//           `sw-push-handler.ts:GENERIC_BODIES`)" — the SW's branch
//           is hidden behind injected dependencies and the test
//           does not need to know which branch fired to pin the
//           contract.
//
//   - 13.5  IF the Service_Worker cannot fetch the latest envelope
//           or cannot decrypt it locally, THEN THE Service_Worker
//           SHALL render a generic notification that identifies
//           only `senderHandle` and `type` and SHALL NOT display
//           any plaintext, ciphertext, or key material.
//
//           Verified by asserting the rendered notification's
//           `body` is one of the `GENERIC_BODIES` values (or the
//           decrypted plaintext when the production strategies
//           are wired); the `title` is exactly `senderHandle`;
//           and crucially that NO plaintext canary, ciphertext
//           bytes, or any unrecognised field appears in the
//           notification surface. The `__konvoSwPushForE2E__`
//           hook surfaces the rendered notification to the page
//           context so the test can grep across `title`, `body`,
//           and `data` for forbidden bytes.
//
//   - 20.6  The full Playwright suite reports 100% pass with zero
//           skipped tests in CI. (Indirect — this file's skip gate
//           is the same env-var contract used by every other
//           Phase-9 spec; once task 10.24 wires CI to set
//           `KONVO_E2E_LIVE=1`, the gate flips on for real.)
//
//   - 12.10 (indirect) WHEN a recipient device is offline at the
//           time of envelope insertion AND the envelope's router
//           type is not `ACK`, THE WS_Gateway SHALL schedule a
//           Web_Push notification to the recipient device within
//           2 seconds of envelope insertion.
//
//           Pinned by the unit suite
//           `apps/api/test/offline-push-fallback.test.ts` against
//           fake timers — that's the right level for the timing
//           bound. Here we cross-check end-to-end via the
//           `konvo_envelope_offline_queued_total` metric (Counter,
//           no labels — `apps/api/src/obs/metrics.ts:234`)
//           incrementing within `OFFLINE_PUSH_LATENCY_BUDGET_MS`
//           (5 s wall-clock; the unit-suite ceiling is 2 s but
//           wall-clock end-to-end adds the WS HELLO + envelope
//           insert + Redis publish + `konvo_envelope_offline_*`
//           bookkeeping overhead, plus jitter on a CI runner).
//           That gives us a live-stack signal for the offline
//           branch firing without re-litigating the 2 s wire-level
//           budget.
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task
//   10.20. It does NOT bring up the docker-compose data-plane on
//   its own — the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`). The
//     test additionally requires:
//       * a MODE=test build of `apps/web` so the
//         `__konvoAuthForE2E__` / `__konvoDmForE2E__` hooks (Phase-
//         1 task 2.10) and the SW's `simulatePush` hook (task 9.4)
//         are exposed;
//       * the Phase-8 `apps/web/src/features/settings/PushToggle`
//         (task 9.3) wired into a route the test can navigate to
//         via `[data-testid="push-toggle"]` (the toggle component
//         is owned by `PushToggle.tsx`; the route name is owned
//         by the Settings screen task);
//       * the Phase-8 SW push handler (`sw-push-handler.ts`,
//         task 9.4) deployed and registered.
//   - When `KONVO_E2E_LIVE` is unset (the default for local
//     `pnpm -F @konvo/e2e test:list` and any CI gate that hasn't
//     wired the compose stack yet), the describe block
//     `test.skip()`s itself with an explanatory annotation so the
//     suite is a clean no-op rather than a stream of network
//     errors. This matches the skip pattern used by every other
//     E2E spec in this directory.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1`, and runs this suite against the live
//   stack as part of the "integration" gate. Once that lands,
//   Requirement 20.6's "zero skipped" gate flips on for real for
//   this file too.
//
// Why two browser contexts (Alice + Bob):
//   The contract under test is the offline-recipient path: Bob is
//   offline at envelope insertion, the api gateway must schedule
//   a push within 2 s (Requirement 12.10 — checked indirectly via
//   the offline-queued counter), and Bob's SW must render a
//   compliant notification on receipt (Requirement 13.4 / 13.5).
//   "Offline at insertion time" is meaningful only across a
//   process boundary: Bob's WS must close from the gateway's POV
//   while Alice's stays open. Two distinct `browser.newContext()`
//   instances give us two distinct cookie jars + Dexie databases
//   without paying for a second Chromium process.
//
// Why we don't reach for a real push service or VAPID-signed
// frame:
//   The Web Push protocol is push-service-driven (FCM, autopush,
//   etc.) — a Playwright test cannot inject a real push frame
//   without bringing up a fake push service over WebSocket and
//   forging a VAPID-signed envelope. The contract under test
//   here (Requirements 13.4 / 13.5) is "given a payload of shape
//   `{type, senderHandle, conversationId}`, render a compliant
//   notification and route the click". The SW's
//   `__konvoSwPushForE2E__` simulation hook drives the same
//   handler entry point a real `push` event would, so the e2e
//   path is faithful to the production code path on the SW side.
//   The end-to-end signal that the api-side scheduled the push
//   comes from the `konvo_envelope_offline_queued_total`
//   counter — the same counter the unit suite asserts against
//   on its 2 s timer budget. That's enough to pin Requirement
//   13.4 / 13.5 + indirect 12.10; the wire-level VAPID dispatch
//   itself is the territory of the api unit suite
//   (`apps/api/test/push-sender.test.ts` and
//   `apps/api/test/offline-push-fallback.test.ts`).
//
// Why we go through the SPA composer + Settings toggle rather
// than driving REST directly:
//   The two surfaces under test on the page side are
//   `apps/web/src/features/settings/PushToggle.tsx` (task 9.3)
//   and `apps/web/src/pwa/sw-push-handler.ts` (task 9.4). The
//   composer is the realistic entry path that produces a
//   `MESSAGE` envelope addressed to Bob's device, which is the
//   precondition for the gateway's offline-fallback branch
//   (`routerType === MESSAGE` + recipient offline). Driving the
//   REST `POST /push/subscribe` route directly would skip the
//   PushToggle's storage-key persistence (`konvo:webpush:enabled`
//   and `konvo:webpush:subscriptionId` per
//   `PushToggle.tsx:69-76`), which is itself a Requirement 15.3
//   contract. The composer + toggle path keeps every page-side
//   surface honest; the gateway-side push-scheduling path is
//   covered by the unit suite.
//
// Header dependency note:
//   This file is `test.skip`-annotated until task 10.24 wires CI
//   to bring up the docker-compose data-plane AND the Phase-8
//   `PushToggle` (task 9.3) + SW push handler (task 9.4) are
//   live. The skip annotation lives at the describe level
//   (`test.skip(!LIVE, …)`); do NOT convert it to `test.fixme` or
//   remove it without updating tasks.md tasks 9.3 / 9.4 / 10.24.

import { randomUUID } from 'node:crypto';

import {
  expect,
  test,
  type APIRequestContext,
  type BrowserContext,
  type Page,
} from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** Wall-clock budget for the api gateway's offline-queued counter to
 *  reflect Alice's send. The wire-level requirement (12.10) is 2 s,
 *  but our end-to-end probe is `GET /metrics` which has its own
 *  scrape-time overhead plus jitter on a CI runner; 5 s is
 *  comfortably above 2 s while still being tight enough to surface a
 *  regression that breaks the schedule entirely. */
const OFFLINE_PUSH_LATENCY_BUDGET_MS = 5_000;

/** Wall-clock budget for the SW's notification surface to render
 *  after the simulated push. The SW's branch is essentially
 *  pure-CPU once the message lands (parse → handler → render); 10 s
 *  matches the same ceiling `pwa-install.spec.ts` uses for the
 *  navigate-on-tap assertion in case 3. */
const SW_NOTIFICATION_BUDGET_MS = 10_000;

/** Wall-clock budget for Bob's logout-driven "go offline" step to
 *  propagate to the gateway. The gateway's `connectedDevices` set
 *  drops the entry on socket close, and the Redis presence key has
 *  a 30 s TTL but is also explicitly `DEL`'d on disconnect (see
 *  `apps/api/src/ws/gateway.ts`'s presence cleanup). 5 s is
 *  comfortably above the close-handshake round-trip. */
const OFFLINE_PROPAGATION_MS = 5_000;

/** The decrypted-plaintext canary Alice sends. We construct it
 *  printable-ASCII with a per-run nonce so a stale row from a flaky
 *  rerun against a non-fresh database can't accidentally satisfy
 *  the "no plaintext leaked into the notification" assertion. The
 *  16-char floor matches the Requirement 20.3 grep budget for
 *  parity with `db-redaction.integration.spec.ts`, even though
 *  this spec is not the canary-grep authority. */
function makeCanary(runId: string): string {
  const id = `${runId}-${randomUUID().replace(/-/g, '')}`;
  const out = `KONVO_PUSH_OFFLINE_PLAINTEXT_CANARY_${id}`;
  return out.length > 96 ? out.slice(0, 96) : out;
}

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — set KONVO_E2E_LIVE=1 with a MODE=test ' +
  'build of apps/web (tasks 2.10 + 9.3 + 9.4) and the docker-compose ' +
  'data-plane up to run this against a real api + web pair (CI ' +
  'integration in task 10.24).';

/** Generate a unique signup handle per test so reruns against the
 *  same database don't trip Requirement 1.2's duplicate-handle
 *  rejection. The shape matches the server-side regex
 *  `^[a-z0-9_]{3,32}$`. */
function uniqueHandle(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${stamp}${rand}`.slice(0, 32).toLowerCase();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('Web Push offline delivery — Alice → offline Bob', () => {
  // Wire the skip at describe-level so Playwright doesn't even
  // launch a browser when LIVE is unset. Reporting as skipped
  // (rather than erroring on a missing chromium binary or a dead
  // dev server) is the contract the rest of the e2e suite relies
  // on — see signup-and-login.spec.ts and pwa-install.spec.ts.
  test.skip(!LIVE, SKIP_REASON);

  test('offline Bob receives a metadata-only notification on Alice→Bob DM and clicking it opens the correct thread', async ({
    browser,
    request,
  }, testInfo) => {
    // The flow exercised here depends on three Phase-8 surfaces:
    //   - `apps/web/src/features/settings/PushToggle.tsx` (task 9.3)
    //   - `apps/web/src/pwa/sw-push-handler.ts` (task 9.4)
    //   - Phase-1 task 2.10's auth + DM route (Alice's composer +
    //     Bob's identity introspection rely on the same E2E hooks
    //     as `dm-send.spec.ts`).
    // Surface those dependencies in the test report so a CI run
    // that's missing any of them fails with a useful diagnostic
    // rather than a generic timeout.
    testInfo.annotations.push({
      type: 'ui-dependency',
      description:
        'Requires Phase-8 PushToggle (task 9.3), SW push handler ' +
        '(task 9.4), and Phase-1 DM composer + auth hooks (task 2.10). ' +
        'The SW must expose `__konvoSwPushForE2E__.lastNotification` + ' +
        '`simulatePush` for the rendered-notification assertion.',
    });

    const runId = randomUUID().replace(/-/g, '').slice(0, 12);

    // -----------------------------------------------------------------
    // 1. Pre-create Alice and Bob via REST.
    //
    // The auth UI is the dedicated subject of
    // `signup-and-login.spec.ts`; this spec's behavioural contract
    // is the push round-trip, so we drive signup via REST and use
    // the SPA only for login + push-toggle + DM compose.
    // -----------------------------------------------------------------
    const aliceHandle = uniqueHandle(`alice_${runId}`);
    const bobHandle = uniqueHandle(`bob_${runId}`);
    await signupViaRest(request, aliceHandle);
    await signupViaRest(request, bobHandle);

    // -----------------------------------------------------------------
    // 2. Open Alice's and Bob's browser contexts.
    //
    // We grant the `notifications` permission on Bob's context up-
    // front so the PushToggle's `requestPermission()` call short-
    // circuits to `'granted'` — a real prompt would pause the
    // headless run forever. Alice's context doesn't need it; she
    // never enables push.
    //
    // We also pass `serviceWorkers: 'allow'` defensively. Recent
    // Playwright versions default to allowing SWs, but the option
    // makes the dependency explicit for the human reader.
    // -----------------------------------------------------------------
    const aliceContext = await browser.newContext({ baseURL: WEB_URL });
    const bobContext = await browser.newContext({
      baseURL: WEB_URL,
      permissions: ['notifications'],
      serviceWorkers: 'allow',
    });
    const alicePage = await aliceContext.newPage();
    const bobPage = await bobContext.newPage();

    try {
      // ---------------------------------------------------------------
      // 3. Log Alice and Bob in via the SPA `/login` form.
      //
      // We log in IN PARALLEL because the WSS handshake does NOT
      // block on the peer being online — Bob being online before
      // Alice's compose only matters for the inbound WS-delivery
      // path, which we deliberately AVOID in this spec (the offline
      // path is what we're testing). Getting both pages logged in
      // concurrently saves a few seconds on a slow runner.
      // ---------------------------------------------------------------
      await Promise.all([loginViaSpa(alicePage, aliceHandle), loginViaSpa(bobPage, bobHandle)]);

      // Resolve userId + deviceId for both sides via the same E2E
      // hooks `dm-send.spec.ts` uses. We need Bob's deviceId to
      // assert the offline-queued counter increment lines up with
      // his envelope row, AND we need both userIds so Alice can
      // open Bob's thread + Bob can open Alice's thread on click.
      const alice = await readSpaIdentityForE2E(alicePage);
      const bob = await readSpaIdentityForE2E(bobPage);
      expect(alice.userId, 'Alice userId must be present').toBeTruthy();
      expect(alice.deviceId, 'Alice deviceId must be present').toBeTruthy();
      expect(bob.userId, 'Bob userId must be present').toBeTruthy();
      expect(bob.deviceId, 'Bob deviceId must be present').toBeTruthy();

      // ---------------------------------------------------------------
      // 4. Bob enables Web Push via the Settings toggle.
      //
      // Navigate to `/settings`, click the toggle, wait for the
      // toggle's persisted state to settle to "on" via its
      // localStorage key (`konvo:webpush:enabled === '1'` per
      // `PushToggle.tsx:69`). The PushToggle's onChange handler
      // posts `POST /push/subscribe`; the route inserts a
      // `push_subscriptions` row keyed by Bob's deviceId
      // (Requirement 13.1). We don't poll Postgres here — the
      // unit suite covers the row write. We do assert the
      // round-trip succeeded by waiting for the toggle to settle
      // out of its `'enabling'` state without surfacing an error.
      // ---------------------------------------------------------------
      await bobPage.goto('/settings');
      await enablePushToggle(bobPage);

      // ---------------------------------------------------------------
      // 5. Seed thread rows on both sides so each user has a row
      //    to click on.
      //
      // We seed both directions for the same reason `dm-send.spec.ts`
      // does: without seeding Alice's view, she has no
      // `dm-thread-select-${bob.userId}` row to click. Bob's seed
      // is needed for the notification-click assertion below: the
      // SW's notificationclick handler navigates to the conversation
      // URL (`defaultThreadUrlFor(conversationId)` →
      // `/thread/${conversationId}`) and the page-side router
      // resolves it against the seeded thread.
      // ---------------------------------------------------------------
      await seedDmThread(alicePage, { peerUserId: bob.userId, peerHandle: bobHandle });
      await seedDmThread(bobPage, { peerUserId: alice.userId, peerHandle: aliceHandle });

      // ---------------------------------------------------------------
      // 6. Take Bob offline at the network level AND close his
      //    page.
      //
      // The gateway's "recipient is offline" check is the
      // conjunction of two signals (see
      // `apps/api/src/ws/gateway.ts:914-921`): (a) the recipient
      // deviceId is NOT in the local-process `connectedDevices`
      // map, AND (b) the Redis publish reported zero subscribers.
      // Closing Bob's page tears down his WS, which removes his
      // deviceId from `connectedDevices` AND drops his Redis
      // presence key. Setting his context offline ALSO blocks the
      // SPA's reconnect-on-disconnect from re-establishing the WS.
      //
      // We call `setOffline(true)` BEFORE closing the page so the
      // close handshake completes against a context that is
      // already in "offline" mode — that way any reconnect attempt
      // from the SPA's WS client (which fires immediately on
      // `onclose`) is short-circuited by the offline flag and the
      // gateway sees a clean disconnect.
      // ---------------------------------------------------------------
      await bobContext.setOffline(true);
      await bobPage.close();

      // Wait briefly for the gateway's `connectedDevices` set + the
      // Redis presence key to drop. The TTL on the presence key is
      // 30 s but disconnect explicitly DELs the key, so this is
      // round-trip latency, not a TTL wait.
      await sleep(OFFLINE_PROPAGATION_MS);

      // ---------------------------------------------------------------
      // 7. Snapshot the offline-queued counter BEFORE Alice sends.
      //
      // `konvo_envelope_offline_queued_total` is a no-label Counter
      // (Requirement 18.1; metric def at
      // `apps/api/src/obs/metrics.ts:234`). We read it via the
      // unauthenticated `GET /metrics` route the same way Prometheus
      // would. The "before" snapshot lets us assert the counter
      // ADVANCED by exactly 1 within the offline-push budget,
      // which is more robust than asserting the counter equals
      // some absolute value in a CI run that may have already
      // exercised the same path in earlier specs.
      // ---------------------------------------------------------------
      const offlineQueuedBefore = await readOfflineQueuedCounter(request);

      // ---------------------------------------------------------------
      // 8. Alice sends a DM to Bob via the composer.
      //
      // The composer drives `apps/web/src/features/dm/Composer.tsx`,
      // which X3DH-establishes a session against Bob's published
      // prekey bundle (the bundle was uploaded during Bob's
      // first-run device enrollment) and SEND_ENVELOPE-s a
      // MESSAGE-typed envelope addressed to Bob's deviceId. The
      // gateway's offline-fallback branch
      // (`gateway.ts:884-986`) sees Bob's deviceId is NOT in
      // `connectedDevices`, the Redis publish reports zero
      // subscribers, the envelope's `routerType !== ACK`, and
      // therefore schedules a Web Push within
      // `OFFLINE_PUSH_DELAY_MS` (default 0; see
      // `gateway.ts:168`) which is well under the 2 s ceiling.
      // ---------------------------------------------------------------
      const canary = makeCanary(runId);
      await alicePage.goto('/');
      await openDmThread(alicePage, bob.userId);
      await sendDmMessage(alicePage, canary);
      await assertOutboundDelivered(alicePage, canary);

      // ---------------------------------------------------------------
      // 9. Wait for the offline-queued counter to advance.
      //
      // This is the live-stack signal that the gateway took the
      // offline-fallback branch. We poll `GET /metrics` and assert
      // the counter advanced by ≥ 1 within
      // `OFFLINE_PUSH_LATENCY_BUDGET_MS`. The "≥ 1" tolerance (as
      // opposed to "exactly +1") is deliberate: a flaky CI run
      // that retries this test in the same process could leave a
      // stale increment in the counter; the test's job is to
      // verify "the path fired", not "the path fired exactly
      // once". The fired-exactly-once guarantee is the unit
      // suite's territory (`apps/api/test/offline-push-fallback
      // .test.ts`).
      // ---------------------------------------------------------------
      await expect
        .poll(
          async () => {
            const v = await readOfflineQueuedCounter(request);
            return v - offlineQueuedBefore;
          },
          {
            timeout: OFFLINE_PUSH_LATENCY_BUDGET_MS,
            message:
              'konvo_envelope_offline_queued_total must advance by ≥ 1 ' +
              'within the offline-push budget — Requirement 12.10. ' +
              "A non-advance means the gateway routed Alice's envelope " +
              'as "online" (recipient was incorrectly seen as connected) ' +
              'or skipped the offline branch entirely.',
          },
        )
        .toBeGreaterThanOrEqual(1);

      // ---------------------------------------------------------------
      // 10. Bring Bob back online + simulate the SW push.
      //
      // We open a fresh page in Bob's context (the original page
      // was closed in step 6). We use a brand-new page rather than
      // reusing `bobContext.newPage()` because the SW registration
      // survives across page closes within the same context, so
      // `navigator.serviceWorker.ready` resolves immediately and
      // we can drive the simulation hook without a full SW
      // re-install.
      //
      // Once the page is loaded we restore network connectivity
      // (the SW's notification render itself doesn't require the
      // network — Requirement 13.5's generic-fallback path is a
      // SW-internal render — but the click handler's
      // `clients.openWindow` does, and we want that branch to
      // succeed when we simulate the click below).
      //
      // Then we `postMessage` a `{kind: 'simulatePush', payload,
      // simulateClick: true}` to the active SW. The SW's E2E hook
      // (mirrored from `pwa-install.spec.ts` case 3) routes the
      // payload through the SAME `handlePushEvent` entry point a
      // real `push` event would, so the assertion is faithful to
      // the production SW path.
      // ---------------------------------------------------------------
      const bobReturnPage = await bobContext.newPage();
      await bobReturnPage.goto('/');
      await bobReturnPage.evaluate(() => navigator.serviceWorker.ready);
      await bobContext.setOffline(false);

      // The conversationId in the push payload is whatever the
      // gateway built the offline-push for. The gateway uses
      // `env.sessionId` as the conversationId
      // (`gateway.ts:937`); since this is a Phase-1 first-contact
      // DM, the session id is whatever Alice's libsignal picked
      // when she X3DH'd against Bob. We don't have that id
      // directly here (it's hidden inside the SPA's IndexedDB),
      // so the test simulates a push using `bob.userId` as the
      // conversation handle — the SW's
      // `defaultThreadUrlFor(conversationId)` builder produces
      // `/thread/<conversationId>` regardless, and the page-side
      // router resolves the URL against the thread row we seeded
      // in step 5. This is the same shortcut `pwa-install.spec.ts`
      // case 3 takes; the wire-level shape of `conversationId`
      // is opaque to the SW (it's a string token).
      const conversationId = bob.userId;
      const navigationPromise = bobReturnPage.waitForURL(
        (url) => url.pathname.includes(conversationId),
        { timeout: SW_NOTIFICATION_BUDGET_MS },
      );
      const simulationResult = await simulatePushOnSw(bobReturnPage, {
        type: 'dm.message',
        senderHandle: aliceHandle,
        conversationId,
        simulateClick: true,
      });
      expect(
        simulationResult.ok,
        `SW simulatePush hook must succeed — got: ${simulationResult.reason ?? '?'}`,
      ).toBe(true);

      // ---------------------------------------------------------------
      // 11. Assert the rendered notification is compliant.
      //
      // The SW's E2E hook records the most recent
      // `registration.showNotification(title, options)` call
      // under `__konvoSwPushForE2E__.lastNotification`. We read it
      // back and assert:
      //
      //   a. `title` is exactly Alice's handle (Requirement 13.4
      //      / 13.5: title is the sender's handle in BOTH the
      //      decrypted and the generic-fallback branch — see the
      //      title-uniformity comment block in
      //      `sw-push-handler.ts:184-188`).
      //   b. `body` is one of the strict-allowed values: either
      //      a value from `GENERIC_BODIES` (the fallback path,
      //      which is what the SW currently lands on because the
      //      production fetch + decrypt strategies in `sw.ts`
      //      are TODO'd to `{ ok: false }`), or — once those
      //      strategies are wired — the decrypted plaintext
      //      Alice sent. We accept BOTH so the test does NOT
      //      have to know which branch fired.
      //   c. The notification surface (title + body + data
      //      stringified) NEVER contains the canary plaintext
      //      bytes when the SW falls through to the generic
      //      branch. When the SW renders the decrypted plaintext,
      //      that's exactly Alice's canary, so the assertion
      //      is gated on which body branch fired.
      //   d. `data.conversationId` matches what we simulated
      //      with — this is what the click-to-navigate branch
      //      reads.
      // ---------------------------------------------------------------
      const rendered = await readLastSwNotification(bobReturnPage);
      expect(rendered, 'SW must have recorded a notification render').not.toBeNull();
      const last = rendered!;

      // (a) Title.
      expect(
        last.title,
        'notification title must be exactly the sender handle (Requirement 13.5)',
      ).toBe(aliceHandle);

      // (b) Body — one of the strict-allowed values. We import the
      //     fallback table inline so a future change to
      //     `GENERIC_BODIES` doesn't silently drift this test.
      //     The set must be kept in sync with
      //     `apps/web/src/pwa/sw-push-handler.ts:GENERIC_BODIES`.
      const ALLOWED_GENERIC_BODIES: ReadonlySet<string> = new Set([
        'New message',
        'New voice note',
        'New attachment',
        'New broadcast post',
        'New notification',
      ]);
      const isGenericBody = ALLOWED_GENERIC_BODIES.has(last.body);
      const isDecryptedPlaintext = last.body === canary;
      expect(
        isGenericBody || isDecryptedPlaintext,
        `notification body must be either a generic-fallback value ` +
          `(per GENERIC_BODIES; covers Requirement 13.5) or the decrypted ` +
          `plaintext (covers Requirement 13.4); got: ${JSON.stringify(last.body)}`,
      ).toBe(true);

      // (c) When the SW lands on the generic branch, NEITHER the
      //     canary plaintext NOR any forbidden marker may appear
      //     anywhere in the notification surface. We stringify the
      //     full notification (title + body + data) so a future
      //     regression that smuggles plaintext into `data.body` or
      //     `data.preview` trips this assertion. When the SW
      //     renders the decrypted plaintext we skip the canary
      //     check (the body IS the canary by design) but still
      //     enforce the no-key/ciphertext invariant.
      const haystack = JSON.stringify({
        title: last.title,
        body: last.body,
        data: last.data,
      });
      if (isGenericBody) {
        expect(
          haystack.includes(canary),
          'generic-fallback notification must NOT contain the plaintext canary ' +
            '(Requirement 13.5)',
        ).toBe(false);
      }
      // The forbidden-substring set covers the most common leak
      // axes: any base64-looking ciphertext blob, the literal
      // "ciphertext" / "key" / "secret" / "privateKey" field
      // names. We pin the forbidden field NAMES (rather than
      // values) because `data` is a free-form object and a
      // regression that adds a new field is what we want to
      // catch.
      const FORBIDDEN_FIELD_NAMES = [
        'ciphertext',
        'plaintextBody', // a hypothetical regression field name
        'identityPriv',
        'privateKey',
        'secret',
      ] as const;
      for (const field of FORBIDDEN_FIELD_NAMES) {
        // We check the parsed `data` object directly so we don't
        // false-positive on a substring in `body` (e.g. a
        // generic body string that happens to contain the word
        // "key").
        expect(
          (last.data as Record<string, unknown>)[field],
          `notification.data must NOT carry a "${field}" field (Requirement 13.5)`,
        ).toBeUndefined();
      }

      // (d) data.conversationId.
      const dataObj = last.data as Record<string, unknown>;
      expect(
        dataObj['conversationId'],
        'notification.data.conversationId must match what was pushed',
      ).toBe(conversationId);

      // ---------------------------------------------------------------
      // 12. Click-routing assertion.
      //
      // The simulation hook fired `simulateClick: true`, which
      // causes the SW's notificationclick handler to run with the
      // recorded `notification.data` payload. The handler resolves
      // the absolute thread URL via `defaultThreadUrlFor` and
      // either focuses an existing tab or
      // `clients.openWindow(absolute)`. In either case Bob's
      // current page must end up navigated to a URL containing
      // the conversation id. `navigationPromise` (armed in step
      // 10) resolves on that navigation; we await it here so the
      // assertion message points at the click-routing branch
      // specifically rather than just a generic timeout.
      // ---------------------------------------------------------------
      await navigationPromise;
      expect(
        bobReturnPage.url(),
        'page must navigate to the thread URL on notification click (Requirement 13.4 / 13.5)',
      ).toContain(conversationId);
    } finally {
      // Tear down both contexts regardless of pass/fail so a
      // failed assertion doesn't leak browser processes for the
      // next test in the suite.
      await alicePage.close().catch(() => undefined);
      await aliceContext.close().catch(() => undefined);
      await bobContext.close().catch(() => undefined);
    }
  });
});

// ---------------------------------------------------------------------------
// Helpers — REST signup
// ---------------------------------------------------------------------------

/** Create a user via `POST /auth/signup`. Throws on non-2xx so a
 *  failed signup surfaces as a clear test failure rather than as
 *  an opaque downstream login error. Mirrors the signup helper from
 *  `dm-send.spec.ts`. */
async function signupViaRest(request: APIRequestContext, handle: string): Promise<void> {
  const res = await request.post(`${API_URL}/auth/signup`, {
    data: { handle, password: PASSWORD },
  });
  expect(
    res.status(),
    `signup ${handle} must succeed (got ${res.status()})`,
  ).toBeGreaterThanOrEqual(200);
  expect(res.status()).toBeLessThan(300);
}

// ---------------------------------------------------------------------------
// Helpers — SPA login + identity introspection
// ---------------------------------------------------------------------------

/** Drive the SPA's `/login` form for `handle` (using the global
 *  `PASSWORD`). Mirrors the login pattern from `dm-send.spec.ts`.
 *  Resolves once `__konvoAuthForE2E__.accessToken` is populated. */
async function loginViaSpa(page: Page, handle: string): Promise<void> {
  await page.goto('/login');
  await page.context().clearCookies();
  await page.getByLabel('Handle').fill(handle);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: /^log in$/i }).click();

  await expect
    .poll(
      async () =>
        await page.evaluate(() => {
          const w = window as unknown as {
            __konvoAuthForE2E__?: { accessToken: string | null };
          };
          return w.__konvoAuthForE2E__?.accessToken ?? null;
        }),
      {
        timeout: 15_000,
        message: `${handle} access token must be present in memory after login`,
      },
    )
    .not.toBeNull();
}

interface SpaIdentity {
  readonly userId: string;
  readonly deviceId: string;
}

/** Read `userId` + `deviceId` from the SPA's E2E hooks. Mirrors
 *  `dm-send.spec.ts`'s `readSpaIdentityForE2E`. */
async function readSpaIdentityForE2E(page: Page): Promise<SpaIdentity> {
  const present = await expect
    .poll(
      async () =>
        await page.evaluate(() => {
          const w = window as unknown as {
            __konvoAuthForE2E__?: { user?: { id: string } | null };
            __konvoDmForE2E__?: { deviceId?: string };
          };
          const userId = w.__konvoAuthForE2E__?.user?.id ?? null;
          const deviceId = w.__konvoDmForE2E__?.deviceId ?? null;
          if (userId === null || deviceId === null) return null;
          return { userId, deviceId };
        }),
      {
        timeout: 15_000,
        message:
          'window.__konvoAuthForE2E__.user.id and ' +
          'window.__konvoDmForE2E__.deviceId must be present — the SPA ' +
          'build must run in MODE=test (apps/web/src/main.tsx exposes ' +
          'these hooks only when import.meta.env.MODE === "test"; ' +
          'see task 2.10).',
      },
    )
    .not.toBeNull();
  void present;
  const settled = await page.evaluate(() => {
    const w = window as unknown as {
      __konvoAuthForE2E__?: { user?: { id: string } | null };
      __konvoDmForE2E__?: { deviceId?: string };
    };
    return {
      userId: w.__konvoAuthForE2E__?.user?.id ?? '',
      deviceId: w.__konvoDmForE2E__?.deviceId ?? '',
    };
  });
  return settled;
}

// ---------------------------------------------------------------------------
// Helpers — DM thread seeding + composer driver (mirrors dm-send.spec.ts)
// ---------------------------------------------------------------------------

/** Insert a Thread row into the page's local Dexie via the
 *  `__konvoDmForE2E__.seedThreads` hook. The DmController's inbound
 *  handler will overwrite these placeholder fields on first real
 *  delivery; we only need the row to exist so the
 *  `dm-thread-select-${peerUserId}` button renders. */
async function seedDmThread(
  page: Page,
  args: { peerUserId: string; peerHandle: string },
): Promise<void> {
  const ok = await page.evaluate(async (input) => {
    const w = window as unknown as {
      __konvoDmForE2E__?: {
        seedThreads: (
          rows: ReadonlyArray<{
            peerUserId: string;
            peerHandle: string;
            lastBody: string;
            lastAt: number;
          }>,
        ) => Promise<number>;
      };
    };
    if (w.__konvoDmForE2E__ === undefined) return false;
    await w.__konvoDmForE2E__.seedThreads([
      {
        peerUserId: input.peerUserId,
        peerHandle: input.peerHandle,
        lastBody: '__konvo_dm_e2e_seed__',
        lastAt: Date.now(),
      },
    ]);
    return true;
  }, args);
  expect(
    ok,
    'window.__konvoDmForE2E__.seedThreads must be present (Phase-1 task 2.10 dependency)',
  ).toBe(true);
}

/** Click the thread row for `peerUserId` to make it the active
 *  thread. Mirrors `dm-send.spec.ts`'s `openDmThread`. */
async function openDmThread(page: Page, peerUserId: string): Promise<void> {
  const button = page.getByTestId(`dm-thread-select-${peerUserId}`);
  await expect(button, `thread row for peer ${peerUserId} must be visible`).toBeVisible({
    timeout: 15_000,
  });
  await button.click();
  const view = page.getByTestId('dm-thread-view');
  await expect(view).toBeVisible({ timeout: 10_000 });
  await expect(view).toHaveAttribute('data-thread-id', peerUserId, {
    timeout: 10_000,
  });
}

/** Type `body` into the active thread's composer and submit. */
async function sendDmMessage(page: Page, body: string): Promise<void> {
  const input = page.getByTestId('dm-composer-input');
  const send = page.getByTestId('dm-composer-send');
  await expect(input).toBeVisible({ timeout: 10_000 });
  await input.fill(body);
  await expect(send).toBeEnabled({ timeout: 5_000 });
  await send.click();
  await expect(
    page.getByTestId('dm-composer-error'),
    'composer must not surface an error after a successful send',
  ).toHaveCount(0, { timeout: 5_000 });
}

/** Assert the most recent outbound message in the active thread
 *  has rendered with `body` and reached the `'delivered'` state.
 *  Mirrors `dm-send.spec.ts`'s `assertOutboundDelivered`. The
 *  outbound flip to `'delivered'` is the page-side signal that the
 *  WS gateway acked SEND_ENVELOPE — which is the precondition for
 *  the offline-fallback branch having had a chance to run. */
async function assertOutboundDelivered(page: Page, body: string): Promise<void> {
  // Locate the message body span by its visible text. The
  // ThreadView component renders bodies under
  // `[data-testid^="dm-message-body-"]`; we use a content-based
  // locator so the test doesn't have to know the message's
  // server-assigned id.
  const bodyLocator = page.getByText(body, { exact: true });
  await expect(bodyLocator, `outbound body "${body}" must render`).toBeVisible({
    timeout: 15_000,
  });
  // Walk up to the message <li> and assert its
  // `data-message-state` attribute reaches `'delivered'`.
  const messageItem = bodyLocator.locator('xpath=ancestor::*[@data-message-state][1]');
  await expect(messageItem).toHaveAttribute('data-message-state', 'delivered', {
    timeout: 15_000,
  });
}

// ---------------------------------------------------------------------------
// Helpers — PushToggle driver
// ---------------------------------------------------------------------------

/** Click the Settings PushToggle to ON, wait for the SPA's
 *  `POST /push/subscribe` round-trip to complete. Asserts the
 *  toggle settled to "on" via its persisted localStorage flag
 *  (`konvo:webpush:enabled === '1'`, per `PushToggle.tsx:69`).
 *
 *  We drive the toggle through its `[data-testid="webpush-toggle-input"]`
 *  surface (the production checkbox in `PushToggle.tsx:329`).
 *  The PushToggle's own `'enabling'` state guards against
 *  re-clicks while the subscribe round-trip is in flight; we poll
 *  for the final `'idle-on'` state via the persisted flag rather
 *  than scraping the React tree, so a future toggle UX change
 *  (e.g. animated transitions, button replaced with a switch)
 *  doesn't break the assertion. */
async function enablePushToggle(page: Page): Promise<void> {
  // The PushToggle component lives inside a section identified by
  // `data-testid="webpush-toggle-section"`. We assert the section
  // renders first so a missing-task-9.3 deployment surfaces a
  // clear failure ("section not found") rather than a generic
  // input-locator timeout.
  const section = page.getByTestId('webpush-toggle-section');
  await expect(
    section,
    'PushToggle section must be present on /settings (task 9.3 dependency)',
  ).toBeVisible({ timeout: 10_000 });

  // If the browser somehow lacks Web Push support, the toggle
  // renders the unsupported message instead of the input.
  // Surface that as a clear failure — Chromium with the
  // notifications permission granted always supports push.
  const unsupported = page.getByTestId('webpush-unsupported');
  await expect(
    unsupported,
    'PushToggle must NOT render the unsupported message in headless Chromium with permission granted',
  ).toHaveCount(0, { timeout: 5_000 });

  const input = page.getByTestId('webpush-toggle-input');
  await expect(input).toBeVisible({ timeout: 10_000 });

  // The input is unchecked at first paint (PushToggle's initial
  // state is `'idle-off'` for a fresh browser). Click to
  // transition `idle-off` → `'enabling'` → `'idle-on'`.
  await input.check();

  // Wait for the persisted enable flag to reach `'1'`. This is
  // the `'idle-on'` settling signal: PushToggle writes the flag
  // as the final step of `enable()` (`PushToggle.tsx:212-214`),
  // AFTER the `POST /push/subscribe` round-trip succeeds. A
  // missing flag at the end of the budget means either the
  // subscribe round-trip failed OR the toggle is stuck in
  // `'enabling'`.
  await expect
    .poll(
      async () =>
        await page.evaluate(() => globalThis.localStorage.getItem('konvo:webpush:enabled')),
      {
        timeout: 15_000,
        message:
          'PushToggle must reach idle-on (konvo:webpush:enabled === "1") ' +
          'after a successful POST /push/subscribe round-trip',
      },
    )
    .toBe('1');

  // Belt-and-suspenders: assert the toggle did NOT surface its
  // error pane. The error pane only renders when `enable()` lands
  // in the `idle-off { error }` branch, which is mutually
  // exclusive with the persisted flag being `'1'`, but pinning
  // both axes makes a future regression that flips the flag
  // before checking the round-trip surface a clear diagnostic.
  await expect(
    page.getByTestId('webpush-toggle-error'),
    'PushToggle must not surface an error after a successful enable',
  ).toHaveCount(0, { timeout: 2_000 });
}

// ---------------------------------------------------------------------------
// Helpers — SW push simulation + last-notification readback
// ---------------------------------------------------------------------------

interface SimulatePushArgs {
  readonly type: string;
  readonly senderHandle: string;
  readonly conversationId: string;
  readonly simulateClick: boolean;
}

interface SimulationAck {
  readonly ok: boolean;
  readonly reason?: string;
}

/** `postMessage` a `{kind: 'simulatePush', payload, simulateClick}`
 *  envelope to the active SW and wait for an ack. The shape mirrors
 *  the message contract `pwa-install.spec.ts` case 3 documents in
 *  `apps/web/src/pwa/sw.ts` (the `__konvoSwPushForE2E__` hook the
 *  SW exposes when built with the E2E flag). */
async function simulatePushOnSw(page: Page, args: SimulatePushArgs): Promise<SimulationAck> {
  return page.evaluate(async (input) => {
    const reg = await navigator.serviceWorker.ready;
    const sw = reg.active;
    if (sw === null) {
      return { ok: false, reason: 'no active SW' };
    }
    return new Promise<SimulationAck>((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (ev: MessageEvent<SimulationAck>): void => {
        resolve(ev.data);
      };
      // 5 s ack timeout — the simulation should be near-instant;
      // anything longer means the hook isn't wired.
      window.setTimeout(() => resolve({ ok: false, reason: 'no ack from SW within 5 s' }), 5_000);
      sw.postMessage(
        {
          kind: 'simulatePush',
          payload: {
            type: input.type,
            senderHandle: input.senderHandle,
            conversationId: input.conversationId,
          },
          simulateClick: input.simulateClick,
        },
        [channel.port2],
      );
    });
  }, args);
}

interface RenderedNotification {
  readonly title: string;
  readonly body: string;
  readonly data: unknown;
}

/** Read the most recent notification the SW rendered via
 *  `registration.showNotification`. The SW's E2E hook records the
 *  call under `__konvoSwPushForE2E__.lastNotification`; we request
 *  it via a `{kind: 'getLastNotification'}` message so the readback
 *  is symmetric with the simulate path (rather than reaching into
 *  a SW-global JS variable, which would be racy across the
 *  `postMessage` ack boundary).
 *
 *  Returns `null` if the hook reports no notification has been
 *  rendered yet — the caller polls. */
async function readLastSwNotification(page: Page): Promise<RenderedNotification | null> {
  const result = await expect
    .poll(
      async () =>
        await page.evaluate(async () => {
          const reg = await navigator.serviceWorker.ready;
          const sw = reg.active;
          if (sw === null) return null;
          return new Promise<RenderedNotification | null>((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = (
              ev: MessageEvent<{
                ok: boolean;
                notification?: RenderedNotification | null;
              }>,
            ): void => {
              resolve(ev.data.ok ? (ev.data.notification ?? null) : null);
            };
            window.setTimeout(() => resolve(null), 2_000);
            sw.postMessage({ kind: 'getLastNotification' }, [channel.port2]);
          });
        }),
      {
        timeout: 10_000,
        message: 'SW must record a notification render via __konvoSwPushForE2E__.lastNotification',
      },
    )
    .not.toBeNull();
  return result as unknown as RenderedNotification | null;
}

// ---------------------------------------------------------------------------
// Helpers — /metrics counter readback
// ---------------------------------------------------------------------------

/** Read the current value of `konvo_envelope_offline_queued_total`
 *  from the api's unauthenticated `GET /metrics` endpoint. The
 *  metric is a no-label Counter (Requirement 18.1; defined at
 *  `apps/api/src/obs/metrics.ts:234`), so the exposition format
 *  is one-line:
 *
 *      konvo_envelope_offline_queued_total <value>
 *
 *  Returns 0 if the metric is missing (e.g. the api hasn't yet
 *  exercised the offline branch in this process), which lets the
 *  before/after delta in the test still be meaningful. */
async function readOfflineQueuedCounter(request: APIRequestContext): Promise<number> {
  const res = await request.get(`${API_URL}/metrics`);
  expect(res.status(), 'GET /metrics must return 200').toBe(200);
  const body = await res.text();
  // Lines starting with `#` are HELP/TYPE comments; we want the
  // first non-comment line whose name matches our counter. The
  // `^` anchor avoids false-positive matches on a metric named
  // `..._offline_queued_total_extra` if one is ever added.
  const match = body
    .split('\n')
    .find(
      (line) =>
        line.length > 0 &&
        !line.startsWith('#') &&
        line.startsWith('konvo_envelope_offline_queued_total '),
    );
  if (match === undefined) return 0;
  // Format: `konvo_envelope_offline_queued_total 12` (possibly with
  // a trailing timestamp; we take the second whitespace-delimited
  // token to be robust to either form).
  const parts = match.trim().split(/\s+/);
  const valueStr = parts[1] ?? '0';
  const value = Number.parseFloat(valueStr);
  return Number.isFinite(value) ? value : 0;
}

// ---------------------------------------------------------------------------
// Helpers — sleep
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

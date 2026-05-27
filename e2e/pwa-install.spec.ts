// e2e/pwa-install.spec.ts
//
// E2E coverage for task 9.6 — "Lighthouse PWA score and offline
// cache". Mirrors design.md §16.4 row 9 ("pwa-install.spec.ts |
// Phase 8 | Lighthouse PWA score ≥ 90; service worker registers;
// offline cache hits") and the verification gate in Requirement
// 20.6.
//
// _Validates: Requirements 14.2, 14.3, 14.4, 20.5, 20.6_
//
// Validates Requirements:
//   - 14.2  WHILE the Web_Client is offline, THE Service_Worker
//           SHALL serve the cached application shell (HTML, CSS,
//           JS bundle, icon assets) such that the Web_Client
//           renders the shell within 3 seconds of navigation.
//   - 14.3  WHILE the Web_Client is offline, THE Service_Worker
//           SHALL serve from precache the 500 most recent direct-
//           message and broadcast messages per conversation OR
//           all messages from the last 30 days, whichever is
//           smaller — i.e. cached threads must be visible after an
//           offline reload.
//   - 14.4  WHEN the Lighthouse PWA audit is run against the chat
//           home of a production build, THE score SHALL be at
//           least 90.
//   - 20.5  Re-statement of 14.4 in the system-level verification
//           list (Lighthouse PWA category score ≥ 90 / 100 against
//           a production build).
//   - 20.6  The full Playwright suite reports 100% pass with zero
//           skipped tests in CI. (Indirect — this file's skip
//           gate is the same env-var contract used by every other
//           Phase-9 spec; once task 10.24 wires CI to set
//           `KONVO_E2E_LIVE=1`, the gate flips on for real.)
//
// Test cases mirror the four bullets in tasks.md task 9.6:
//   1. INSTALL PROMPT + SW REGISTRATION. The PWA's
//      `apps/web/src/pwa/InstallPrompt.tsx` listens for
//      `beforeinstallprompt` and surfaces an `[data-testid=
//      "install-prompt-button"]`. Headless Chromium does NOT fire
//      `beforeinstallprompt` deterministically (the event is
//      browser-driven and gated on engagement heuristics), so the
//      test dispatches a synthetic event whose shape matches
//      `BeforeInstallPromptEventLike` from `InstallPrompt.tsx`.
//      In parallel we wait for `navigator.serviceWorker.ready` to
//      assert the Workbox SW (`apps/web/src/pwa/sw.ts`) registered
//      successfully.
//   2. OFFLINE RELOAD RENDERS CACHED THREADS WITHIN 3 s. We seed
//      a couple of thread rows directly into Dexie via
//      `page.evaluate` (the full DM send/receive flow is exercised
//      by `signup-and-login.spec.ts` + `offline-queue.integration
//      .spec.ts`; here we only need the cache to be warm), flip
//      the browser context offline, reload, and assert the
//      `[data-testid="dm-thread-list"]` panel renders within 3 s.
//   3. WEB PUSH WHEN OFFLINE OPENS THE CORRECT THREAD ON TAP.
//      We post a message to the active SW that mimics the shape
//      of a `push` event payload (`{type, senderHandle,
//      conversationId}`), and synthesise a `notificationclick`
//      via `serviceWorker.controller.postMessage` so the SW's
//      handler runs the same `clients.openWindow` / `focus`
//      branch a real notification tap would. We then assert the
//      page navigates to the thread URL the SW computes for
//      `conversationId`.
//   4. LIGHTHOUSE PWA SCORE ≥ 90. We launch a fresh Chromium with
//      a remote-debugging port via `playwright-lighthouse`, run
//      the PWA-only audit against the chat home, and assert the
//      category score ≥ 0.9. Lighthouse 12 removed the PWA
//      category, so we pin `lighthouse@^11.7.1` (last release
//      that still ships the category) in `e2e/package.json`.
//
// IMPORTANT — running against a live stack:
//   This spec does NOT bring up the docker-compose data-plane on
//   its own and it does NOT install Lighthouse on demand:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`). The
//     Lighthouse run additionally requires that `apps/web` is
//     served as a *production build* (Requirement 14.4 explicitly
//     scopes the audit to "the chat home of a production build")
//     — the dev server skips the SW registration in `register.ts`
//     by default, so a Lighthouse run against `vite dev` would
//     fail the SW-registered check unfairly.
//   - When `KONVO_E2E_LIVE` is unset (the default for local
//     `pnpm test:e2e:list` and any CI gate that hasn't wired the
//     compose stack yet), each test `test.skip()`s itself with an
//     explanatory annotation so the suite is a clean no-op rather
//     than a stream of network errors. This matches the skip
//     pattern used by every other E2E spec in this directory.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, builds
//   `apps/web` for production, exports `KONVO_E2E_LIVE=1`, and
//   runs this suite against the live stack. Once that lands,
//   Requirement 20.6's "zero skipped" gate flips on for real for
//   this file too.
//
// Why a synthetic `beforeinstallprompt` and not the real event:
//   The real event is browser-driven and gated on user-engagement
//   heuristics (Chromium counts visits, session duration, etc.).
//   A headless E2E run starts from a clean profile every time and
//   never accrues engagement, so the event simply never fires.
//   Waiting for it would either skip the test (Requirement 20.6
//   "zero skipped") or hang it. The synthetic event still exercises
//   the production code path under test — `InstallPrompt`'s
//   listener, the deferred-event capture, and the
//   `[data-testid="install-prompt-button"]` render — because the
//   DOM event API doesn't distinguish between browser-fired and
//   dispatched events for this contract.
//
// Why we seed Dexie directly for the offline-reload check:
//   The full DM ingest path (libsignal X3DH → ratchet decrypt →
//   Dexie persist) is exercised end-to-end by
//   `offline-queue.integration.spec.ts`. Threading that flow
//   through this spec would couple it to the WS gateway, the
//   prekey bundle service, and at least one peer device, all of
//   which are already covered. The 14.3 contract under test here
//   is "the SW's precache + Dexie cache is what renders when
//   offline", not "X3DH works"; seeding Dexie directly via the
//   exposed `__konvoDmForE2E__` test hook keeps this spec focused
//   on the cache behaviour. The hook is gated on
//   `import.meta.env.MODE === 'test'` in production code, so the
//   surface exists only in test/CI builds.
//
// Why the SW push path uses `postMessage` and not a real `push`:
//   The Web Push protocol is push-service-driven (FCM, autopush,
//   etc.); a Playwright test cannot inject a real push frame
//   without bringing up a fake push service over WebSocket and
//   forging a VAPID-signed envelope. The SW's contract under test
//   here (Requirements 13.4 + 13.5) is "given a payload of shape
//   `{type, senderHandle, conversationId}`, render a notification
//   and on click open the matching thread". `postMessage` from
//   the page reaches the same code path because the SW's
//   `addEventListener('message', ...)` handler in `sw.ts` is the
//   E2E entry point we wire for this contract — see the comment
//   block at the simulation site below for the message shape.

import {
  expect,
  test,
  type BrowserContext,
  type Page,
} from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. The skip is wired at the
 *  `describe`-level (see `test.skip(condition, reason)` below) so
 *  Playwright never launches a browser when LIVE is unset — that
 *  way the test reports as skipped rather than erroring on a
 *  missing chromium binary in environments where browsers haven't
 *  been pre-installed. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — set KONVO_E2E_LIVE=1 with a ' +
  'production build of apps/web up to run this against a real ' +
  'PWA stack (see task 10.24 for CI integration).';

/** The Lighthouse PWA category score floor, as a 0..1 fraction.
 *  Requirements 14.4 and 20.5 phrase this as "≥ 90 (out of 100)";
 *  `playwright-lighthouse`'s API uses 0..1, so we keep the
 *  fraction here and surface "0.9" alongside "≥ 90" in the
 *  failure message for traceability. */
const LIGHTHOUSE_PWA_FLOOR = 0.9;

/** The 3-second offline-shell budget from Requirement 14.2 / 14.3.
 *  Centralised so a future spec change updates one site. */
const OFFLINE_RENDER_BUDGET_MS = 3_000;


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('PWA install + offline cache + Lighthouse PWA score', () => {
  // Wire the skip at describe-level so Playwright doesn't even
  // launch a browser when LIVE is unset. Reporting as skipped
  // (rather than erroring on a missing chromium binary or a dead
  // dev server) is the contract the rest of the e2e suite relies
  // on — see signup-and-login.spec.ts and broadcast-post.spec.ts.
  test.skip(!LIVE, SKIP_REASON);

  // -------------------------------------------------------------------------
  // 1. Install prompt + SW registration
  // -------------------------------------------------------------------------
  test('install prompt surfaces and the service worker registers', async ({
    page,
  }) => {
    // Land on the chat home. Requirements 14.4 / 20.5 phrase the
    // Lighthouse audit as "the chat home of a production build";
    // for this and every other case in this file we navigate to
    // `/` so the test exercises the same surface the requirement
    // targets.
    await page.goto('/');

    // The Workbox SW (`apps/web/src/pwa/sw.ts`) is registered by
    // `apps/web/src/pwa/register.ts` at page load. We assert via
    // `navigator.serviceWorker.ready` rather than scraping
    // `getRegistrations()` because `ready` only resolves once the
    // SW has reached the `activated` state — which is the point at
    // which the precache and `/api/*` runtime cache rules from
    // `sw.ts` are actually live. A bare `getRegistration()` would
    // resolve as soon as the registration record exists, even
    // before `install` finishes; that's not strong enough to
    // satisfy Requirement 14.2's "shell renders within 3 s" gate.
    const swScope = await page.evaluate(async () => {
      if (!('serviceWorker' in navigator)) return null;
      // Wait up to the page test-default timeout (10 s) for the SW
      // to reach `activated`. We don't impose a tighter bound here
      // because activation can race with the first paint on a
      // cold-start CI runner.
      const reg = await navigator.serviceWorker.ready;
      return reg.scope;
    });
    expect(
      swScope,
      'navigator.serviceWorker.ready must resolve with a registered scope ' +
        '(Requirement 14.1 / 14.2 — SW must register and activate before the ' +
        'shell-cached offline path can serve)',
    ).toBeTruthy();
    // The SW is registered against the origin root (`scope: '/'`)
    // per `register.ts`'s `DEFAULT_SW_URL` constant. We assert the
    // exact scope rather than just non-null so a future change
    // that scopes the SW to `/app/` (or similar) trips the test
    // and forces a deliberate update.
    expect(swScope).toBe(`${WEB_URL}/`);

    // Dispatch a synthetic `beforeinstallprompt` event whose shape
    // matches `BeforeInstallPromptEventLike` from
    // `apps/web/src/pwa/InstallPrompt.tsx`. The component captures
    // the deferred event and renders the install button. We use
    // `Object.defineProperty` rather than constructing a custom
    // class so the runtime check inside InstallPrompt
    // (`event.preventDefault()` + access to `prompt` + `userChoice`)
    // sees a fully-formed surface.
    await page.evaluate(() => {
      const fakeEvent = new Event('beforeinstallprompt', {
        bubbles: false,
        cancelable: true,
      }) as Event & {
        prompt?: () => Promise<void>;
        userChoice?: Promise<{ outcome: string; platform: string }>;
      };
      // `prompt` and `userChoice` mirror the real PWA event surface
      // so InstallPrompt's click handler can call them without
      // tripping a TypeError. The promise resolves to `dismissed`
      // so the component clears the deferred event after the
      // synthetic click — same code path as a real user dismissing
      // the prompt.
      fakeEvent.prompt = () => Promise.resolve();
      fakeEvent.userChoice = Promise.resolve({
        outcome: 'dismissed',
        platform: 'test',
      });
      window.dispatchEvent(fakeEvent);
    });

    // The InstallPrompt component renders an
    // `[data-testid="install-prompt-button"]` button once the
    // `beforeinstallprompt` event has been captured. The visibility
    // check + the explicit accessible name double-pin the contract
    // — a regression that drops either side trips this.
    const installButton = page.getByTestId('install-prompt-button');
    await expect(installButton).toBeVisible({ timeout: 5_000 });
    await expect(installButton).toHaveAccessibleName(/install konvo/i);
  });

  // -------------------------------------------------------------------------
  // 2. Offline reload renders cached threads within 3 s
  // -------------------------------------------------------------------------
  test('offline reload renders cached threads within 3 s', async ({
    context,
    page,
  }) => {
    // Land on the chat home and wait for the SW to activate so the
    // precache + runtime cache rules are live before we go offline.
    await page.goto('/');
    await page.evaluate(() => navigator.serviceWorker.ready);

    // Seed two thread rows directly into Dexie via the
    // `__konvoDmForE2E__` test hook the SPA exposes when
    // `import.meta.env.MODE === 'test'`. The hook accepts a list of
    // (peerUserId, peerHandle, lastBody, lastAt) tuples and inserts
    // them into the `threads` table; the `[data-testid=
    // "dm-thread-list"]` panel reads from this table directly via
    // `useDmThreads` (`apps/web/src/features/dm/useDmStore.ts`).
    //
    // We use two threads so the test catches a regression that
    // hides the panel on multi-thread state (e.g. a missing
    // `key={peerUserId}` in the list).
    const seedResult = await page.evaluate(async () => {
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
      if (w.__konvoDmForE2E__ === undefined) {
        return { hookPresent: false, count: 0 };
      }
      const count = await w.__konvoDmForE2E__.seedThreads([
        {
          peerUserId: 'peer-aaaaaaaa',
          peerHandle: 'alice',
          lastBody: 'cached message 1',
          lastAt: Date.now() - 60_000,
        },
        {
          peerUserId: 'peer-bbbbbbbb',
          peerHandle: 'bob',
          lastBody: 'cached message 2',
          lastAt: Date.now() - 30_000,
        },
      ]);
      return { hookPresent: true, count };
    });
    // The hook is only present in test-mode builds. If a CI run
    // somehow gets here without `MODE=test` set in the dev
    // server's vite config, fail loudly rather than silently
    // skipping the assertion — that's the kind of regression
    // Requirement 20.6's "zero skipped" gate is meant to catch.
    expect(
      seedResult.hookPresent,
      'window.__konvoDmForE2E__ must be present — the SPA build must run in ' +
        'MODE=test for this spec (apps/web/src/main.tsx exposes the hook ' +
        'only when import.meta.env.MODE === "test")',
    ).toBe(true);
    expect(seedResult.count).toBe(2);

    // Flip the browser context offline. `setOffline(true)` cuts
    // the underlying HTTP fetcher AND surfaces `navigator.onLine
    // === false` to the page; the SW's NetworkFirst route from
    // `sw.ts` falls through to the cache, and the page-side
    // `register.ts`'s reconnect hook arms.
    await context.setOffline(true);

    // Reload from cache. We measure wall-clock time from the
    // moment we issue the reload to the moment the
    // `[data-testid="dm-thread-list"]` panel reaches the DOM, so
    // the assertion lines up with Requirement 14.2's "within 3
    // seconds of navigation" wording. Using `Date.now()` rather
    // than `performance.now()` keeps the diff between the
    // assertion message and the requirement's seconds-based
    // budget readable on failure.
    const navStart = Date.now();
    // `waitUntil: 'commit'` resolves as soon as the navigation
    // request commits — which is enough for the document to be
    // served from the precache without our timer including any
    // post-load network idle that's not part of the spec gate.
    await page.reload({ waitUntil: 'commit' });

    // The thread-list panel under test is `dm-thread-list`. The
    // task brief mentions a generic `[data-testid="thread-list-
    // item"]`; the production component's id is
    // `dm-thread-list` (with row ids `dm-thread-row-${peerUserId}`)
    // — see `apps/web/src/features/dm/ThreadList.tsx`. We assert
    // the panel itself is visible AND that at least one seeded
    // row is present, which together pin the contract more
    // tightly than a single id check.
    const threadList = page.getByTestId('dm-thread-list');
    await expect(threadList).toBeVisible({
      timeout: OFFLINE_RENDER_BUDGET_MS,
    });
    await expect(
      page.getByTestId('dm-thread-row-peer-aaaaaaaa'),
    ).toBeVisible({ timeout: OFFLINE_RENDER_BUDGET_MS });

    const renderMs = Date.now() - navStart;
    expect(
      renderMs,
      `cached thread list must render within ${OFFLINE_RENDER_BUDGET_MS} ms ` +
        `of an offline reload (Requirement 14.2 / 14.3); rendered in ${renderMs} ms`,
    ).toBeLessThan(OFFLINE_RENDER_BUDGET_MS);

    // Restore the network for any subsequent test sharing the
    // context. (Playwright's default is a fresh context per test,
    // but this is cheap and keeps the cleanup explicit for the
    // human reading this file later.)
    await context.setOffline(false);
  });

  // -------------------------------------------------------------------------
  // 3. Web Push when offline opens the correct thread on tap
  // -------------------------------------------------------------------------
  test('a Web Push received offline opens the correct thread on tap', async ({
    context,
    page,
  }) => {
    await page.goto('/');
    await page.evaluate(() => navigator.serviceWorker.ready);

    // Seed a single thread so the SW's notification-click handler
    // has a real conversation to navigate to. Same hook as case 2.
    const conversationId = 'peer-cccccccc';
    await page.evaluate(async (peerUserId) => {
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
      if (w.__konvoDmForE2E__ === undefined) {
        throw new Error(
          'window.__konvoDmForE2E__ missing — build must run in MODE=test',
        );
      }
      await w.__konvoDmForE2E__.seedThreads([
        {
          peerUserId,
          peerHandle: 'carol',
          lastBody: 'pushed message',
          lastAt: Date.now(),
        },
      ]);
    }, conversationId);

    // Take the page offline so the SW's offline branch is the one
    // exercised — Requirements 13.4 / 13.5 say the SW MUST render
    // a notification regardless of online state, and the offline
    // path is the one Requirement 20.5's "received while offline"
    // wording targets.
    await context.setOffline(true);

    // Simulate the push → notificationclick → openWindow chain via
    // a typed message to the active SW. The SW's E2E test hook in
    // `apps/web/src/pwa/sw.ts` accepts a `{kind: 'simulatePush',
    // payload}` message and runs the exact same handler the real
    // `push` event would (`fetch latest envelope → decrypt →
    // render notification`), then immediately fires the same
    // `notificationclick` branch that `clients.openWindow` would
    // take. The hook is gated on a build-time flag so production
    // SW bundles don't expose it.
    //
    // The payload shape mirrors design.md §17 ("payloads carry
    // only `{type, sender_handle, conversation_id}`") — see also
    // Requirement 13.3.
    const navigationPromise = page.waitForURL(
      (url) => url.pathname.includes(conversationId),
      { timeout: 10_000 },
    );
    const simulationResult = await page.evaluate(async (peerUserId) => {
      const reg = await navigator.serviceWorker.ready;
      const sw = reg.active;
      if (sw === null) {
        return { ok: false, reason: 'no active SW' };
      }
      // Use a MessageChannel so the SW can ack synchronously and
      // we can fail fast if the hook isn't wired (rather than
      // hanging until the test timeout).
      const ack = await new Promise<{ ok: boolean; reason?: string }>(
        (resolve) => {
          const channel = new MessageChannel();
          channel.port1.onmessage = (
            ev: MessageEvent<{ ok: boolean; reason?: string }>,
          ): void => {
            resolve(ev.data);
          };
          // 5 s ack timeout — the simulation should be near-
          // instant; anything longer means the hook isn't wired.
          window.setTimeout(
            () =>
              resolve({
                ok: false,
                reason: 'no ack from SW within 5 s',
              }),
            5_000,
          );
          sw.postMessage(
            {
              kind: 'simulatePush',
              payload: {
                type: 'dm',
                senderHandle: 'carol',
                conversationId: peerUserId,
              },
              // `simulateClick: true` tells the hook to also fire
              // the notificationclick branch right after the
              // synthetic notification is rendered, so the test
              // doesn't depend on a real user tap.
              simulateClick: true,
            },
            [channel.port2],
          );
        },
      );
      return ack;
    }, conversationId);

    expect(
      simulationResult.ok,
      `SW simulatePush hook must succeed — got: ${simulationResult.reason ?? '?'}`,
    ).toBe(true);

    // The SW's notificationclick handler calls `clients.openWindow`
    // (or `client.focus` + `client.navigate` if a same-origin
    // client already exists). In either case the page's URL must
    // end up pointing at the conversation. Production routing for
    // DMs lands in a follow-up task; the design.md §3 path layout
    // calls it `/dm/:handle`. We assert "the URL contains the
    // conversation id we pushed" rather than pinning the exact
    // prefix so a router rename (e.g. `/thread/...` → `/dm/...`)
    // doesn't break this case until the router itself is the
    // contract under test. The thread is identified via
    // `peerUserId` because that's the conversation key the DM
    // store uses (see `apps/web/src/features/dm/ThreadList.tsx`).
    await navigationPromise;
    expect(page.url()).toContain(conversationId);

    await context.setOffline(false);
  });

  // -------------------------------------------------------------------------
  // 4. Lighthouse PWA category score ≥ 90
  // -------------------------------------------------------------------------
  test('Lighthouse PWA category score is at least 90', async ({
    browserName,
  }, testInfo) => {
    // `playwright-lighthouse` only supports Chromium because
    // Lighthouse drives Chrome via the DevTools protocol. Every
    // other test in this suite already runs Chromium-only
    // (`projects` in `playwright.config.ts`); we re-assert here
    // so a future cross-browser project addition fails loudly
    // rather than silently producing a bogus 0-score run.
    test.skip(
      browserName !== 'chromium',
      'Lighthouse audits are Chromium-only',
    );

    // Lighthouse runs are wall-clock-heavy (cold-load + audit
    // collection takes 30-60 s on a typical CI runner). Override
    // the per-test default 60 s timeout so a slow runner doesn't
    // produce a spurious failure.
    test.setTimeout(180_000);

    // Lazy-import `playwright-lighthouse` + `lighthouse` so this
    // file can still be ENUMERATED (`pnpm test:e2e:list`) when
    // the packages aren't installed yet — the dynamic import only
    // runs inside a live-stack test, which by definition runs in
    // CI where everything is installed. If for any reason the
    // packages are missing at runtime in a live-stack invocation,
    // we surface a clear failure pointing at e2e/package.json so
    // the next maintainer doesn't have to dig.
    let runLighthouse: typeof import('playwright-lighthouse').playAudit;
    try {
      const mod = await import('playwright-lighthouse');
      runLighthouse = mod.playAudit;
    } catch (err) {
      throw new Error(
        'playwright-lighthouse is not installed — add it to ' +
          'e2e/package.json devDependencies (see task 9.6). ' +
          `Underlying error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // Launch a dedicated Chromium with a remote-debugging port so
    // Lighthouse can attach via CDP. We can't reuse the Playwright
    // browser fixture because Playwright doesn't expose its
    // CDP port via the public test API; spinning up a separate
    // browser for the audit is the documented integration pattern
    // from `playwright-lighthouse`'s README.
    const { chromium } = await import('@playwright/test');
    const debugPort = pickDebugPort();
    const browser = await chromium.launch({
      args: [`--remote-debugging-port=${debugPort}`],
    });
    let auditPage: Page | undefined;
    let auditContext: BrowserContext | undefined;
    try {
      auditContext = await browser.newContext();
      auditPage = await auditContext.newPage();
      // Land on the chat home and wait for the SW to activate so
      // the PWA installability checks Lighthouse runs (manifest,
      // SW, themed colour, …) all pass. Without this, the audit
      // races the SW registration and produces a flaky 80-ish
      // score.
      await auditPage.goto(WEB_URL);
      await auditPage.evaluate(() => navigator.serviceWorker.ready);

      // Run the audit. We restrict to the PWA category (the only
      // one Requirement 14.4 / 20.5 actually scopes) so an
      // unrelated drop in the Performance category — which the
      // requirements don't gate — doesn't fail this test. Note
      // the `lighthouse@^11` pin in e2e/package.json: lighthouse
      // 12 dropped the PWA category, so a future bump must be
      // accompanied by a spec update.
      const auditReport = await runLighthouse({
        page: auditPage,
        port: debugPort,
        thresholds: {
          // Score is a 0..100 integer in `playwright-lighthouse`'s
          // threshold input (it asserts `score >= threshold`),
          // even though the underlying lighthouse API returns
          // 0..1 fractions. We use 90 to match the requirement
          // wording verbatim.
          pwa: 90,
        },
        // Disable the HTML/JSON report files to keep the test's
        // artifacts small — the assertion is the score; the report
        // is only useful when debugging a regression locally.
        reports: {
          formats: { html: false, json: false },
        },
        // Fresh tracing each run; don't reuse cached results.
        ignoreError: false,
      } as Parameters<typeof runLighthouse>[0]);

      // `playAudit` throws if any threshold is not met; reaching
      // this line means the PWA score is ≥ 90. We re-extract and
      // re-assert the score against the 0.9 fraction to surface
      // the actual number on success (helpful when bisecting a
      // regression that drops it from 100 to 90 over time).
      const lhrUnknown = (auditReport as unknown as { lhr?: unknown }).lhr;
      const pwaScore = readPwaScore(lhrUnknown);
      expect(
        pwaScore,
        `Lighthouse PWA category score must be ≥ ${LIGHTHOUSE_PWA_FLOOR} ` +
          '(Requirement 14.4 / 20.5)',
      ).toBeGreaterThanOrEqual(LIGHTHOUSE_PWA_FLOOR);

      testInfo.annotations.push({
        type: 'lighthouse-pwa-score',
        description: `${(pwaScore * 100).toFixed(0)} / 100`,
      });
    } finally {
      // Tear down the dedicated browser regardless of pass/fail
      // so a failed audit doesn't leak a Chromium process.
      if (auditPage !== undefined) {
        await auditPage.close().catch(() => undefined);
      }
      if (auditContext !== undefined) {
        await auditContext.close().catch(() => undefined);
      }
      await browser.close().catch(() => undefined);
    }
  });
});


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Pick a free-ish remote-debugging port for the Lighthouse run.
 * We spread the port over a small range based on the worker
 * index so two parallel workers don't collide on the same port
 * (Playwright currently runs e2e workers serially per
 * `playwright.config.ts`'s `workers: 1`, but the helper is cheap
 * enough to future-proof).
 */
function pickDebugPort(): number {
  const base = 9222;
  const workerIdx = parseInt(
    process.env['TEST_WORKER_INDEX'] ?? '0',
    10,
  );
  return base + (Number.isFinite(workerIdx) ? workerIdx : 0);
}

/**
 * Extract the PWA category score from a Lighthouse v11 LHR JSON
 * blob. The shape is `{categories: {pwa: {score: number}}}` per
 * the Lighthouse audit-results contract. We narrow defensively so
 * a future shape change surfaces a typed assertion failure rather
 * than `undefined.score` blowing up.
 *
 * Returns NaN if the score is missing — the assertion above
 * surfaces "NaN ≥ 0.9 is false" with a clear message naming the
 * underlying contract.
 */
function readPwaScore(lhr: unknown): number {
  if (lhr === null || typeof lhr !== 'object') return Number.NaN;
  const categories = (lhr as { categories?: unknown }).categories;
  if (categories === null || typeof categories !== 'object') return Number.NaN;
  const pwa = (categories as { pwa?: unknown }).pwa;
  if (pwa === null || typeof pwa !== 'object') return Number.NaN;
  const score = (pwa as { score?: unknown }).score;
  return typeof score === 'number' ? score : Number.NaN;
}

// API_URL is intentionally referenced from the WEB_URL-fronted
// page rather than directly here; this binding is kept for
// future tests in this file that need to hit the api directly
// (e.g. seeding fixtures via REST). Suppress the unused-binding
// lint by exporting it as a no-op constant.
export const KONVO_E2E_API_URL_REF = API_URL;

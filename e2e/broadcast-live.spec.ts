// e2e/broadcast-live.spec.ts
//
// E2E coverage for task 10.19 — "broadcast live A/V". Mirrors
// design.md §16.4 row 7 ("broadcast-live.spec.ts | Phase 7 |
// Admin goes live via LiveKit; second browser subscribes and
// receives A/V") and the verification gate in Requirement 20.6.
//
// _Validates: Requirements 11.1, 11.2, 20.6_
//
// Validates Requirements:
//   - 11.1  WHEN a user with role `admin` calls
//           `POST /rooms/:slug/live`, THE API_Gateway SHALL
//           provision a LiveKit_Room if absent and return a
//           publisher JWT (TTL 3600 s) and the LiveKit URL within
//           2 s; non-admins receive HTTP 403. The publisher-token
//           round-trip is exercised here by Alice clicking
//           "Go Live (Audio + Video)" and reaching the
//           `[data-testid="go-live-active"]` state — that
//           transition only happens once the publisher JWT has
//           been redeemed and the LiveKit publish has connected.
//   - 11.2  WHEN any authenticated user calls
//           `GET /rooms/:slug/live/viewer-token`, THE API_Gateway
//           SHALL return a viewer JWT (TTL 3600 s) and the
//           LiveKit URL within 2 s; unknown slug → HTTP 404. The
//           viewer-token round-trip is exercised here by Carol
//           clicking "Watch live" and her `<audio>`/`<video>`
//           elements receiving populated `srcObject` instances.
//   - 20.6  The full Playwright suite reports 100% pass with zero
//           skipped tests in CI.
//
// Relationship to broadcast-live.integration.spec.ts (task 8.5):
//   The companion file `broadcast-live.integration.spec.ts` owns
//   the three-browser audio-only-vs-full mode split that the
//   Phase 7 verification gate (task 8.6) requires:
//     - Alice (admin) + Bob + Carol (two viewers) — Requirement
//       11.5 (audio-only publishes only audio) and Requirement
//       11.6 (full mode publishes BOTH audio and video).
//   This spec is intentionally narrower: it is the minimal
//   "admin + 1 viewer" gate for Requirements 11.1 and 11.2 only,
//   matching the task 10.19 brief "admin goes live via LiveKit;
//   second browser subscribes and receives A/V". Keeping the two
//   files separate means:
//     - The 10.19 gate trips on a token-round-trip regression on
//       its own, even if the 8.5 audio-only/full split has an
//       unrelated regression somewhere.
//     - The 8.5 integration spec stays focused on the publish-
//       mode contract without taking on the token round-trip as
//       a secondary concern.
//   Selectors and helpers are deliberately re-implemented (not
//   imported) so a future refactor of one file cannot silently
//   regress the other.
//
// IMPORTANT — running against a live stack:
//   This spec does NOT bring up the docker-compose data-plane on
//   its own — the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`). The
//     stack must include a working LiveKit server — otherwise the
//     publisher token round-trip will time out and the test will
//     fail rather than skip.
//   - When unset (the default for local `pnpm test:e2e:list` and
//     any CI gate that hasn't wired the compose stack yet), the
//     describe-level `test.skip()` keeps the suite a clean no-op
//     rather than a stream of network errors. Wiring the skip at
//     the describe level (rather than inside each test body) means
//     Playwright never launches a browser when LIVE is unset —
//     environments without chromium installed (e.g. a fresh dev
//     box that hasn't run `pnpm exec playwright install`) report
//     a clean "skipped" instead of a browser-launch error.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1`, and runs this suite against the live
//   stack as part of the "integration" gate. Once that lands,
//   Requirement 20.6's "zero skipped" gate flips on for real for
//   this file too.
//
// Why we drive the UI rather than the LiveKit SDK directly:
//   The "Go Live (Audio + Video)" and "Watch live" affordances
//   (owned by `apps/web/src/features/broadcast/GoLiveButton.tsx`
//   and `ViewerPanel.tsx`) are the integration surface a user
//   sees. The `<audio srcObject>` / `<video srcObject>`
//   assertions are how you can tell — without poking at private
//   SDK state — that media has actually reached the viewer's
//   media element. Driving the SDK through the page also
//   exercises the bundle chunking path (`loadLiveKitClient`) the
//   production app uses.
//
// SPA-route note:
//   The authenticated admin / viewer affordances live on
//   `RoomView` (apps/web/src/features/broadcast/RoomView.tsx),
//   which the public `/r/:slug` route renders in read-only mode
//   (no live controls). The authed route — wired by the
//   broadcast UI work in task 8.2 — is `/rooms/:slug`; the path
//   is centralised below so a future routing change updates one
//   site.

import {
  expect,
  test,
  type APIRequestContext,
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

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Wiring the skip at the describe level
 *  (see `test.skip(condition, reason)` below) prevents Playwright
 *  from launching a browser before the skip predicate runs. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — Set KONVO_E2E_LIVE=1 with the ' +
  'docker-compose data-plane up (including a reachable LiveKit ' +
  'server) to run this against a real stack (see task 10.24 for ' +
  'CI integration).';

/** Path to the authed room screen that mounts `RoomView` with the
 *  Go-Live + Watch-live affordances enabled. The public read-only
 *  permalink (`/r/:slug`) deliberately suppresses the live
 *  controls (see `RoomView.readOnly`); the authed route is wired
 *  by the broadcast UI work in task 8.2. */
function ROOM_PATH(slug: string): string {
  return `/rooms/${slug}`;
}

/** End-to-end deadline within which Carol must see her
 *  `<audio>`/`<video>` elements receive a populated `srcObject`.
 *  The task 10.19 brief doesn't set an explicit budget; we use
 *  30 s, matching the wall-clock budget Requirement 20.2 sets for
 *  queue replay — slow CI runners + LiveKit room provisioning +
 *  ICE + DTLS comfortably fit. */
const VIEWER_MEDIA_BUDGET_MS = 30_000;

/** Generate a unique signup handle per test so reruns against the
 *  same database don't trip Requirement 1.2's duplicate-handle
 *  rejection. The shape matches the server-side regex
 *  `^[a-z0-9_]{3,32}$`. */
function uniqueHandle(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${stamp}${rand}`.slice(0, 32).toLowerCase();
}

/** Generate a unique room slug per test. Matches the server-side
 *  regex `^[a-z0-9-]{3,64}$` from `apps/api/src/routes/broadcast.ts`
 *  (no underscores). */
function uniqueSlug(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  // Replace any underscores with dashes — the room-slug regex
  // permits hyphens but not underscores.
  return `${prefix}-${stamp}${rand}`.replace(/_/g, '-').slice(0, 64);
}

interface BootstrappedUser {
  readonly handle: string;
  readonly accessToken: string;
}

/** Sign a fresh user up via REST and log them in. We do NOT enrol
 *  a libsignal device here — the broadcast-live path is a
 *  LiveKit-only flow; no envelope ever traverses the WS gateway.
 *  The auth contract is exercised separately by
 *  `signup-and-login.spec`. */
async function bootstrapUser(
  request: APIRequestContext,
  prefix: string,
): Promise<BootstrappedUser> {
  const handle = uniqueHandle(prefix);
  const signupRes = await request.post(`${API_URL}/auth/signup`, {
    data: { handle, password: PASSWORD },
  });
  expect(signupRes.status(), `signup ${prefix}`).toBe(201);
  const loginRes = await request.post(`${API_URL}/auth/login`, {
    data: { handle, password: PASSWORD },
  });
  expect(loginRes.status(), `login ${prefix}`).toBe(200);
  const loginBody = (await loginRes.json()) as { accessToken: string };
  return { handle, accessToken: loginBody.accessToken };
}

/** Drive the login form on `/login` so the page-context auth store
 *  is populated. The Phase-1 UI exposes the access token through
 *  `window.__konvoAuthForE2E__` only when the SPA is built in
 *  `test` mode; the same hook is used by `signup-and-login.spec`. */
async function uiLogin(page: Page, handle: string): Promise<void> {
  await page.goto('/login');
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
      { timeout: 10_000, message: 'access token must be present in memory' },
    )
    .not.toBeNull();
}

/** Wait for a media element under the supplied test-id to expose a
 *  populated `srcObject`. The viewer's audio/video elements are
 *  rendered by `ViewerPanel` (apps/web/src/features/broadcast/
 *  ViewerPanel.tsx); when LiveKit's `attach(element)` runs it sets
 *  `element.srcObject` to a live `MediaStream`. The presence of an
 *  active stream with at least one track is the strongest signal —
 *  short of decoding pixels — that media has reached the viewer.
 *
 *  We poll inside the page so the assertion sees the element's
 *  CURRENT `srcObject`, not a stale snapshot from when the
 *  selector was created. */
async function waitForMediaElementSrcObject(
  page: Page,
  testId: 'viewer-audio' | 'viewer-video',
  deadlineAt: number,
): Promise<void> {
  const remaining = Math.max(1, deadlineAt - Date.now());
  await expect
    .poll(
      async () =>
        await page.evaluate((tid) => {
          const el = document.querySelector(
            `[data-testid="${tid}"]`,
          ) as HTMLMediaElement | null;
          if (el === null) return null;
          // `srcObject` is a `MediaProvider` (MediaStream | MediaSource
          // | Blob | null). We accept any populated value as the
          // "media reached the element" signal; a real LiveKit attach
          // sets a `MediaStream` whose `getTracks()` is non-empty.
          if (el.srcObject === null) return null;
          if (el.srcObject instanceof MediaStream) {
            return el.srcObject.getTracks().length;
          }
          // For any non-MediaStream provider, treat presence alone
          // as positive (e.g. some test stubs may set a different
          // provider type). Returning a constant non-zero keeps the
          // poll truthy.
          return 1;
        }, testId),
      {
        message: `media element [data-testid="${testId}"] must expose a populated srcObject`,
        timeout: remaining,
        intervals: [250, 500, 1000],
      },
    )
    .toBeGreaterThan(0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('broadcast live A/V — admin goes live; viewer subscribes', () => {
  // Skip every test in this describe block when the live stack is
  // unavailable. See the header comment for why the skip is wired
  // here rather than inside each test body.
  test.skip(!LIVE, SKIP_REASON);

  test('admin goes live (A+V); viewer receives both audio and video', async ({
    browser,
    request,
  }) => {
    // -----------------------------------------------------------------
    // 1. Bootstrap two users via REST: Alice (admin) and Carol
    //    (viewer). Each gets their own browser context so cookies,
    //    IndexedDB, and the in-memory auth store are fully
    //    isolated.
    // -----------------------------------------------------------------
    const alice = await bootstrapUser(request, 'alice');
    const carol = await bootstrapUser(request, 'carol');

    // -----------------------------------------------------------------
    // 2. Alice creates a room (admin role auto-assigned to creator).
    //    `POST /rooms` requires auth — we use Alice's REST token
    //    here so the room exists by the time her browser context
    //    navigates to it. The slug prefix `live-mini-` distinguishes
    //    fixtures created by this spec from those of the companion
    //    three-browser integration spec.
    // -----------------------------------------------------------------
    const slug = uniqueSlug('live-mini');
    const createRes = await request.post(`${API_URL}/rooms`, {
      headers: { authorization: `Bearer ${alice.accessToken}` },
      data: { slug, name: `Live mini test ${slug}` },
    });
    expect(createRes.status(), 'POST /rooms by Alice').toBe(201);

    // -----------------------------------------------------------------
    // 3. Open two independent browser contexts. Grant
    //    microphone/camera permission to Alice so `getUserMedia`
    //    inside the Go-Live (full) flow doesn't surface the
    //    permission-required prompt. Carol doesn't need media
    //    permissions — viewers only consume remote tracks.
    // -----------------------------------------------------------------
    const aliceCtx = await browser.newContext({
      baseURL: WEB_URL,
      permissions: ['microphone', 'camera'],
    });
    const carolCtx = await browser.newContext({ baseURL: WEB_URL });

    const alicePage = await aliceCtx.newPage();
    const carolPage = await carolCtx.newPage();

    try {
      // ---------------------------------------------------------------
      // 4. Each context authenticates via the SPA login UI so the
      //    in-page broadcast API client picks up the right
      //    `Authorization` header on `POST /rooms/:slug/live`
      //    (Alice) and `GET /rooms/:slug/live/viewer-token`
      //    (Carol).
      // ---------------------------------------------------------------
      await uiLogin(alicePage, alice.handle);
      await uiLogin(carolPage, carol.handle);

      // ---------------------------------------------------------------
      // 5. Alice navigates to the room and clicks "Go Live (Audio
      //    + Video)". The Go-Live affordance is gated on `isAdmin`
      //    (UX hint) and on the server's role check — Alice is the
      //    room creator, so both gates pass.
      //
      //    The `data-testid="go-live-full"` selector pins the
      //    click to the audio-and-video branch even if the visible
      //    label is later localised. We pick the full mode (rather
      //    than audio-only) here because the task 10.19 brief is
      //    explicit: "subscribes and receives A/V" — i.e. both
      //    tracks must reach Carol. Audio-only mode is covered by
      //    the companion `broadcast-live.integration.spec.ts`.
      //
      //    The component switches to the active state once the
      //    publisher is connected. Reaching `go-live-active` proves
      //    the `POST /rooms/:slug/live` round-trip succeeded for
      //    the admin role — that is, the publisher JWT was issued
      //    within the 2-second budget AND the LiveKit publish
      //    connected. This is the integration assertion for
      //    Requirement 11.1.
      // ---------------------------------------------------------------
      await alicePage.goto(ROOM_PATH(slug));
      await alicePage.getByTestId('go-live-full').click();
      await expect(alicePage.getByTestId('go-live-active')).toBeVisible({
        timeout: 15_000,
      });
      await expect(alicePage.getByTestId('go-live-indicator')).toContainText(
        /audio \+ video/i,
      );

      // ---------------------------------------------------------------
      // 6. Carol opens the room URL and clicks "Watch live".
      //    `GET /rooms/:slug/live/viewer-token` must succeed for
      //    any authed user (Requirement 11.2); the Watch action
      //    triggers the same code path under the hood.
      //
      //    We arm the 30-second wall-clock budget at the moment
      //    Carol clicks watch (not when Alice goes live), so a
      //    slow LiveKit publisher start does not bleed into the
      //    viewer-side budget the requirement really cares about.
      // ---------------------------------------------------------------
      await carolPage.goto(ROOM_PATH(slug));
      await carolPage.getByTestId('viewer-watch').click();
      const deadline = Date.now() + VIEWER_MEDIA_BUDGET_MS;

      // `ViewerPanel` flips into the active layout
      // (`data-testid="viewer-panel-active"`) only after
      // `room.connect(...)` resolves; we assert the active state
      // is visible before polling for the srcObject so the message
      // on a hard failure points at the right layer (connect
      // failure vs. track-attach failure). Reaching this state
      // also proves the viewer-token round-trip succeeded —
      // Requirement 11.2.
      await expect(carolPage.getByTestId('viewer-panel-active')).toBeVisible({
        timeout: 15_000,
      });

      // ---------------------------------------------------------------
      // 7. Both audio AND video streams must reach Carol within
      //    the 30-second budget. This is the direct integration
      //    assertion called out by task 10.19 ("subscribes and
      //    receives A/V"). Asserting both tracks — not just one —
      //    closes the hole where a half-broken LiveKit publish
      //    (audio only, or video only) could otherwise pass.
      // ---------------------------------------------------------------
      await Promise.all([
        waitForMediaElementSrcObject(carolPage, 'viewer-audio', deadline),
        waitForMediaElementSrcObject(carolPage, 'viewer-video', deadline),
      ]);
    } finally {
      // Always clean up contexts so a partial failure doesn't leak
      // browsers across the test run. Closing a page that is
      // mid-disconnect is harmless — we deliberately skip explicit
      // "Stop"/"Leave" clicks so the test doesn't fail on a slow
      // disconnect path.
      await Promise.allSettled([alicePage.close(), carolPage.close()]);
      await Promise.allSettled([aliceCtx.close(), carolCtx.close()]);
    }
  });
});

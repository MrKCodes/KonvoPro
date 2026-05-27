// e2e/broadcast-live.integration.spec.ts
//
// Integration coverage for task 8.5 — "admin go-live with two
// viewers". Mirrors the Phase 7 verification gate (tasks.md task
// 8.6) and design.md §16.4 row 7 ("broadcast-live.spec.ts |
// Broadcast Live | Admin Go Live publishes audio + optional video
// via LiveKit; viewers receive media").
//
// Validates Requirements:
//   - 11.1  WHEN a user with role `admin` calls
//           `POST /rooms/:slug/live`, THE API_Gateway SHALL
//           provision a LiveKit_Room if absent and return a
//           publisher JWT (TTL 3600 s) and the LiveKit URL within
//           2 s; non-admins receive HTTP 403.
//   - 11.2  WHEN any authenticated user calls
//           `GET /rooms/:slug/live/viewer-token`, THE API_Gateway
//           SHALL return a viewer JWT (TTL 3600 s) and the
//           LiveKit URL within 2 s; unknown slug → HTTP 404.
//   - 11.5  WHERE the admin selects audio-only mode, THE
//           Web_Client SHALL publish only the audio track to
//           LiveKit. Both viewers SHALL receive that audio track.
//   - 11.6  WHERE the admin selects full audio-and-video mode,
//           THE Web_Client SHALL publish both audio and video
//           tracks. Both viewers SHALL receive both tracks.
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task
//   8.5. It does NOT bring up the docker-compose data-plane on
//   its own — the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`). The
//     stack must include a working LiveKit server — otherwise the
//     publisher token round-trip will time out and the test will
//     fail rather than skip.
//   - When unset (the default for local `pnpm test:e2e:list` and
//     any CI gate that hasn't wired the compose stack yet), each
//     test `test.skip()`s itself with an explanatory annotation
//     so the suite is a clean no-op rather than a stream of
//     network errors.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1`, and runs this suite against the live
//   stack as part of the "integration" gate. Once that lands,
//   Requirement 20.6's "zero skipped" gate flips on for real for
//   this file too.
//
// Why three browser contexts (Alice, Bob, Carol) rather than one
// admin + one viewer:
//   Requirement 11.3 caps the LiveKit room at 200 active viewers;
//   the Phase 7 verification gate (8.6) explicitly requires "≥ 2
//   viewers in separate browsers see and hear them". Two
//   independent viewer contexts also flush out any single-
//   subscriber assumption the publisher path might accidentally
//   bake in: a per-publisher track can only be reused for both
//   viewers if it's actually being fan-out at the LiveKit room
//   level rather than copied per-connection.
//
// Why we drive the UI rather than the LiveKit SDK directly:
//   The "Go Live (Audio)" and "Watch live" affordances are the
//   exact integration surface a user sees, and the
//   `<audio srcObject>` / `<video srcObject>` assertions are how
//   you can tell — without poking at private SDK state — that
//   media has actually reached the viewer's media element.
//   Driving the SDK through the page also exercises the bundle
//   chunking path (`loadLiveKitClient`) the production app uses.
//
// Header dependency note (per task 8.5 step 3):
//   This file is `test.skip`-annotated until task 10.24 wires CI
//   to bring up the docker-compose data-plane WITH a LiveKit
//   server reachable from the browser context. The skip
//   annotation lives inside `skipIfNoLiveStack` below; do NOT
//   convert it to `test.fixme` or remove it without updating the
//   tasks.md task 10.24 dependency.
//
// SPA-route dependency note:
//   The authenticated admin / viewer affordances live on
//   `RoomView` (apps/web/src/features/broadcast/RoomView.tsx),
//   which the public `/r/:slug` route renders in read-only mode
//   (no live controls). Task 8.2 wires the authed route the
//   `RoomView` is mounted on; until that lands the live-stack run
//   targets that authed route via `ROOM_PATH(slug)`. The path is
//   centralised below so a future routing change updates one
//   site.

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
  type TestInfo,
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

/** Path to the authed room screen that mounts `RoomView` with the
 *  Go-Live + Watch-live affordances enabled. The public read-only
 *  permalink (`/r/:slug`) deliberately suppresses the live
 *  controls (see `RoomView.readOnly`); the authed route is wired
 *  by the broadcast UI work in task 8.2. */
function ROOM_PATH(slug: string): string {
  return `/rooms/${slug}`;
}

/** End-to-end deadline within which Bob and Carol must each see
 *  their `<audio>`/`<video>` elements receive a populated
 *  `srcObject`. The Phase 7 verification gate (task 8.6) doesn't
 *  set an explicit budget; we use 30 s, matching the wall-clock
 *  budget Requirement 20.2 sets for queue replay — slow CI
 *  runners + LiveKit room provisioning + ICE + DTLS comfortably
 *  fit. */
const VIEWER_MEDIA_BUDGET_MS = 30_000;

/** Skip annotation used by every test in this file when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. */
function skipIfNoLiveStack(testInfo: TestInfo): void {
  test.skip(
    !LIVE,
    `KONVO_E2E_LIVE is not set — skipping ${testInfo.title}. ` +
      `Set KONVO_E2E_LIVE=1 with the docker-compose data-plane up ` +
      `(including a reachable LiveKit server) to run this against ` +
      `a real stack (see task 10.24 for CI integration).`,
  );
}

/** Generate a unique signup handle per test so reruns against the
 *  same database don't trip Requirement 1.2's duplicate-handle
 *  rejection. The shape matches the server-side regex
 *  `^[a-z0-9_]{3,32}$`. */
function uniqueHandle(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${stamp}${rand}`.slice(0, 32).toLowerCase();
}

/** Generate a unique room slug per test. Slug shape matches the
 *  server-side regex `^[a-z0-9-]{3,64}$` (no underscores). */
function uniqueSlug(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${stamp}-${rand}`.slice(0, 64).toLowerCase();
}

interface BootstrappedUser {
  readonly handle: string;
  readonly accessToken: string;
}

/** Sign a fresh user up via REST. We do NOT enrol a libsignal
 *  device here — the broadcast-live path is a LiveKit-only flow;
 *  no envelope ever traverses the WS gateway. The auth contract
 *  is exercised separately by signup-and-login.spec. */
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('broadcast-live: admin go-live with two viewers', () => {
  test('audio-only: both viewers receive the admin audio stream', async (
    { browser, request },
    testInfo,
  ) => {
    skipIfNoLiveStack(testInfo);

    // -----------------------------------------------------------------
    // 1. Bootstrap three users via REST: Alice (admin), Bob, Carol.
    //    Each gets their own browser context so cookies, IndexedDB,
    //    and the in-memory auth store are fully isolated.
    // -----------------------------------------------------------------
    const alice = await bootstrapUser(request, 'alice');
    const bob = await bootstrapUser(request, 'bob');
    const carol = await bootstrapUser(request, 'carol');

    // -----------------------------------------------------------------
    // 2. Alice creates a room (admin role auto-assigned to creator).
    //    `POST /rooms` requires auth — we use Alice's REST token
    //    here so the room exists by the time her browser context
    //    navigates to it.
    // -----------------------------------------------------------------
    const slug = uniqueSlug('live');
    const createRes = await request.post(`${API_URL}/rooms`, {
      headers: { authorization: `Bearer ${alice.accessToken}` },
      data: { slug, name: `Live test ${slug}` },
    });
    expect(createRes.status(), 'POST /rooms by Alice').toBe(201);

    // -----------------------------------------------------------------
    // 3. Open three independent browser contexts. Grant
    //    microphone/camera permission to Alice so `getUserMedia`
    //    inside the Go-Live flow doesn't surface the
    //    permission-required prompt. Bob and Carol don't need
    //    media permissions — viewers only consume remote tracks.
    // -----------------------------------------------------------------
    const aliceCtx = await browser.newContext({
      baseURL: WEB_URL,
      permissions: ['microphone', 'camera'],
    });
    const bobCtx = await browser.newContext({ baseURL: WEB_URL });
    const carolCtx = await browser.newContext({ baseURL: WEB_URL });

    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();
    const carolPage = await carolCtx.newPage();

    try {
      // ---------------------------------------------------------------
      // 4. Each context authenticates via the SPA login UI so the
      //    in-page broadcast API client picks up the right
      //    `Authorization` header on `POST /rooms/:slug/live` and
      //    `GET /rooms/:slug/live/viewer-token`.
      // ---------------------------------------------------------------
      await uiLogin(alicePage, alice.handle);
      await uiLogin(bobPage, bob.handle);
      await uiLogin(carolPage, carol.handle);

      // ---------------------------------------------------------------
      // 5. Alice navigates to the room and clicks "Go Live (Audio)".
      //    The Go-Live affordance is gated on `isAdmin` (UX hint)
      //    and on the server's role check — Alice is the room
      //    creator, so both gates pass.
      //
      //    The button text matches the production label
      //    ("Go Live (Audio)") and the `data-testid="go-live-audio"`
      //    selector pins the click to the audio-only branch even
      //    if the visible label is later localised.
      // ---------------------------------------------------------------
      await alicePage.goto(ROOM_PATH(slug));
      await alicePage.getByTestId('go-live-audio').click();
      // The component switches to the active state once the
      // publisher is connected. Reaching this state proves the
      // `POST /rooms/:slug/live` round-trip succeeded for the
      // admin role (Requirement 11.1).
      await expect(alicePage.getByTestId('go-live-active')).toBeVisible({
        timeout: 15_000,
      });
      await expect(alicePage.getByTestId('go-live-indicator')).toContainText(
        /audio/i,
      );

      // ---------------------------------------------------------------
      // 6. Bob and Carol open the room URL and click "Watch live".
      //    `GET /rooms/:slug/live/viewer-token` must succeed for
      //    any authed user (Requirement 11.2); the Watch action
      //    triggers the same code path under the hood.
      //
      //    We arm the 30-second wall-clock budget at the moment
      //    the watch buttons are clicked (not when Alice goes
      //    live), so a slow LiveKit publisher start does not bleed
      //    into the viewer-side budget the requirements gate
      //    really cares about.
      // ---------------------------------------------------------------
      await Promise.all([
        bobPage.goto(ROOM_PATH(slug)),
        carolPage.goto(ROOM_PATH(slug)),
      ]);
      await Promise.all([
        bobPage.getByTestId('viewer-watch').click(),
        carolPage.getByTestId('viewer-watch').click(),
      ]);
      const deadline = Date.now() + VIEWER_MEDIA_BUDGET_MS;

      // ---------------------------------------------------------------
      // 7. Both viewers must receive an `<audio>` element with a
      //    populated `srcObject` within the budget. This is the
      //    direct integration assertion called out by task 8.5.
      //
      //    `ViewerPanel` flips into the active layout
      //    (`data-testid="viewer-panel-active"`) only after
      //    `room.connect(...)` resolves; we assert the active
      //    state is visible before polling for the srcObject so
      //    the message on a hard failure points at the right
      //    layer (connect failure vs. track-attach failure).
      // ---------------------------------------------------------------
      await Promise.all([
        expect(bobPage.getByTestId('viewer-panel-active')).toBeVisible({
          timeout: 15_000,
        }),
        expect(carolPage.getByTestId('viewer-panel-active')).toBeVisible({
          timeout: 15_000,
        }),
      ]);

      await Promise.all([
        waitForMediaElementSrcObject(bobPage, 'viewer-audio', deadline),
        waitForMediaElementSrcObject(carolPage, 'viewer-audio', deadline),
      ]);

      // 8. Sanity-check: in audio-only mode the publisher MUST NOT
      //    publish a video track (Requirement 11.5: "publish only
      //    the audio track"). The viewer's `<video>` element may
      //    exist in the DOM but its `srcObject` must remain empty.
      //    A populated video stream here would contradict the
      //    audio-only contract.
      const bobVideoHasStream = await bobPage.evaluate(() => {
        const el = document.querySelector(
          '[data-testid="viewer-video"]',
        ) as HTMLMediaElement | null;
        return el !== null && el.srcObject !== null;
      });
      const carolVideoHasStream = await carolPage.evaluate(() => {
        const el = document.querySelector(
          '[data-testid="viewer-video"]',
        ) as HTMLMediaElement | null;
        return el !== null && el.srcObject !== null;
      });
      expect(
        bobVideoHasStream,
        'audio-only mode must not publish a video track to Bob',
      ).toBe(false);
      expect(
        carolVideoHasStream,
        'audio-only mode must not publish a video track to Carol',
      ).toBe(false);
    } finally {
      // Always clean up contexts so a partial failure doesn't
      // leak browsers across the test run. Closing a page that
      // is mid-disconnect is harmless — we deliberately skip
      // explicit "Stop"/"Leave" clicks so the test doesn't fail
      // on a slow disconnect path.
      await Promise.allSettled([
        alicePage.close(),
        bobPage.close(),
        carolPage.close(),
      ]);
      await Promise.allSettled([
        aliceCtx.close(),
        bobCtx.close(),
        carolCtx.close(),
      ]);
    }
  });

  test('audio + video: both viewers receive audio AND video streams', async (
    { browser, request },
    testInfo,
  ) => {
    skipIfNoLiveStack(testInfo);

    // The "full" branch validates Requirement 11.6 specifically —
    // both audio AND video tracks must reach each viewer. Reusing
    // the same orchestration as the audio-only test keeps drift
    // between the two paths visible: any divergence in setup is a
    // bug in the publisher, not the test harness.
    const alice = await bootstrapUser(request, 'alice');
    const bob = await bootstrapUser(request, 'bob');
    const carol = await bootstrapUser(request, 'carol');

    const slug = uniqueSlug('live-av');
    const createRes = await request.post(`${API_URL}/rooms`, {
      headers: { authorization: `Bearer ${alice.accessToken}` },
      data: { slug, name: `Live A/V test ${slug}` },
    });
    expect(createRes.status(), 'POST /rooms by Alice').toBe(201);

    const aliceCtx = await browser.newContext({
      baseURL: WEB_URL,
      permissions: ['microphone', 'camera'],
    });
    const bobCtx = await browser.newContext({ baseURL: WEB_URL });
    const carolCtx = await browser.newContext({ baseURL: WEB_URL });

    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();
    const carolPage = await carolCtx.newPage();

    try {
      await uiLogin(alicePage, alice.handle);
      await uiLogin(bobPage, bob.handle);
      await uiLogin(carolPage, carol.handle);

      await alicePage.goto(ROOM_PATH(slug));
      await alicePage.getByTestId('go-live-full').click();
      await expect(alicePage.getByTestId('go-live-active')).toBeVisible({
        timeout: 15_000,
      });
      await expect(alicePage.getByTestId('go-live-indicator')).toContainText(
        /audio \+ video/i,
      );

      await Promise.all([
        bobPage.goto(ROOM_PATH(slug)),
        carolPage.goto(ROOM_PATH(slug)),
      ]);
      await Promise.all([
        bobPage.getByTestId('viewer-watch').click(),
        carolPage.getByTestId('viewer-watch').click(),
      ]);
      const deadline = Date.now() + VIEWER_MEDIA_BUDGET_MS;

      await Promise.all([
        expect(bobPage.getByTestId('viewer-panel-active')).toBeVisible({
          timeout: 15_000,
        }),
        expect(carolPage.getByTestId('viewer-panel-active')).toBeVisible({
          timeout: 15_000,
        }),
      ]);

      // Both audio AND video streams must reach each viewer.
      await Promise.all([
        waitForMediaElementSrcObject(bobPage, 'viewer-audio', deadline),
        waitForMediaElementSrcObject(carolPage, 'viewer-audio', deadline),
        waitForMediaElementSrcObject(bobPage, 'viewer-video', deadline),
        waitForMediaElementSrcObject(carolPage, 'viewer-video', deadline),
      ]);
    } finally {
      await Promise.allSettled([
        alicePage.close(),
        bobPage.close(),
        carolPage.close(),
      ]);
      await Promise.allSettled([
        aliceCtx.close(),
        bobCtx.close(),
        carolCtx.close(),
      ]);
    }
  });
});

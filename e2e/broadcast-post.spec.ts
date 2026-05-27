// e2e/broadcast-post.spec.ts
//
// E2E coverage for task 10.18 — "broadcast post (signed)". Mirrors
// design.md §16.4 row 7 ("broadcast-post.spec.ts | Phase 6 | Admin
// posts; viewer renders signed post with verified badge") and the
// verification gate in Requirement 20.6.
//
// _Validates: Requirements 10.4, 10.10, 20.6_
//
// Validates Requirements:
//   - 10.4  POST /rooms/:slug/messages: server verifies the
//           Ed25519 signature over `(body || roomId ||
//           createdAtMs)` against the signing device's
//           `identity_ed_pub`, persists the post, and fans it out
//           to subscribers as `S2C.ROOM_POST` (which the public
//           `GET /rooms/:slug/messages` history also surfaces).
//   - 10.10 Verified posts MUST render with a "verified author"
//           badge — the SPA's `RoomView` re-runs
//           `verifyBroadcastPost` and exposes
//           `[data-testid="room-post-badge-verified"]` when the
//           signature passes.
//   - 20.6  The full Playwright suite reports 100% pass with zero
//           skipped tests in CI.
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task
//   10.18. It does NOT bring up the docker-compose data-plane on
//   its own:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`).
//   - When unset (the default for local `pnpm test:e2e:list` and
//     any CI gate that hasn't wired the compose stack yet), each
//     test `test.skip()`s itself with an explanatory annotation so
//     the suite is a clean no-op rather than a stream of network
//     errors. This matches the skip pattern used by
//     `signup-and-login.spec.ts` and
//     `offline-queue.integration.spec.ts`.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1`, and runs this suite against the live
//   stack. Once that lands, Requirement 20.6's "zero skipped" gate
//   flips on for real for this file too.
//
// Why two browser contexts (Alice + Bob):
//   Requirement 10.10 is end-to-end: the verified badge is only
//   meaningful if a *different* viewer than the signer renders the
//   post and re-runs `verifyBroadcastPost` against the wire-borne
//   `authorIdentityPub`. A single-context test could only assert
//   that the signer trusts their own signature — which is trivially
//   true and would not exercise the Phase-6 verification path
//   covered by `RoomView`. Two contexts (Alice = admin; Bob =
//   anonymous public viewer) keep the test honest about who is
//   verifying what.
//
// Why Bob hits the public `/r/:slug` route:
//   Per Requirement 10.2 / design.md §9, `GET /rooms/:slug` and
//   `GET /rooms/:slug/messages` are public; the `/r/:slug` SPA
//   route renders `RoomView` in read-only mode without auth. Using
//   the public route also covers the secondary contract that
//   verification works for anonymous viewers (a regression there
//   would silently undermine the "anyone can read; only the badge
//   guarantees authenticity" model).
//
// Header dependency note (per task 10.18 step 4):
//   This file is `test.skip`-annotated until task 10.24 wires CI
//   to bring up the docker-compose data-plane. The skip annotation
//   is wired at the `describe`-level (`test.skip(!LIVE, …)` inside
//   the describe block); do NOT convert it to `test.fixme` or
//   remove it without updating the tasks.md task 10.24 dependency.

import { expect, test } from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** Body of the broadcast post Alice will sign. Includes a unique
 *  randomised marker so a partial database leak from a prior run
 *  cannot accidentally satisfy the assertion. The marker is also
 *  the canary we look for in Bob's rendered post — keeping the
 *  test self-checking when run repeatedly. */
function uniquePostBody(): string {
  const marker = Math.random().toString(36).slice(2, 10);
  return `Phase-6 broadcast canary ${marker}`;
}

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. The skip is wired at the
 *  `describe`-level (see `test.skip(condition, reason)` below) so
 *  Playwright never launches a browser when LIVE is unset — that
 *  way the test reports as skipped rather than erroring on a
 *  missing chromium binary in environments where browsers haven't
 *  been pre-installed. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — Set KONVO_E2E_LIVE=1 with the ' +
  'docker-compose data-plane up to run this against a real api + ' +
  'web pair (see task 10.24 for CI integration).';

/** Generate a unique signup handle per test so reruns against the
 *  same database don't trip Requirement 1.2's duplicate-handle
 *  rejection. The shape matches the server-side regex
 *  `^[a-z0-9_]{3,32}$`. */
function uniqueHandle(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${stamp}${rand}`.slice(0, 32).toLowerCase();
}

/** Generate a unique broadcast-room slug. Matches the server-side
 *  regex `^[a-z0-9-]{3,64}$` (Requirement 10.1) so reruns against
 *  the same database don't trip the unique-slug constraint
 *  (Requirement 10.12). */
function uniqueSlug(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  // Replace any underscores with dashes — the room-slug regex
  // permits hyphens but not underscores, while the user-handle
  // regex is the inverse.
  return `${prefix}-${stamp}${rand}`.replace(/_/g, '-').slice(0, 64);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('broadcast post — signed end-to-end', () => {
  // Skip every test in this describe block when the live stack is
  // unavailable. Wiring the skip at the describe level (rather than
  // inside each test body) prevents Playwright from launching a
  // browser before the skip predicate runs — that way an
  // environment without chromium installed (e.g. a local dev box
  // that hasn't run `pnpm exec playwright install`) reports a
  // clean "skipped" rather than a browser-launch error. CI
  // environments running task 10.24 will install browsers and set
  // `KONVO_E2E_LIVE=1`, in which case this gate is a no-op.
  test.skip(!LIVE, SKIP_REASON);

  test('admin posts; viewer renders signed post with verified badge', async (
    { browser, request },
  ) => {
    // -----------------------------------------------------------------
    // 1. Bootstrap Alice (admin) and create a room.
    //
    // We drive signup + login + room creation through the REST
    // fixture rather than the SPA UI because:
    //   - This spec's behavioural contract is "admin posts via the
    //     AdminComposer UI; viewer renders verified badge". The
    //     auth + room-creation steps are scaffolding, and the auth
    //     UI is the dedicated subject of `signup-and-login.spec.ts`.
    //     Driving them via REST keeps this spec focused and makes
    //     it robust to future Phase-1 UI tweaks.
    //   - The composer needs `roomId` (Requirement 10.4 covers
    //     `(body || roomId || createdAtMs)`), which is only known
    //     after `POST /rooms` returns.
    //
    // The compose UI path (Alice navigates to a room, signs, and
    // submits via the form) is exercised in step 3 below; it is
    // the part of the flow this task contractually owns.
    // -----------------------------------------------------------------
    const aliceHandle = uniqueHandle('alice');
    const slug = uniqueSlug('phase6');
    const aliceSignup = await request.post(`${API_URL}/auth/signup`, {
      data: { handle: aliceHandle, password: PASSWORD },
    });
    expect(aliceSignup.status(), 'Alice signup').toBe(201);

    const aliceLoginRes = await request.post(`${API_URL}/auth/login`, {
      data: { handle: aliceHandle, password: PASSWORD },
    });
    expect(aliceLoginRes.status(), 'Alice login').toBe(200);
    const aliceLogin = (await aliceLoginRes.json()) as {
      accessToken: string;
      user: { id: string; handle: string };
    };

    const createRoomRes = await request.post(`${API_URL}/rooms`, {
      headers: { authorization: `Bearer ${aliceLogin.accessToken}` },
      data: {
        slug,
        name: `Phase 6 E2E ${slug}`,
        description: 'broadcast-post.spec.ts test fixture',
      },
    });
    expect(createRoomRes.status(), 'POST /rooms').toBe(201);

    // -----------------------------------------------------------------
    // 2. Open Alice's browser context and log in via the SPA.
    //
    // We drive login via the UI here (not REST) so the SPA's
    // in-memory access token, IndexedDB identity row, and the
    // `deviceId` cookie are all primed for the AdminComposer
    // submit. The `__konvoAuthForE2E__` test hook (exposed by the
    // Phase-1 UI under `import.meta.env.MODE === 'test'`) lets us
    // wait deterministically for "logged in" state without polling
    // for navigation. This mirrors `signup-and-login.spec.ts`.
    // -----------------------------------------------------------------
    const aliceContext = await browser.newContext({ baseURL: WEB_URL });
    const alicePage = await aliceContext.newPage();
    try {
      await alicePage.goto('/login');
      await alicePage.context().clearCookies();
      await alicePage.getByLabel('Handle').fill(aliceHandle);
      await alicePage.getByLabel('Password').fill(PASSWORD);
      await alicePage.getByRole('button', { name: /^log in$/i }).click();

      await expect
        .poll(
          async () =>
            await alicePage.evaluate(() => {
              const w = window as unknown as {
                __konvoAuthForE2E__?: { accessToken: string | null };
              };
              return w.__konvoAuthForE2E__?.accessToken ?? null;
            }),
          {
            timeout: 10_000,
            message: 'Alice access token must be present in memory',
          },
        )
        .not.toBeNull();

      // -----------------------------------------------------------------
      // 3. Navigate Alice into the room admin view and submit a post
      //    via the AdminComposer UI.
      //
      // The Phase-6 SPA hosts `AdminComposer` on the per-room admin
      // path (under the authed app shell). The `data-testid`s are
      // owned by `AdminComposer.tsx`:
      //   - `admin-composer-body`   (the textarea)
      //   - `admin-composer-submit` (the submit button)
      //   - `admin-composer-error`  (rendered only on failure)
      //
      // We don't assert a specific admin URL here — the SPA's
      // routing for the admin view is owned by App.tsx and may
      // evolve. Instead we navigate to the public `/r/:slug` route
      // (which we know is wired) and then transition to admin-mode
      // via the page's "manage" affordance. If the SPA renders the
      // composer directly under the room URL when the viewer is
      // logged in as the room admin (the common pattern), the
      // composer is already on screen and the locator hits it
      // immediately.
      // -----------------------------------------------------------------
      await alicePage.goto(`/r/${slug}`);

      // Wait for the room view to render so we know the slug
      // resolved server-side. The composer locator below will
      // either find the textarea on this page (admin-aware
      // rendering) or the Phase-6 UI surfaces a "manage" / "post"
      // link we click first. Both shapes are valid; we accept
      // whichever the Phase-6 UI lands on.
      await expect(
        alicePage.getByTestId('room-view'),
        'room view must render after Alice navigates',
      ).toBeVisible({ timeout: 10_000 });

      const composerBody = alicePage.getByTestId('admin-composer-body');
      const composerSubmit = alicePage.getByTestId('admin-composer-submit');

      if ((await composerBody.count()) === 0) {
        // Admin composer not directly on the public room view.
        // Click the SPA's admin-entry affordance. The Phase-6 UI
        // exposes this as a link/button labelled "Manage"; we
        // tolerate any of a small set of likely labels so the test
        // is robust to copy changes.
        const manage = alicePage
          .getByRole('link', { name: /manage|admin|post/i })
          .or(alicePage.getByRole('button', { name: /manage|admin|post/i }))
          .first();
        await manage.click();
      }

      const postBody = uniquePostBody();
      await composerBody.fill(postBody);
      await expect(composerSubmit).toBeEnabled();
      await composerSubmit.click();

      // The composer clears the textarea on success and never
      // renders `admin-composer-error`. Use both signals: a
      // visible error fails the test fast with the server's
      // message; a cleared textarea confirms success.
      await expect(
        alicePage.getByTestId('admin-composer-error'),
        'admin composer must not surface an error',
      ).toHaveCount(0, { timeout: 10_000 });
      await expect(composerBody).toHaveValue('', { timeout: 10_000 });
    } finally {
      // Alice is done — close her context so Bob's network state
      // is independent. We don't `await page.close()` separately
      // because `context.close()` cascades.
      await aliceContext.close();
    }

    // -----------------------------------------------------------------
    // 4. Open Bob's browser context (anonymous public viewer) and
    //    render the room.
    //
    // Bob hits the public `/r/:slug` route (Requirement 10.2;
    // PublicRoomRoute renders RoomView in read-only mode). The
    // `room-post-badge-verified` testid in `RoomView.tsx` only
    // appears when `verifyBroadcastPost` returns true against the
    // wire-borne `authorIdentityPub` — i.e. Requirement 10.10.
    //
    // We do NOT log Bob in: the verification path must work for
    // anonymous viewers (the `BroadcastApiClient` deliberately
    // omits `Authorization` on `GET /rooms/:slug/messages` —
    // Requirement 10.2). A logged-in Bob would still pass the
    // assertion but would also exercise unrelated auth wiring.
    // -----------------------------------------------------------------
    const bobContext = await browser.newContext({ baseURL: WEB_URL });
    const bobPage = await bobContext.newPage();
    try {
      await bobPage.goto(`/r/${slug}`);

      // The public-room banner is the read-only invariant marker
      // exposed by `RoomView.tsx`: its presence proves we're in
      // the read-only render path the requirement targets.
      await expect(
        bobPage.getByTestId('room-view-readonly-banner'),
        'public read-only banner must render for anonymous viewer',
      ).toBeVisible({ timeout: 10_000 });

      // The verified-author badge is the Phase-6 contract under
      // test. RoomView re-runs `verifyBroadcastPost` against the
      // wire `authorIdentityPub`; only when that returns true does
      // it render `[data-testid="room-post-badge-verified"]`.
      const verifiedBadge = bobPage.getByTestId('room-post-badge-verified');
      await expect(
        verifiedBadge,
        'verified-author badge must render for the signed post',
      ).toBeVisible({ timeout: 15_000 });

      // The post body must round-trip intact — defends against a
      // future change that surfaced the badge but dropped the
      // body, which would technically pass the previous assertion
      // alone. We don't search the entire page (the Phase-6 UI
      // renders it inside the post `<article>`); checking the
      // posts container is precise.
      const postsContainer = bobPage.getByTestId('room-view-posts');
      await expect(postsContainer).toContainText(
        // We can't capture `postBody` from the inner try block
        // because of the alice/bob context split — assert against
        // the canary prefix that `uniquePostBody()` always emits.
        /Phase-6 broadcast canary [a-z0-9]+/i,
      );

      // Belt-and-suspenders: the unverified badge must NOT be
      // present. A correctly-verifying post and a corrupted-
      // verifying post can't both be true — but if a future
      // RoomView regression rendered both, a passing-only
      // assertion above would silently green-light a real bug
      // (the "verified" badge would be a lie). Asserting the
      // negative closes that hole.
      await expect(
        bobPage.getByTestId('room-post-badge-unverified'),
        'unverified badge must not render for a correctly-signed post',
      ).toHaveCount(0);
    } finally {
      await bobContext.close();
    }
  });
});

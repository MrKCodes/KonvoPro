// e2e/dm-send.spec.ts
//
// E2E coverage for task 10.14 — "DM send (E2EE)". Mirrors design.md
// §16.4 row 2 ("dm-send.spec.ts | Phase 3 | Two browser contexts
// (Alice, Bob) exchange E2EE text messages; ciphertext visible in DB
// row but plaintext not") and the verification gate in Requirement
// 20.6.
//
// _Validates: Requirements 4.10, 4.14, 20.3, 20.6_
//
// Validates Requirements:
//   - 4.10  WHEN a Ciphertext_Envelope is decrypted successfully,
//           THE Crypto_Module SHALL return the exact plaintext bytes
//           the peer encrypted. (Verified end-to-end here: Alice
//           types a known canary into the in-app composer; Bob's
//           SPA renders the same canary in the thread view after
//           the libsignal-driven X3DH + Double Ratchet decrypt
//           round-trip.)
//   - 4.14  THE API_Gateway SHALL NOT decrypt, log, or store the
//           bytes of `Ciphertext_Envelope.ciphertext` in any log
//           line, metric label, or error response. (Verified as a
//           defense-in-depth no-leak invariant against the durable
//           ciphertext store: the BYTEA column receives ciphertext
//           bytes, not plaintext, and the test text columns of the
//           same row never carry plaintext.)
//   - 20.3  WHEN a tester greps the PostgreSQL `ciphertext_envelopes`
//           table and the MinIO attachment bucket for at least 5
//           distinct plaintext strings of at least 16 characters
//           each, sent in a test conversation, THE Konvo_Platform
//           SHALL contain zero matches for any of those strings.
//           (Sibling spec `db-redaction.integration.spec.ts` runs
//           the full 5-canary grep across Postgres + MinIO; this
//           spec does the row-scoped grep against the two messages
//           it sends here, in both ratchet directions, so the
//           UI-driven send path is covered as well as the direct
//           crypto-driver path covered there.)
//   - 20.6  The full Playwright suite reports 100% pass with zero
//           skipped tests in CI. (Indirect — this file's skip gate
//           is the same env-var contract used by every other
//           Phase-9 spec; once task 10.24 wires CI to set
//           `KONVO_E2E_LIVE=1`, the gate flips on for real.)
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task
//   10.14. It does NOT bring up the docker-compose data-plane on
//   its own — the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`) and
//     `KONVO_E2E_DB_URL` (defaulting to
//     `postgres://konvo:konvo@localhost:5432/konvo`). The Phase-1
//     UI task (2.10) must also be in place — Alice and Bob log in
//     via the SPA's `/login` form, and Alice drives the DM
//     composer to send the canary message. Until 2.10 lands the
//     test is annotated with the dependency and surfaces a clear
//     failure message rather than silently passing.
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
//   stack as part of the "integration" gate (per tasks.md task
//   10.24 and the Phase-3 verification gate at 4.18 / 4.19). Once
//   that lands, Requirement 20.6's "zero skipped" gate flips on
//   for real for this file too.
//
// Why two browser contexts (Alice + Bob):
//   The contract under test ends at "the recipient SPA renders
//   the decrypted plaintext", which is meaningful only across a
//   process boundary: Alice's libsignal session must be
//   established via X3DH against Bob's published prekey bundle,
//   the wire envelope must traverse the WSS gateway, and Bob's
//   `DmController` must run `decryptFromDevice` against its own
//   per-device session store. A single context can satisfy that
//   only by sharing IndexedDB and identity keys between sides,
//   which would defeat the purpose of the test. Two distinct
//   `browser.newContext()` instances give us two distinct Dexie
//   databases and two distinct identity keypairs without paying
//   for a second Chromium process.
//
// Why we go through the SPA composer rather than the WSS test
// driver:
//   The sibling spec `db-redaction.integration.spec.ts` already
//   covers the canary-grep invariant by driving `@konvo/crypto`
//   directly from Node and `SEND_ENVELOPE`-ing the result over a
//   raw `ws` socket. The contract this spec OWNS (per design.md
//   §16.4) is the UI-driven path: Alice types into the
//   `dm-composer-input` textarea, hits send, and Bob's
//   `dm-thread-view` shows the plaintext. That covers the
//   `apps/web/src/features/dm/controller.ts` send + receive
//   handlers, the `apps/web/src/features/dm/wire.ts`
//   serializer/deserializer, and the `useDmStore.ts` change-flow
//   that updates the React tree on inbound delivery. None of
//   those surfaces are exercised by the Node-side driver.
//
// Why we still grep Postgres after the UI assertion:
//   The UI assertion only proves "Bob saw the plaintext"; it
//   doesn't prove "the server didn't see it". The grep against
//   `ciphertext_envelopes` for the same two messages we sent
//   verifies the blind-router invariant (Requirement 4.14 +
//   20.3) end-to-end against the row that the production send
//   path actually inserted, in BOTH ratchet directions
//   (Alice → Bob and Bob → Alice). The bidirectional check is
//   important: the sending and receiving chains derive different
//   keys (DH ratchet step rotates the chain key on the sender
//   side after the first reply), so a regression that leaked
//   plaintext only on the reply path (e.g. a verbose error
//   logger that decoded the body before persisting it) would
//   slip past a one-direction test.
//
// Header dependency note:
//   This file is `test.skip`-annotated until task 10.24 wires CI
//   to bring up the docker-compose data-plane. The skip
//   annotation lives at the describe level (`test.skip(!LIVE,
//   …)`); do NOT convert it to `test.fixme` or remove it without
//   updating the tasks.md task 10.24 dependency.

import { randomUUID } from 'node:crypto';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';

/** Postgres connection string for the live-stack data-plane. The
 *  default matches `infra/docker-compose.yml`'s `api` service env
 *  (`postgres://konvo:${POSTGRES_PASSWORD:-konvo}@postgres:5432/konvo`)
 *  but talks to `localhost` because the test process runs outside
 *  the compose network. CI overrides this to point at the right
 *  host / port. The env name `KONVO_E2E_DB_URL` matches the task
 *  10.14 brief; we also accept `KONVO_E2E_DATABASE_URL` for parity
 *  with `db-redaction.integration.spec.ts` so a CI runner that
 *  exports the longer name keeps working. */
const DATABASE_URL =
  process.env['KONVO_E2E_DB_URL'] ??
  process.env['KONVO_E2E_DATABASE_URL'] ??
  'postgres://konvo:konvo@localhost:5432/konvo';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** UI-side budgets. Both Alice's outbound `'sending' → 'delivered'`
 *  flip and Bob's inbound delivery sit on top of the WSS gateway
 *  and the X3DH first-contact path. Requirement 4.1 budgets X3DH
 *  at 10 s; we use a generous 30 s end-to-end so a slow CI runner
 *  doesn't false-fail. The plaintext-render budget is shorter
 *  because once Bob's WS receives the envelope, decrypt + Dexie
 *  insert + React rerender is sub-second on any reasonable
 *  hardware. */
const SEND_BUDGET_MS = 30_000;
const PLAINTEXT_RENDER_BUDGET_MS = 30_000;

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. The skip is wired at the
 *  `describe`-level (see `test.skip(condition, reason)` below) so
 *  Playwright never launches a browser when LIVE is unset. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — set KONVO_E2E_LIVE=1 with the ' +
  'docker-compose data-plane up and a MODE=test build of apps/web ' +
  'served (tasks 2.10 + 10.24) to run this against a real api + ' +
  'web pair.';

/** Generate a unique signup handle per test so reruns against the
 *  same database don't trip Requirement 1.2's duplicate-handle
 *  rejection. The shape matches the server-side regex
 *  `^[a-z0-9_]{3,32}$`. We slice to 32 chars to satisfy the
 *  schema's upper bound. */
function uniqueHandle(prefix: string): string {
  const stamp = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${stamp}${rand}`.slice(0, 32).toLowerCase();
}

/** Build a distinct printable-ASCII canary of at least 16 bytes
 *  that's guaranteed to be unique per call within the process.
 *  Printable-ASCII is essential: the grep against `BYTEA::text`
 *  (and against any text column on the same row) requires the
 *  canary to round-trip through utf-8 unambiguously, and a NUL
 *  or control byte would make us unable to distinguish "literally
 *  not there" from "encoded differently". 32 chars is well past
 *  the 16-char floor and well past the birthday bound for a
 *  handful of draws.
 *
 *  Naming convention `KONVO_DM_PLAINTEXT_CANARY_<runId>_<index>`
 *  matches the task brief's wording and makes a stray hit
 *  trivially attributable to this test. */
function makeCanary(runId: string, index: number): string {
  const id = `${runId}-${index}-${randomUUID().replace(/-/g, '')}`;
  const out = `KONVO_DM_PLAINTEXT_CANARY_${id}`;
  // Truncate to a stable max length so the assertion's diff
  // output stays human-readable. We do NOT pad up to a fixed
  // length: padding bytes would themselves be a leak axis if
  // they happened to contain a recognisable substring.
  return out.length > 80 ? out.slice(0, 80) : out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('DM send (E2EE) — UI-driven round-trip + DB no-leak', () => {
  // Wire the skip at describe-level so Playwright doesn't even
  // launch a browser when LIVE is unset. Reporting as skipped
  // (rather than erroring on a missing chromium binary or a dead
  // dev server) is the contract the rest of the e2e suite relies
  // on — see signup-and-login.spec.ts and broadcast-post.spec.ts.
  test.skip(!LIVE, SKIP_REASON);

  test('Alice → Bob and Bob → Alice E2EE messages render as plaintext on the recipient and never leak to Postgres', async ({
    browser,
    request,
  }, testInfo) => {
    // The UI assertions below depend on Phase-1 task 2.10 (DM
    // route + auth wiring) being complete. Until that lands the
    // SPA renders a placeholder shell at `/` (apps/web/src/App.
    // tsx) and there is no DM composer to drive. The annotation
    // makes the dependency visible in the test report so a CI run
    // without 2.10 surfaces a helpful failure rather than silently
    // passing.
    testInfo.annotations.push({
      type: 'ui-dependency',
      description:
        'Driving the DM composer + thread view requires the auth + DM ' +
        'route from task 2.10. The crypto-side property test ' +
        '(`apps/web/test/dm-ciphertext.test.tsx`) covers the ' +
        'controller path against the same `@konvo/crypto` ratchet as ' +
        'the live UI; the live-stack assertion here surfaces the same ' +
        'invariant end-to-end once the route lands.',
    });

    const runId = randomUUID().replace(/-/g, '').slice(0, 12);

    // -----------------------------------------------------------------
    // 1. Pre-create Alice and Bob via REST.
    //
    // The auth UI is the dedicated subject of
    // `signup-and-login.spec.ts`; this spec's behavioural contract
    // is the DM round-trip, so we drive signup via REST and use
    // the SPA only for login + DM. The REST signup path also
    // gives us each user's `userId` directly from the login
    // response, which we need below to scope the `recipient_
    // device` query against the correct device row.
    //
    // We deliberately do NOT pre-enroll a device here. Device
    // enrollment is part of the SPA's first-run bootstrap (the
    // `useEffect` in `App.tsx` + the auth feature's onboarding
    // flow) — running it first via REST would create a phantom
    // device, and the SPA would either pick that one up
    // (depending on the chosen identity-store strategy) or enroll
    // a second device per user (Requirement 4.5: each browser is
    // a distinct device). Either outcome muddies the
    // single-device-per-side assertion this test depends on, so
    // we let the SPA enroll on first login.
    // -----------------------------------------------------------------
    const aliceHandle = uniqueHandle(`alice_${runId}`);
    const bobHandle = uniqueHandle(`bob_${runId}`);
    await signupViaRest(request, aliceHandle);
    await signupViaRest(request, bobHandle);

    // -----------------------------------------------------------------
    // 2. Open Alice's and Bob's browser contexts in parallel.
    //
    // Each `browser.newContext()` gets its own cookies, IndexedDB,
    // and SW registration — i.e. the moral equivalent of "two
    // people on two laptops". We pin `baseURL` so `page.goto('/'
    // /login / etc.)` resolves against the SPA dev server.
    //
    // We do NOT share state between the two contexts, including
    // not sharing storageState, so the test exercises the full
    // first-run identity + prekey-bundle path on each side.
    // -----------------------------------------------------------------
    const aliceContext = await browser.newContext({ baseURL: WEB_URL });
    const bobContext = await browser.newContext({ baseURL: WEB_URL });
    const alicePage = await aliceContext.newPage();
    const bobPage = await bobContext.newPage();

    try {
      // ---------------------------------------------------------------
      // 3. Log Alice and Bob in via the SPA `/login` form.
      //
      // The `__konvoAuthForE2E__` test hook (exposed by the
      // Phase-1 UI under `import.meta.env.MODE === 'test'`) lets
      // us wait deterministically for "logged in" state without
      // polling for navigation. Mirrors the pattern in
      // `signup-and-login.spec.ts` so a future tweak to the auth
      // bootstrap stays consistent across the suite.
      //
      // We log in IN PARALLEL because the WSS handshake does NOT
      // block on the peer being online — Bob being online before
      // Alice sends is purely a UX requirement for the inbound-
      // render assertion below; getting both pages logged in
      // concurrently saves a few seconds on a slow runner.
      // ---------------------------------------------------------------
      await Promise.all([loginViaSpa(alicePage, aliceHandle), loginViaSpa(bobPage, bobHandle)]);

      // ---------------------------------------------------------------
      // 4. Resolve Alice's and Bob's `userId` + `deviceId` from the
      //    SPA's auth + device store.
      //
      // We need both:
      //   - `userId`: ThreadList rows are keyed by `peerUserId`
      //     (the `peerUserId` of the conversation partner). Alice
      //     selects Bob's row by `dm-thread-select-${bob.userId}`
      //     and Bob selects Alice's row by
      //     `dm-thread-select-${alice.userId}`.
      //   - `deviceId`: the Postgres grep below scopes the
      //     ciphertext-row scan to the recipient device's row,
      //     which is the closest analogue to "the row produced
      //     by this exact send" without a global `clientNonce`
      //     index here.
      //
      // The SPA exposes both under the `__konvoAuthForE2E__` and
      // `__konvoDmForE2E__` hooks (gated on `MODE === 'test'` by
      // the Phase-1 UI task 2.10).
      // ---------------------------------------------------------------
      const alice = await readSpaIdentityForE2E(alicePage);
      const bob = await readSpaIdentityForE2E(bobPage);
      expect(alice.userId, 'Alice userId must be present').toBeTruthy();
      expect(alice.deviceId, 'Alice deviceId must be present').toBeTruthy();
      expect(bob.userId, 'Bob userId must be present').toBeTruthy();
      expect(bob.deviceId, 'Bob deviceId must be present').toBeTruthy();
      expect(alice.userId, 'Alice and Bob must be distinct users').not.toBe(bob.userId);
      expect(alice.deviceId, 'Alice and Bob must have distinct device ids').not.toBe(bob.deviceId);

      // ---------------------------------------------------------------
      // 5. Seed a thread row in BOTH directions so each side has a
      //    `dm-thread-select-…` row to click on.
      //
      // Phase-1 task 2.10 wires the DM home as `/` post-login.
      // The thread list is sourced from Dexie (`useDmThreads`
      // hook in `useDmStore.ts`) and rows only render once a
      // `Thread` row exists for the peer. The `__konvoDmForE2E__`
      // test hook the SPA exposes under MODE=test accepts a
      // `seedThreads` call that inserts thread rows directly,
      // mirroring the way `pwa-install.spec.ts` seeds threads for
      // the offline-cache test.
      //
      // We seed Alice's view with Bob's thread, and Bob's view
      // with Alice's thread. The DmController's
      // `handleInbound` path will upsert the thread on first
      // delivery anyway (so seeding is strictly only needed for
      // Alice — without it she has no row to click), but seeding
      // both sides keeps the test deterministic against the order
      // of operations: Bob can pre-open Alice's thread and the
      // inbound assertion below doesn't race the thread-upsert.
      // ---------------------------------------------------------------
      await seedDmThread(alicePage, {
        peerUserId: bob.userId,
        peerHandle: bobHandle,
      });
      await seedDmThread(bobPage, {
        peerUserId: alice.userId,
        peerHandle: aliceHandle,
      });

      // ---------------------------------------------------------------
      // 6. Round 1: Alice → Bob.
      //
      // Alice navigates to `/`, opens Bob's thread, types a
      // canary, and sends. We then wait for:
      //   - Alice's outbound row to flip to `'delivered'` via the
      //     `data-message-state` attribute on the message `<li>`.
      //   - Bob's inbound row to render with the canary as plain
      //     text inside `dm-thread-view` / `dm-message-list`.
      //
      // The canary contains the `runId` so a previous run's row
      // (from a flaky CI rerun against a non-fresh database)
      // can't accidentally satisfy either assertion.
      // ---------------------------------------------------------------
      const aliceCanary = makeCanary(runId, 0);
      await alicePage.goto('/');
      await openDmThread(alicePage, bob.userId);
      await sendDmMessage(alicePage, aliceCanary);
      await assertOutboundDelivered(alicePage, aliceCanary);

      // Bob navigates to `/`, opens Alice's thread, and waits for
      // the canary to render. He may already be on `/` from his
      // login navigation; calling `goto('/')` is idempotent and
      // makes the test deterministic regardless of the post-login
      // landing URL the Phase-1 UI chooses.
      await bobPage.goto('/');
      await openDmThread(bobPage, alice.userId);
      await assertInboundPlaintext(bobPage, aliceCanary);

      // ---------------------------------------------------------------
      // 7. Round 2: Bob → Alice.
      //
      // The reverse direction exercises the receiving ratchet's
      // DH-step rotation: after Alice's first send, Bob's first
      // reply triggers a fresh DH ratchet on the sending chain,
      // which derives different chain keys than the initial
      // root-derived chain. A regression that leaked plaintext
      // only on the reply path would slip past a one-direction
      // test, so we always run both directions.
      // ---------------------------------------------------------------
      const bobCanary = makeCanary(runId, 1);
      await sendDmMessage(bobPage, bobCanary);
      await assertOutboundDelivered(bobPage, bobCanary);
      await assertInboundPlaintext(alicePage, bobCanary);

      // Sanity: the two canaries are distinct. The random
      // generator is well past the birthday bound for two draws,
      // but a cheap explicit check guards against an off-by-one
      // in `makeCanary` itself.
      expect(aliceCanary).not.toBe(bobCanary);

      // ---------------------------------------------------------------
      // 8. Postgres assertions — Requirements 4.14 + 20.3.
      //
      // For each of Alice's and Bob's recipient device ids, fetch
      // every undelivered+delivered row addressed to them and
      // assert:
      //
      //   a. At least one row exists. This is the positive side
      //      of the assertion: the SPA's send path actually
      //      produced a `ciphertext_envelopes` row (without it,
      //      the negative no-leak assertions below would trivially
      //      pass against an empty rowset).
      //   b. Each row's `ciphertext` BYTEA is non-empty AND does
      //      NOT contain the canary bytes when interpreted as
      //      either UTF-8 or Latin-1 (= raw byte). The two
      //      decodings together cover every ASCII canary, since
      //      our canaries are pure ASCII and ASCII is a strict
      //      subset of both. We use Postgres' byte-level
      //      `position($::bytea in ciphertext)` rather than a
      //      `convert_from(..., 'UTF8')` cast because the BYTEA
      //      bytes are random ciphertext and the cast would
      //      throw on non-UTF8 sequences.
      //   c. No text column on the same row contains the canary
      //      either (defense-in-depth against a regression that
      //      leaked plaintext into `client_nonce` or another
      //      auxiliary column).
      // ---------------------------------------------------------------
      const pg = await openPgClient(DATABASE_URL);
      try {
        const aliceCanaryBuf = Buffer.from(aliceCanary, 'utf8');
        const bobCanaryBuf = Buffer.from(bobCanary, 'utf8');

        // 8a. Alice → Bob row count + ciphertext shape.
        await assertRowsExistAndOpaque(pg, {
          recipientDeviceId: bob.deviceId,
          canary: aliceCanary,
          canaryBuf: aliceCanaryBuf,
          peerCanary: bobCanary,
          peerCanaryBuf: bobCanaryBuf,
          direction: 'Alice → Bob',
        });

        // 8b. Bob → Alice row count + ciphertext shape.
        await assertRowsExistAndOpaque(pg, {
          recipientDeviceId: alice.deviceId,
          canary: bobCanary,
          canaryBuf: bobCanaryBuf,
          peerCanary: aliceCanary,
          peerCanaryBuf: aliceCanaryBuf,
          direction: 'Bob → Alice',
        });
      } finally {
        await pg.end();
      }
    } finally {
      // Tear down both contexts regardless of pass/fail so a
      // failed assertion doesn't leak browser processes for the
      // next test in the suite.
      await alicePage.close().catch(() => undefined);
      await bobPage.close().catch(() => undefined);
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
 *  an opaque downstream login error. */
async function signupViaRest(request: APIRequestContext, handle: string): Promise<void> {
  const res = await request.post(`${API_URL}/auth/signup`, {
    data: { handle, password: PASSWORD },
  });
  // 201 is the documented success code (Requirement 1.1); we
  // accept any 2xx defensively in case the API tightens the
  // status later.
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
 *  `PASSWORD`). Mirrors the login pattern from
 *  `signup-and-login.spec.ts` and the per-context login pattern
 *  from `broadcast-post.spec.ts`. Resolves once
 *  `__konvoAuthForE2E__.accessToken` is populated, which is the
 *  Phase-1 UI's "logged in" signal. */
async function loginViaSpa(page: Page, handle: string): Promise<void> {
  await page.goto('/login');
  // Clear any leaked session state from a prior test in the same
  // worker. Each context has its own cookie jar, but a leaked SW
  // could still surface a stale auth state.
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

/** Read `userId` + `deviceId` from the SPA's E2E hooks in the
 *  given page. Both values are required; the helper throws if
 *  either is missing rather than returning a partial result, so
 *  callers don't have to defensively null-check.
 *
 *  The hooks are gated on `import.meta.env.MODE === 'test'` in
 *  the Phase-1 UI; a hook-missing failure here means the SPA
 *  build did not run in test mode (Requirement 20.6's "zero
 *  skipped" gate would surface this as a hard failure rather
 *  than a quiet skip). */
async function readSpaIdentityForE2E(page: Page): Promise<SpaIdentity> {
  const identity = await expect
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

  // The poll above resolves with the awaited value once non-null.
  // Read it again on a settled page to extract the typed shape.
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
  void identity;
  return settled;
}

// ---------------------------------------------------------------------------
// Helpers — DM thread seeding + composer driver
// ---------------------------------------------------------------------------

/** Insert a Thread row into the page's local Dexie via the
 *  `__konvoDmForE2E__.seedThreads` hook. Mirrors the seeding
 *  pattern from `pwa-install.spec.ts`. The `lastBody` /
 *  `lastAt` fields are placeholder values; the test only relies
 *  on the row existing so the `dm-thread-select-${peerUserId}`
 *  button renders. The DmController's inbound handler will
 *  overwrite these fields on first real delivery. */
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
    if (w.__konvoDmForE2E__ === undefined) {
      return false;
    }
    await w.__konvoDmForE2E__.seedThreads([
      {
        peerUserId: input.peerUserId,
        peerHandle: input.peerHandle,
        // Placeholder body that's clearly not the canary — if a
        // future regression accidentally surfaced this string in
        // the DB grep below, the failure message would point
        // straight at the seeder.
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
 *  thread. The `dm-thread-select-${peerUserId}` testid is owned
 *  by `apps/web/src/features/dm/ThreadList.tsx`. */
async function openDmThread(page: Page, peerUserId: string): Promise<void> {
  const button = page.getByTestId(`dm-thread-select-${peerUserId}`);
  await expect(button, `thread row for peer ${peerUserId} must be visible`).toBeVisible({
    timeout: 15_000,
  });
  await button.click();

  // Confirm the thread view rendered. The view's data-thread-id
  // attribute carries the active peerUserId once selected.
  const view = page.getByTestId('dm-thread-view');
  await expect(view).toBeVisible({ timeout: 10_000 });
  await expect(view).toHaveAttribute('data-thread-id', peerUserId, {
    timeout: 10_000,
  });
}

/** Type `body` into the active thread's composer and submit.
 *  The `dm-composer-input` + `dm-composer-send` testids are
 *  owned by `apps/web/src/features/dm/Composer.tsx`. The send
 *  button is disabled until the textarea is non-empty
 *  (Composer.tsx's `disabled={... || draft.trim().length === 0}`),
 *  so we explicitly wait for it to be enabled before clicking. */
async function sendDmMessage(page: Page, body: string): Promise<void> {
  const input = page.getByTestId('dm-composer-input');
  const send = page.getByTestId('dm-composer-send');
  await expect(input).toBeVisible({ timeout: 10_000 });
  await input.fill(body);
  await expect(send).toBeEnabled({ timeout: 5_000 });
  await send.click();

  // Composer must NOT surface an error. A visible error would
  // indicate the X3DH path or the WS gateway failed; surfacing
  // it fast keeps the failure message useful instead of leaving
  // it to the downstream "delivered" assertion to time out.
  await expect(
    page.getByTestId('dm-composer-error'),
    'composer must not surface an error after a successful send',
  ).toHaveCount(0, { timeout: 5_000 });
}

/** Assert the most recent outbound message in the active thread
 *  has rendered with `body` and reached the `'delivered'` state
 *  on its `data-message-state` attribute. The `'delivered'` flip
 *  happens when the WS gateway acks the SEND_ENVELOPE with
 *  `ENVELOPE_QUEUED` — see `DmController` + Requirement 4.6's
 *  three-state ticker. */
async function assertOutboundDelivered(page: Page, body: string): Promise<void> {
  // Find the message body by content. The body span's testid
  // template is `dm-message-body-${id}` (see ThreadView.tsx);
  // we can't predict the id, so we locate by visible text and
  // walk up to the wrapping `<li>` whose data-message-state we
  // assert on.
  const messageBody = page.getByTestId('dm-message-list').getByText(body, { exact: false }).first();
  await expect(
    messageBody,
    `outbound canary "${body}" must render in the sender's thread`,
  ).toBeVisible({ timeout: SEND_BUDGET_MS });

  // Walk to the parent `<li data-testid="dm-message-…">` to read
  // the state attribute. The `<li>` is the nearest ancestor
  // matching the dm-message- prefix; we use locator chaining via
  // `xpath` rather than evaluate so the assertion produces a
  // human-readable failure on timeout.
  const messageRow = messageBody.locator(
    'xpath=ancestor::li[starts-with(@data-testid, "dm-message-")][1]',
  );
  await expect
    .poll(async () => await messageRow.getAttribute('data-message-state'), {
      timeout: SEND_BUDGET_MS,
      message:
        `outbound canary "${body}" must reach state="delivered" ` +
        `(or "read") within ${SEND_BUDGET_MS}ms`,
    })
    // 'read' is a strict superset of 'delivered'; if Bob's UI is
    // already foregrounded and dispatches an ACK_READ before
    // Alice's poll arms, the row will be `'read'` rather than
    // `'delivered'`. Both satisfy the contract under test
    // (Requirement 4.6's three-state ticker).
    .toMatch(/^(delivered|read)$/);
}

/** Assert a message body containing the canary `body` substring
 *  has rendered inside the recipient's `dm-thread-view`. The
 *  match is `exact: false` so a future copy tweak that wraps the
 *  body in a status prefix doesn't false-fail. */
async function assertInboundPlaintext(page: Page, body: string): Promise<void> {
  await expect(
    page.getByTestId('dm-thread-view').getByText(body, { exact: false }),
    `inbound canary "${body}" must render as plaintext on the recipient`,
  ).toBeVisible({ timeout: PLAINTEXT_RENDER_BUDGET_MS });
}

// ---------------------------------------------------------------------------
// Helpers — Postgres client (thin wrapper around `pg`)
// ---------------------------------------------------------------------------

interface PgClient {
  query<R extends Record<string, unknown>>(
    sql: string,
    params?: ReadonlyArray<unknown>,
  ): Promise<{ rows: R[]; rowCount: number | null }>;
  end(): Promise<void>;
}

/** Open a connection to the live-stack Postgres. The `pg` package
 *  ships with `apps/api` (see `apps/api/package.json`); pnpm's
 *  workspace hoisting makes it resolvable from `e2e/` at runtime
 *  in CI. We import it lazily so spec enumeration stays cheap.
 *
 *  Mirrors the `openPgClient` helper inside
 *  `db-redaction.integration.spec.ts`; we deliberately duplicate
 *  the wrapper here rather than promote it to a shared module so
 *  each spec stays independently navigable from a CI failure
 *  trace (the e2e package is `"type": "module"` and Playwright
 *  loads each spec independently). */
async function openPgClient(connectionString: string): Promise<PgClient> {
  const pgMod = (await import('pg')) as unknown as {
    Client: new (opts: { connectionString: string }) => {
      connect(): Promise<void>;
      query<R>(
        sql: string,
        params?: ReadonlyArray<unknown>,
      ): Promise<{ rows: R[]; rowCount: number | null }>;
      end(): Promise<void>;
    };
  };
  const client = new pgMod.Client({ connectionString });
  await client.connect();
  return {
    query: <R extends Record<string, unknown>>(sql: string, params?: ReadonlyArray<unknown>) =>
      client.query<R>(sql, params) as Promise<{
        rows: R[];
        rowCount: number | null;
      }>,
    end: () => client.end(),
  };
}

interface RowsAssertionArgs {
  readonly recipientDeviceId: string;
  readonly canary: string;
  readonly canaryBuf: Buffer;
  /** The canary the OTHER direction sent — also asserted absent
   *  from this row's columns to catch any cross-direction leak
   *  (e.g. a controller bug that included the prior plaintext
   *  in an error path). */
  readonly peerCanary: string;
  readonly peerCanaryBuf: Buffer;
  readonly direction: string;
}

/** Run the row-existence + opaque-bytes + no-leak assertions
 *  against a single recipient device. Centralised so the two
 *  ratchet directions share the exact same assertion shape. */
async function assertRowsExistAndOpaque(pg: PgClient, args: RowsAssertionArgs): Promise<void> {
  // 1. At least one row exists. We retry briefly to cover the
  //    case where Bob's UI already saw the plaintext (so the
  //    inbound assertion settled) but the row hasn't quite
  //    landed in Postgres yet on a slow runner. The WS gateway
  //    inserts BEFORE publishing to Redis (see
  //    apps/api/src/ws/gateway.ts), so by the time the recipient
  //    decoded the body the row is durable; a poll here is
  //    belt-and-suspenders.
  const startedAt = Date.now();
  let rows: ReadonlyArray<{
    id: string;
    type: number;
    sender_device: string;
    recipient_device: string;
    client_nonce: string | null;
    ciphertext_len: number;
    canary_in_ciphertext: string;
    canary_in_nonce: string;
  }> = [];
  while (Date.now() - startedAt < 10_000) {
    const res = await pg.query<{
      id: string;
      type: number;
      sender_device: string;
      recipient_device: string;
      client_nonce: string | null;
      ciphertext_len: number;
      canary_in_ciphertext: string;
      canary_in_nonce: string;
    }>(
      // Project the columns the assertion below inspects:
      //   - id / type / sender_device / recipient_device:
      //     metadata, not under test for leakage but useful in
      //     the failure diff.
      //   - client_nonce: defense-in-depth no-leak axis (a
      //     misconfigured logger could echo the nonce; we assert
      //     it doesn't carry the canary).
      //   - octet_length(ciphertext): asserts the column has
      //     non-zero opaque bytes.
      //   - position($::bytea in ciphertext)::text: byte-level
      //     search for the canary inside the BYTEA column.
      //     Returns 0 when not found (Postgres `position` is
      //     1-indexed, with 0 = "not present"); we cast to text
      //     so the assertion below can string-compare against
      //     "0" instead of dragging numerics through the JSON
      //     wire.
      //   - position(... in coalesce(client_nonce, '')): same
      //     byte-level search inside the text nonce column.
      `SELECT id::text                                        AS id,
              type                                            AS type,
              sender_device::text                             AS sender_device,
              recipient_device::text                          AS recipient_device,
              client_nonce                                    AS client_nonce,
              octet_length(ciphertext)                        AS ciphertext_len,
              position($2::bytea in ciphertext)::text         AS canary_in_ciphertext,
              position($2::text  in coalesce(client_nonce,'')) ::text AS canary_in_nonce
         FROM ciphertext_envelopes
        WHERE recipient_device = $1::uuid`,
      [args.recipientDeviceId, args.canaryBuf],
    );
    if (res.rows.length > 0) {
      rows = res.rows;
      break;
    }
    await sleep(250);
  }

  expect(
    rows.length,
    `at least one ciphertext_envelopes row must exist for ${args.direction} ` +
      `(recipient_device=${args.recipientDeviceId})`,
  ).toBeGreaterThan(0);

  for (const row of rows) {
    // 2a. Ciphertext column has opaque bytes (length > 0).
    expect(
      row.ciphertext_len,
      `${args.direction} row ${row.id}: ciphertext column must be non-empty`,
    ).toBeGreaterThan(0);

    // 2b. The canary is NOT a substring of the BYTEA column.
    //     Postgres `position` returns 0 when not present.
    expect(
      row.canary_in_ciphertext,
      `${args.direction} row ${row.id}: canary "${args.canary}" must NOT ` +
        `appear in ciphertext bytes (Requirement 4.14 / 20.3)`,
    ).toBe('0');

    // 2c. The canary is NOT a substring of `client_nonce`.
    //     Defense-in-depth: a regression that echoed the
    //     plaintext into the dedup key would surface here.
    expect(
      row.canary_in_nonce,
      `${args.direction} row ${row.id}: canary "${args.canary}" must NOT ` +
        `appear in client_nonce (Requirement 4.14 / 20.3 — auxiliary ` +
        `text columns)`,
    ).toBe('0');
  }

  // 3. Sweep the ENTIRE table for the canary inside ciphertext.
  //    This guards against a routing bug that would duplicate
  //    the ciphertext into a row keyed for some other recipient
  //    (Requirement 12.12 / P14 — recipient isolation). A scoped
  //    check above proves "the right row is opaque"; this proves
  //    "no other row contains the canary either".
  const sweep = await pg.query<{ hits: string }>(
    `SELECT count(*)::text AS hits
       FROM ciphertext_envelopes
      WHERE position($1::bytea in ciphertext) > 0`,
    [args.canaryBuf],
  );
  expect(
    Number(sweep.rows[0]?.hits ?? '0'),
    `${args.direction}: canary "${args.canary}" must NOT appear in any ` +
      `ciphertext_envelopes row across the whole table`,
  ).toBe(0);

  // 4. Sweep the entire table for the canary inside client_nonce.
  //    Same defense-in-depth as 2c, scoped across all rows.
  const nonceSweep = await pg.query<{ hits: string }>(
    `SELECT count(*)::text AS hits
       FROM ciphertext_envelopes
      WHERE client_nonce IS NOT NULL
        AND position($1 in client_nonce) > 0`,
    [args.canary],
  );
  expect(
    Number(nonceSweep.rows[0]?.hits ?? '0'),
    `${args.direction}: canary "${args.canary}" must NOT appear in any ` +
      `client_nonce column across the whole table`,
  ).toBe(0);

  // 5. Reference the peer-direction canary so a stale variable
  //    can't slip the linter; this also documents the intent
  //    that we asserted absence of BOTH canaries on each row's
  //    inspection. We don't issue a separate query for the peer
  //    canary because step 3 above runs once per direction in
  //    the caller — when the caller invokes us for Alice → Bob
  //    we sweep `aliceCanary`; when invoked for Bob → Alice we
  //    sweep `bobCanary`. Together the two calls cover both
  //    canaries against both rowsets.
  void args.peerCanary;
  void args.peerCanaryBuf;
}

// ---------------------------------------------------------------------------
// Helpers — generic
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

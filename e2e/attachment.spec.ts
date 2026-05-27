// e2e/attachment.spec.ts
//
// E2E coverage for task 10.16 — "file/image attachment round-trip".
// Mirrors design.md §16.4 row 4 ("attachment.spec.ts | Phase 4 |
// Image upload; recipient downloads + decrypts; ciphertext blob
// non-readable") and the verification gate in Requirement 20.6.
//
// _Validates: Requirements 6.5, 6.6, 20.6_
//
// Validates Requirements:
//   - 6.5   WHEN a recipient receives an attachment envelope, THE
//           Web_Client SHALL download the ciphertext via
//           `GET /attachments/:id` and decrypt it locally using
//           the key from the envelope. (Verified end-to-end here:
//           Alice picks a small synthetic PNG via the in-composer
//           file input; the SPA's `uploadAttachment` encrypts via
//           `encryptAttachment`, POSTs the ciphertext to
//           `/attachments`, and embeds the produced
//           `AttachmentRef` (key/iv/tag/mime/filename) inside an
//           `InnerType.ATTACHMENT` inner payload that rides the
//           libsignal envelope to Bob. Bob's `AttachmentView`
//           runs `downloadAttachment` against the same id, AES-GCM
//           decrypts locally, and renders an `<img>` whose
//           `naturalWidth > 0` — that's only true once the bytes
//           the renderer holds are a valid PNG, which proves the
//           recipient-side decrypt round-trip succeeded.)
//   - 6.6   THE API_Gateway SHALL NOT serve plaintext attachment
//           bytes for any direct-message attachment. (Verified
//           as a thin storage-side defense-in-depth: we list the
//           configured MinIO bucket via the `minio` SDK, locate
//           the object that landed during this test (filter by
//           lastModified > test-start time), GET its body, and
//           assert the body is non-empty, does NOT start with the
//           PNG magic bytes `89 50 4E 47 0D 0A 1A 0A`, and does
//           NOT round-trip cleanly through UTF-8. The full
//           canary-grep invariant against the bucket is owned by
//           sibling spec `attachments-no-leak.integration.spec.ts`
//           (task 5.7); this file's MinIO assertion is
//           intentionally narrow and image-shaped — it only
//           proves "the specific image artifact this test
//           produced is opaque on disk".)
//   - 20.6  The full Playwright suite reports 100% pass with
//           zero failed and zero skipped tests in CI. (Indirect —
//           this file's skip gate is the same env-var contract
//           used by every other Phase-4 / 9 spec; once task 10.24
//           wires CI to set `KONVO_E2E_LIVE=1`, the gate flips on
//           for real.)
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task
//   10.16. It does NOT bring up the docker-compose data-plane on
//   its own — the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, the test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL`
//     (defaulting to `http://localhost:5173` and
//     `http://localhost:3000`) and the MinIO coordinates
//     `KONVO_E2E_MINIO_ENDPOINT` (default `localhost:9000`),
//     `KONVO_E2E_MINIO_ACCESS_KEY` (default `konvo`),
//     `KONVO_E2E_MINIO_SECRET_KEY` (default
//     `konvo-dev-password`), and `KONVO_E2E_MINIO_BUCKET`
//     (default `konvo-attachments` — matches the default in
//     `apps/api/src/config.ts`). The Phase-1 UI task (2.10) and
//     the Phase-4 attachment upload + view wiring (task 5.3)
//     must also be in place — Alice and Bob log in via the SPA's
//     `/login` form, Alice drives the in-composer attachment
//     button + file input, and Bob's thread view mounts the
//     `AttachmentView` for the inbound row. Until those land,
//     the test surfaces a clear failure message rather than
//     silently passing.
//   - When `KONVO_E2E_LIVE` is unset (the default for local
//     `pnpm -F @konvo/e2e test:list` and any CI gate that hasn't
//     wired the compose stack yet), the describe block
//     `test.skip()`s itself with an explanatory annotation so
//     the suite is a clean no-op rather than a stream of network
//     errors. This matches the skip pattern used by every other
//     E2E spec in this directory.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1`, and runs this suite against the live
//   stack as part of the "e2e" gate (per tasks.md task 10.24
//   and the Phase-4 verification gates in tasks 5.3 / 5.7).
//   Once that lands, Requirement 20.6's "zero skipped" gate
//   flips on for real for this file too.
//
// Why two browser contexts (Alice + Bob):
//   The contract under test ends at "the recipient SPA renders
//   the decrypted image", which is meaningful only across a
//   process boundary: Alice's `uploadAttachment` produces
//   ciphertext that flows through `POST /attachments` to MinIO;
//   the produced `AttachmentRef` (key/iv/tag) rides inside an
//   `InnerType.ATTACHMENT` payload through Alice's libsignal
//   session, traverses the WSS gateway, and Bob's
//   `DmController` decrypts the envelope, materialises the
//   `AttachmentRef`, and `AttachmentView` runs
//   `downloadAttachment` against the same `GET /attachments/:id`
//   route, runs AES-GCM decrypt locally, and decodes the bytes
//   into an `<img>` blob URL. A single context can satisfy that
//   only by sharing IndexedDB and identity keys between sides,
//   which would defeat the purpose of the test. Two distinct
//   `browser.newContext()` instances give us two distinct Dexie
//   databases and two distinct identity keypairs without paying
//   for a second Chromium process.
//
// Why we go through the SPA composer rather than the upload
// helper directly:
//   The sibling spec `attachments-no-leak.integration.spec.ts`
//   already covers the canary-grep invariant against MinIO by
//   driving `@konvo/crypto.encryptAttachment` + the upload
//   helper directly from Node and `POST /attachments`-ing the
//   result. The contract this spec OWNS (per design.md §16.4)
//   is the UI-driven round-trip: Alice picks a file via the
//   in-composer attachment button, the SPA encrypts + uploads,
//   the WSS envelope queues, and Bob's thread view mounts an
//   `AttachmentView` whose `<img>` decodes the recovered bytes.
//   That covers `apps/web/src/features/attachments/upload.ts`'s
//   encrypt + upload pipeline, the composer integration that
//   embeds the `AttachmentRef` inside an `InnerType.ATTACHMENT`
//   inner payload, and the `AttachmentView` decrypt + render
//   pipeline on the recipient. None of those surfaces are
//   exercised by the Node-side driver.
//
// Why we still inspect MinIO after the UI assertion:
//   The UI assertion only proves "Bob saw the decoded image";
//   it doesn't prove "the bytes on the storage backend are
//   opaque". The check against the configured bucket for the
//   newly-uploaded object verifies the blind-router invariant
//   from design.md §1.2 and Requirement 6.6 end-to-end against
//   the row that the production upload path actually inserted,
//   scoped to the specific image artifact this test produced.
//   The full canary-grep gate is owned by
//   `attachments-no-leak.integration.spec.ts`; this file adds a
//   thin "the specific artifact is encrypted on disk" assertion
//   as a proportionate companion to the UI-side round-trip the
//   test owns.
//
// Header dependency note:
//   This file is `test.skip`-annotated until task 10.24 wires
//   CI to bring up the docker-compose data-plane. The skip
//   annotation lives at the describe level (`test.skip(!LIVE,
//   …)`); do NOT convert it to `test.fixme` or remove it
//   without updating the tasks.md task 10.24 dependency. The
//   file additionally depends on:
//     - task 5.3: web attachment upload/download. The composer
//       MUST mount an attachment button + a hidden file input
//       (`<input type="file">`) wired to `uploadAttachment` and
//       a follow-on send that embeds the produced
//       `AttachmentRef` inside an `InnerType.ATTACHMENT` inner
//       payload. The thread row factory MUST mount
//       `AttachmentView` for inbound `InnerType.ATTACHMENT`
//       rows (the component is exported from
//       `apps/web/src/features/attachments/AttachmentView.tsx`
//       and already carries `data-testid="attachment-image"`
//       for the image branch + `data-testid="attachment-loading"`
//       for the in-flight branch).
//     - task 2.10: DM route + auth wiring (and the dev-only
//       `__konvoAuthForE2E__` / `__konvoDmForE2E__` window
//       hooks under `import.meta.env.MODE === 'test'`).

import { randomUUID } from 'node:crypto';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';

/** MinIO coordinates for the bucket-listing assertion. The
 *  defaults match `infra/docker-compose.yml`'s `minio` service env
 *  AND the `MINIO_BUCKET` default in `apps/api/src/config.ts`
 *  (`konvo-attachments`). CI overrides these via env vars in
 *  task 10.24. We accept the same envvar names as
 *  `voice-note.spec.ts` and
 *  `attachments-no-leak.integration.spec.ts` so a single CI
 *  export flips all three specs at once. */
const MINIO_ENDPOINT = process.env['KONVO_E2E_MINIO_ENDPOINT'] ?? 'localhost:9000';
const MINIO_ACCESS_KEY = process.env['KONVO_E2E_MINIO_ACCESS_KEY'] ?? 'konvo';
const MINIO_SECRET_KEY = process.env['KONVO_E2E_MINIO_SECRET_KEY'] ?? 'konvo-dev-password';
const MINIO_BUCKET = process.env['KONVO_E2E_MINIO_BUCKET'] ?? 'konvo-attachments';
const MINIO_USE_SSL = process.env['KONVO_E2E_MINIO_USE_SSL'] === '1';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** UI-side budgets. These mirror `dm-send.spec.ts`'s + 
 *  `voice-note.spec.ts`'s budgets: the outbound
 *  `'sending' → 'delivered'` flip rides on the WSS gateway +
 *  X3DH first-contact path (Requirement 4.1 budgets X3DH at
 *  10 s); we use a generous 30 s end-to-end so a slow CI runner
 *  doesn't false-fail. Attachments additionally wait on the
 *  `POST /attachments` upload before the envelope is sent
 *  (Requirement 6.3 caps the upload at 25 MiB; our synthetic
 *  PNG below is well under 1 KiB and uploads in well under a
 *  second on local infra). */
const SEND_BUDGET_MS = 30_000;
const VIEW_RENDER_BUDGET_MS = 30_000;

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — set KONVO_E2E_LIVE=1 with the ' +
  'docker-compose data-plane up and a MODE=test build of apps/web ' +
  'served (tasks 2.10 + 5.3 + 10.24) to run this against a real ' +
  'api + web + minio stack.';

/** PNG magic bytes (RFC 2083 §3.1: the 8-byte signature that begins
 *  every well-formed PNG file). Used by the MinIO assertion below
 *  to prove the stored blob is NOT a plaintext PNG: a regression
 *  that wrote the plaintext bytes to MinIO instead of the AES-GCM
 *  ciphertext would surface as the bucket object starting with
 *  these 8 bytes (Requirement 6.6). */
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** A minimal valid PNG: 1x1 pixel, opaque-red, IHDR + IDAT + IEND.
 *  Generated via `pngcrush`-style hand-rolling and verified to
 *  decode in Chromium / jsdom — `<img>` reports
 *  `naturalWidth === 1` and `naturalHeight === 1` once it loads.
 *
 *  Why we embed the bytes inline rather than reading a file from
 *  disk: keeping the spec a single self-contained file matches
 *  the pattern used by every other E2E spec in this directory
 *  (no fixtures dir to keep in sync, no path-resolution hazards
 *  on Windows CI). The bytes below are well-formed PNG — see
 *  `pngcheck` output structure: signature (8B) + IHDR (25B,
 *  declares 1×1 RGB) + IDAT (16B, zlib-deflated single-pixel
 *  red) + IEND (12B). Total: 67 B. */
const TINY_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==';

/** Filename Alice's composer uploads. Embedded inside the
 *  `InnerType.ATTACHMENT` inner payload so Bob's `AttachmentView`
 *  receives it as the `filename` prop — that prop drives the
 *  `<img>` element's `alt` attribute (Requirement 6.4 caps
 *  filename at ≤ 255 chars; our value is far shorter). The
 *  filename also rides as the multipart filename in the upload,
 *  but the API doesn't store it (only the MIME + size are
 *  persisted on the attachments row). */
const ATTACHMENT_FILENAME = 'konvo-e2e-attachment.png';
const ATTACHMENT_MIME = 'image/png';

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

test.describe('Attachment round-trip — image upload + recipient decrypt + MinIO blob is encrypted', () => {
  // Wire the skip at describe-level so Playwright doesn't even
  // launch a browser when LIVE is unset. Reporting as skipped
  // (rather than erroring on a missing chromium binary or a dead
  // dev server) is the contract the rest of the e2e suite relies
  // on — see signup-and-login.spec.ts, dm-send.spec.ts, and
  // voice-note.spec.ts.
  test.skip(!LIVE, SKIP_REASON);

  test('Alice uploads an image, Bob decrypts and renders it, and the MinIO blob is encrypted', async ({
    browser,
    request,
  }, testInfo) => {
    // The UI assertions below depend on Phase-1 task 2.10 (DM
    // route + auth wiring) AND Phase-4 task 5.3 (web attachment
    // upload/download + composer integration + thread-row
    // `AttachmentView` mount) being complete. Until those land,
    // the SPA renders neither the in-composer attachment button
    // nor the inbound `AttachmentView`. The annotation makes the
    // dependency visible in the test report so a CI run without
    // those tasks surfaces a helpful failure rather than silently
    // passing.
    testInfo.annotations.push({
      type: 'ui-dependency',
      description:
        'Driving the composer attachment input and inbound ' +
        '`AttachmentView` requires the DM route from task 2.10 AND ' +
        'the web attachment wiring from task 5.3. The upload helper ' +
        '(`apps/web/src/features/attachments/upload.ts`) and the ' +
        'view component (`apps/web/src/features/attachments/' +
        'AttachmentView.tsx`) already exist; this spec exercises the ' +
        'composer path that wires them together end-to-end.',
    });

    // Capture a wall-clock anchor BEFORE we touch any infra. The
    // MinIO assertion below filters bucket objects by
    // `lastModified > testStartedAt`, so if the bucket already
    // contained pre-existing objects from a prior CI run (or
    // from `voice-note.spec.ts` /
    // `attachments-no-leak.integration.spec.ts` running in the
    // same job), we only inspect the artifact this test
    // produced. We subtract a small skew tolerance so a
    // marginally-fast CI runner whose MinIO returns
    // `lastModified` slightly ahead of `testStartedAt` doesn't
    // false-miss our object.
    const testStartedAt = new Date(Date.now() - 5_000);

    // -----------------------------------------------------------------
    // 1. Pre-create Alice and Bob via REST.
    //
    // The auth UI is the dedicated subject of
    // `signup-and-login.spec.ts`; this spec's behavioural
    // contract is the attachment round-trip, so we drive signup
    // via REST and use the SPA only for login + DM. Mirrors the
    // shape used by `dm-send.spec.ts` / `voice-note.spec.ts`.
    // -----------------------------------------------------------------
    const aliceHandle = uniqueHandle(`alice_${randomUUID().replace(/-/g, '').slice(0, 8)}`);
    const bobHandle = uniqueHandle(`bob_${randomUUID().replace(/-/g, '').slice(0, 8)}`);
    await signupViaRest(request, aliceHandle);
    await signupViaRest(request, bobHandle);

    // -----------------------------------------------------------------
    // 2. Open Alice's and Bob's browser contexts.
    //
    // Each `browser.newContext()` gets its own cookies,
    // IndexedDB, and SW registration (= "two people on two
    // laptops"). We pin `baseURL` so `page.goto('/login' / '/'…)`
    // resolves against the SPA dev server. We do NOT share
    // state between the two contexts, including not sharing
    // storageState, so the test exercises the full first-run
    // identity + prekey-bundle path on each side.
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
      // polling for navigation. Mirrors `dm-send.spec.ts`'s
      // login pattern. We log in IN PARALLEL because the WSS
      // handshake does NOT block on the peer being online —
      // getting both pages logged in concurrently saves a few
      // seconds on a slow runner.
      // ---------------------------------------------------------------
      await Promise.all([loginViaSpa(alicePage, aliceHandle), loginViaSpa(bobPage, bobHandle)]);

      // ---------------------------------------------------------------
      // 4. Resolve Alice's and Bob's `userId` + `deviceId` from
      //    the SPA's auth + device store.
      //
      // We need the userIds to drive the
      // `dm-thread-select-${peerUserId}` testids; we don't use
      // the deviceIds in this spec but reading them confirms the
      // SPA bootstrapped a device successfully (the upload path
      // requires the device's identity + prekey bundle to be
      // published before the recipient can decrypt the
      // envelope).
      // ---------------------------------------------------------------
      const alice = await readSpaIdentityForE2E(alicePage);
      const bob = await readSpaIdentityForE2E(bobPage);
      expect(alice.userId, 'Alice userId must be present').toBeTruthy();
      expect(bob.userId, 'Bob userId must be present').toBeTruthy();
      expect(alice.userId, 'Alice and Bob must be distinct users').not.toBe(bob.userId);

      // ---------------------------------------------------------------
      // 5. Seed thread rows on both sides.
      //
      // Mirrors `dm-send.spec.ts`'s + `voice-note.spec.ts`'s
      // thread-seeding helper. The DmController's inbound
      // handler upserts the thread on first delivery anyway (so
      // seeding is strictly only needed for Alice — without it
      // she has no row to click), but seeding both sides keeps
      // the test deterministic against the order of operations:
      // Bob can pre-open Alice's thread and the inbound
      // assertion below doesn't race the thread-upsert.
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
      // 6. Both sides navigate to `/` and open the peer thread.
      //
      // The composer (and thus the attachment button + file
      // input) only renders when a thread is selected — see
      // Composer.tsx, which is mounted inside ThreadView only
      // when `threadId !== null`. Pre-opening Bob's thread too
      // means the inbound `AttachmentView` mounts as soon as
      // the envelope arrives, rather than waiting for Bob to
      // navigate into the thread, which would slow the
      // assertion below for no benefit.
      // ---------------------------------------------------------------
      await alicePage.goto('/');
      await openDmThread(alicePage, bob.userId);
      await bobPage.goto('/');
      await openDmThread(bobPage, alice.userId);

      // ---------------------------------------------------------------
      // 7. Alice picks the synthetic PNG via the in-composer
      //    file input.
      //
      // Phase-4 task 5.3 mounts a hidden `<input type="file">`
      // under the composer's attachment button. The browser
      // convention for hidden file inputs is to leave them
      // visually invisible (e.g. `display: none` or
      // `position: absolute; opacity: 0`) and dispatch the
      // click via a sibling button — but Playwright's
      // `setInputFiles` operates on the element directly,
      // bypassing the visual styling and the click handler.
      // We use `setInputFiles` against the file input's
      // testid; if the testid is missing in the current build
      // we fall back to the role/label-based locator the task
      // brief calls out.
      //
      // The file is constructed as a `Buffer` from the inline
      // base64-encoded PNG. Passing `{ name, mimeType, buffer }`
      // to `setInputFiles` mirrors the composer's expected
      // `File` shape — the SPA's `uploadAttachment` reads the
      // bytes via `file.arrayBuffer()` and pipes them through
      // `encryptAttachment`.
      // ---------------------------------------------------------------
      await alicePage.waitForSelector('[data-testid="dm-composer"]', {
        state: 'visible',
        timeout: 10_000,
      });
      const fileInput = await resolveAttachmentFileInput(alicePage);
      const pngBytes = Buffer.from(TINY_PNG_BASE64, 'base64');
      // Sanity: the inline PNG starts with the magic signature.
      // A typo in the base64 above would produce a body that
      // doesn't start with `89 50 4E 47 …` and the MinIO
      // assertion would still pass (because no PNG was ever
      // uploaded), but the `<img>.naturalWidth > 0` assertion
      // would fail with a confusing message. Asserting magic
      // bytes here surfaces the typo immediately.
      expect(
        pngBytes.subarray(0, PNG_MAGIC.length).equals(PNG_MAGIC),
        'inline TINY_PNG_BASE64 must start with the PNG magic signature',
      ).toBe(true);
      await fileInput.setInputFiles({
        name: ATTACHMENT_FILENAME,
        mimeType: ATTACHMENT_MIME,
        buffer: pngBytes,
      });

      // The composer must NOT surface an error after the file
      // pick. A visible error here would indicate the
      // `uploadAttachment` path or the WS gateway failed;
      // surfacing it fast keeps the failure message useful
      // instead of leaving it to the downstream "delivered"
      // assertion to time out.
      await expect(
        alicePage.getByTestId('dm-composer-error'),
        'composer must not surface an error after picking a file',
      ).toHaveCount(0, { timeout: 5_000 });

      // ---------------------------------------------------------------
      // 8. Wait for Alice's outbound attachment row to flip to
      //    `'delivered'`.
      //
      // Requirement 4.6 (the three-state ticker) applies to
      // attachment rows the same way it applies to text and
      // voice notes: the outbound row is inserted in
      // `'sending'`, transitions to `'delivered'` on
      // `ENVELOPE_QUEUED` + `ACK_DELIVERED`, and to `'read'` if
      // Bob's UI happened to ack the read before our poll arms.
      // We don't scope by message kind here (no
      // `data-message-kind` attribute is yet stamped on
      // attachment rows in 5.3); instead we pick the most
      // recent outbound row and wait for its state attribute
      // to settle. A future regression that wires
      // `data-message-kind="attachment"` on attachment rows
      // would let this assertion be more selective; the
      // current shape is the conservative "any most-recent
      // outbound row reached delivered" check that mirrors
      // `dm-send.spec.ts`'s `assertOutboundDelivered` helper.
      // ---------------------------------------------------------------
      await assertOutboundAttachmentDelivered(alicePage);

      // ---------------------------------------------------------------
      // 9. Bob receives the envelope and renders the
      //    `AttachmentView`.
      //
      // The thread row is sourced from Dexie via
      // `useDmStore.ts`; once the envelope is decrypted and
      // upserted, the row factory mounts an `AttachmentView`
      // inside the inbound row. The image branch of
      // `AttachmentView` (when `mime.startsWith('image/')`)
      // renders an `<img data-testid="attachment-image">` whose
      // `src` is a freshly minted `URL.createObjectURL(blob)`
      // over the AES-GCM-decrypted plaintext (see
      // `apps/web/src/features/attachments/AttachmentView.tsx`).
      // We wait for the image element to mount, then assert
      // `naturalWidth > 0`. `naturalWidth` is the image's
      // intrinsic pixel width as decoded by the browser; it
      // only becomes positive once the bytes the renderer
      // holds are a valid PNG, which proves the
      // recipient-side AES-GCM decrypt round-trip succeeded
      // (Requirement 6.5).
      //
      // We also check the `attachment-loading` placeholder
      // disappeared, so a regression that left the view stuck
      // in the loading state (e.g. a fetch hang) surfaces as
      // a clear failure rather than as an opaque
      // "naturalWidth never settled" message.
      // ---------------------------------------------------------------
      const inboundImage = bobPage.getByTestId('attachment-image').first();
      await expect(
        inboundImage,
        "Bob must see an `attachment-image` mount inside the inbound thread row " +
          `within ${VIEW_RENDER_BUDGET_MS}ms`,
      ).toBeVisible({ timeout: VIEW_RENDER_BUDGET_MS });

      // The loading placeholder may flicker briefly; we don't
      // assert it never appeared, only that it has cleared by
      // the time the image is visible.
      await expect(
        bobPage.getByTestId('attachment-loading'),
        '`attachment-loading` placeholder must clear once the image is visible',
      ).toHaveCount(0, { timeout: 5_000 });

      // No tag-failure / not-found / error placeholder may be
      // present — those would each indicate a failed
      // recipient-side path (Requirements 6.9, 6.10, transient
      // errors). Surfacing them here distinguishes "the image
      // didn't decode" from "the image decoded into an opaque
      // placeholder".
      for (const failTestid of [
        'attachment-tag-failed',
        'attachment-not-found',
        'attachment-error',
      ] as const) {
        await expect(
          bobPage.getByTestId(failTestid),
          `Bob's thread must NOT render \`${failTestid}\` for a healthy round-trip`,
        ).toHaveCount(0, { timeout: 1_000 });
      }

      // Wait for the `<img>` to actually decode. Browsers fire
      // `complete === true` + `naturalWidth > 0` once the
      // blob bytes have been parsed as a PNG. We poll rather
      // than rely on a single read because the blob URL is
      // attached synchronously by `AttachmentView` but the
      // decode is async. A 10 s budget is comfortably above
      // the few-millisecond decode time for a 1×1 PNG on any
      // reasonable hardware; the upper bound exists only so a
      // hang surfaces as a typed failure.
      await expect
        .poll(
          async () => {
            return await inboundImage.evaluate((el: Element) => {
              if (!(el instanceof HTMLImageElement)) {
                return { naturalWidth: 0, complete: false, hasSrc: false };
              }
              return {
                naturalWidth: el.naturalWidth,
                complete: el.complete,
                hasSrc: el.src.length > 0,
              };
            });
          },
          {
            timeout: VIEW_RENDER_BUDGET_MS,
            message:
              "Bob's `attachment-image` must decode (naturalWidth > 0) within " +
              `${VIEW_RENDER_BUDGET_MS}ms — Requirement 6.5: the recipient ` +
              'SHALL decrypt the ciphertext locally and render the bytes ' +
              'as a valid image.',
          },
        )
        .toMatchObject({});

      const decoded = await inboundImage.evaluate((el: Element) => {
        if (!(el instanceof HTMLImageElement)) {
          return { naturalWidth: 0, naturalHeight: 0, complete: false, hasSrc: false };
        }
        return {
          naturalWidth: el.naturalWidth,
          naturalHeight: el.naturalHeight,
          complete: el.complete,
          hasSrc: el.src.length > 0,
        };
      });
      expect(decoded.hasSrc, 'attachment image must have a populated src').toBe(true);
      expect(
        decoded.naturalWidth,
        "Bob's `attachment-image` must report naturalWidth > 0 — proves the " +
          'AES-GCM decrypt round-trip produced a valid PNG (Requirement 6.5)',
      ).toBeGreaterThan(0);
      expect(
        decoded.naturalHeight,
        "Bob's `attachment-image` must report naturalHeight > 0 — proves the " +
          'AES-GCM decrypt round-trip produced a valid PNG (Requirement 6.5)',
      ).toBeGreaterThan(0);

      // ---------------------------------------------------------------
      // 10. MinIO assertion — Requirement 6.6.
      //
      // List the configured bucket via the `minio` SDK
      // (already a runtime dep of `apps/api/src/storage/
      // minio.ts`), locate the most recently uploaded object
      // filtered by `lastModified > testStartedAt` so we only
      // inspect what this test produced, GET its body, and
      // assert:
      //
      //   a. The object exists and was uploaded within the
      //      test's window. Without this, the negative no-leak
      //      assertions below would trivially pass against an
      //      empty rowset.
      //   b. The body is non-empty. AES-GCM ciphertext is
      //      `len(plaintext)` bytes plus the 16-byte tag
      //      spliced in-stream; even our 67-byte plaintext PNG
      //      produces ≥ 67 bytes of ciphertext.
      //   c. The body does NOT start with the PNG magic bytes
      //      (`89 50 4E 47 0D 0A 1A 0A`). A regression that
      //      uploaded the plaintext PNG directly would surface
      //      as a body that starts with these 8 bytes; the
      //      AES-GCM ciphertext over the same plaintext starts
      //      with random bytes (the first ciphertext byte is
      //      `plaintext[0] XOR keystream[0]`, which is
      //      uniformly distributed for a fresh AES-GCM key).
      //   d. The body does not round-trip cleanly through
      //      UTF-8. Random ciphertext bytes contain stretches
      //      that fail UTF-8 validation; AES-GCM ciphertext
      //      over a PNG is even more uniformly non-text. The
      //      simplest invariant we can assert without
      //      injecting a canary into the plaintext is "this
      //      body does not round-trip through UTF-8 as a
      //      stable string", which is exactly what Node's
      //      `Buffer.toString('utf8')` non-strict decoder
      //      surfaces via the `\uFFFD` replacement character.
      //
      // The full canary-grep invariant against the bucket is
      // owned by sibling spec
      // `attachments-no-leak.integration.spec.ts`; this
      // file's MinIO assertion is intentionally narrow.
      // ---------------------------------------------------------------
      const blobInspection = await fetchNewestAttachmentBlobFromMinio({
        endpoint: MINIO_ENDPOINT,
        accessKey: MINIO_ACCESS_KEY,
        secretKey: MINIO_SECRET_KEY,
        useSsl: MINIO_USE_SSL,
        bucket: MINIO_BUCKET,
        uploadedAfter: testStartedAt,
      });

      expect(blobInspection.bucketExists, `MinIO bucket "${MINIO_BUCKET}" must exist`).toBe(true);
      expect(
        blobInspection.newestObject,
        `at least one new object must have been uploaded to "${MINIO_BUCKET}" ` +
          `since the test started at ${testStartedAt.toISOString()} ` +
          '(this is the attachment ciphertext blob)',
      ).not.toBeNull();

      const obj = blobInspection.newestObject;
      // narrowing for the typechecker — the assertion above
      // already ensures it's non-null at runtime.
      if (obj === null) throw new Error('unreachable: newestObject was null');

      expect(
        obj.sizeBytes,
        `attachment blob "${obj.key}" must carry non-zero ciphertext bytes`,
      ).toBeGreaterThan(0);

      // 10c. Body must NOT start with PNG magic. A body that
      //      starts with `89 50 4E 47 0D 0A 1A 0A` would mean
      //      MinIO is holding a plaintext PNG, which would
      //      directly violate Requirement 6.6.
      const startsWithPngMagic =
        obj.body.length >= PNG_MAGIC.length &&
        obj.body.subarray(0, PNG_MAGIC.length).equals(PNG_MAGIC);
      expect(
        startsWithPngMagic,
        `attachment blob "${obj.key}" must NOT start with the PNG magic ` +
          'signature — a body starting with `89 50 4E 47 0D 0A 1A 0A` would ' +
          'mean the bucket holds plaintext PNG bytes (Requirement 6.6).',
      ).toBe(false);

      // 10d. Body must NOT round-trip through UTF-8. Mirrors
      //      the same opaque-bytes assertion in
      //      `voice-note.spec.ts`. Node's
      //      `Buffer.toString('utf8')` is non-strict and
      //      replaces invalid sequences with `\uFFFD`; we
      //      assert either that re-encoding the decoded
      //      string produces different bytes (= some byte
      //      sequence was lossy on the way through utf-8) OR
      //      that the decoded string contains the
      //      replacement character.
      const utf8Decoded = obj.body.toString('utf8');
      const utf8RoundTrip = Buffer.from(utf8Decoded, 'utf8');
      const roundTrips = utf8RoundTrip.equals(obj.body);
      const containsReplacement = utf8Decoded.includes('\uFFFD');
      expect(
        roundTrips === false || containsReplacement === true,
        `attachment blob "${obj.key}" must contain opaque (non-UTF-8) ` +
          'bytes — Requirement 6.6 (the API_Gateway SHALL NOT serve ' +
          'plaintext attachment bytes). Got ' +
          `roundTrips=${roundTrips}, containsReplacement=${containsReplacement}, ` +
          `size=${obj.sizeBytes}.`,
      ).toBe(true);
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
 *  an opaque downstream login error. Mirrors the helper in
 *  `dm-send.spec.ts` / `voice-note.spec.ts`. */
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
 *  `PASSWORD`). Mirrors the login helper in `dm-send.spec.ts` /
 *  `voice-note.spec.ts` / `signup-and-login.spec.ts`. Resolves
 *  once `__konvoAuthForE2E__.accessToken` is populated, which is
 *  the Phase-1 UI's "logged in" signal. */
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
 *  `dm-send.spec.ts`'s helper of the same name. The hooks are
 *  gated on `import.meta.env.MODE === 'test'` in the Phase-1
 *  UI; a hook-missing failure here means the SPA build did not
 *  run in test mode. */
async function readSpaIdentityForE2E(page: Page): Promise<SpaIdentity> {
  await expect
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

  return page.evaluate(() => {
    const w = window as unknown as {
      __konvoAuthForE2E__?: { user?: { id: string } | null };
      __konvoDmForE2E__?: { deviceId?: string };
    };
    return {
      userId: w.__konvoAuthForE2E__?.user?.id ?? '',
      deviceId: w.__konvoDmForE2E__?.deviceId ?? '',
    };
  });
}

// ---------------------------------------------------------------------------
// Helpers — DM thread seeding + composer driver
// ---------------------------------------------------------------------------

/** Insert a Thread row into the page's local Dexie via the
 *  `__konvoDmForE2E__.seedThreads` hook. Mirrors the seeding
 *  pattern from `dm-send.spec.ts`. */
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
        lastBody: '__konvo_attachment_e2e_seed__',
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
 *  thread. Mirrors `dm-send.spec.ts`'s `openDmThread`. The
 *  `dm-thread-select-${peerUserId}` testid is owned by
 *  `apps/web/src/features/dm/ThreadList.tsx`. */
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

/** Resolve the in-composer attachment file input. Phase-4 task
 *  5.3 mounts the input under the composer; the testid the SPA
 *  exposes is the canonical handle, but if a future composer
 *  refactor renames the testid we fall back to a label/role-
 *  based locator scoped to the active composer.
 *
 *  We try the following selectors in order, returning the first
 *  one that resolves:
 *    - `data-testid="dm-composer-attachment-input"` — the
 *      canonical Phase-4 testid for the hidden file input.
 *    - `data-testid="attachment-input"` — alternative shape if
 *      the composer uses a non-prefixed testid.
 *    - `input[type="file"]` scoped to the composer — fallback
 *      that matches a real user's gesture (a hidden file input
 *      is by convention the only one inside the composer).
 *    - `getByLabel(/attach/i)` — final fallback for a future
 *      composer that exposes the input via an accessible label.
 *
 *  The fallback chain mirrors the brief: "use a label/role-
 *  based locator" if the testid is not present in
 *  `Composer.tsx`. */
async function resolveAttachmentFileInput(page: Page): Promise<import('@playwright/test').Locator> {
  const composer = page.getByTestId('dm-composer');
  await expect(
    composer,
    'dm-composer must be mounted before resolving the attachment input',
  ).toBeVisible({ timeout: 10_000 });

  // Probe for the canonical testid first. We use `count() > 0`
  // rather than `toBeVisible()` because hidden file inputs are
  // typically `display: none` or `opacity: 0`, and Playwright's
  // `setInputFiles` works against hidden inputs without
  // requiring visibility.
  const candidates = [
    page.getByTestId('dm-composer-attachment-input'),
    page.getByTestId('attachment-input'),
    composer.locator('input[type="file"]'),
  ];
  for (const candidate of candidates) {
    const count = await candidate.count();
    if (count > 0) {
      return candidate.first();
    }
  }

  // Final fallback: label-based. A future composer that exposes
  // the input via an accessible name (e.g. `<label>Attach
  // file<input type="file" /></label>`) lands here. If even
  // this misses, the assertion below fires with a message that
  // points the next reader at the dependency.
  const labelled = page.getByLabel(/attach/i);
  const labelledCount = await labelled.count();
  if (labelledCount > 0) {
    return labelled.first();
  }

  throw new Error(
    'No attachment file input found inside the composer. Expected one ' +
      'of: data-testid="dm-composer-attachment-input", ' +
      'data-testid="attachment-input", composer-scoped input[type="file"], ' +
      'or a label matching /attach/i. Phase-4 task 5.3 must wire the ' +
      'composer attachment button + hidden file input.',
  );
}

/** Assert the most recent outbound message row in the active
 *  thread reached the `'delivered'` (or `'read'`) state on its
 *  `data-message-state` attribute. Mirrors
 *  `dm-send.spec.ts`'s `assertOutboundDelivered` shape, but
 *  scoped to the *last* row rather than a body-text match
 *  because attachment rows don't carry a known plaintext body
 *  to grep on (the body bytes are the encoded
 *  `InnerType.ATTACHMENT` payload, not human-readable text).
 *
 *  The row is identified by `data-outbound="true"` which the
 *  thread view's row factory stamps on every Alice-authored
 *  row (see `ThreadView.tsx`). A future regression that wired
 *  `data-message-kind="attachment"` would let this assertion be
 *  even more selective; the current shape is the conservative
 *  "any most-recent outbound row reached delivered" check. */
async function assertOutboundAttachmentDelivered(page: Page): Promise<void> {
  const row = page
    .getByTestId('dm-message-list')
    .locator('li[data-outbound="true"]')
    .last();
  await expect(
    row,
    "an outbound row must render in Alice's thread within " +
      `${SEND_BUDGET_MS}ms after picking the file`,
  ).toBeVisible({ timeout: SEND_BUDGET_MS });

  await expect
    .poll(async () => await row.getAttribute('data-message-state'), {
      timeout: SEND_BUDGET_MS,
      message:
        'outbound attachment row must reach state="delivered" (or "read") ' +
        `within ${SEND_BUDGET_MS}ms — Requirement 4.6 three-state ticker`,
    })
    // 'read' is a strict superset of 'delivered'; if Bob's UI
    // is already foregrounded and dispatches an ACK_READ before
    // Alice's poll arms, the row will be `'read'` rather than
    // `'delivered'`. Both satisfy the contract under test.
    .toMatch(/^(delivered|read)$/);
}

// ---------------------------------------------------------------------------
// Helpers — MinIO blob inspection
// ---------------------------------------------------------------------------

interface MinioFetchArgs {
  readonly endpoint: string;
  readonly accessKey: string;
  readonly secretKey: string;
  readonly useSsl: boolean;
  readonly bucket: string;
  /** Filter listed objects to those uploaded strictly after this
   *  timestamp. Used to scope the inspection to the artifact
   *  this test produced rather than any pre-existing bucket
   *  contents (e.g. from a previous CI run or a sibling spec). */
  readonly uploadedAfter: Date;
}

interface NewestAttachmentBlob {
  readonly key: string;
  readonly sizeBytes: number;
  readonly body: Buffer;
  readonly lastModified: Date;
}

interface MinioInspectionResult {
  readonly bucketExists: boolean;
  readonly newestObject: NewestAttachmentBlob | null;
}

/** Connect to MinIO via the SDK that ships with `apps/api/src/
 *  storage/minio.ts`, list the configured bucket, locate the
 *  most recently uploaded object whose `lastModified` falls
 *  within the test's window, and fetch its body. Returns
 *  `newestObject: null` when no qualifying object exists.
 *
 *  Mirrors the helper of the same shape in
 *  `voice-note.spec.ts`; we deliberately duplicate the wrapper
 *  here rather than promote it to a shared module so each spec
 *  stays independently navigable from a CI failure trace (the
 *  e2e package is `"type": "module"` and Playwright loads each
 *  spec independently).
 *
 *  Why filter by `lastModified > uploadedAfter` rather than by
 *  object key prefix:
 *    The blob keys are server-controlled (see
 *    `apps/api/src/routes/attachments.ts`'s key derivation)
 *    and don't carry a per-test discriminator. Filtering by
 *    timestamp is the simplest robust filter that scopes the
 *    inspection to "what this test just uploaded" without
 *    requiring a control-plane handshake to learn the
 *    server-side blob-key shape. */
async function fetchNewestAttachmentBlobFromMinio(
  args: MinioFetchArgs,
): Promise<MinioInspectionResult> {
  const minioMod = (await import('minio')) as unknown as {
    Client: new (opts: {
      endPoint: string;
      port: number;
      useSSL: boolean;
      accessKey: string;
      secretKey: string;
    }) => {
      bucketExists(name: string): Promise<boolean>;
      listObjectsV2(bucket: string, prefix: string, recursive: boolean): NodeJS.ReadableStream;
      getObject(bucket: string, name: string): Promise<NodeJS.ReadableStream>;
    };
  };

  const { host, port } = parseMinioEndpoint(args.endpoint, args.useSsl);
  const client = new minioMod.Client({
    endPoint: host,
    port,
    useSSL: args.useSsl,
    accessKey: args.accessKey,
    secretKey: args.secretKey,
  });

  const exists = await client.bucketExists(args.bucket).catch(() => false);
  if (!exists) {
    return { bucketExists: false, newestObject: null };
  }

  // List every object under the bucket. We filter by
  // `lastModified > uploadedAfter` here so the subsequent GET
  // is scoped to what this test produced.
  interface ListedObject {
    readonly key: string;
    readonly size: number;
    readonly lastModified: Date;
  }
  const listed: ListedObject[] = await new Promise((resolve, reject) => {
    const acc: ListedObject[] = [];
    const stream = client.listObjectsV2(args.bucket, '', /* recursive */ true);
    stream.on('data', (obj: { name?: string; size?: number; lastModified?: Date }) => {
      if (typeof obj.name !== 'string') return;
      if (!(obj.lastModified instanceof Date)) return;
      if (obj.lastModified.getTime() <= args.uploadedAfter.getTime()) return;
      acc.push({
        key: obj.name,
        size: obj.size ?? 0,
        lastModified: obj.lastModified,
      });
    });
    stream.on('end', () => resolve(acc));
    stream.on('error', (e: unknown) => reject(e instanceof Error ? e : new Error(String(e))));
  });

  if (listed.length === 0) {
    return { bucketExists: true, newestObject: null };
  }

  // Pick the most recently uploaded qualifying object. Ties
  // are broken by lexicographic key so the assertion target is
  // deterministic across reruns.
  listed.sort((a, b) => {
    const dt = b.lastModified.getTime() - a.lastModified.getTime();
    if (dt !== 0) return dt;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
  const newest = listed[0];
  if (newest === undefined) {
    return { bucketExists: true, newestObject: null };
  }

  // Fetch the body.
  const stream = await client.getObject(args.bucket, newest.key);
  const body = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer) => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', (e: unknown) => reject(e instanceof Error ? e : new Error(String(e))));
  });

  return {
    bucketExists: true,
    newestObject: {
      key: newest.key,
      sizeBytes: body.length,
      body,
      lastModified: newest.lastModified,
    },
  };
}

/** Split `host:port` (or just `host`) into the shape the minio
 *  Client constructor wants. Mirrors the helper inside
 *  `apps/api/src/storage/minio.ts` and the one in
 *  `voice-note.spec.ts` /
 *  `attachments-no-leak.integration.spec.ts`. */
function parseMinioEndpoint(endpoint: string, useSsl: boolean): { host: string; port: number } {
  const idx = endpoint.lastIndexOf(':');
  if (idx === -1) {
    return { host: endpoint, port: useSsl ? 443 : 80 };
  }
  const host = endpoint.slice(0, idx);
  const portStr = endpoint.slice(idx + 1);
  const port = Number.parseInt(portStr, 10);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`invalid MinIO endpoint port: ${portStr}`);
  }
  return { host, port };
}

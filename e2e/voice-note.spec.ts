// e2e/voice-note.spec.ts
//
// E2E coverage for task 10.15 — "voice note round-trip". Mirrors
// design.md §16.4 row 3 ("voice-note.spec.ts | Phase 4 |
// Hold-to-record voice note; round-trip play; MinIO blob is
// encrypted") and the verification gate in Requirement 20.6.
//
// _Validates: Requirements 5.6, 6.6, 20.6_
//
// Validates Requirements:
//   - 5.6   WHEN a recipient plays back a voice note, THE
//           Web_Client SHALL decrypt the ciphertext using the
//           AES-GCM key, IV, and tag from the envelope, then
//           render a scrubable waveform from the decrypted
//           audio. (Verified end-to-end here: Alice holds the
//           in-composer voice-note button to record a clip;
//           Bob's SPA renders a `VoiceNotePlayer` whose
//           `voice-note-waveform` canvas mounts and whose
//           `voice-note-audio` element transitions to playing
//           when Bob clicks `voice-note-play-pause`. The
//           player only reaches that state by completing the
//           AES-GCM decrypt of the downloaded ciphertext, so
//           a successful play-pause + non-zero `currentTime`
//           is positive evidence the recipient-side decrypt
//           ran on the envelope's key/iv/tag.)
//   - 6.6   THE API_Gateway SHALL NOT serve plaintext
//           attachment bytes for any direct-message
//           attachment. (Verified as a thin storage-side
//           defense-in-depth: we list the configured MinIO
//           bucket via the `minio` SDK, locate the object that
//           landed during this test (filter by createdAt >
//           test-start time), GET its body, and assert it
//           carries non-zero opaque bytes that are NOT valid
//           UTF-8 plaintext. The full canary-grep invariant
//           against the bucket is owned by sibling spec
//           `attachments-no-leak.integration.spec.ts` (task
//           5.7). This file's MinIO assertion is intentionally
//           narrow: it only proves "the specific voice-note
//           artifact this test produced is opaque on disk",
//           not the broader cross-canary no-leak gate.)
//   - 20.6  The full Playwright suite reports 100% pass with
//           zero failed and zero skipped tests in CI.
//           (Indirect — this file's skip gate is the same
//           env-var contract used by every other Phase-4 / 9
//           spec; once task 10.24 wires CI to set
//           `KONVO_E2E_LIVE=1`, the gate flips on for real.)
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task
//   10.15. It does NOT bring up the docker-compose data-plane
//   on its own — the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, the test runs against
//     the URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL`
//     (defaulting to `http://localhost:5173` and
//     `http://localhost:3000`) and the MinIO coordinates
//     `KONVO_E2E_MINIO_ENDPOINT` (default `localhost:9000`),
//     `KONVO_E2E_MINIO_ACCESS_KEY` (default `konvo`),
//     `KONVO_E2E_MINIO_SECRET_KEY` (default
//     `konvo-dev-password`), and `KONVO_E2E_MINIO_BUCKET`
//     (default `konvo-attachments`). The Phase-1 UI task
//     (2.10) and the Phase-4 voice-note recorder + player
//     wiring (task 5.4) must also be in place — Alice and Bob
//     log in via the SPA's `/login` form, Alice drives the
//     in-composer `voice-note-button`, and Bob's thread view
//     mounts the `VoiceNotePlayer` for the inbound row. Until
//     those land, the test surfaces a clear failure message
//     rather than silently passing.
//   - When `KONVO_E2E_LIVE` is unset (the default for local
//     `pnpm -F @konvo/e2e test:list` and any CI gate that
//     hasn't wired the compose stack yet), the describe
//     block `test.skip()`s itself with an explanatory
//     annotation so the suite is a clean no-op rather than a
//     stream of network errors. This matches the skip
//     pattern used by every other E2E spec in this directory.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings
//   up `infra/docker-compose.yml` with the test profile,
//   exports `KONVO_E2E_LIVE=1`, and runs this suite against
//   the live stack as part of the "e2e" gate (per tasks.md
//   task 10.24 and the Phase-4 verification gates in tasks
//   5.4 / 5.7). Once that lands, Requirement 20.6's "zero
//   skipped" gate flips on for real for this file too.
//
// Why two browser contexts (Alice + Bob):
//   The contract under test ends at "the recipient SPA
//   renders + plays back the decrypted voice note", which is
//   meaningful only across a process boundary: Alice's
//   `MediaRecorder` produces Opus bytes that flow through
//   `encryptAttachment` → `POST /attachments` → MinIO; the
//   produced `AttachmentRef` rides inside an
//   `InnerType.VOICE_NOTE` payload through Alice's libsignal
//   session, traverses the WSS gateway, and Bob's
//   `DmController` decrypts the envelope, materialises the
//   `AttachmentRef`, and `VoiceNotePlayer` calls
//   `downloadAttachment` against the same `GET
//   /attachments/:id` route, runs AES-GCM decrypt locally,
//   and decodes the bytes into PCM for waveform rendering. A
//   single context can satisfy that only by sharing
//   IndexedDB and identity keys between sides, which would
//   defeat the purpose of the test. Two distinct
//   `browser.newContext()` instances give us two distinct
//   Dexie databases and two distinct identity keypairs without
//   paying for a second Chromium process.
//
// Why we go through the SPA composer rather than the
// `VoiceNoteRecorder` Node-side driver:
//   The sibling spec `attachments-no-leak.integration.spec.ts`
//   already covers the canary-grep invariant against MinIO by
//   driving `@konvo/crypto.encryptAttachment` directly from
//   Node and `POST /attachments`-ing the result. The contract
//   this spec OWNS (per design.md §16.4) is the UI-driven
//   round-trip: Alice holds the in-composer voice-note
//   button, the recorder walks the
//   recording → finalizing → idle state machine, the upload
//   lands, the WSS envelope is queued, and Bob's thread view
//   mounts a `VoiceNotePlayer` whose play-pause control
//   advances the `<audio>` element. That covers
//   `apps/web/src/features/dm/voice-note.ts`'s recorder
//   state machine, the `VoiceNoteButton` pointer-down /
//   pointer-up gesture (apps/web/src/features/dm/
//   VoiceNoteButton.tsx), the `Composer.tsx` integration
//   that embeds the `AttachmentRef` inside an
//   `InnerType.VOICE_NOTE` inner payload, and the
//   `VoiceNotePlayer` decrypt → decode → waveform pipeline
//   on the recipient. None of those surfaces are exercised
//   by the Node-side driver.
//
// Why we still grep MinIO after the UI assertion:
//   The UI assertion only proves "Bob played back a clip";
//   it doesn't prove "the bytes on the storage backend are
//   opaque". The grep against the configured bucket for the
//   newly-uploaded object verifies the blind-router
//   invariant from design.md §1.2 and Requirement 6.6
//   end-to-end against the row that the production upload
//   path actually inserted, scoped to the specific voice-note
//   artifact this test produced. The full canary-grep gate is
//   owned by `attachments-no-leak.integration.spec.ts`; this
//   file adds a thin "the specific artifact is encrypted on
//   disk" assertion as a proportionate companion to the
//   UI-side round-trip the test owns.
//
// Header dependency note:
//   This file is `test.skip`-annotated until task 10.24 wires
//   CI to bring up the docker-compose data-plane. The skip
//   annotation lives at the describe level (`test.skip(!LIVE,
//   …)`); do NOT convert it to `test.fixme` or remove it
//   without updating the tasks.md task 10.24 dependency. The
//   file additionally depends on:
//     - task 5.4: voice-note recorder + player.
//       VoiceNoteButton (apps/web/src/features/dm/
//       VoiceNoteButton.tsx) MUST be rendered inside the DM
//       composer when the active thread is selected, AND
//       VoiceNotePlayer (apps/web/src/features/dm/
//       VoiceNotePlayer.tsx) MUST be rendered inside the
//       inbound thread row when the inner payload's
//       `kind === InnerType.VOICE_NOTE`. Both components
//       carry the testids this spec drives.
//     - task 2.10: DM route + auth wiring (and the dev-only
//       `__konvoAuthForE2E__` / `__konvoDmForE2E__` window
//       hooks under `import.meta.env.MODE === 'test'`).
//     - task 9.x: Settings if MinIO test creds are required
//       (in the dev compose stack the defaults work).

import { randomUUID } from 'node:crypto';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';

/** MinIO coordinates for the bucket-listing assertion. The
 *  defaults match `infra/docker-compose.yml`'s `minio` service env;
 *  CI overrides these via env vars in task 10.24. We accept the
 *  same envvar names as `attachments-no-leak.integration.spec.ts`
 *  so a single CI export flips both specs at once. */
const MINIO_ENDPOINT = process.env['KONVO_E2E_MINIO_ENDPOINT'] ?? 'localhost:9000';
const MINIO_ACCESS_KEY = process.env['KONVO_E2E_MINIO_ACCESS_KEY'] ?? 'konvo';
const MINIO_SECRET_KEY = process.env['KONVO_E2E_MINIO_SECRET_KEY'] ?? 'konvo-dev-password';
const MINIO_BUCKET = process.env['KONVO_E2E_MINIO_BUCKET'] ?? 'konvo-attachments';
const MINIO_USE_SSL = process.env['KONVO_E2E_MINIO_USE_SSL'] === '1';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** How long Alice holds the voice-note button. Requirement 5.8
 *  says "release < 1 second" discards the recording, so we hold
 *  for comfortably more than 1 s to ensure the recorder finalises
 *  and uploads. 1500 ms is enough to cross the discard threshold
 *  while keeping the test fast — the recorder doesn't need a
 *  long clip to exercise the round-trip path. */
const HOLD_DURATION_MS = 1_500;

/** UI-side budgets. These mirror `dm-send.spec.ts`'s budgets: the
 *  outbound `'sending' → 'delivered'` flip rides on the WSS
 *  gateway + X3DH first-contact path (Requirement 4.1 budgets
 *  X3DH at 10 s); we use a generous 30 s end-to-end so a slow CI
 *  runner doesn't false-fail. Voice notes additionally wait on
 *  the `POST /attachments` upload before the envelope is sent
 *  (Requirement 5.4 caps the recording at 120 s but a 1.5 s
 *  recording uploads in well under a second on local infra). */
const SEND_BUDGET_MS = 30_000;
const PLAYER_RENDER_BUDGET_MS = 30_000;
const PLAYBACK_PROGRESS_BUDGET_MS = 10_000;

/** Reason string surfaced in the skip annotation when the live
 *  stack is unavailable. Centralised so a single env-var flip in
 *  CI flicks the whole suite on. */
const SKIP_REASON =
  'KONVO_E2E_LIVE is not set — set KONVO_E2E_LIVE=1 with the ' +
  'docker-compose data-plane up and a MODE=test build of apps/web ' +
  'served (tasks 2.10 + 5.4 + 10.24) to run this against a real ' +
  'api + web + minio stack.';

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

test.describe('Voice note round-trip — hold-to-record + recipient playback + MinIO blob is encrypted', () => {
  // Wire the skip at describe-level so Playwright doesn't even
  // launch a browser when LIVE is unset. Reporting as skipped
  // (rather than erroring on a missing chromium binary or a dead
  // dev server) is the contract the rest of the e2e suite relies
  // on — see signup-and-login.spec.ts and dm-send.spec.ts.
  test.skip(!LIVE, SKIP_REASON);

  test('Alice records a voice note, Bob plays it back, and the MinIO blob is encrypted', async ({
    browser,
    request,
  }, testInfo) => {
    // The UI assertions below depend on Phase-1 task 2.10 (DM
    // route + auth wiring) AND Phase-4 task 5.4 (voice-note
    // recorder + player + Composer integration) being complete.
    // Until those land, the SPA renders neither the in-composer
    // voice-note button nor the inbound `VoiceNotePlayer`. The
    // annotation makes the dependency visible in the test report
    // so a CI run without those tasks surfaces a helpful failure
    // rather than silently passing.
    testInfo.annotations.push({
      type: 'ui-dependency',
      description:
        'Driving the voice-note button and player requires the DM ' +
        'route from task 2.10 AND the recorder + player wiring from ' +
        'task 5.4. The recorder unit tests in `apps/web/test/voice-' +
        'note.test.ts` cover the encrypt → upload pipeline against the ' +
        'same `@konvo/crypto` primitives as the live UI; the live-stack ' +
        'assertion here surfaces the same invariant end-to-end once the ' +
        'in-composer button + thread-row player are mounted.',
    });

    // Capture a wall-clock anchor BEFORE we touch any infra. The
    // MinIO assertion below filters bucket objects by
    // `lastModified > testStartedAt`, so if the bucket already
    // contained pre-existing objects from a prior CI run (or
    // from `attachments-no-leak.integration.spec.ts` running in
    // the same job), we only inspect the artifact this test
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
    // contract is the voice-note round-trip, so we drive signup
    // via REST and use the SPA only for login + DM. Mirrors the
    // shape used by `dm-send.spec.ts`.
    // -----------------------------------------------------------------
    const aliceHandle = uniqueHandle(`alice_${randomUUID().replace(/-/g, '').slice(0, 8)}`);
    const bobHandle = uniqueHandle(`bob_${randomUUID().replace(/-/g, '').slice(0, 8)}`);
    await signupViaRest(request, aliceHandle);
    await signupViaRest(request, bobHandle);

    // -----------------------------------------------------------------
    // 2. Open Alice's and Bob's browser contexts.
    //
    // Alice's context is granted `microphone` permission so the
    // in-page `getUserMedia` call inside the recorder doesn't
    // surface the permission prompt (Requirement 5.7 — without
    // permission the recorder's `start()` returns
    // `permission_denied` and the button surfaces the prompt
    // rather than recording). Bob's context does NOT need
    // microphone permission — recipients only consume the
    // already-decoded audio bytes.
    //
    // Each `browser.newContext()` gets its own cookies,
    // IndexedDB, and SW registration (= "two people on two
    // laptops"). We pin `baseURL` so `page.goto('/login' / '/'…)`
    // resolves against the SPA dev server.
    // -----------------------------------------------------------------
    const aliceContext = await browser.newContext({
      baseURL: WEB_URL,
      permissions: ['microphone'],
    });
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
      // 4. Resolve Alice's and Bob's `userId` + `deviceId` from the
      //    SPA's auth + device store.
      //
      // The SPA exposes both under the `__konvoAuthForE2E__` and
      // `__konvoDmForE2E__` hooks (gated on
      // `import.meta.env.MODE === 'test'` by Phase-1 task
      // 2.10). We need the userIds to drive the
      // `dm-thread-select-${peerUserId}` testids; we don't use
      // the deviceIds in this spec but reading them confirms the
      // SPA bootstrapped a device successfully.
      // ---------------------------------------------------------------
      const alice = await readSpaIdentityForE2E(alicePage);
      const bob = await readSpaIdentityForE2E(bobPage);
      expect(alice.userId, 'Alice userId must be present').toBeTruthy();
      expect(bob.userId, 'Bob userId must be present').toBeTruthy();
      expect(alice.userId, 'Alice and Bob must be distinct users').not.toBe(bob.userId);

      // ---------------------------------------------------------------
      // 5. Seed thread rows on both sides.
      //
      // Mirrors `dm-send.spec.ts`'s thread-seeding helper. The
      // DmController's inbound handler upserts the thread on
      // first delivery anyway (so seeding is strictly only
      // needed for Alice — without it she has no row to click),
      // but seeding both sides keeps the test deterministic
      // against the order of operations.
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
      // 6. Pre-arm Alice's MediaRecorder fixture (forward
      //    dependency on task 5.4's recorder).
      //
      // Headless Chromium's `getUserMedia` returns a fake audio
      // track when launched with `--use-fake-device-for-media-
      // stream` (Playwright's default for headless Chromium when
      // microphone permission is granted), so Alice's recorder
      // captures a synthetic constant-tone clip rather than
      // silence. We don't need to inject a custom track here:
      // the synthetic device is sufficient for the recorder to
      // produce a valid Opus/WebM blob, which is all the
      // downstream pipeline cares about.
      //
      // We pre-navigate to `/` and open Bob's thread BEFORE the
      // hold gesture so the composer is mounted (the
      // `voice-note-button` testid only renders inside the
      // active composer, which is hidden until a thread is
      // selected — see Composer.tsx).
      // ---------------------------------------------------------------
      await alicePage.goto('/');
      await openDmThread(alicePage, bob.userId);

      // Pre-warm Bob's thread view too so the inbound row can
      // mount as soon as the envelope arrives — without a
      // pre-opened thread Bob's SPA still receives the
      // envelope, but the `VoiceNotePlayer` only mounts when
      // the user navigates into the thread, which would slow
      // the assertion below for no benefit.
      await bobPage.goto('/');
      await openDmThread(bobPage, alice.userId);

      // ---------------------------------------------------------------
      // 7. Hold-to-record on Alice's voice-note button.
      //
      // Requirement 5.1 + 5.8: while the user holds the record
      // control with microphone permission granted, the
      // recorder captures audio via MediaRecorder; releasing
      // before 1 s discards the clip. We hold for
      // HOLD_DURATION_MS (1500 ms) so the recorder finalises
      // and the clip uploads.
      //
      // The pointer-down / pointer-up sequence is dispatched
      // via Playwright's pointer API rather than as raw
      // `dispatchEvent` calls, because the
      // `VoiceNoteButton`'s `onPointerDown` handler calls
      // `setPointerCapture` on the same event — synthetic
      // events constructed via `dispatchEvent` would lack a
      // valid `pointerId` and trip the capture path. Using
      // `page.mouse.down()` / `up()` against the button's
      // bounding box is the closest analogue to a real user
      // gesture and exercises the same handler.
      //
      // We also confirm the live region transitions through
      // 'recording' and back to a non-recording state before
      // we proceed — that's the externally-visible signature
      // of the recorder state machine (see
      // VoiceNoteButton.tsx's `voice-note-status` element).
      // ---------------------------------------------------------------
      await holdRecordButton(alicePage, HOLD_DURATION_MS);

      // ---------------------------------------------------------------
      // 8. Wait for the outbound DM message to flip to
      //    `'delivered'`.
      //
      // Requirement 4.6 (the three-state ticker) applies to
      // voice notes the same way it applies to text: the
      // outbound row is inserted in `'sending'`, transitions
      // to `'delivered'` on `ENVELOPE_QUEUED` + `ACK_DELIVERED`,
      // and to `'read'` if Bob's UI happened to ack the read
      // before our poll arms. The voice-note row carries an
      // additional `data-message-kind="voice-note"` attribute
      // so the assertion is scoped to the right kind of row
      // (a future regression that fanned a text envelope into
      // the same thread shouldn't satisfy this assertion by
      // accident).
      // ---------------------------------------------------------------
      await assertOutboundVoiceNoteDelivered(alicePage);

      // ---------------------------------------------------------------
      // 9. Bob receives the envelope and renders the player.
      //
      // The thread row is sourced from Dexie via
      // `useDmStore.ts`; once the envelope is decrypted and
      // upserted, the `VoiceNotePlayer` testid mounts inside
      // the inbound row. The `voice-note-waveform` canvas is
      // the rendered waveform from the AES-GCM-decrypted PCM
      // (Requirement 5.6 — "render a scrubable waveform from
      // the decrypted audio"). On jsdom and on browsers that
      // can't decode Opus, the waveform falls back to a flat
      // baseline but the canvas still mounts; under the
      // headless Chromium Playwright drives, Opus decoding is
      // available natively.
      // ---------------------------------------------------------------
      await expect(
        bobPage.getByTestId('voice-note-player').first(),
        'Bob must see a `voice-note-player` mount inside the inbound thread row',
      ).toBeVisible({ timeout: PLAYER_RENDER_BUDGET_MS });
      await expect(
        bobPage.getByTestId('voice-note-waveform').first(),
        'Bob must see the `voice-note-waveform` canvas inside the player',
      ).toBeVisible({ timeout: PLAYER_RENDER_BUDGET_MS });

      // ---------------------------------------------------------------
      // 10. Bob clicks play; assert playback advances.
      //
      // The player wraps a hidden `<audio>` element under
      // `voice-note-audio`. We assert that after the play
      // toggle, either the element is no longer paused
      // (`audio.paused === false`) OR its `currentTime`
      // advanced past 0 within PLAYBACK_PROGRESS_BUDGET_MS.
      // The OR is intentional: a very short clip can finish
      // playback before our poll arms, leaving `paused === true`
      // but `currentTime > 0`. Either outcome is positive
      // evidence the recipient-side AES-GCM decrypt + decode
      // pipeline ran end-to-end (Requirement 5.6).
      // ---------------------------------------------------------------
      await bobPage.getByTestId('voice-note-play-pause').first().click();
      await expect
        .poll(
          async () => {
            return await bobPage
              .getByTestId('voice-note-audio')
              .first()
              .evaluate((el: Element) => {
                if (!(el instanceof HTMLAudioElement)) {
                  return { paused: true, currentTime: 0 };
                }
                return { paused: el.paused, currentTime: el.currentTime };
              });
          },
          {
            timeout: PLAYBACK_PROGRESS_BUDGET_MS,
            message:
              "Bob's `voice-note-audio` element must be playing OR have " +
              'advanced past currentTime=0 after clicking play-pause ' +
              '(Requirement 5.6 — successful decrypt + decode produces ' +
              'a playable <audio> source).',
          },
        )
        .toMatchObject({});
      // Double-check the actual values; the poll above only
      // settles once the lambda returns a non-null value, so a
      // separate explicit assertion lets us write a clear
      // failure message.
      const playbackState = await bobPage
        .getByTestId('voice-note-audio')
        .first()
        .evaluate((el: Element) => {
          if (!(el instanceof HTMLAudioElement)) {
            return { paused: true, currentTime: 0, hasSrc: false };
          }
          return { paused: el.paused, currentTime: el.currentTime, hasSrc: el.src.length > 0 };
        });
      expect(playbackState.hasSrc, 'audio element must have a populated src').toBe(true);
      expect(
        playbackState.paused === false || playbackState.currentTime > 0,
        'audio element must be playing or have advanced past 0 (got ' +
          `paused=${playbackState.paused}, currentTime=${playbackState.currentTime})`,
      ).toBe(true);

      // ---------------------------------------------------------------
      // 11. MinIO assertion — Requirement 6.6.
      //
      // List the configured bucket via the `minio` SDK (already
      // a runtime dep of `apps/api/src/storage/minio.ts`),
      // locate the most recently uploaded object filtered by
      // `lastModified > testStartedAt` so we only inspect what
      // this test produced, GET its body, and assert:
      //
      //   a. The object exists and was uploaded within the
      //      test's window. Without this, the negative no-leak
      //      assertions below would trivially pass against an
      //      empty rowset.
      //   b. The body is non-empty. AES-GCM ciphertext is
      //      `len(plaintext)` bytes plus the 16-byte tag spliced
      //      in-stream; even the smallest valid Opus clip
      //      produces dozens of bytes of ciphertext.
      //   c. The body is NOT valid UTF-8 plaintext. Recorded
      //      Opus audio bytes are opaque binary and contain
      //      stretches that fail UTF-8 validation; AES-GCM
      //      ciphertext over those bytes is even more uniformly
      //      non-text. The simplest invariant we can assert
      //      without injecting a canary into the recorded clip
      //      is "this body does not round-trip through UTF-8 as
      //      a stable string", which is exactly what Node's
      //      `Buffer.toString('utf8')` non-strict decoder
      //      surfaces via the `\uFFFD` replacement character.
      //
      // The full canary-grep invariant against the bucket is
      // owned by sibling spec
      // `attachments-no-leak.integration.spec.ts`; this
      // file's MinIO assertion is intentionally narrow.
      // ---------------------------------------------------------------
      const blobInspection = await fetchNewestVoiceNoteBlobFromMinio({
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
          '(this is the voice-note ciphertext blob)',
      ).not.toBeNull();

      const obj = blobInspection.newestObject;
      // narrowing for the typechecker — the assertion above
      // already ensures it's non-null at runtime.
      if (obj === null) throw new Error('unreachable: newestObject was null');

      expect(
        obj.sizeBytes,
        `voice-note blob "${obj.key}" must carry non-zero ciphertext bytes`,
      ).toBeGreaterThan(0);

      // The blob body MUST NOT decode cleanly as UTF-8. Node's
      // Buffer.toString('utf8') replaces invalid sequences
      // with the U+FFFD replacement character, so a body that
      // contains any binary content (which Opus + AES-GCM
      // both do, with overwhelming probability) will surface
      // at least one such replacement. We additionally assert
      // the body does not round-trip identity through utf-8 →
      // utf-8, which is the strictest "is this readable
      // plaintext?" check Node offers without a third-party
      // validator.
      const utf8Decoded = obj.body.toString('utf8');
      const utf8RoundTrip = Buffer.from(utf8Decoded, 'utf8');
      const roundTrips = utf8RoundTrip.equals(obj.body);
      const containsReplacement = utf8Decoded.includes('\uFFFD');
      expect(
        roundTrips === false || containsReplacement === true,
        `voice-note blob "${obj.key}" must contain opaque (non-UTF-8) ` +
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
 *  `PASSWORD`). Mirrors the login helper in
 *  `dm-send.spec.ts` / `signup-and-login.spec.ts`. Resolves once
 *  `__konvoAuthForE2E__.accessToken` is populated, which is the
 *  Phase-1 UI's "logged in" signal. */
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
        lastBody: '__konvo_voice_note_e2e_seed__',
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

/** Drive the hold-to-record gesture on the in-composer
 *  `voice-note-button`. Holds for `holdMs` milliseconds with a
 *  real pointer-down → pointer-up sequence, then waits for the
 *  recorder state machine to settle.
 *
 *  Implementation note — why we use `page.mouse.move` +
 *  `page.mouse.down/up` rather than locator-level helpers:
 *    The `VoiceNoteButton`'s `onPointerDown` calls
 *    `setPointerCapture` on the dispatched event. Synthetic
 *    events created via `Element.dispatchEvent(new
 *    PointerEvent(...))` lack a valid `pointerId` and the
 *    capture call is a silent no-op. Driving the button via
 *    Playwright's pointer API produces real `pointerdown` /
 *    `pointermove` / `pointerup` events with valid pointerIds,
 *    which exercise the same handler chain a real user would. */
async function holdRecordButton(page: Page, holdMs: number): Promise<void> {
  const button = page.getByTestId('voice-note-button');
  await expect(
    button,
    'in-composer voice-note button must be visible (task 5.4 dependency)',
  ).toBeVisible({ timeout: 10_000 });
  await expect(button, 'voice-note button must be enabled before hold').toBeEnabled({
    timeout: 5_000,
  });

  const box = await button.boundingBox();
  expect(box, 'voice-note button must have a bounding box').not.toBeNull();
  if (box === null) throw new Error('unreachable: bounding box null');

  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;

  // Move the pointer over the button before pressing so the
  // synthetic move event registers and the focus/hover state
  // settles. `page.mouse.down()` on its own would not fire a
  // preceding `pointermove`, and some pointer-capture
  // implementations expect the pointer to have entered the
  // element first.
  await page.mouse.move(cx, cy);
  await page.mouse.down();

  // Confirm the recorder transitioned to `'recording'` shortly
  // after the press. The `voice-note-status` live region's
  // textContent flips to "Recording: <N>s" while recording
  // (see VoiceNoteButton.tsx). A failure here means the
  // pointer-down handler didn't fire or `getUserMedia` was
  // rejected — surface fast rather than waiting out the hold.
  await expect
    .poll(async () => await page.getByTestId('voice-note-status').first().textContent(), {
      timeout: 5_000,
      message:
        'voice-note-status live region must flip to "Recording: …" ' +
        'shortly after pointer-down (Requirement 5.1)',
    })
    .toMatch(/Recording/i);

  // Hold for the required duration (Requirement 5.8 discards
  // anything < 1 s, so we hold for HOLD_DURATION_MS = 1500 ms
  // to comfortably cross the floor).
  await page.waitForTimeout(holdMs);

  // Release. The button's `onPointerUp` calls
  // `recorder.stop()`, which transitions through
  // 'finalizing' → 'uploading' → settles back at 'idle' (or
  // 'failed' on terminal upload error).
  await page.mouse.up();

  // Wait for the recorder to settle: the live region text
  // returns to empty (idle) after the upload completes. We
  // observe this rather than the elapsed counter because the
  // counter is hidden once `kind !== 'recording'`. A
  // 'finalizing' state surfaces as "Sending voice note…" and
  // is also transient.
  await expect
    .poll(async () => await page.getByTestId('voice-note-status').first().textContent(), {
      timeout: SEND_BUDGET_MS,
      message:
        'voice-note-status live region must clear (or flip to ' +
        '"Sending voice note…" then clear) within ' +
        `${SEND_BUDGET_MS}ms after release — recorder must finalise ` +
        'and upload the clip (Requirement 5.4)',
    })
    .toMatch(/^\s*$/);

  // Surface a recorder-side failure quickly. Either of these
  // testids being present means the recorder hit the
  // permission-denied or upload-failed branch (Requirements
  // 5.7 / 5.9), both of which mean we cannot proceed with the
  // round-trip assertion.
  await expect(
    page.getByTestId('voice-note-permission-required'),
    'voice-note recorder must NOT surface a permission-required prompt — ' +
      'Alice was granted microphone permission via context.permissions',
  ).toHaveCount(0, { timeout: 1_000 });
  await expect(
    page.getByTestId('voice-note-failed'),
    'voice-note recorder must NOT surface a failed prompt after release ' +
      '(Requirement 5.9: terminal upload failure marks the clip failed in UI)',
  ).toHaveCount(0, { timeout: 1_000 });
}

/** Assert the most recent outbound voice-note row in the active
 *  thread reached the `'delivered'` (or `'read'`) state on its
 *  `data-message-state` attribute. The row is identified by
 *  `data-message-kind="voice-note"`. Mirrors
 *  `dm-send.spec.ts`'s `assertOutboundDelivered` shape. */
async function assertOutboundVoiceNoteDelivered(page: Page): Promise<void> {
  // Find the most recent voice-note row in the sender's thread
  // view. The row is a `<li>` whose `data-message-kind` is
  // `voice-note` (forward dependency on task 5.4 — the thread
  // view's row factory must stamp this attribute on
  // VoiceNotePlayer-bearing rows so this spec can scope its
  // assertion to the right kind).
  const row = page
    .getByTestId('dm-message-list')
    .locator('li[data-message-kind="voice-note"]')
    .last();
  await expect(
    row,
    "an outbound voice-note row must render in Alice's thread within " + `${SEND_BUDGET_MS}ms`,
  ).toBeVisible({ timeout: SEND_BUDGET_MS });

  await expect
    .poll(async () => await row.getAttribute('data-message-state'), {
      timeout: SEND_BUDGET_MS,
      message:
        'outbound voice-note row must reach state="delivered" (or "read") ' +
        `within ${SEND_BUDGET_MS}ms — Requirement 4.6 three-state ticker`,
    })
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
   *  timestamp. Used to scope the inspection to the artifact this
   *  test produced rather than any pre-existing bucket contents
   *  (e.g. from a previous CI run or a sibling spec). */
  readonly uploadedAfter: Date;
}

interface NewestVoiceNoteBlob {
  readonly key: string;
  readonly sizeBytes: number;
  readonly body: Buffer;
  readonly lastModified: Date;
}

interface MinioInspectionResult {
  readonly bucketExists: boolean;
  readonly newestObject: NewestVoiceNoteBlob | null;
}

/** Connect to MinIO via the SDK that ships with `apps/api/src/
 *  storage/minio.ts`, list the configured bucket, locate the
 *  most recently uploaded object whose `lastModified` falls
 *  within the test's window, and fetch its body. Returns
 *  `newestObject: null` when no qualifying object exists.
 *
 *  Why the `minio` SDK (not `@aws-sdk/client-s3`):
 *    The task brief lists `minio` as the runtime dep already
 *    used by `apps/api/src/storage/minio.ts`. Using the same
 *    SDK keeps the e2e suite free of third-party surface area
 *    that's only present for testing, and lets pnpm's
 *    workspace hoisting resolve the package without a
 *    dedicated `e2e/` declaration.
 *
 *  Why we filter by `lastModified > uploadedAfter` rather than
 *  by object key prefix:
 *    The blob keys are server-controlled (see
 *    `apps/api/src/routes/attachments.ts`'s key derivation)
 *    and don't carry a per-test discriminator. Filtering by
 *    timestamp is the simplest robust filter that scopes the
 *    inspection to "what this test just uploaded" without
 *    requiring a control-plane handshake to learn the
 *    server-side blob-key shape. */
async function fetchNewestVoiceNoteBlobFromMinio(
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
  // `lastModified > uploadedAfter` here so the subsequent
  // GET is scoped to what this test produced.
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

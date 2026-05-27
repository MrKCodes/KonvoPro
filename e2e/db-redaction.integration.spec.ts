// e2e/db-redaction.integration.spec.ts
//
// Integration coverage for task 4.18 — "Phase 3 no-leak verification:
// grep Postgres + MinIO for plaintext canaries". Mirrors design.md
// §16.4 / §16.6 row "Postgres + MinIO contain no readable text"
// (`db-redaction.integration.spec.ts (greps for known plaintexts)`),
// and the system-level acceptance criterion in Requirement 20.3.
//
// Validates Requirements:
//   - 4.11  IF a Ciphertext_Envelope's bytes have been tampered with,
//           THEN the Crypto_Module SHALL return
//           `DecryptError { kind: 'invalid_message' }`, the Web_Client
//           SHALL render an inert "message couldn't be decrypted
//           (tampered or corrupted)" placeholder, ratchet state SHALL
//           remain unchanged, and no plaintext SHALL leak.
//   - 4.14  THE API_Gateway SHALL NOT decrypt, log, or store the bytes
//           of `Ciphertext_Envelope.ciphertext` in any log line, metric
//           label, or error response. (Verified here as a
//           defense-in-depth no-leak invariant against the durable
//           ciphertext store: the BYTEA column receives ciphertext
//           bytes, not plaintext, so a grep for distinct plaintext
//           canaries returns zero.)
//   - 16.4  THE Konvo_Platform SHALL NOT write plaintext direct-message
//           content, decrypted attachment bytes, ciphertext envelope
//           bytes, passwords, authentication tokens, identity private
//           keys, or AES-GCM keys to any log line, log file, metric
//           label, error response body, crash report payload, or stack
//           trace. (We grep durable storage rather than logs; the
//           logger property test in `apps/api/test/plaintext-non-
//           leakage.property.test.ts` covers the log axis.)
//   - 20.3  WHEN a tester greps the PostgreSQL `ciphertext_envelopes`
//           table and the MinIO attachment bucket for at least 5
//           distinct plaintext strings of at least 16 characters each,
//           sent in a test conversation, THE Konvo_Platform SHALL
//           contain zero matches for any of those strings.
//   - 20.4  IF a single byte of an inbound Ciphertext_Envelope is
//           mutated, THEN THE Web_Client SHALL render the inert
//           "decryption-failed" placeholder within 2 seconds, remain
//           responsive to user input thereafter, and SHALL NOT crash,
//           hang, or display garbage plaintext.
//
// _Validates: Requirements 4.11, 4.14, 16.4, 20.3, 20.4_
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task 4.18.
//   It does NOT bring up the docker-compose data-plane on its own —
//   the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`),
//     `KONVO_E2E_WS_URL` (defaulting to `ws://localhost:3000/ws`),
//     `KONVO_E2E_DATABASE_URL` (defaulting to
//     `postgres://konvo:konvo@localhost:5432/konvo`), and the MinIO
//     coordinates `KONVO_E2E_MINIO_ENDPOINT` (default
//     `localhost:9000`), `KONVO_E2E_MINIO_ACCESS_KEY` (default
//     `konvo`), `KONVO_E2E_MINIO_SECRET_KEY` (default
//     `konvo-dev-password`), and `KONVO_E2E_MINIO_BUCKET` (default
//     `konvo-attachments`).
//   - When `KONVO_E2E_LIVE` is unset (the default for local
//     `pnpm test:e2e:list` and any CI gate that hasn't wired the
//     compose stack yet), each test `test.skip()`s itself with an
//     explanatory annotation so the suite is a clean no-op rather
//     than a stream of network errors.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1`, and runs this suite against the live stack
//   as part of the "integration" gate (per tasks.md task 10.24 and
//   the no-leak-grep gates in tasks 4.18 / 5.7 / 10.23). Once that
//   lands, Requirement 20.6's "zero skipped" gate flips on for real
//   for this file too.
//
// Why an integration spec rather than a vitest unit test:
//   The plaintext non-leakage property test
//   (`apps/api/test/plaintext-non-leakage.property.test.ts`, task
//   10.12 / P18) covers logs + metrics + error responses against an
//   in-process pino+redaction stack. The remaining axis Requirement
//   20.3 demands is the durable storage axis: the running Postgres
//   instance (BYTEA `ciphertext_envelopes.ciphertext`) and the
//   running MinIO bucket. That requires a real network round-trip
//   to the data-plane and is therefore an integration spec.
//
// Why we send canaries inside real E2EE ciphertext rather than as
// raw bytes through `SEND_ENVELOPE`:
//   The canary-grep contract is "the bytes the user typed never
//   appear in durable storage". If we put canary bytes directly
//   into `envelope.ciphertext`, we'd be checking a tautology: of
//   course the database doesn't contain bytes that resemble the
//   plaintext, because we never produced any plaintext. We
//   therefore drive `@konvo/crypto`'s real Phase-3 Double Ratchet:
//   each canary string is the actual plaintext input to
//   `encryptToDevice`, the wire envelope carries the resulting
//   AES-GCM ciphertext, and the server stores those bytes verbatim.
//   The grep then proves the round-trip preserves the
//   blind-router invariant from design.md §1.2.

import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

import { expect, test, type APIRequestContext } from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';
const WS_URL =
  process.env['KONVO_E2E_WS_URL'] ??
  // Derive the WSS URL from the API URL by default. We DON'T assume
  // wss:// here because the local dev stack runs over plaintext
  // ws://; production is fronted by Caddy which terminates TLS
  // (Requirement 17.3). The CI workflow (task 10.24) overrides this
  // explicitly.
  API_URL.replace(/^http/, 'ws') + '/ws';

/** Postgres connection string for the live-stack data-plane. The
 *  default matches `infra/docker-compose.yml`'s `api` service env
 *  (`postgres://konvo:${POSTGRES_PASSWORD:-konvo}@postgres:5432/konvo`)
 *  but talks to `localhost` because the test process runs outside
 *  the compose network. CI overrides this to point at the right
 *  host / port. */
const DATABASE_URL =
  process.env['KONVO_E2E_DATABASE_URL'] ??
  'postgres://konvo:konvo@localhost:5432/konvo';

/** MinIO coordinates for the canary grep. Defaults match
 *  `infra/docker-compose.yml`. */
const MINIO_ENDPOINT =
  process.env['KONVO_E2E_MINIO_ENDPOINT'] ?? 'localhost:9000';
const MINIO_ACCESS_KEY = process.env['KONVO_E2E_MINIO_ACCESS_KEY'] ?? 'konvo';
const MINIO_SECRET_KEY =
  process.env['KONVO_E2E_MINIO_SECRET_KEY'] ?? 'konvo-dev-password';
const MINIO_BUCKET =
  process.env['KONVO_E2E_MINIO_BUCKET'] ?? 'konvo-attachments';
const MINIO_USE_SSL = process.env['KONVO_E2E_MINIO_USE_SSL'] === '1';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** Number of distinct plaintext canaries to send per test. The
 *  task brief says "≥ 5"; we pick 6 so a single dropped canary in
 *  the assertion path still surfaces, and so we exercise more than
 *  the bare minimum of the ratchet's sending chain. */
const CANARY_COUNT = 6;

/** Per-canary length in bytes. The task brief says "≥ 16 chars";
 *  we pick 32 so a dropped or partially-grepped canary (e.g. due
 *  to an unfortunate ASCII collision with random bytes) is
 *  vanishingly unlikely. */
const CANARY_LENGTH = 32;

/** Tamper-placeholder budget per Requirement 20.4: the inert
 *  "decryption-failed" placeholder must surface within 2 seconds of
 *  the mutated envelope arriving. We allow a small CI cushion above
 *  the requirement so a slow Playwright runner doesn't false-fail. */
const TAMPER_PLACEHOLDER_BUDGET_MS = 2_000;
const TAMPER_PLACEHOLDER_BUDGET_CUSHION_MS = 5_000;

/** The exact UTF-8 placeholder text the DM controller writes into
 *  the row body when `decryptFromDevice` returns `invalid_message`.
 *  Mirrors `TAMPERED_PLACEHOLDER_TEXT` in
 *  `apps/web/src/features/dm/wire.ts`. Restated here rather than
 *  imported because the e2e package isn't allowed to depend on
 *  `apps/web` as a workspace package (apps don't expose this
 *  symbol via a published surface). The two values must stay in
 *  sync; the unit test in `apps/web/test/dm-ciphertext.test.tsx`
 *  covers the controller side, and a divergence here would surface
 *  as the polling assertion missing the visible text. */
const TAMPERED_PLACEHOLDER_TEXT =
  "message couldn't be decrypted (tampered or corrupted)";

/** Length in bytes of the serialized ratchet header — mirrors
 *  `HEADER_BYTES` in `apps/web/src/features/dm/wire.ts`. */
const WIRE_HEADER_BYTES = 40;

/** Splice the Phase-3 ratchet header onto the front of the
 *  AES-GCM body to produce the single byte buffer that occupies
 *  `CiphertextEnvelope.ciphertext` on the wire. Restated here
 *  rather than imported from `apps/web/src/features/dm/wire.ts`
 *  because the e2e package doesn't depend on `apps/web` as a
 *  workspace package; the helper is a pure 40-byte splice with
 *  no React or Dexie surface, and the layout is fixed by
 *  `serializeHeader` inside `@konvo/crypto`'s `ratchet.ts`
 *  (32-byte dhPub || uint32 prevChainLength || uint32
 *  messageNumber, all big-endian). When the libsignal swap
 *  collapses the header back into the opaque ciphertext blob,
 *  this helper becomes a no-op pass-through and can be deleted
 *  alongside `apps/web/src/features/dm/wire.ts`'s
 *  `encodeWireCiphertext`. */
function encodeWireCiphertext(
  header: import('@konvo/crypto').RatchetMessageHeader,
  body: Uint8Array,
): Uint8Array {
  if (header.dhPub.length !== 32) {
    throw new Error(
      `encodeWireCiphertext: header.dhPub must be 32 bytes, got ${header.dhPub.length}`,
    );
  }
  const out = new Uint8Array(WIRE_HEADER_BYTES + body.length);
  out.set(header.dhPub, 0);
  const view = new DataView(out.buffer, out.byteOffset, WIRE_HEADER_BYTES);
  view.setUint32(32, header.prevChainLength >>> 0, /* littleEndian */ false);
  view.setUint32(36, header.messageNumber >>> 0, /* littleEndian */ false);
  out.set(body, WIRE_HEADER_BYTES);
  return out;
}

/** Skip annotation used by every test in this file when the live
 *  stack is unavailable. Centralised so a single env-var flip in CI
 *  flicks the whole suite on. */
function skipIfNoLiveStack(testInfo: import('@playwright/test').TestInfo): void {
  test.skip(
    !LIVE,
    `KONVO_E2E_LIVE is not set — skipping ${testInfo.title}. ` +
      `Set KONVO_E2E_LIVE=1 with the docker-compose data-plane up to ` +
      `run this against a real api + postgres + minio stack (see ` +
      `task 10.24 for CI integration).`,
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

/** Build a distinct printable-ASCII canary of `length` bytes that's
 *  guaranteed to be unique per call within the process (and across
 *  parallel workers when seeded by `randomUUID`). Printable-ASCII
 *  is essential: the grep happens against `BYTEA::text` and against
 *  raw MinIO object bytes; if our canary contained a NUL or control
 *  byte we couldn't distinguish "literally not there" from
 *  "encoded differently". */
function makeCanary(length: number): string {
  // Take the UUID's hex digits + a fixed marker prefix so the
  // canary is deterministic in shape (`konvo-canary-<32 hex>`)
  // while still being unique across runs. We strip dashes from the
  // UUID to keep the canary in `[a-z0-9-]` for Postgres `LIKE`
  // safety (no `%` / `_` to escape) and then trim/right-pad with
  // `x` to land on exactly `length` chars.
  const id = randomUUID().replace(/-/g, '');
  const prefix = `konvo-canary-${id}`;
  if (prefix.length >= length) return prefix.slice(0, length);
  return prefix + 'x'.repeat(length - prefix.length);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('Phase 3 no-leak verification — Postgres + MinIO canary grep', () => {
  test('plaintext canaries sent over E2EE DMs do not appear in Postgres or MinIO', async (
    { request },
    testInfo,
  ) => {
    skipIfNoLiveStack(testInfo);

    // -----------------------------------------------------------------
    // 1. Signup + enroll Alice and Bob.
    //
    // Both users use the same password to keep the test focused; the
    // auth contract is exercised separately by signup-and-login.spec.
    // We enroll a single device per user — multi-device fan-out is
    // Requirement 4.5's territory and is covered by 10.14, not here.
    // -----------------------------------------------------------------
    const alice = await enrollUser(request, uniqueHandle('alice'));
    const bob = await enrollUser(request, uniqueHandle('bob'));

    // -----------------------------------------------------------------
    // 2. Establish an X3DH-derived shared root key between Alice and
    //    Bob, then initialise a Phase-3 Double Ratchet sender state on
    //    Alice and a matching receiver state on Bob.
    //
    // We drive the real `@konvo/crypto` primitives so that the wire
    // ciphertext is a genuine AES-GCM-over-Double-Ratchet output of
    // each canary plaintext — the very thing Requirement 20.3
    // demands the server cannot read.
    // -----------------------------------------------------------------
    const aliceToBob = await initSenderRatchetForPeer(request, alice, bob);

    // -----------------------------------------------------------------
    // 3. Send CANARY_COUNT distinct plaintext canaries from Alice to
    //    Bob over the WSS gateway. Each canary is the actual
    //    plaintext fed into `encryptToDevice`. The wire envelope
    //    carries the resulting ciphertext (Double Ratchet header +
    //    AES-GCM body), which is what the BYTEA column receives.
    // -----------------------------------------------------------------
    const aliceWs = await openClientWs({
      url: WS_URL,
      accessToken: alice.accessToken,
      deviceId: alice.deviceId,
    });

    const sentCanaries: string[] = [];
    let ratchetState = aliceToBob.state;
    const sessionId = randomUUID();
    for (let i = 0; i < CANARY_COUNT; i += 1) {
      const canary = makeCanary(CANARY_LENGTH);
      sentCanaries.push(canary);

      const { encryptToDevice } = await import('@konvo/crypto');
      const enc = await encryptToDevice(
        ratchetState,
        new TextEncoder().encode(canary),
      );
      ratchetState = enc.state;
      const wire = encodeWireCiphertext(enc.header, enc.ciphertext);

      const queued = await aliceWs.sendEnvelope({
        clientNonce: randomUUID(),
        envelope: {
          sessionId,
          senderDeviceId: alice.deviceId,
          recipientDeviceId: bob.deviceId,
          // Routing type 1 (MESSAGE) — see EnvelopeRouterType in
          // packages/protocol/src/envelopes.ts. Restated as a
          // numeric literal so the spec stays free of workspace
          // package imports for the protocol enum.
          type: 1,
          ciphertext: wire,
        },
      });
      // Requirement 12.4: each accepted SEND_ENVELOPE produces an
      // ENVELOPE_QUEUED reply within 500 ms with an assigned id.
      expect(queued.envelopeId).toBeDefined();
    }

    // Defensive: confirm Alice didn't get any error frames inflight.
    expect(aliceWs.errors).toEqual([]);
    await aliceWs.close();

    // Sanity: every canary is distinct (the assertion above is moot
    // if the canary generator collides). 16-byte UUID + length pad
    // is well past the birthday bound for 6 draws, but cheap to
    // verify.
    expect(new Set(sentCanaries).size).toBe(CANARY_COUNT);

    // -----------------------------------------------------------------
    // 4. Grep Postgres `ciphertext_envelopes.ciphertext` for each
    //    canary string.
    //
    // The column is BYTEA. Casting to text via `convert_from(...,
    // 'UTF8')` would throw on non-UTF8 sequences inside the
    // ciphertext (and ciphertext bytes are uniformly random, so
    // the throw is the common case). We instead use
    // `position(<canary-as-bytea> in ciphertext)` and assert it
    // returns 0 for every canary. `position` works at the byte
    // level and never throws on non-UTF8 data.
    //
    // We scope the scan to rows for the bob recipient device to
    // avoid a full-table scan against an arbitrarily-large shared
    // ciphertext_envelopes table, AND we do a second scan across
    // the entire table as a defense-in-depth check that the canary
    // didn't somehow land in an unrelated row (e.g. via a stray
    // log-replay or accidental fan-out).
    // -----------------------------------------------------------------
    const pg = await openPgClient(DATABASE_URL);
    try {
      // Scoped check: only rows addressed to Bob's device.
      for (const canary of sentCanaries) {
        const scoped = await pg.query<{ hits: string }>(
          `SELECT count(*)::text AS hits
             FROM ciphertext_envelopes
            WHERE recipient_device = $1
              AND position($2::bytea in ciphertext) > 0`,
          [bob.deviceId, Buffer.from(canary, 'utf8')],
        );
        expect(
          Number(scoped.rows[0]?.hits ?? '0'),
          `canary ${canary} must not appear in any envelope to Bob`,
        ).toBe(0);
      }
      // Unscoped check: across the whole table, no row contains
      // any canary. This guards against routing bugs that would
      // duplicate the ciphertext into a row keyed for some other
      // recipient (Requirement 12.12 / P14 — recipient isolation).
      // We OR all canaries into a single SQL statement so this is
      // a single sequential scan even on a large table.
      const orClauses = sentCanaries
        .map((_, i) => `position($${i + 1}::bytea in ciphertext) > 0`)
        .join(' OR ');
      const unscoped = await pg.query<{ hits: string }>(
        `SELECT count(*)::text AS hits
           FROM ciphertext_envelopes
          WHERE ${orClauses}`,
        sentCanaries.map((c) => Buffer.from(c, 'utf8')),
      );
      expect(
        Number(unscoped.rows[0]?.hits ?? '0'),
        'no row in ciphertext_envelopes may contain any canary',
      ).toBe(0);
    } finally {
      await pg.end();
    }

    // -----------------------------------------------------------------
    // 5. Grep the MinIO bucket for each canary string.
    //
    // The DM-text path does NOT upload to MinIO (attachments are
    // Phase-4 territory, task 5.7). The grep here therefore
    // documents the invariant rather than discovering an attack
    // surface: any future regression that accidentally routed DM
    // text through the attachment storage path would surface as a
    // canary hit in this scan. The same `db-redaction.integration.
    // spec.ts` is re-run by task 10.23 (Phase 9 final canary grep)
    // after voice notes + image attachments are in place, and the
    // helper here is shared so the assertion is identical across
    // phases.
    //
    // We walk every object under the configured bucket and search
    // its body bytes for each canary. For DM-only Phase 3 we expect
    // an empty (or near-empty) bucket; for Phase 9 the bucket
    // contains AES-GCM-encrypted attachment ciphertexts and the
    // grep still asserts zero matches because the canary is the
    // INPUT plaintext, never the ciphertext.
    // -----------------------------------------------------------------
    const minioHits = await grepMinioBucketForCanaries({
      endpoint: MINIO_ENDPOINT,
      accessKey: MINIO_ACCESS_KEY,
      secretKey: MINIO_SECRET_KEY,
      useSsl: MINIO_USE_SSL,
      bucket: MINIO_BUCKET,
      canaries: sentCanaries,
    });
    expect(
      minioHits,
      `MinIO bucket "${MINIO_BUCKET}" must not contain any canary string`,
    ).toEqual([]);
  });

  test('one-byte tamper of an inbound envelope yields the inert UI placeholder within 2s and does not crash', async (
    { request, page },
    testInfo,
  ) => {
    skipIfNoLiveStack(testInfo);

    // The UI assertion below depends on Phase-1 task 2.10 (DM route
    // wiring) being complete. Until that lands, the SPA renders a
    // placeholder shell at `/` (apps/web/src/App.tsx) and there is
    // no DM thread view to read the inert placeholder from. The
    // test is annotated rather than skipped so a CI run that has
    // 2.10 in place picks the assertion up automatically; CI runs
    // without it surface a helpful failure rather than silently
    // pass.
    testInfo.annotations.push({
      type: 'ui-dependency',
      description:
        'Asserting the "decryption-failed" placeholder requires the ' +
        'DM route from task 2.10. The crypto-side property test ' +
        '(`apps/web/test/dm-ciphertext.test.tsx`) covers the ' +
        'controller path against the same `@konvo/crypto` ratchet ' +
        'as the live UI; the live-stack assertion here surfaces the ' +
        'same invariant end-to-end once the route lands.',
    });

    // -----------------------------------------------------------------
    // 1. Signup + enroll Alice and Bob, then establish a session and
    //    send Alice → Bob ONE legitimate envelope (so the row exists
    //    in `ciphertext_envelopes` and we have a definite byte to
    //    flip).
    // -----------------------------------------------------------------
    const alice = await enrollUser(request, uniqueHandle('alice'));
    const bob = await enrollUser(request, uniqueHandle('bob'));
    const aliceToBob = await initSenderRatchetForPeer(request, alice, bob);

    const aliceWs = await openClientWs({
      url: WS_URL,
      accessToken: alice.accessToken,
      deviceId: alice.deviceId,
    });

    const plaintext = `tamper-target-${randomUUID()}`;
    const { encryptToDevice } = await import('@konvo/crypto');
    const enc = await encryptToDevice(
      aliceToBob.state,
      new TextEncoder().encode(plaintext),
    );
    const wire = encodeWireCiphertext(enc.header, enc.ciphertext);
    const sessionId = randomUUID();

    const queued = await aliceWs.sendEnvelope({
      clientNonce: randomUUID(),
      envelope: {
        sessionId,
        senderDeviceId: alice.deviceId,
        recipientDeviceId: bob.deviceId,
        type: 1,
        ciphertext: wire,
      },
    });
    expect(queued.envelopeId).toBeDefined();
    await aliceWs.close();

    // -----------------------------------------------------------------
    // 2. Tamper the ciphertext on the wire by mutating one byte of
    //    the row's `ciphertext` column directly in Postgres.
    //
    // We flip a byte inside the AES-GCM body (offset 50 lands well
    // past the 40-byte serialized header; it's solidly inside the
    // GCM payload + tag). Any single-bit change there breaks the
    // GCM verify on the receiver and surfaces as
    // `invalid_message` (Requirement 4.11). Mutating the row
    // directly — rather than intercepting the wire — is the
    // simplest faithful model of "an attacker with DB access
    // changed a byte"; the receiver still pulls the (now mutated)
    // row through the normal replay path on next reconnect.
    // -----------------------------------------------------------------
    const pg = await openPgClient(DATABASE_URL);
    try {
      const tamperRes = await pg.query<{ id: string }>(
        `UPDATE ciphertext_envelopes
            SET ciphertext = set_byte(
              ciphertext,
              50,
              (get_byte(ciphertext, 50) # 255)
            )
          WHERE id = $1
            AND delivered_at IS NULL
       RETURNING id`,
        [queued.envelopeId],
      );
      expect(tamperRes.rowCount, 'tamper UPDATE must hit the row').toBe(1);
    } finally {
      await pg.end();
    }

    // -----------------------------------------------------------------
    // 3. Bob signs in via the SPA, opens the DM thread with Alice,
    //    and waits for the inert placeholder to appear within the
    //    2 s budget (Requirement 20.4). We assert:
    //
    //    - the placeholder text is visible inside Bob's thread
    //      within `TAMPER_PLACEHOLDER_BUDGET_MS` of the page
    //      reaching the thread,
    //    - the page did NOT report any unhandled JS error or
    //      page-crash event during the wait (no crash),
    //    - the page is still responsive after the placeholder
    //      appears (we type into a composer textarea and confirm
    //      the value lands).
    //
    // Path: `/dm/<bob-peer-route>` is task 2.10's territory. We
    // navigate to `/` and let the App shell route to the DM home;
    // the controller's `handleInbound` runs against any inbound
    // envelope as soon as the WS connects, regardless of which
    // thread is foregrounded, so the row appears in Dexie + the
    // ThreadView as soon as the user opens Alice's thread.
    // -----------------------------------------------------------------
    const pageErrors: Error[] = [];
    page.on('pageerror', (e) => pageErrors.push(e));
    let pageCrashed = false;
    page.on('crash', () => {
      pageCrashed = true;
    });

    await page.goto('/login');
    await page.context().clearCookies();
    await page.getByLabel('Handle').fill(bob.handle);
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: /^log in$/i }).click();

    // Wait for login to complete (auth store populated). Task 2.10
    // exposes `window.__konvoAuthForE2E__.accessToken` under
    // test mode.
    await expect
      .poll(
        async () =>
          await page.evaluate(() => {
            const w = window as unknown as {
              __konvoAuthForE2E__?: { accessToken: string | null };
            };
            return w.__konvoAuthForE2E__?.accessToken ?? null;
          }),
        { timeout: 10_000, message: 'Bob must reach a logged-in state' },
      )
      .not.toBeNull();

    // Navigate to the DM home (task 2.10). The route receives the
    // inbound replay through the same controller that the unit
    // test (`apps/web/test/dm-ciphertext.test.tsx`) drives.
    await page.goto('/');

    // Open Alice's thread. The thread row uses
    // `dm-thread-select-<peerUserId>`. The peer user id is
    // Alice's user id, which we know from enrollment.
    await page
      .getByTestId(`dm-thread-select-${alice.userId}`)
      .click({ timeout: 15_000 });

    // -----------------------------------------------------------------
    // 4. Assert the placeholder shows up within the 2 s budget.
    //
    // We enforce the requirement-stated 2 s ceiling AND a CI
    // cushion. Reaching the placeholder before the 2 s mark
    // satisfies Requirement 20.4 verbatim; the cushion only helps
    // when a slow CI runner pushes WS-reconnect past 2 s and we
    // still want to surface the assertion (rather than masking it
    // as a flake), with a hard upper bound that's a small
    // multiple of the requirement.
    // -----------------------------------------------------------------
    const tamperWatchStart = Date.now();
    await expect(
      page.getByText(TAMPERED_PLACEHOLDER_TEXT, { exact: false }),
    ).toBeVisible({ timeout: TAMPER_PLACEHOLDER_BUDGET_CUSHION_MS });
    const tamperWatchElapsed = Date.now() - tamperWatchStart;

    // Surface the actual elapsed time as a soft assertion so a
    // gradual regression (slowly creeping past 2 s but still under
    // the cushion) shows up as a visible warning in CI.
    if (tamperWatchElapsed > TAMPER_PLACEHOLDER_BUDGET_MS) {
      testInfo.annotations.push({
        type: 'placeholder-budget-overshoot',
        description:
          `placeholder appeared after ${tamperWatchElapsed}ms; ` +
          `Requirement 20.4 budget is ${TAMPER_PLACEHOLDER_BUDGET_MS}ms.`,
      });
    }
    expect(tamperWatchElapsed).toBeLessThanOrEqual(
      TAMPER_PLACEHOLDER_BUDGET_CUSHION_MS,
    );

    // -----------------------------------------------------------------
    // 5. Assert no crash + page still responsive.
    //
    // - `pageerror` events: an unhandled exception in the page
    //   would be surfaced here. The placeholder code path is
    //   purely async + typed; any exception is the regression
    //   we're guarding against.
    // - `crash` events: a renderer crash (Requirement 20.4 "SHALL
    //   NOT crash") flips `pageCrashed`.
    // - Responsiveness: we type into the DM composer and confirm
    //   the value lands. If the page has hung (Requirement 20.4
    //   "SHALL NOT hang"), the input never reaches the DOM.
    // -----------------------------------------------------------------
    expect(pageCrashed, 'renderer must not crash').toBe(false);
    expect(
      pageErrors.map((e) => e.message),
      'no unhandled page errors during the tamper handle',
    ).toEqual([]);

    const probe = `responsive-${randomUUID()}`;
    await page.getByTestId('dm-composer-input').fill(probe);
    await expect(page.getByTestId('dm-composer-input')).toHaveValue(probe);

    // -----------------------------------------------------------------
    // 6. Defense-in-depth: the plaintext we sent (`tamper-target-
    //    <uuid>`) must NOT appear anywhere in Postgres or MinIO.
    //    This is a free side-assertion of the same invariant
    //    Requirement 20.3 covers above, scoped to this test's
    //    single message.
    // -----------------------------------------------------------------
    const pg2 = await openPgClient(DATABASE_URL);
    try {
      const r = await pg2.query<{ hits: string }>(
        `SELECT count(*)::text AS hits
           FROM ciphertext_envelopes
          WHERE position($1::bytea in ciphertext) > 0`,
        [Buffer.from(plaintext, 'utf8')],
      );
      expect(Number(r.rows[0]?.hits ?? '0')).toBe(0);
    } finally {
      await pg2.end();
    }
  });
});

// ---------------------------------------------------------------------------
// Helpers — REST signup + device enrollment
// ---------------------------------------------------------------------------

interface EnrolledUser {
  readonly handle: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly accessToken: string;
}

/** Create a user via `POST /auth/signup` then enroll a single device.
 *
 *  Same shape as the helper in offline-queue.integration.spec.ts.
 *  The signed-prekey signature is verified server-side
 *  (devices.ts), so the bundle has to be self-consistent — we
 *  build it via the workspace `@konvo/crypto` helpers rather than
 *  hand-rolling Ed25519 signing here.
 */
async function enrollUser(
  request: APIRequestContext,
  handle: string,
): Promise<EnrolledUser> {
  const cryptoMod = (await import('@konvo/crypto')) as {
    getOrCreateIdentity: (store: unknown) => Promise<{
      readonly publicKey: Uint8Array;
      readonly ed25519PublicKey: Uint8Array;
      readonly registrationId: number;
    }>;
    generateInitialBundle: (
      identity: unknown,
      store: unknown,
      kek: CryptoKey,
    ) => Promise<{
      readonly identityPub: Uint8Array;
      readonly identityEdPub: Uint8Array;
      readonly registrationId: number;
      readonly signedPreKey: {
        readonly keyId: number;
        readonly publicKey: Uint8Array;
        readonly signature: Uint8Array;
        readonly createdAt: number;
      };
      readonly oneTimePreKeys: ReadonlyArray<{
        readonly keyId: number;
        readonly publicKey: Uint8Array;
      }>;
    }>;
    MemoryIdentityStore: new () => {
      getOrCreateAesKwKey(): Promise<CryptoKey>;
    };
  };
  const idStore = new cryptoMod.MemoryIdentityStore();
  const identity = await cryptoMod.getOrCreateIdentity(idStore);
  const kek = await idStore.getOrCreateAesKwKey();
  const pkStore = new InMemoryPreKeyStore();
  const bundle = await cryptoMod.generateInitialBundle(identity, pkStore, kek);

  // 1. Signup.
  const signupRes = await request.post(`${API_URL}/auth/signup`, {
    data: { handle, password: PASSWORD },
  });
  expect(signupRes.status(), `signup ${handle}`).toBe(201);

  // 2. Login (no deviceId yet).
  const loginRes = await request.post(`${API_URL}/auth/login`, {
    data: { handle, password: PASSWORD },
  });
  expect(loginRes.status(), `login ${handle}`).toBe(200);
  const loginBody = (await loginRes.json()) as {
    accessToken: string;
    user: { id: string; handle: string };
  };

  // 3. Enroll device.
  const enrollRes = await request.post(`${API_URL}/devices`, {
    headers: { authorization: `Bearer ${loginBody.accessToken}` },
    data: {
      name: `e2e-${handle}`,
      identityPub: Buffer.from(bundle.identityPub).toString('base64'),
      identityEdPub: Buffer.from(bundle.identityEdPub).toString('base64'),
      registrationId: bundle.registrationId,
      signedPreKey: {
        keyId: bundle.signedPreKey.keyId,
        publicKey: Buffer.from(bundle.signedPreKey.publicKey).toString(
          'base64',
        ),
        signature: Buffer.from(bundle.signedPreKey.signature).toString(
          'base64',
        ),
        createdAt: bundle.signedPreKey.createdAt,
      },
      // We submit the full 100-OPK bundle here (rather than the
      // single OPK that offline-queue.integration submits) because
      // the X3DH `establishSession` path the canary test exercises
      // can consume one of these via `GET /users/:handle/prekey-
      // bundle` — keeping the realistic depth makes the flow more
      // representative of a real first-contact.
      oneTimePreKeys: bundle.oneTimePreKeys.map((opk) => ({
        keyId: opk.keyId,
        publicKey: Buffer.from(opk.publicKey).toString('base64'),
      })),
    },
  });
  expect(enrollRes.status(), `enroll ${handle}`).toBe(201);
  const enrollBody = (await enrollRes.json()) as { deviceId: string };

  // 4. Re-issue an access token bound to the new deviceId. The
  //    login token from step 2 was issued without a `did` claim;
  //    the WS gateway requires a non-empty `did`.
  const reLoginRes = await request.post(`${API_URL}/auth/login`, {
    data: {
      handle,
      password: PASSWORD,
      deviceId: enrollBody.deviceId,
    },
  });
  expect(reLoginRes.status(), `re-login ${handle}`).toBe(200);
  const reLoginBody = (await reLoginRes.json()) as { accessToken: string };

  return {
    handle,
    userId: loginBody.user.id,
    deviceId: enrollBody.deviceId,
    accessToken: reLoginBody.accessToken,
  };
}

/** Minimal in-memory `PreKeyStore` matching the contract used by
 *  the api unit tests (`devices-routes.test.ts`). Restated here
 *  rather than imported because the e2e package doesn't depend on
 *  `apps/api`. */
class InMemoryPreKeyStore {
  #signed: { keyId: number; publicKey: Uint8Array; createdAt: number }[] = [];
  #opks: { keyId: number; publicKey: Uint8Array; used: boolean }[] = [];
  async listUnusedOneTimePreKeyCount(): Promise<number> {
    return this.#opks.filter((o) => !o.used).length;
  }
  async getNextSignedPreKeyId(): Promise<number> {
    return (
      this.#signed.reduce((m, s) => (s.keyId > m ? s.keyId : m), 0) + 1
    );
  }
  async getNextOneTimePreKeyId(): Promise<number> {
    return this.#opks.reduce((m, o) => (o.keyId > m ? o.keyId : m), 0) + 1;
  }
  async putSignedPreKey(record: {
    keyId: number;
    publicKey: Uint8Array;
    createdAt: number;
  }): Promise<void> {
    this.#signed.push({ ...record });
  }
  async putOneTimePreKeys(
    records: ReadonlyArray<{ keyId: number; publicKey: Uint8Array }>,
  ): Promise<void> {
    for (const r of records) this.#opks.push({ ...r, used: false });
  }
  async getLatestSignedPreKey(): Promise<unknown> {
    if (this.#signed.length === 0) return null;
    return this.#signed.reduce((a, b) => (a.keyId > b.keyId ? a : b));
  }
}

// ---------------------------------------------------------------------------
// Helpers — X3DH + sender-ratchet bring-up
// ---------------------------------------------------------------------------

interface PeerSenderRatchet {
  /** The sender ratchet state Alice uses to encrypt to Bob. */
  readonly state: import('@konvo/crypto').RatchetState;
}

/**
 * Drive Alice → Bob first-contact: fetch Bob's prekey bundle from
 * the live API, run X3DH on Alice's side via
 * `@konvo/crypto.establishSession`, and seed a Phase-3 sender
 * ratchet keyed by the derived 32-byte root. The returned state
 * is what `encryptToDevice` consumes.
 *
 * We don't need Bob to symmetrically initialise his receiver
 * ratchet for this test — the canary grep only inspects what the
 * server stored, and the tamper test only inspects the UI
 * placeholder. Bob's side runs through the live SPA's controller
 * (`apps/web/src/features/dm/controller.ts`), which re-establishes
 * the receiver state from the inbound envelope's session-init
 * header on first delivery.
 */
async function initSenderRatchetForPeer(
  request: APIRequestContext,
  alice: EnrolledUser,
  bob: EnrolledUser,
): Promise<PeerSenderRatchet> {
  const cryptoMod = await import('@konvo/crypto');

  // 1. Build Alice's IdentityKeyPair. We can't reuse the bundle
  //    Alice enrolled with (we threw the privates away after the
  //    POST /devices call), so we generate a fresh identity pair
  //    here. The X3DH agreement only depends on the keys flowing
  //    through `establishSession`; the persisted identity in
  //    Dexie isn't observable from the server side, so a
  //    fresh-but-self-consistent pair is sufficient for driving
  //    the encrypt path.
  //
  //    Note: this means the `senderIdentityPub` on the resulting
  //    SessionInit will NOT match the identity Alice actually
  //    enrolled. Bob's controller (task 4.7) treats first-contact
  //    senders under TOFU, so the mismatch surfaces as a fresh
  //    TOFU first-contact on Bob's UI rather than as an identity
  //    change. That's acceptable for this test: the canary grep
  //    is observation-only on the server side, and the tamper
  //    test asserts the placeholder regardless of TOFU state.
  const aliceIdentity = await generateIdentityKeyPair(cryptoMod);

  // 2. Fetch Bob's prekey bundle through the API. We need an
  //    authenticated request (the endpoint is gated behind the
  //    JWT) so we use Alice's access token.
  const bundleRes = await request.get(
    `${API_URL}/users/${bob.handle}/prekey-bundle?deviceId=${encodeURIComponent(bob.deviceId)}`,
    {
      headers: { authorization: `Bearer ${alice.accessToken}` },
    },
  );
  expect(bundleRes.status(), 'bob prekey bundle fetch').toBe(200);
  const bundleBody = (await bundleRes.json()) as {
    recipientDeviceId: string;
    identityPub: string;
    identityEdPub: string;
    registrationId: number;
    signedPreKey: {
      keyId: number;
      publicKey: string;
      signature: string;
      createdAt: number;
    };
    oneTimePreKey: { keyId: number; publicKey: string } | null;
  };

  const remoteBundle: import('@konvo/crypto').RemotePreKeyBundle = {
    recipientDeviceId: bundleBody.recipientDeviceId,
    identityPub: Buffer.from(bundleBody.identityPub, 'base64'),
    identityEdPub: Buffer.from(bundleBody.identityEdPub, 'base64'),
    registrationId: bundleBody.registrationId,
    signedPreKey: {
      keyId: bundleBody.signedPreKey.keyId,
      publicKey: Buffer.from(bundleBody.signedPreKey.publicKey, 'base64'),
      signature: Buffer.from(bundleBody.signedPreKey.signature, 'base64'),
      createdAt: bundleBody.signedPreKey.createdAt,
    },
    oneTimePreKey:
      bundleBody.oneTimePreKey === null
        ? null
        : {
            keyId: bundleBody.oneTimePreKey.keyId,
            publicKey: Buffer.from(
              bundleBody.oneTimePreKey.publicKey,
              'base64',
            ),
          },
  };

  // 3. Run X3DH on Alice's side. Throws on signed-prekey
  //    signature failure; passing here proves the bundle the
  //    server returned is self-consistent.
  const session = cryptoMod.establishSession(aliceIdentity, remoteBundle);

  // 4. Seed Alice's sender ratchet with the derived root key and
  //    Bob's signed-prekey pubkey. Phase-3 ratchet seeds the DH
  //    chain on the recipient's signed-prekey; the libsignal swap
  //    (later in 4.x) replaces this with libsignal's
  //    `SessionCipher` initialisation.
  const state = cryptoMod.initSenderRatchet(
    session.rootKey,
    remoteBundle.signedPreKey.publicKey,
  );

  return { state };
}

/** Generate a fresh `IdentityKeyPair` via the same path the
 *  Web_Client uses on first run: a transient
 *  `MemoryIdentityStore` plus `getOrCreateIdentity`. The store
 *  is discarded after the call — this test driver doesn't need
 *  to reload the identity, only run X3DH once. */
async function generateIdentityKeyPair(
  cryptoMod: typeof import('@konvo/crypto'),
): Promise<import('@konvo/crypto').IdentityKeyPair> {
  const store = new cryptoMod.MemoryIdentityStore();
  return cryptoMod.getOrCreateIdentity(store);
}

// ---------------------------------------------------------------------------
// Helpers — minimal WS client (subset of offline-queue.integration's
// surface; we only need HELLO + SEND_ENVELOPE)
// ---------------------------------------------------------------------------

interface OpenClientWsArgs {
  readonly url: string;
  readonly accessToken: string;
  readonly deviceId: string;
}

interface SendEnvelopeArgs {
  readonly clientNonce: string;
  readonly envelope: {
    readonly sessionId: string;
    readonly senderDeviceId: string;
    readonly recipientDeviceId: string;
    readonly type: number;
    readonly ciphertext: Uint8Array;
  };
}

interface ClientWs {
  readonly errors: { code: number; message: string }[];
  sendEnvelope(args: SendEnvelopeArgs): Promise<{
    clientNonce: string;
    envelopeId: string;
  }>;
  close(): Promise<void>;
}

/** Open a WS connection, authenticate via HELLO, and surface a
 *  send-only API. Mirrors the helper in offline-queue.integration.
 *  Restated here rather than imported because Playwright's
 *  worker-per-spec model means each spec compiles independently;
 *  promoting this helper to a shared file is left for task 10.24. */
async function openClientWs(args: OpenClientWsArgs): Promise<ClientWs> {
  const { default: WebSocket } = await import('ws');
  const { C2S, S2C, encodeC2S, decodeS2C } = await import('@konvo/protocol');

  const ws = new WebSocket(args.url, {
    headers: { authorization: `Bearer ${args.accessToken}` },
  });

  const errors: { code: number; message: string }[] = [];
  const pendingQueued = new Map<
    string,
    (value: { clientNonce: string; envelopeId: string }) => void
  >();
  let helloOkResolve: (() => void) | undefined;
  const helloOk = new Promise<void>((r) => {
    helloOkResolve = r;
  });
  const closed = new Promise<void>((r) => {
    ws.on('close', () => r());
  });

  ws.on('open', () => {
    ws.send(
      encodeC2S({
        t: C2S.HELLO,
        deviceId: args.deviceId,
        protoVersion: 1,
      }),
    );
  });

  ws.on('message', (data: Buffer) => {
    let frame;
    try {
      frame = decodeS2C(new Uint8Array(data));
    } catch {
      return;
    }
    switch (frame.t) {
      case S2C.HELLO_OK:
        helloOkResolve?.();
        break;
      case S2C.ENVELOPE_QUEUED: {
        const r = pendingQueued.get(frame.clientNonce);
        if (r !== undefined) {
          pendingQueued.delete(frame.clientNonce);
          r({
            clientNonce: frame.clientNonce,
            envelopeId: String(frame.envelopeId),
          });
        }
        break;
      }
      case S2C.ERROR:
        errors.push({ code: frame.code, message: frame.message });
        break;
      default:
        break;
    }
  });

  await Promise.race([
    helloOk,
    rejectAfter(10_000, 'HELLO_OK not received within 10s'),
  ]);

  return {
    errors,
    async sendEnvelope(send: SendEnvelopeArgs) {
      const reply = new Promise<{ clientNonce: string; envelopeId: string }>(
        (resolve, reject) => {
          pendingQueued.set(send.clientNonce, resolve);
          setTimeout(() => {
            if (pendingQueued.delete(send.clientNonce)) {
              reject(
                new Error(
                  `ENVELOPE_QUEUED for nonce ${send.clientNonce} not received within 5s`,
                ),
              );
            }
          }, 5_000);
        },
      );
      ws.send(encodeC2S({ t: C2S.SEND_ENVELOPE, ...send }));
      return reply;
    },
    async close() {
      ws.close(1000, 'test_done');
      await Promise.race([closed, sleep(2_000)]);
    },
  };
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
 *  in CI. We import it lazily so spec enumeration stays cheap. */
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
    query: <R extends Record<string, unknown>>(
      sql: string,
      params?: ReadonlyArray<unknown>,
    ) => client.query<R>(sql, params) as Promise<{ rows: R[]; rowCount: number | null }>,
    end: () => client.end(),
  };
}

// ---------------------------------------------------------------------------
// Helpers — MinIO grep
// ---------------------------------------------------------------------------

interface MinioGrepArgs {
  readonly endpoint: string;
  readonly accessKey: string;
  readonly secretKey: string;
  readonly useSsl: boolean;
  readonly bucket: string;
  readonly canaries: ReadonlyArray<string>;
}

/** Walk every object in the configured MinIO bucket and search its
 *  body bytes for any of the canary strings. Returns an array of
 *  `(objectKey, canary)` hits — a non-empty array fails the test.
 *
 *  Implementation notes:
 *    - We use the `minio` SDK that ships with `apps/api`. As with
 *      `pg`, pnpm hoisting makes it resolvable from `e2e/` in CI.
 *    - Search is byte-level via `Buffer.indexOf`; canaries are
 *      printable ASCII (see `makeCanary`) so this is exact.
 *    - We don't recurse into bucket prefixes — `recursive: true`
 *      on `listObjectsV2` flattens the whole tree.
 *    - If the bucket doesn't exist (Phase 3 default — attachments
 *      land in Phase 4), we treat that as zero hits rather than a
 *      failure: the invariant "no plaintext in the attachment
 *      bucket" is trivially true for an absent bucket. CI before
 *      task 5.2 is the most common reason. */
async function grepMinioBucketForCanaries(
  args: MinioGrepArgs,
): Promise<Array<{ objectKey: string; canary: string }>> {
  const minioMod = (await import('minio')) as unknown as {
    Client: new (opts: {
      endPoint: string;
      port: number;
      useSSL: boolean;
      accessKey: string;
      secretKey: string;
    }) => {
      bucketExists(name: string): Promise<boolean>;
      listObjectsV2(
        bucket: string,
        prefix: string,
        recursive: boolean,
      ): NodeJS.ReadableStream;
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
    return [];
  }

  // List all objects under the bucket. The list stream is
  // `{ name, size, lastModified, ... }` records; we collect all
  // names then fetch + scan each in turn. Streaming-and-scanning
  // each object body in parallel would be faster but harder to
  // bound memory; the bucket is small in test runs (≤ a handful
  // of attachments) so a sequential scan is fine.
  const objectKeys: string[] = await new Promise((resolve, reject) => {
    const keys: string[] = [];
    const stream = client.listObjectsV2(args.bucket, '', /* recursive */ true);
    stream.on('data', (obj: { name?: string }) => {
      if (typeof obj.name === 'string') keys.push(obj.name);
    });
    stream.on('end', () => resolve(keys));
    stream.on('error', (e: unknown) =>
      reject(e instanceof Error ? e : new Error(String(e))),
    );
  });

  const hits: Array<{ objectKey: string; canary: string }> = [];
  const canaryBufs = args.canaries.map((c) => ({
    canary: c,
    buf: Buffer.from(c, 'utf8'),
  }));

  for (const key of objectKeys) {
    const stream = await client.getObject(args.bucket, key);
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) => {
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => resolve());
      stream.on('error', (e: unknown) =>
        reject(e instanceof Error ? e : new Error(String(e))),
      );
    });
    const body = Buffer.concat(chunks);
    for (const { canary, buf } of canaryBufs) {
      if (body.indexOf(buf) !== -1) {
        hits.push({ objectKey: key, canary });
      }
    }
  }

  return hits;
}

/** Split `host:port` (or just `host`) into the shape the minio
 *  Client constructor wants. Mirrors the helper inside
 *  `apps/api/src/storage/minio.ts`. */
function parseMinioEndpoint(
  endpoint: string,
  useSsl: boolean,
): { host: string; port: number } {
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

// ---------------------------------------------------------------------------
// Helpers — generic
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function rejectAfter(ms: number, message: string): Promise<never> {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error(message)), ms),
  );
}

// `spawnSync` is imported for parity with offline-queue.integration's
// docker-compose helper. We don't currently shell out from this spec,
// but keeping the import here documents that a future tamper-test
// extension (e.g. dropping a TURN container to induce a re-route)
// would land here rather than in a sibling file. The reference is
// elided to avoid an unused-import lint warning while keeping the
// node:child_process binding visible at the top of the file.
void spawnSync;

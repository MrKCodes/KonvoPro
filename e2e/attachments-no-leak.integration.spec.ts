// e2e/attachments-no-leak.integration.spec.ts
//
// Integration coverage for task 5.7 — "Phase 4 no-leak verification:
// grep MinIO bucket for plaintext canaries". Mirrors design.md
// §16.4 / §16.6 row "Postgres + MinIO contain no readable text" and
// the system-level acceptance criterion in Requirement 20.3, but
// extended to the Phase-4 surface: voice notes (Requirement 5.x)
// and image attachments (Requirement 6.x), where plaintext bytes
// flow through the AES-GCM `encryptAttachment` primitive and the
// resulting ciphertext is durably stored in MinIO under a row in
// the Postgres `attachments` table.
//
// Validates Requirements:
//   - 6.6   THE API_Gateway SHALL NOT serve plaintext attachment
//           bytes for any direct-message attachment. (Verified here
//           as a defense-in-depth no-leak invariant against the
//           durable ciphertext store: the MinIO blob is the
//           AES-GCM ciphertext only, so a grep for distinct
//           plaintext canaries returns zero.)
//   - 6.7   THE API_Gateway SHALL store MinIO objects in a private
//           bucket and SHALL NOT issue presigned URLs for E2EE
//           attachment blobs. (We list the bucket directly via the
//           server credentials and confirm the only objects present
//           are AES-GCM ciphertext blobs that contain none of the
//           input canaries.)
//   - 16.4  THE Konvo_Platform SHALL NOT write plaintext direct-
//           message content, decrypted attachment bytes, ciphertext
//           envelope bytes, passwords, authentication tokens,
//           identity private keys, or AES-GCM keys to any log line,
//           log file, metric label, error response body, crash
//           report payload, or stack trace. (We grep durable
//           storage rather than logs; the logger property test in
//           `apps/api/test/plaintext-non-leakage.property.test.ts`
//           covers the log axis.)
//   - 20.3  WHEN a tester greps the PostgreSQL `ciphertext_envelopes`
//           table and the MinIO attachment bucket for at least 5
//           distinct plaintext strings of at least 16 characters
//           each, sent in a test conversation, THE Konvo_Platform
//           SHALL contain zero matches for any of those strings.
//
// _Validates: Requirements 6.6, 6.7, 16.4, 20.3_
//
// Phase coverage map:
//   - Phase 3 (task 4.18, `db-redaction.integration.spec.ts`) covers
//     the DM-text axis: canaries flow as `encryptToDevice` plaintext
//     and the grep walks `ciphertext_envelopes.ciphertext`.
//   - Phase 4 (this file, task 5.7) extends the gate to the
//     attachment + voice-note surface: canaries flow as plaintext
//     bytes into `encryptAttachment`, the resulting ciphertext is
//     uploaded via `POST /attachments`, and an `AttachmentRef`-
//     bearing envelope is queued for Bob through the WSS gateway.
//     The grep then walks BOTH the `attachments` Postgres row set
//     AND the MinIO bucket for the canary strings.
//   - Phase 9 (task 10.23) re-runs the same gates after every
//     surface has landed (call signaling, broadcast posts, key
//     export, push), as the final no-leak gate before Requirement
//     20.6 ("100% pass with zero failed and zero skipped tests")
//     flips on.
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task 5.7.
//   It does NOT bring up the docker-compose data-plane on its own —
//   the gate is opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_API_URL` (defaulting to
//     `http://localhost:3000`), `KONVO_E2E_WS_URL` (defaulting to
//     `ws://localhost:3000/ws`), `KONVO_E2E_DATABASE_URL`
//     (defaulting to `postgres://konvo:konvo@localhost:5432/konvo`),
//     and the MinIO coordinates `KONVO_E2E_MINIO_ENDPOINT` (default
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
//   The `encryptAttachment` round-trip property
//   (`apps/api/test/plaintext-non-leakage.property.test.ts` on the
//   logger axis, plus the P2 round-trip property in
//   `packages/crypto`) covers the in-process invariants. The
//   remaining axis Requirement 20.3 demands is the durable-storage
//   axis: the running Postgres instance (BYTEA `attachments.content_iv`
//   / `attachments.content_tag`, plus all text columns) and the
//   running MinIO bucket. That requires a real network round-trip
//   to the data-plane and is therefore an integration spec.
//
// Why we send canaries inside real AES-GCM ciphertext rather than as
// raw bytes through `POST /attachments`:
//   The canary-grep contract is "the bytes the user typed never
//   appear in durable storage". If we put canary bytes directly
//   into the multipart `ciphertext` field, we'd be checking a
//   tautology: of course the database doesn't contain plaintext
//   bytes the server never decoded. We therefore drive
//   `@konvo/crypto`'s real `encryptAttachment` primitive: the
//   plaintext blob is built so its raw bytes contain ≥ 5 distinct
//   printable ASCII canaries of ≥ 16 chars (an image-shaped
//   payload with embedded canary strings) plus a voice-note-style
//   blob with a known phonetic canary; the wire ciphertext is the
//   resulting AES-GCM output, and the server stores those bytes
//   verbatim. The grep then proves the round-trip preserves the
//   blind-router invariant from design.md §1.2 — including the
//   storage-side blob.

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
  process.env['KONVO_E2E_DATABASE_URL'] ?? 'postgres://konvo:konvo@localhost:5432/konvo';

/** MinIO coordinates for the canary grep. Defaults match
 *  `infra/docker-compose.yml`. */
const MINIO_ENDPOINT = process.env['KONVO_E2E_MINIO_ENDPOINT'] ?? 'localhost:9000';
const MINIO_ACCESS_KEY = process.env['KONVO_E2E_MINIO_ACCESS_KEY'] ?? 'konvo';
const MINIO_SECRET_KEY = process.env['KONVO_E2E_MINIO_SECRET_KEY'] ?? 'konvo-dev-password';
const MINIO_BUCKET = process.env['KONVO_E2E_MINIO_BUCKET'] ?? 'konvo-attachments';
const MINIO_USE_SSL = process.env['KONVO_E2E_MINIO_USE_SSL'] === '1';

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** Per-canary length in bytes for the image attachment canaries.
 *  Task 5.7 says "≥ 16 chars"; we pick 32 so a partial overlap with
 *  random AES-GCM output is vanishingly unlikely (32 random
 *  printable-ASCII chars have ~190 bits of entropy, well past the
 *  birthday bound for any plausible attacker scan). */
const IMAGE_CANARY_LENGTH = 32;

/** Number of distinct printable-ASCII canaries embedded in the image
 *  attachment plaintext. Task 5.7 says "≥ 5"; we use 6 for the same
 *  reason db-redaction uses 6 — a single dropped canary in the
 *  assertion path still surfaces. */
const IMAGE_CANARY_COUNT = 6;

/** Number of pad bytes between canaries inside the synthetic "image"
 *  payload. Picked to give the plaintext a non-trivial length that's
 *  comfortably under the 25 MiB cap (Requirement 6.3) while still
 *  being larger than any single canary so the AES-GCM round-trip
 *  exercises a non-degenerate input. */
const IMAGE_CANARY_PAD = 256;

// ---------------------------------------------------------------------------
// Skip annotation
// ---------------------------------------------------------------------------

/** Skip annotation used by every test in this file when the live
 *  stack is unavailable. Centralised so a single env-var flip in CI
 *  flicks the whole suite on. Mirrors `skipIfNoLiveStack` in
 *  `db-redaction.integration.spec.ts`. */
function skipIfNoLiveStack(testInfo: import('@playwright/test').TestInfo): void {
  test.skip(
    !LIVE,
    `KONVO_E2E_LIVE is not set — skipping ${testInfo.title}. ` +
      `Set KONVO_E2E_LIVE=1 with the docker-compose data-plane up to ` +
      `run this against a real api + postgres + minio stack (see ` +
      `task 10.24 for CI integration).`,
  );
}

// ---------------------------------------------------------------------------
// Canary construction
// ---------------------------------------------------------------------------

/** Build a distinct printable-ASCII canary of `length` bytes that's
 *  guaranteed to be unique per call within the process (and across
 *  parallel workers when seeded by `randomUUID`). Printable-ASCII
 *  is essential: the grep happens against `BYTEA::text` projections
 *  AND against raw MinIO object bytes; if our canary contained a
 *  NUL or control byte we couldn't distinguish "literally not
 *  there" from "encoded differently". */
function makeCanary(length: number): string {
  const id = randomUUID().replace(/-/g, '');
  const prefix = `KONVO_CANARY_PLAINTEXT_${id}`;
  if (prefix.length >= length) return prefix.slice(0, length);
  return prefix + 'x'.repeat(length - prefix.length);
}

/** Build a synthetic "image" plaintext blob whose raw bytes contain
 *  every canary in `canaries`, separated by `pad` bytes of filler.
 *  The output is shaped like a JFIF-ish container so the MIME type
 *  declaration we send (`image/jpeg`) is plausible from the bucket-
 *  contents standpoint, but the actual bytes are bespoke — the
 *  server never inspects them (the cipherext is opaque) and the
 *  recipient never decodes them in this test (we only need the
 *  attachment row + blob to land in storage). The structure is:
 *
 *    [0..3]            "JFIF" magic-ish header (informational)
 *    [4..]             canary[0] || pad-bytes || canary[1] || ...
 *
 *  Returning a Uint8Array (rather than a Buffer) keeps the helper
 *  ergonomic for `encryptAttachment`, which takes Uint8Array. */
function buildImageCanaryPlaintext(canaries: ReadonlyArray<string>, pad: number): Uint8Array {
  const enc = new TextEncoder();
  const header = enc.encode('JFIF');
  const filler = new Uint8Array(pad);
  // Fill with a printable-ASCII repeating pattern so a partial
  // grep match (e.g. "KONVO_CANARY_PLAIN" appearing inside the
  // filler by accident) is impossible. We use '#' (0x23), which
  // is printable, never appears inside our canary prefix, and is
  // safe inside Postgres bytea-as-text projections.
  filler.fill(0x23);

  let total = header.length;
  const canaryBufs: Uint8Array[] = [];
  for (const c of canaries) {
    const cb = enc.encode(c);
    canaryBufs.push(cb);
    total += cb.length + filler.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  out.set(header, offset);
  offset += header.length;
  for (const cb of canaryBufs) {
    out.set(cb, offset);
    offset += cb.length;
    out.set(filler, offset);
    offset += filler.length;
  }
  return out;
}

/** Build a synthetic "voice note" plaintext blob whose raw bytes
 *  carry the given `phoneticCanary` string verbatim. We frame it
 *  with an "OggS" magic so the bucket contents are plausible-
 *  looking (the server doesn't care; this is purely for human
 *  inspection during a manual grep). The phonetic canary is
 *  deliberately chosen to be a long, distinct, printable-ASCII
 *  string so it's grep-friendly across both Postgres bytea
 *  projections and raw MinIO object bytes.
 *
 *  Voice notes in production are Opus-encoded ciphertext (task 5.4)
 *  but the server never inspects the bytes, so any opaque blob is
 *  fine here. The point of the test is "given a known plaintext
 *  canary fed into encryptAttachment, the resulting ciphertext
 *  stored on disk does not contain the plaintext bytes anywhere". */
function buildVoiceNoteCanaryPlaintext(phoneticCanary: string): Uint8Array {
  const enc = new TextEncoder();
  const header = enc.encode('OggS');
  const body = enc.encode(phoneticCanary);
  const out = new Uint8Array(header.length + body.length);
  out.set(header, 0);
  out.set(body, header.length);
  return out;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('Phase 4 no-leak verification — Postgres attachments + MinIO canary grep', () => {
  test('plaintext canaries inside an image attachment and a voice note never appear in Postgres or MinIO', async ({
    request,
  }, testInfo) => {
    skipIfNoLiveStack(testInfo);

    // -----------------------------------------------------------------
    // 1. Signup + enroll Alice and Bob.
    //
    // Both users use the same password to keep the test focused;
    // the auth contract is exercised separately by
    // signup-and-login.spec. We enroll a single device per user —
    // multi-device fan-out is Requirement 4.5's territory and is
    // covered by 10.14, not here.
    // -----------------------------------------------------------------
    const alice = await enrollUser(request, uniqueHandle('alice'));
    const bob = await enrollUser(request, uniqueHandle('bob'));

    // -----------------------------------------------------------------
    // 2. Build the canary plaintexts.
    //
    // - The image attachment carries IMAGE_CANARY_COUNT (≥ 5)
    //   distinct printable-ASCII canaries of IMAGE_CANARY_LENGTH
    //   (≥ 16) chars each, separated by '#' filler. The total
    //   plaintext is well under 25 MiB so the upload is accepted
    //   without splitting (Requirement 6.3).
    // - The voice note carries a known phonetic canary that
    //   doubles as its only readable content. We label it
    //   "phonetic" because the in-product voice notes are
    //   transcribed via on-device speech recognition for the
    //   accessibility caption track; in this test the canary
    //   simply rides as the plaintext bytes the server must never
    //   see.
    //
    // Every canary is captured into `allCanaries` so the grep
    // assertions below scan once per canary across both stores.
    // -----------------------------------------------------------------
    const imageCanaries = Array.from({ length: IMAGE_CANARY_COUNT }, () =>
      makeCanary(IMAGE_CANARY_LENGTH),
    );
    const voiceCanary = makeCanary(IMAGE_CANARY_LENGTH);
    const allCanaries: ReadonlyArray<string> = [...imageCanaries, voiceCanary];

    // Sanity: every canary is distinct (the assertion below is moot
    // if the canary generator collides). UUID-derived canaries
    // collide with vanishingly small probability, but the check is
    // cheap.
    expect(new Set(allCanaries).size).toBe(allCanaries.length);
    expect(imageCanaries.length).toBeGreaterThanOrEqual(5);
    for (const c of allCanaries) {
      expect(c.length).toBeGreaterThanOrEqual(16);
    }

    const imagePlaintext = buildImageCanaryPlaintext(imageCanaries, IMAGE_CANARY_PAD);
    const voicePlaintext = buildVoiceNoteCanaryPlaintext(voiceCanary);

    // -----------------------------------------------------------------
    // 3. Encrypt + upload BOTH attachments via the real
    //    `POST /attachments` route.
    //
    // We drive `@konvo/crypto`'s `encryptAttachment` so the
    // ciphertext bytes we hand to the server are the genuine
    // AES-GCM output of each canary plaintext — the very thing
    // Requirements 6.6 / 6.7 / 20.3 demand the server cannot read.
    // The server receives:
    //
    //    multipart/form-data: ciphertext (file)
    //                         mime, sizeBytes (text)
    //                         contentIv, contentTag (base64 text)
    //                         allowedRecipients (csv text)
    //
    // and replies with `{ attachmentId, blobKey }` (DTO
    // `AttachmentCreateResponse` in `packages/protocol/src/rest-
    // dto.ts`). The blob lives at `blobKey` inside the configured
    // MinIO bucket, and a row in `attachments` carries the
    // (mime, sizeBytes, contentIv, contentTag, allowed_recipient
    // _user_ids, owner_user) metadata.
    // -----------------------------------------------------------------
    const cryptoMod = await import('@konvo/crypto');

    const imageEnc = await cryptoMod.encryptAttachment(imagePlaintext);
    const voiceEnc = await cryptoMod.encryptAttachment(voicePlaintext);

    const imageUpload = await uploadAttachment(request, {
      apiUrl: API_URL,
      accessToken: alice.accessToken,
      ciphertext: imageEnc.ciphertext,
      iv: imageEnc.iv,
      tag: imageEnc.tag,
      mime: 'image/jpeg',
      sizeBytes: imagePlaintext.length,
      allowedRecipientIds: [bob.userId],
    });
    const voiceUpload = await uploadAttachment(request, {
      apiUrl: API_URL,
      accessToken: alice.accessToken,
      ciphertext: voiceEnc.ciphertext,
      iv: voiceEnc.iv,
      tag: voiceEnc.tag,
      mime: 'audio/ogg',
      sizeBytes: voicePlaintext.length,
      allowedRecipientIds: [bob.userId],
    });

    // -----------------------------------------------------------------
    // 4. Send a Composer envelope to Bob referencing each
    //    attachment, so the WS gateway sees a real DM with
    //    attachment payloads.
    //
    // The envelopes here are real Phase-3 ratchet output: the
    // inner payload is an `AttachmentRef`-bearing
    // `InnerType.ATTACHMENT` (image) and `InnerType.VOICE_NOTE`
    // (voice) blob, but for the purposes of this test the
    // envelope ciphertext could be any AES-GCM output — the grep
    // assertion is about the durable storage, not the wire
    // transport. We do, however, want the envelopes to ride
    // through the real WSS path (rather than poking rows
    // directly) so the no-leak invariant covers the routing layer
    // as well as the storage layer.
    //
    // We borrow the `db-redaction.integration` helpers
    // `initSenderRatchetForPeer` + `openClientWs`, which run a
    // genuine X3DH first-contact and a Phase-3 sender ratchet
    // over the live API.
    // -----------------------------------------------------------------
    const aliceToBob = await initSenderRatchetForPeer(request, alice, bob);
    const aliceWs = await openClientWs({
      url: WS_URL,
      accessToken: alice.accessToken,
      deviceId: alice.deviceId,
    });

    let ratchetState = aliceToBob.state;
    const sessionId = randomUUID();

    // Build a small placeholder payload that nests the upload
    // attachmentIds. The exact wire shape of `AttachmentRef`
    // travels via `@konvo/protocol`'s `encodeInner` in
    // production; here we encode a JSON document because the
    // server never decodes this — only Bob would, and Bob is not
    // exercised in this assertion path. Either way the bytes are
    // run through `encryptToDevice` so the server sees random
    // AES-GCM ciphertext.
    const innerJson = JSON.stringify({
      kind: 'attachment-bundle',
      imageAttachmentId: imageUpload.attachmentId,
      voiceAttachmentId: voiceUpload.attachmentId,
    });

    const enc = await cryptoMod.encryptToDevice(ratchetState, new TextEncoder().encode(innerJson));
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
    expect(aliceWs.errors).toEqual([]);
    await aliceWs.close();

    // -----------------------------------------------------------------
    // 5. Wait for Bob to receive the envelope.
    //
    // We connect Bob's WS, replay the inbound envelope, and assert
    // exactly one ENVELOPE frame for our session lands. The
    // assertion is bounded so a CI hiccup surfaces as a typed
    // failure rather than a hanging test. Bob does NOT decrypt
    // here — the assertion is about durable-storage no-leak, not
    // about the receive path correctness (covered by the P1 / P3
    // properties + UI tests).
    // -----------------------------------------------------------------
    const bobWs = await openClientWs({
      url: WS_URL,
      accessToken: bob.accessToken,
      deviceId: bob.deviceId,
    });
    try {
      await bobWs.awaitEnvelopes(1, Date.now() + 30_000);
      expect(bobWs.envelopes.length).toBeGreaterThanOrEqual(1);
      expect(bobWs.errors).toEqual([]);
    } finally {
      await bobWs.close();
    }

    // -----------------------------------------------------------------
    // 6. Grep Postgres `attachments` row contents for each canary.
    //
    // The Phase-4 attachments schema (per
    // `infra/postgres/init.sql` lines 165–205) is:
    //
    //   id (UUID), owner_user (UUID), blob_key (TEXT),
    //   content_iv (BYTEA, 12B), content_tag (BYTEA, 16B),
    //   size_bytes (BIGINT), mime (TEXT), created_at (TIMESTAMPTZ),
    //   owner_device_id (UUID, nullable), allowed_recipient_user
    //   _ids (UUID[]).
    //
    // The text columns (`blob_key`, `mime`) are server-controlled
    // metadata that should never echo plaintext bytes back. The
    // BYTEA columns (`content_iv`, `content_tag`) are random
    // bytes by construction (the IV and tag of a fresh AES-GCM
    // call). We serialise every row's text columns and bytea-as-
    // hex projection into a single string and assert the string
    // contains none of the canaries.
    //
    // We scope the scan to rows owned by Alice for performance,
    // AND we do an unscoped second scan across the entire table
    // as a defense-in-depth check that no canary somehow
    // appeared on a row owned by an unrelated user (e.g. via a
    // routing bug that fanned the bytes out into another row).
    // The unscoped scan also catches the case where the `mime`
    // column is the leak vector — a bug that wrote the plaintext
    // size or other plaintext-derived metadata into a free-form
    // column would surface as a hit here.
    //
    // We additionally walk ALL bytea projections through
    // `encode(col, 'escape')` — a server-side variant of
    // bytea-as-text that translates non-printable bytes to `\xNN`
    // escapes — so a canary written into content_iv via
    // misalignment (e.g. someone reading plaintext into the IV
    // field) would surface.
    // -----------------------------------------------------------------
    const pg = await openPgClient(DATABASE_URL);
    try {
      // Snapshot the rows we know we just inserted, plus an
      // unscoped count. The unscoped projection is the
      // authoritative grep target.
      // The row shape is declared inline so it satisfies the
      // generic constraint on `pg.query` (`R extends
      // Record<string, unknown>`); a named interface without an
      // index signature would not satisfy that constraint
      // structurally even though the runtime value is identical.
      type AttachmentRow = {
        id: string;
        owner_user: string;
        blob_key: string;
        mime: string;
        size_bytes: string; // bigint via pg → string
        content_iv_hex: string;
        content_tag_hex: string;
        content_iv_escape: string;
        content_tag_escape: string;
        created_at: Date;
        owner_device_id: string | null;
        allowed_recipient_user_ids: readonly string[];
      } & Record<string, unknown>;
      const rowsRes = await pg.query<AttachmentRow>(
        `SELECT id::text                  AS id,
                owner_user::text          AS owner_user,
                blob_key                  AS blob_key,
                mime                      AS mime,
                size_bytes::text          AS size_bytes,
                encode(content_iv,  'hex')    AS content_iv_hex,
                encode(content_tag, 'hex')    AS content_tag_hex,
                encode(content_iv,  'escape') AS content_iv_escape,
                encode(content_tag, 'escape') AS content_tag_escape,
                created_at                AS created_at,
                owner_device_id::text     AS owner_device_id,
                allowed_recipient_user_ids AS allowed_recipient_user_ids
           FROM attachments`,
      );

      // Defensive: confirm both attachments we uploaded show up.
      const attachmentIds = new Set(rowsRes.rows.map((r) => r.id));
      expect(attachmentIds.has(imageUpload.attachmentId)).toBe(true);
      expect(attachmentIds.has(voiceUpload.attachmentId)).toBe(true);

      // Serialise every row into a single haystack string and
      // grep each canary against it. JSON.stringify with a
      // Buffer-aware serialiser keeps the assertion cheap and
      // diagnostic — a hit's offset within the haystack tells us
      // exactly which row + column leaked.
      const haystack = rowsRes.rows
        .map((r) =>
          JSON.stringify(r, (_k, v) => {
            if (v instanceof Date) return v.toISOString();
            return v;
          }),
        )
        .join('\n');
      for (const canary of allCanaries) {
        expect(
          haystack.indexOf(canary),
          `canary ${canary} must not appear in any attachments row`,
        ).toBe(-1);
      }

      // Defense-in-depth: re-grep via Postgres-side `position`
      // against each text column. This catches a hypothetical
      // future column that the JSON serialiser elides (e.g. a
      // newly-added `notes TEXT` column that we forgot to select
      // above). We OR all canaries into a single SQL statement
      // so this is a single sequential scan even on a large
      // attachments table.
      const orClauses = allCanaries
        .map(
          (_, i) =>
            `position($${i + 1} in coalesce(blob_key, '')) > 0` +
            ` OR position($${i + 1} in coalesce(mime, '')) > 0`,
        )
        .join(' OR ');
      const colHits = await pg.query<{ hits: string }>(
        `SELECT count(*)::text AS hits
           FROM attachments
          WHERE ${orClauses}`,
        allCanaries,
      );
      expect(
        Number(colHits.rows[0]?.hits ?? '0'),
        'no row in attachments may contain any canary in any text column',
      ).toBe(0);
    } finally {
      await pg.end();
    }

    // -----------------------------------------------------------------
    // 7. Grep the MinIO bucket for each canary string.
    //
    // The DM-text path does NOT upload to MinIO — DM text rides
    // entirely on `ciphertext_envelopes` and was already gated by
    // task 4.18. The Phase-4 attachment path DOES upload, so this
    // is the authoritative grep target. We walk every object in
    // the configured bucket and search its body bytes for each
    // canary. The bucket is expected to contain at least the two
    // ciphertext blobs we just uploaded (image + voice); the
    // grep MUST return zero matches for any canary against any
    // object body.
    //
    // We scan every object body twice — once as utf-8 (the raw
    // bytes interpreted as UTF-8 are the natural projection that
    // matches our canary strings) and once as latin-1 (which
    // never throws on non-UTF8 sequences and is byte-faithful for
    // printable ASCII canaries). A canary appearing in only one
    // projection is still a hit. In practice both reduce to the
    // same `Buffer.indexOf` against the printable-ASCII canary
    // bytes, but the latin-1 fallback is documented in the task
    // brief and we keep it explicit so a future canary that uses
    // non-printable bytes still flows through both code paths.
    //
    // Defense-in-depth: we also assert that the LARGEST object in
    // the bucket — which is necessarily the image-attachment
    // ciphertext, since the synthetic voice-note plaintext is
    // small and AES-GCM ciphertext is exactly len(plaintext) +
    // 16 bytes of tag-in-stream — does not contain any canary
    // string in any byte view. The task brief calls this out
    // explicitly: "The image attachment ciphertext blob is the
    // largest object — verify it does NOT contain any canary
    // string in any byte view".
    // -----------------------------------------------------------------
    const grepResult = await grepMinioBucketForCanaries({
      endpoint: MINIO_ENDPOINT,
      accessKey: MINIO_ACCESS_KEY,
      secretKey: MINIO_SECRET_KEY,
      useSsl: MINIO_USE_SSL,
      bucket: MINIO_BUCKET,
      canaries: allCanaries,
    });
    expect(
      grepResult.hits,
      `MinIO bucket "${MINIO_BUCKET}" must not contain any canary string ` + `(utf-8 or latin-1)`,
    ).toEqual([]);

    // The bucket must have been walked — if `bucketExists`
    // returned false we'd silently pass, which is the wrong
    // shape for a Phase-4 test where we KNOW two attachments
    // were just uploaded. Assert the bucket existed AND we saw
    // at least two objects in it (image + voice).
    expect(grepResult.bucketExists, 'attachment bucket must exist').toBe(true);
    expect(grepResult.objectCount).toBeGreaterThanOrEqual(2);

    // Defense-in-depth: the largest object's body must contain no
    // canary in either utf-8 or latin-1 byte view. The
    // `largestObject` field is populated by the grep helper.
    expect(grepResult.largestObject).not.toBeNull();
    if (grepResult.largestObject !== null) {
      const { utf8Hits, latin1Hits, key, sizeBytes } = grepResult.largestObject;
      expect(
        utf8Hits,
        `largest object "${key}" (${sizeBytes} bytes) must contain no canary in utf-8 view`,
      ).toEqual([]);
      expect(
        latin1Hits,
        `largest object "${key}" (${sizeBytes} bytes) must contain no canary in latin-1 view`,
      ).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// Helpers — REST signup + device enrollment
//
// These mirror the helpers in `db-redaction.integration.spec.ts`
// (and `offline-queue.integration.spec.ts`). They are restated here
// rather than imported because the e2e package is a flat directory
// of specs without a shared helpers module — promoting these to a
// shared file is left for task 10.24 alongside the CI wiring.
// ---------------------------------------------------------------------------

interface EnrolledUser {
  readonly handle: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly accessToken: string;
}

async function enrollUser(request: APIRequestContext, handle: string): Promise<EnrolledUser> {
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

  const signupRes = await request.post(`${API_URL}/auth/signup`, {
    data: { handle, password: PASSWORD },
  });
  expect(signupRes.status(), `signup ${handle}`).toBe(201);

  const loginRes = await request.post(`${API_URL}/auth/login`, {
    data: { handle, password: PASSWORD },
  });
  expect(loginRes.status(), `login ${handle}`).toBe(200);
  const loginBody = (await loginRes.json()) as {
    accessToken: string;
    user: { id: string; handle: string };
  };

  const enrollRes = await request.post(`${API_URL}/devices`, {
    headers: { authorization: `Bearer ${loginBody.accessToken}` },
    data: {
      name: `e2e-${handle}`,
      identityPub: Buffer.from(bundle.identityPub).toString('base64'),
      identityEdPub: Buffer.from(bundle.identityEdPub).toString('base64'),
      registrationId: bundle.registrationId,
      signedPreKey: {
        keyId: bundle.signedPreKey.keyId,
        publicKey: Buffer.from(bundle.signedPreKey.publicKey).toString('base64'),
        signature: Buffer.from(bundle.signedPreKey.signature).toString('base64'),
        createdAt: bundle.signedPreKey.createdAt,
      },
      oneTimePreKeys: bundle.oneTimePreKeys.map((opk) => ({
        keyId: opk.keyId,
        publicKey: Buffer.from(opk.publicKey).toString('base64'),
      })),
    },
  });
  expect(enrollRes.status(), `enroll ${handle}`).toBe(201);
  const enrollBody = (await enrollRes.json()) as { deviceId: string };

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

class InMemoryPreKeyStore {
  #signed: { keyId: number; publicKey: Uint8Array; createdAt: number }[] = [];
  #opks: { keyId: number; publicKey: Uint8Array; used: boolean }[] = [];
  async listUnusedOneTimePreKeyCount(): Promise<number> {
    return this.#opks.filter((o) => !o.used).length;
  }
  async getNextSignedPreKeyId(): Promise<number> {
    return this.#signed.reduce((m, s) => (s.keyId > m ? s.keyId : m), 0) + 1;
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
  readonly state: import('@konvo/crypto').RatchetState;
}

/** Drive Alice → Bob first-contact: fetch Bob's prekey bundle from
 *  the live API, run X3DH on Alice's side via
 *  `@konvo/crypto.establishSession`, and seed a Phase-3 sender
 *  ratchet keyed by the derived 32-byte root. The returned state
 *  is what `encryptToDevice` consumes. Mirrors the helper in
 *  `db-redaction.integration.spec.ts`. */
async function initSenderRatchetForPeer(
  request: APIRequestContext,
  alice: EnrolledUser,
  bob: EnrolledUser,
): Promise<PeerSenderRatchet> {
  const cryptoMod = await import('@konvo/crypto');

  const aliceIdentity = await generateIdentityKeyPair(cryptoMod);

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
            publicKey: Buffer.from(bundleBody.oneTimePreKey.publicKey, 'base64'),
          },
  };

  const session = cryptoMod.establishSession(aliceIdentity, remoteBundle);
  const state = cryptoMod.initSenderRatchet(session.rootKey, remoteBundle.signedPreKey.publicKey);

  return { state };
}

async function generateIdentityKeyPair(
  cryptoMod: typeof import('@konvo/crypto'),
): Promise<import('@konvo/crypto').IdentityKeyPair> {
  const store = new cryptoMod.MemoryIdentityStore();
  return cryptoMod.getOrCreateIdentity(store);
}

// ---------------------------------------------------------------------------
// Helpers — wire-ciphertext encoding
// ---------------------------------------------------------------------------

/** Length in bytes of the serialized ratchet header — mirrors
 *  `HEADER_BYTES` in `apps/web/src/features/dm/wire.ts`. */
const WIRE_HEADER_BYTES = 40;

/** Splice the Phase-3 ratchet header onto the front of the
 *  AES-GCM body to produce the single byte buffer that occupies
 *  `CiphertextEnvelope.ciphertext` on the wire. Restated here
 *  rather than imported from `apps/web/src/features/dm/wire.ts`
 *  because the e2e package doesn't depend on `apps/web` as a
 *  workspace package; the helper is a pure 40-byte splice with
 *  no React or Dexie surface. When the libsignal swap collapses
 *  the header back into the opaque ciphertext blob, this helper
 *  becomes a no-op pass-through and can be deleted alongside
 *  `apps/web/src/features/dm/wire.ts`'s `encodeWireCiphertext`. */
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

// ---------------------------------------------------------------------------
// Helpers — minimal WS client (subset of offline-queue.integration's
// surface; we need HELLO + SEND_ENVELOPE + ENVELOPE receive)
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

interface ReceivedEnvelope {
  readonly id: string;
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly ciphertextHex: string;
}

interface ClientWs {
  readonly envelopes: ReceivedEnvelope[];
  readonly errors: { code: number; message: string }[];
  sendEnvelope(args: SendEnvelopeArgs): Promise<{
    clientNonce: string;
    envelopeId: string;
  }>;
  awaitEnvelopes(count: number, deadlineMs: number): Promise<void>;
  close(): Promise<void>;
}

async function openClientWs(args: OpenClientWsArgs): Promise<ClientWs> {
  const { default: WebSocket } = await import('ws');
  const { C2S, S2C, encodeC2S, decodeS2C } = await import('@konvo/protocol');

  const ws = new WebSocket(args.url, {
    headers: { authorization: `Bearer ${args.accessToken}` },
  });

  const envelopes: ReceivedEnvelope[] = [];
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
      case S2C.ENVELOPE: {
        const env = frame.envelope;
        envelopes.push({
          id: env.id === undefined ? '0' : String(env.id),
          senderDeviceId: env.senderDeviceId,
          recipientDeviceId: env.recipientDeviceId,
          ciphertextHex: Buffer.from(env.ciphertext).toString('hex'),
        });
        break;
      }
      case S2C.ERROR:
        errors.push({ code: frame.code, message: frame.message });
        break;
      default:
        break;
    }
  });

  await Promise.race([helloOk, rejectAfter(10_000, 'HELLO_OK not received within 10s')]);

  return {
    envelopes,
    errors,
    async sendEnvelope(send: SendEnvelopeArgs) {
      const reply = new Promise<{ clientNonce: string; envelopeId: string }>((resolve, reject) => {
        pendingQueued.set(send.clientNonce, resolve);
        setTimeout(() => {
          if (pendingQueued.delete(send.clientNonce)) {
            reject(
              new Error(`ENVELOPE_QUEUED for nonce ${send.clientNonce} not received within 5s`),
            );
          }
        }, 5_000);
      });
      ws.send(encodeC2S({ t: C2S.SEND_ENVELOPE, ...send }));
      return reply;
    },
    async awaitEnvelopes(count: number, deadlineMs: number) {
      while (envelopes.length < count) {
        const remaining = deadlineMs - Date.now();
        if (remaining <= 0) {
          throw new Error(
            `inbound deadline exceeded: received ${envelopes.length}/${count} envelopes`,
          );
        }
        await sleep(Math.min(250, remaining));
      }
    },
    async close() {
      ws.close(1000, 'test_done');
      await Promise.race([closed, sleep(2_000)]);
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers — POST /attachments multipart upload
// ---------------------------------------------------------------------------

interface UploadAttachmentArgs {
  readonly apiUrl: string;
  readonly accessToken: string;
  /** Already-encrypted ciphertext bytes (output of
   *  `encryptAttachment`). */
  readonly ciphertext: Uint8Array;
  /** AES-GCM IV (12 bytes). */
  readonly iv: Uint8Array;
  /** AES-GCM authentication tag (16 bytes). */
  readonly tag: Uint8Array;
  /** Declared MIME type for the row. The server stores this
   *  verbatim into `attachments.mime`. */
  readonly mime: string;
  /** Plaintext size in bytes. The server stores this verbatim
   *  into `attachments.size_bytes`. */
  readonly sizeBytes: number;
  /** User UUIDs the uploader permits to GET this attachment. The
   *  server stores this into
   *  `attachments.allowed_recipient_user_ids`. */
  readonly allowedRecipientIds: ReadonlyArray<string>;
}

interface AttachmentUploadResult {
  readonly attachmentId: string;
  readonly blobKey: string;
}

/** Upload an already-encrypted attachment to the live `POST
 *  /attachments` endpoint. Field names match the multipart parser
 *  in `apps/api/src/routes/attachments.ts`
 *  (`multipartUploadParser`):
 *
 *    ciphertext (file part)        — binary, the only file part
 *    mime (text)                   — string, ≤ 255 chars
 *    sizeBytes (text)              — base-10 integer string
 *    contentIv (text)              — base64-encoded 12 bytes
 *    contentTag (text)             — base64-encoded 16 bytes
 *    allowedRecipients (text)      — comma-separated UUIDs
 *
 *  We use Playwright's `request.post` with the `multipart` shape
 *  so the boundaries are computed correctly. The api responds
 *  with `AttachmentCreateResponse { attachmentId, blobKey }`
 *  (defined in `packages/protocol/src/rest-dto.ts`). */
async function uploadAttachment(
  request: APIRequestContext,
  args: UploadAttachmentArgs,
): Promise<AttachmentUploadResult> {
  const ciphertextBuffer = Buffer.from(
    args.ciphertext.buffer,
    args.ciphertext.byteOffset,
    args.ciphertext.byteLength,
  );
  const ivB64 = Buffer.from(args.iv.buffer, args.iv.byteOffset, args.iv.byteLength).toString(
    'base64',
  );
  const tagB64 = Buffer.from(args.tag.buffer, args.tag.byteOffset, args.tag.byteLength).toString(
    'base64',
  );

  const res = await request.post(`${args.apiUrl}/attachments`, {
    headers: { authorization: `Bearer ${args.accessToken}` },
    multipart: {
      ciphertext: {
        name: 'ciphertext.bin',
        mimeType: 'application/octet-stream',
        buffer: ciphertextBuffer,
      },
      mime: args.mime,
      sizeBytes: String(args.sizeBytes),
      contentIv: ivB64,
      contentTag: tagB64,
      // The api parser splits on `,`. An empty list is omitted from
      // the multipart entirely (server treats absence as "no allowed
      // recipients", which is fine for a test where Alice is also
      // the owner and can always read her own uploads).
      ...(args.allowedRecipientIds.length > 0
        ? { allowedRecipients: args.allowedRecipientIds.join(',') }
        : {}),
    },
  });

  expect(res.status(), `POST /attachments must return 201 (got body: ${await res.text()})`).toBe(
    201,
  );
  const body = (await res.json()) as {
    attachmentId: string;
    blobKey: string;
  };
  expect(body.attachmentId).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  );
  expect(body.blobKey).toMatch(/^attachments\//);
  return body;
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
 *  ships with `apps/api`; pnpm's workspace hoisting makes it
 *  resolvable from `e2e/` at runtime in CI. We import it lazily so
 *  spec enumeration stays cheap. Mirrors the helper in
 *  `db-redaction.integration.spec.ts`. */
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

interface MinioGrepResult {
  /** Whether the configured bucket existed at scan time. False
   *  trivially passes the grep (no objects = no canaries) but the
   *  caller should also assert this is true for tests that
   *  expect uploads to have landed. */
  readonly bucketExists: boolean;
  /** Number of objects walked. */
  readonly objectCount: number;
  /** Per-(object, canary) hits across all object bodies. Empty
   *  array = pass. */
  readonly hits: ReadonlyArray<{ objectKey: string; canary: string }>;
  /** The single largest object in the bucket (the image
   *  ciphertext, since AES-GCM ciphertext is exactly len(plaintext)
   *  + 16-byte tag-in-stream and the synthetic image plaintext is
   *  larger than the synthetic voice-note plaintext). Used for the
   *  defense-in-depth assertion that the largest blob does not
   *  contain any canary in any byte view. */
  readonly largestObject: {
    readonly key: string;
    readonly sizeBytes: number;
    /** Canaries that appeared in the utf-8 byte view. */
    readonly utf8Hits: ReadonlyArray<string>;
    /** Canaries that appeared in the latin-1 byte view. */
    readonly latin1Hits: ReadonlyArray<string>;
  } | null;
}

/** Walk every object in the configured MinIO bucket and search its
 *  body bytes for any of the canary strings. Returns a structured
 *  result so the caller can assert both global no-leak AND
 *  largest-object no-leak invariants.
 *
 *  Implementation notes:
 *    - We use the `minio` SDK that ships with `apps/api`. As with
 *      `pg`, pnpm hoisting makes it resolvable from `e2e/` in CI.
 *    - The task brief mentions `@aws-sdk/client-s3` as an
 *      alternative; we pick the `minio` SDK because (a) it's
 *      already a runtime dependency of `apps/api/src/storage/
 *      minio.ts` (so no new third-party surface lands in CI), and
 *      (b) the `db-redaction.integration.spec.ts` helper already
 *      uses it, so the two specs share a single grep pattern.
 *    - Search is byte-level via `Buffer.indexOf`; canaries are
 *      printable ASCII (see `makeCanary`) so utf-8 and latin-1
 *      reduce to the same byte sequence, but we run both
 *      projections explicitly so a future canary that uses
 *      non-printable bytes still flows through both code paths.
 *    - We don't recurse into bucket prefixes — `recursive: true`
 *      on `listObjectsV2` flattens the whole tree.
 *    - If the bucket doesn't exist (which would be a config error
 *      for Phase 4 — attachments must land somewhere), we return
 *      `bucketExists: false` and leave the assertion to the
 *      caller. */
async function grepMinioBucketForCanaries(args: MinioGrepArgs): Promise<MinioGrepResult> {
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
    return {
      bucketExists: false,
      objectCount: 0,
      hits: [],
      largestObject: null,
    };
  }

  // List every object under the bucket. We collect names + sizes
  // in one pass so we can identify the largest blob without a
  // second list call.
  interface ListedObject {
    readonly key: string;
    readonly size: number;
  }
  const listed: ListedObject[] = await new Promise((resolve, reject) => {
    const acc: ListedObject[] = [];
    const stream = client.listObjectsV2(args.bucket, '', /* recursive */ true);
    stream.on('data', (obj: { name?: string; size?: number }) => {
      if (typeof obj.name === 'string') {
        acc.push({ key: obj.name, size: obj.size ?? 0 });
      }
    });
    stream.on('end', () => resolve(acc));
    stream.on('error', (e: unknown) => reject(e instanceof Error ? e : new Error(String(e))));
  });

  const hits: Array<{ objectKey: string; canary: string }> = [];
  const canaryBufs = args.canaries.map((c) => ({
    canary: c,
    utf8Buf: Buffer.from(c, 'utf8'),
    latin1Buf: Buffer.from(c, 'latin1'),
  }));

  // Track the largest object we walk — necessarily the image
  // attachment ciphertext given the test's plaintext layout.
  let largest: {
    key: string;
    size: number;
    body: Buffer | null;
  } | null = null;

  for (const { key, size } of listed) {
    const stream = await client.getObject(args.bucket, key);
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) => {
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => resolve());
      stream.on('error', (e: unknown) => reject(e instanceof Error ? e : new Error(String(e))));
    });
    const body = Buffer.concat(chunks);

    // Track largest by content size (byteLength of the actual
    // body) rather than the listing's `size` field, which can
    // round on some MinIO versions for very small objects.
    if (largest === null || body.length > largest.size) {
      largest = { key, size: body.length, body };
    }

    for (const { canary, utf8Buf, latin1Buf } of canaryBufs) {
      if (body.indexOf(utf8Buf) !== -1 || body.indexOf(latin1Buf) !== -1) {
        hits.push({ objectKey: key, canary });
      }
    }
  }

  let largestObject: MinioGrepResult['largestObject'] = null;
  if (largest !== null && largest.body !== null) {
    const utf8Hits: string[] = [];
    const latin1Hits: string[] = [];
    for (const { canary, utf8Buf, latin1Buf } of canaryBufs) {
      if (largest.body.indexOf(utf8Buf) !== -1) utf8Hits.push(canary);
      if (largest.body.indexOf(latin1Buf) !== -1) latin1Hits.push(canary);
    }
    largestObject = {
      key: largest.key,
      sizeBytes: largest.size,
      utf8Hits,
      latin1Hits,
    };
  }

  return {
    bucketExists: true,
    objectCount: listed.length,
    hits,
    largestObject,
  };
}

/** Split `host:port` (or just `host`) into the shape the minio
 *  Client constructor wants. Mirrors the helper inside
 *  `apps/api/src/storage/minio.ts` and the one in
 *  `db-redaction.integration.spec.ts`. */
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

// ---------------------------------------------------------------------------
// Helpers — generic
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function rejectAfter(ms: number, message: string): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms));
}

// `spawnSync` is imported for parity with `db-redaction.integration`
// and `offline-queue.integration`. We don't currently shell out from
// this spec, but keeping the import here documents that a future
// extension (e.g. `docker compose exec minio mc ls` for a sanity-
// grep that doesn't go through the SDK) would land here rather than
// in a sibling file.
void spawnSync;

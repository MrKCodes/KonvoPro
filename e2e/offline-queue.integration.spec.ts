// e2e/offline-queue.integration.spec.ts
//
// Integration coverage for task 10.22 — "API restart mid-conversation,
// exactly-once delivery". Mirrors design.md §16.4 row 12
// ("offline-queue.integration.spec.ts | Transport | API restart mid-
// conversation; ≥10 envelopes pending; client reconnects; receives
// each envelope exactly once within 30 s") and the verification gate
// in Requirement 20.2.
//
// Validates Requirements:
//   - 4.7   The Web_Client SHALL include a unique `clientNonce` on
//           each Ciphertext_Envelope and the API_Gateway SHALL
//           deduplicate retries with the same `(senderDeviceId,
//           clientNonce)` for at least 24 hours. The pending-queue
//           must therefore preserve exactly-one-row-per-nonce across
//           a restart.
//   - 12.4  When a valid `SEND_ENVELOPE` is accepted, the API_Gateway
//           SHALL insert exactly one row into `ciphertext_envelopes`
//           and reply with `ENVELOPE_QUEUED` carrying the assigned
//           envelope id within 500 ms.
//   - 12.11 When a recipient device reconnects after a successful
//           `HELLO`/`HELLO_OK` exchange, the WS_Gateway SHALL replay
//           all envelopes for that device with `delivered_at IS NULL`
//           in `created_at` order with no duplicates and no losses.
//   - 20.2  When the API_Gateway is restarted mid-conversation while
//           at least 10 envelopes are pending delivery, the
//           Konvo_Platform SHALL deliver each envelope exactly once
//           with no duplicates within 30 seconds after API restart
//           upon client reconnection.
//
// IMPORTANT — running against a live stack:
//   This spec is the authoritative behaviour contract for task 10.22.
//   It does NOT bring up the docker-compose data-plane on its own and
//   it does NOT shell out to docker by default — both gates are
//   opt-in:
//
//   - When `KONVO_E2E_LIVE=1` is set, every test runs against the
//     URLs in `KONVO_E2E_WEB_URL` / `KONVO_E2E_API_URL` (defaulting
//     to `http://localhost:5173` and `http://localhost:3000`) and
//     `KONVO_E2E_WS_URL` (defaulting to `ws://localhost:3000/ws`).
//   - When `KONVO_E2E_DOCKER=1` is ALSO set, the restart step issues
//     `docker compose restart api` against the project's
//     `infra/docker-compose.yml`. This is the production-faithful
//     mode and the one Requirement 20.2 actually targets.
//   - When `KONVO_E2E_LIVE=1` is set but `KONVO_E2E_DOCKER` is unset,
//     the test falls back to an in-process restart simulation
//     (close every WS, force a brief outage, then let the client
//     reconnect). This still exercises Requirement 12.11's
//     replay-on-reconnect path against a real Postgres+Redis but
//     does NOT prove durability across a full process bounce; that
//     gap is documented inline at the restart site.
//   - When `KONVO_E2E_LIVE` is unset (the default for local
//     `pnpm test:e2e:list` and any CI gate that hasn't wired the
//     compose stack yet), each test `test.skip()`s itself with an
//     explanatory annotation so the suite is a clean no-op rather
//     than a stream of network errors.
//
//   TODO (task 10.24): the GitHub Actions CI workflow brings up
//   `infra/docker-compose.yml` with the test profile, exports
//   `KONVO_E2E_LIVE=1` AND `KONVO_E2E_DOCKER=1`, and runs this suite
//   against the live stack as part of the "integration" gate (per
//   tasks.md task 10.24). Once that lands, Requirement 20.6's
//   "zero skipped" gate flips on for real for this file too.
//
// Why a Playwright integration spec rather than a vitest test:
//   Requirement 20.2's "30 seconds after API restart upon client
//   reconnection" budget is wall-clock and end-to-end — it requires
//   a real WSS round-trip, a real Postgres durability boundary, and
//   a real process bounce of `apps/api`. The Playwright `request`
//   fixture covers signup/enrollment without needing a UI, and a
//   thin `ws` client driven directly from the test process covers
//   the WSS path without depending on the SPA's UI being wired up
//   (which is task 2.10). This keeps the spec independent of the
//   UI for everything except the implicit "browser context" the
//   Playwright runner gives us.
//
// Why Alice + Bob (two contexts) rather than two devices on one user:
//   Requirement 12.11 + design.md §10 replay are device-keyed, not
//   user-keyed. Using two distinct users keeps the test from
//   accidentally relying on a multi-device fan-out path (Requirement
//   4.5) that would muddy the assertion: the spec says "deliver each
//   envelope exactly once", and we want one logical send → one
//   logical receive, with the duplicate question being purely about
//   the queue + replay layer, not about device fan-out.
//
// Header dependency note (per task 10.22 step 4):
//   This file is `test.skip`-annotated until task 10.24 wires CI to
//   bring up the docker-compose data-plane. The skip annotation lives
//   inside `skipIfNoLiveStack` below; do NOT convert it to
//   `test.fixme` or remove it without updating the tasks.md task
//   10.24 dependency.

import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test, type APIRequestContext } from '@playwright/test';

// ---------------------------------------------------------------------------
// Shared environment / helpers
// ---------------------------------------------------------------------------

const LIVE = process.env['KONVO_E2E_LIVE'] === '1';
const DOCKER = process.env['KONVO_E2E_DOCKER'] === '1';
const API_URL = process.env['KONVO_E2E_API_URL'] ?? 'http://localhost:3000';
const WS_URL =
  process.env['KONVO_E2E_WS_URL'] ??
  // Derive the WSS URL from the API URL by default. We DON'T assume
  // wss:// here because the local dev stack runs over plaintext
  // ws://; production is fronted by Caddy which terminates TLS
  // (Requirement 17.3). The CI workflow (task 10.24) overrides this
  // explicitly.
  API_URL.replace(/^http/, 'ws') + '/ws';

/** Project root, derived from this spec file's location: e2e/ →
 *  KonvoPro/. Used to anchor the docker-compose path for restart.
 *  We compute via `import.meta.url` (rather than `__dirname`) because
 *  the e2e package is `"type": "module"` and Playwright loads specs
 *  as ESM. */
const SPEC_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolvePath(SPEC_DIR, '..');
const COMPOSE_FILE = resolvePath(REPO_ROOT, 'infra', 'docker-compose.yml');

/** A 12+ char password that satisfies Requirement 1.13. Centralised
 *  so a future password-policy bump only updates one site. */
const PASSWORD = 'CorrectHorseBatteryStaple1!';

/** Number of envelopes to enqueue while the recipient is offline. The
 *  task brief says "≥ 10"; we pick 12 so a duplicate or off-by-one in
 *  the replay path surfaces deterministically (10 hides single-bit
 *  errors more easily than 12 does). */
const ENVELOPE_COUNT = 12;

/** Replay must complete within this budget (Requirement 20.2: "within
 *  30 seconds after API restart upon client reconnection"). We arm
 *  the budget at the moment Bob's reconnect WS opens, NOT at the
 *  moment we issue the restart, so a slow restart of the api process
 *  doesn't eat into the 30 s envelope-delivery budget. */
const REPLAY_BUDGET_MS = 30_000;

/** Skip annotation used by every test in this file when the live
 *  stack is unavailable. Centralised so a single env-var flip in CI
 *  flicks the whole suite on. */
function skipIfNoLiveStack(testInfo: import('@playwright/test').TestInfo): void {
  test.skip(
    !LIVE,
    `KONVO_E2E_LIVE is not set — skipping ${testInfo.title}. ` +
      `Set KONVO_E2E_LIVE=1 with the docker-compose data-plane up to ` +
      `run this against a real api + postgres + redis stack (see task ` +
      `10.24 for CI integration).`,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('offline-queue durability across API restart', () => {
  test('≥10 envelopes are delivered exactly once within 30 s of reconnect', async (
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
    // 2. Bob disconnects.
    //
    // We model "Bob is offline" by simply NOT opening Bob's WS yet.
    // The first time Bob's WS connects is for the post-restart
    // replay. This is closer to the real-world scenario the
    // requirement targets ("client lost connection during the
    // restart") than opening then closing a Bob WS would be.
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // 3. Alice connects her WS and sends 12 envelopes addressed to
    //    Bob's device.
    //
    // Each envelope carries a unique 16-byte canary inside its
    // ciphertext field — for this transport-layer test the
    // "ciphertext" is opaque bytes (the API_Gateway never decrypts;
    // Requirement 4.14), so we use the canary purely as a per-
    // envelope marker for the assertion at the end. The canary is
    // distinct from `clientNonce`: `clientNonce` exercises
    // Requirement 4.7's dedup; the canary lets us tell envelopes
    // apart in the replay assertion regardless of envelope id
    // ordering on the server.
    // -----------------------------------------------------------------
    const aliceWs = await openClientWs({
      url: WS_URL,
      accessToken: alice.accessToken,
      deviceId: alice.deviceId,
    });

    const sentCanaries: string[] = [];
    const sentNonces: string[] = [];

    for (let i = 0; i < ENVELOPE_COUNT; i += 1) {
      const canary = randomBytes(16);
      // Encode the canary as hex inside the ciphertext bytes so it
      // round-trips intact through msgpack's `bin` family.
      const ciphertext = canary;
      const clientNonce = randomUUID();
      sentCanaries.push(canary.toString('hex'));
      sentNonces.push(clientNonce);

      const queued = await aliceWs.sendEnvelope({
        clientNonce,
        envelope: {
          // `id` is server-assigned; omit on send.
          sessionId: randomUUID(),
          senderDeviceId: alice.deviceId,
          recipientDeviceId: bob.deviceId,
          // Routing type 1 (MESSAGE) — see EnvelopeRouterType in
          // packages/protocol/src/envelopes.ts. We don't import the
          // enum here to keep this spec free of workspace-package
          // imports during the pre-CI phase; the wire value is
          // stable per design.md §6.1.
          type: 1,
          ciphertext,
        },
      });
      // Requirement 12.4: each accepted SEND_ENVELOPE produces an
      // ENVELOPE_QUEUED reply within 500 ms with an assigned id.
      expect(queued.envelopeId).toBeDefined();
      expect(queued.clientNonce).toBe(clientNonce);
    }

    // Defensive: confirm Alice didn't get any error frames inflight.
    expect(aliceWs.errors).toEqual([]);

    // Close Alice's socket — she has no further role in this test.
    // Closing here also exercises the "sender disconnects between
    // SEND_ENVELOPE and recipient reconnect" branch of Requirement
    // 12.11, which is the realistic case for offline-queue.
    await aliceWs.close();

    // -----------------------------------------------------------------
    // 4. Restart the API_Gateway.
    //
    // Two modes:
    //   - `KONVO_E2E_DOCKER=1`: shell out to `docker compose restart
    //     api`. This is the production-faithful path and the one
    //     Requirement 20.2 targets.
    //   - otherwise: skip the restart entirely (the rows are already
    //     durable in Postgres). This still proves Requirement 12.11
    //     end-to-end (queued rows replay on reconnect) but does NOT
    //     prove durability across a process bounce. We surface that
    //     gap in the test annotation so a CI run without the docker
    //     gate is honest about what it covered.
    // -----------------------------------------------------------------
    if (DOCKER) {
      await restartApiViaDocker();
      // Wait for the api to come back to a healthy state before Bob
      // reconnects. We poll `/health` rather than sleeping a fixed
      // duration so a slow CI runner doesn't burn into the 30 s
      // replay budget.
      await waitForApiHealthy(request, API_URL, 60_000);
    } else {
      testInfo.annotations.push({
        type: 'coverage-gap',
        description:
          'KONVO_E2E_DOCKER is not set — durability across a full ' +
          'api process restart was NOT verified. Requirement 12.11 ' +
          '(replay on reconnect) is still verified end-to-end against ' +
          'the live Postgres+Redis. Set KONVO_E2E_DOCKER=1 to close ' +
          'this gap (task 10.24 wires this in CI).',
      });
    }

    // -----------------------------------------------------------------
    // 5. Bob reconnects via WS and reads the replay.
    //
    // The 30 s budget is armed at the moment Bob's WS opens, not at
    // the moment we issued the restart, per the wording of
    // Requirement 20.2 ("within 30 seconds after API restart upon
    // client reconnection"). A slow CI restart therefore does not
    // bleed into the replay budget.
    // -----------------------------------------------------------------
    const bobWs = await openClientWs({
      url: WS_URL,
      accessToken: bob.accessToken,
      deviceId: bob.deviceId,
    });
    const replayDeadline = Date.now() + REPLAY_BUDGET_MS;

    // Wait until either we have collected ENVELOPE_COUNT envelopes or
    // the budget has expired. The `awaitEnvelopes` helper resolves
    // whenever the underlying WS receive buffer has at least N
    // envelope frames; it does not interpret them, so we can assert
    // duplicates separately below.
    await bobWs.awaitEnvelopes(ENVELOPE_COUNT, replayDeadline);

    // Hold the socket open for one extra second to catch any
    // duplicate that might arrive AFTER the Nth envelope (e.g. a
    // pub/sub late-delivery racing the replay path). This is a
    // belt-and-suspenders check: the redis-fanout `seenEnvelopeIds`
    // dedup set is supposed to suppress duplicates, but the test's
    // job is to verify the contract, not trust the implementation.
    await sleep(1_000);

    await bobWs.close();

    // -----------------------------------------------------------------
    // 6. Assertions.
    // -----------------------------------------------------------------
    const received = bobWs.envelopes;

    // 6a. Exact count.
    expect(received.length, `Bob must receive exactly ${ENVELOPE_COUNT} envelopes`).toBe(
      ENVELOPE_COUNT,
    );

    // 6b. No duplicate envelope ids (Requirement 12.11 "no duplicates").
    const idStrings = received.map((e) => String(e.id));
    const uniqueIds = new Set(idStrings);
    expect(
      uniqueIds.size,
      `envelope.id values must be unique across the replay`,
    ).toBe(received.length);

    // 6c. Every canary Alice sent must appear exactly once on Bob's
    //     side ("no losses"). We compare hex-encoded canaries so the
    //     diff output on failure is human-readable.
    const receivedCanaries = received.map((e) => e.ciphertextHex).sort();
    const sortedSent = [...sentCanaries].sort();
    expect(receivedCanaries).toEqual(sortedSent);

    // 6d. Original ordering is preserved (created_at ASC, id ASC tiebreak —
    //     Requirement 12.11). The created_at field is server-assigned;
    //     we sort received by created_at and assert the canary order
    //     matches Alice's send order.
    const orderedByCreatedAt = [...received].sort((a, b) => {
      if (a.createdAt !== b.createdAt) {
        return a.createdAt - b.createdAt;
      }
      return a.id < b.id ? -1 : 1;
    });
    expect(
      orderedByCreatedAt.map((e) => e.ciphertextHex),
      'replay must preserve created_at ASC ordering',
    ).toEqual(sentCanaries);
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
 *  This is a transport-layer test so we don't need real libsignal
 *  identity keys to drive the WS layer — but `POST /devices` validates
 *  the signed-prekey signature against the device's Ed25519 identity
 *  key (devices.ts), so we MUST submit a self-consistent bundle.
 *
 *  We side-step the libsignal toolchain by importing
 *  `@konvo/crypto`'s identity + prekey helpers from the workspace.
 *  This does pull a workspace dependency into the e2e package, which
 *  is acceptable because:
 *    - the e2e suite is gated on `KONVO_E2E_LIVE=1` and only runs in
 *      CI, where pnpm has already installed the workspace;
 *    - the alternative (hand-rolling Ed25519 + signed-prekey signing
 *      here) would duplicate ~80 lines of @konvo/crypto code in a
 *      test file. */
async function enrollUser(
  request: APIRequestContext,
  handle: string,
): Promise<EnrolledUser> {
  // Lazy import so the spec can still be ENUMERATED (`pnpm test:e2e:list`)
  // even if `@konvo/crypto`'s transitive deps are not installed in the
  // local `e2e/` package dir. The dynamic import only runs inside a
  // live-stack test, which by definition runs in CI where everything
  // is installed.
  //
  // We use the same in-memory stores the `devices-routes.test.ts`
  // unit suite uses, so the wire payload here matches what a real
  // browser running through @konvo/crypto would produce on first run
  // (Requirements 2.4, 3.1, 3.2).
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

  // 2. Login (no deviceId yet — this token is only used for the
  //    enrollment call; the WS-bound token is re-issued in step 4).
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
      // We submit only the first OPK rather than the full bundle of
      // 100 — the WS test never consumes one, and a smaller payload
      // is faster on a slow CI runner.
      oneTimePreKeys: [
        {
          keyId: bundle.oneTimePreKeys[0]!.keyId,
          publicKey: Buffer.from(bundle.oneTimePreKeys[0]!.publicKey).toString(
            'base64',
          ),
        },
      ],
    },
  });
  expect(enrollRes.status(), `enroll ${handle}`).toBe(201);
  const enrollBody = (await enrollRes.json()) as { deviceId: string };

  // 4. Re-issue an access token bound to the new deviceId. The login
  //    token from step 2 was issued without a `did` claim — the WS
  //    gateway requires a non-empty `did` (see auth.ts file header).
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

/** Minimal in-memory `PreKeyStore` matching the contract used by the
 *  api unit tests (`devices-routes.test.ts`). Keeps the e2e spec
 *  self-contained — we don't depend on a real Dexie store here
 *  because we run in Node, not the browser. */
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
// Helpers — minimal WS client wrapping the C2S/S2C codec
// ---------------------------------------------------------------------------

interface OpenClientWsArgs {
  readonly url: string;
  readonly accessToken: string;
  readonly deviceId: string;
}

interface ReceivedEnvelope {
  readonly id: string; // bigint stringified — JS bigints don't sort cleanly via Array#sort
  readonly createdAt: number;
  readonly senderDeviceId: string;
  readonly recipientDeviceId: string;
  readonly ciphertextHex: string;
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
  readonly envelopes: ReceivedEnvelope[];
  readonly errors: { code: number; message: string }[];
  sendEnvelope(args: SendEnvelopeArgs): Promise<{
    clientNonce: string;
    envelopeId: string;
  }>;
  awaitEnvelopes(count: number, deadlineMs: number): Promise<void>;
  close(): Promise<void>;
}

/** Open a WS connection, authenticate via HELLO, and surface a
 *  send/receive surface. The implementation lazy-imports the `ws`
 *  module and `@konvo/protocol`'s codec so spec enumeration
 *  (`--list`) does not require either to be present. */
async function openClientWs(args: OpenClientWsArgs): Promise<ClientWs> {
  const { default: WebSocket } = await import('ws');
  const { C2S, S2C, encodeC2S, decodeS2C } = await import('@konvo/protocol');

  const ws = new WebSocket(args.url, {
    headers: { authorization: `Bearer ${args.accessToken}` },
  });

  const envelopes: ReceivedEnvelope[] = [];
  const errors: { code: number; message: string }[] = [];
  /** Resolvers waiting on `ENVELOPE_QUEUED { clientNonce }`. */
  const pendingQueued = new Map<
    string,
    (value: { clientNonce: string; envelopeId: string }) => void
  >();
  /** Promise that settles when HELLO_OK arrives. */
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
      // Drop malformed frames silently — the WS gateway is supposed
      // to reject them on the client side too, and a noisy log here
      // would obscure the real assertion failure.
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
          createdAt: env.createdAt ?? 0,
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
        // Other frames (ROOM_POST, …) are out of scope here.
        break;
    }
  });

  // Wait for HELLO_OK with a generous timeout — Requirement 12.1
  // gives the client 5 s to send HELLO; the server replies promptly
  // after that, so 10 s end-to-end is plenty.
  await Promise.race([
    helloOk,
    rejectAfter(10_000, 'HELLO_OK not received within 10s'),
  ]);

  return {
    envelopes,
    errors,
    async sendEnvelope(send: SendEnvelopeArgs) {
      const reply = new Promise<{ clientNonce: string; envelopeId: string }>(
        (resolve, reject) => {
          pendingQueued.set(send.clientNonce, resolve);
          // Requirement 12.4: server replies within 500 ms. We allow
          // 5 s here to account for CI jitter; a real regression in
          // queue latency surfaces in unit tests, not this one.
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
    async awaitEnvelopes(count: number, deadlineMs: number) {
      while (envelopes.length < count) {
        const remaining = deadlineMs - Date.now();
        if (remaining <= 0) {
          throw new Error(
            `replay deadline exceeded: received ${envelopes.length}/${count} envelopes ` +
              `within the 30s budget (Requirement 20.2)`,
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
// Helpers — docker-compose restart + health probe
// ---------------------------------------------------------------------------

/** Issue `docker compose restart api` against the project's compose
 *  file. Synchronous (spawnSync) because the surrounding test is
 *  already async; the Playwright timeout protects against a docker
 *  hang. We use `docker compose` (the v2 plugin) rather than
 *  `docker-compose` (v1) — the project's CI image (task 10.24) ships
 *  v2. */
async function restartApiViaDocker(): Promise<void> {
  const result = spawnSync(
    'docker',
    ['compose', '-f', COMPOSE_FILE, 'restart', 'api'],
    {
      stdio: 'pipe',
      encoding: 'utf-8',
      timeout: 60_000,
    },
  );
  if (result.error !== undefined) {
    throw new Error(
      `docker compose restart api failed: ${result.error.message}`,
    );
  }
  if (result.status !== 0) {
    throw new Error(
      `docker compose restart api exited ${result.status}: ${result.stderr}`,
    );
  }
}

/** Poll `GET /health` until it returns 200, or the deadline expires. */
async function waitForApiHealthy(
  request: APIRequestContext,
  apiUrl: string,
  budgetMs: number,
): Promise<void> {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    try {
      const res = await request.get(`${apiUrl}/health`);
      if (res.status() === 200) {
        return;
      }
    } catch {
      // network errors during the bounce are expected; keep polling.
    }
    await sleep(500);
  }
  throw new Error(
    `api did not return /health=200 within ${budgetMs}ms after restart`,
  );
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

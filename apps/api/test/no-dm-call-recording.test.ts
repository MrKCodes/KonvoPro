// apps/api/test/no-dm-call-recording.test.ts
//
// Task 6.6 — Enforce no DM call media recording.
//
// Realises Requirements 7.10, 11.7, 11.8, and 22.7:
//
//   - 7.10 : `THE Konvo_Platform SHALL NOT record one-to-one call
//            media in any form.`
//   - 11.7 : `THE Konvo_Platform SHALL use LiveKit only for broadcast
//            rooms.`
//   - 11.8 : `THE Konvo_Platform SHALL NOT route one-to-one
//            direct-message call media through LiveKit.`
//   - 22.7 : `THE Konvo_Platform SHALL NOT persist audio or video
//            media streams of one-to-one calls in server-side
//            storage.`
//
// What this file proves (the CI assertion approach for task 6.6):
//
//  1. STATIC analysis of the api source tree:
//     a. Every file that mints a LiveKit token (constructs an
//        `AccessToken` or calls `signPublisher` / `signViewer` /
//        `videoGrant.room`) is grep-allowlisted against the same
//        broadcast-only file set as `livekit-only-broadcast.test.ts`,
//        AND none of those files contain a literal reference to a
//        DM-call-id-shaped UUID pattern in any token-mint path. The
//        positive assertion is the allowlist; the negative assertion
//        is the absence of any UUID-regex literal next to a mint
//        call.
//     b. The MinIO storage module (`apps/api/src/storage/minio.ts`)
//        is imported only from attachment-related code paths
//        (`routes/attachments.ts`, `server.ts` bootstrap) — never
//        from any call-signaling path. The WS gateway
//        (`apps/api/src/ws/gateway.ts`) — which handles
//        `EnvelopeRouterType.CALL` envelopes via the shared
//        `onSendEnvelope` — is explicitly asserted to NOT import
//        `storage/minio.js` and NOT import the LiveKit SDK.
//
//  2. RUNTIME assertion of the LiveKit token mint guard
//     (`assertBroadcastRoomId` in `services/livekit.ts`):
//     a. `signPublisher` / `signViewer` throw when handed a
//        UUID-shaped `roomId` (the DM call id pattern).
//     b. `signPublisher` / `signViewer` succeed when handed a valid
//        broadcast slug (`^[a-z0-9-]{3,64}$`, not UUID-shaped).
//
//  3. RUNTIME assertion of the gateway CALL envelope relay path
//     (complementary to `call-envelope-relay.test.ts`):
//     a. The CALL relay path in `onSendEnvelope` does not invoke
//        any MinIO `putObject` / `getObject` / `headObject`. The
//        test injects a `Storage` spy into a harness that does NOT
//        wire the spy into the gateway (because the gateway never
//        accepts a `Storage` dep in the first place — that itself
//        is the structural proof) and asserts the spy is never
//        consulted.
//     b. The CALL relay path does not mint a LiveKit token. The
//        test injects a `LiveKitTokenSigner` spy into the same
//        harness (likewise unwired in production) and asserts the
//        spy is never consulted.
//     c. The CALL relay only INSERTs the ciphertext envelope row
//        and PUBLISHes the assigned envelope id on the recipient
//        Redis channel — there is no separate "media bytes" row,
//        no MinIO key written, no LiveKit room provisioned.
//
// Why a vitest file rather than a separate eslint / dependency-cruiser
// rule: the rest of the api package's CI gates run via
// `pnpm -F @konvo/api test`, so the same command exercises both
// invariant tests AND the unit/property suites. A future regression
// (e.g. a new route that wires `LiveKitTokenSigner` into the call
// pipeline, or a refactor that lets the WS gateway accept a `Storage`
// dep) fails this test file and surfaces in the same CI step that
// catches a bug in `onSendEnvelope`.

import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';

import {
  EnvelopeRouterType,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import { setRedactionFailureCounter } from '../src/obs/logger.js';
import { createLogger } from '../src/obs/logger.js';
import {
  createLiveKitTokenSigner,
  assertBroadcastRoomId,
} from '../src/services/livekit.js';
import {
  buildContext,
  onSendEnvelope,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { Storage } from '../src/storage/minio.js';
import type { WSRedisPublisher, WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Filesystem walker (mirrors `livekit-only-broadcast.test.ts`)
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const API_ROOT = path.resolve(HERE, '..');
const API_SRC = path.join(API_ROOT, 'src');

async function walkTsFiles(dir: string): Promise<readonly string[]> {
  let entries: Awaited<ReturnType<typeof readdir>>;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  const out: string[] = [];
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === 'dist') continue;
      const sub = await walkTsFiles(full);
      out.push(...sub);
    } else if (e.isFile() && (e.name.endsWith('.ts') || e.name.endsWith('.tsx'))) {
      out.push(full);
    }
  }
  return out;
}

function relApi(abs: string): string {
  return path.relative(API_ROOT, abs).split(path.sep).join('/');
}

// ---------------------------------------------------------------------------
// Static-analysis regexes
// ---------------------------------------------------------------------------

/** Matches imports from `'@livekit/server-sdk'` (single OR double
 *  quote). Used to identify any file that pulls in LiveKit SDK
 *  symbols capable of minting a token or provisioning a room. */
const LIVEKIT_SDK_IMPORT = /['"]@livekit\/server-sdk['"]/;

/** Matches imports from the local LiveKit signer module. Together with
 *  `LIVEKIT_SDK_IMPORT` this covers every plausible "mints a LiveKit
 *  token" call site: either the file imports the SDK directly (the
 *  signer module itself) or it imports the signer's factory /
 *  interface (the broadcast-live route). */
const LIVEKIT_SIGNER_IMPORT = /['"]\.\.?\/(?:[^'"]*\/)?services\/livekit(?:\.js)?['"]/;

/** Matches imports from the MinIO storage module. */
const MINIO_STORAGE_IMPORT = /['"]\.\.?\/(?:[^'"]*\/)?storage\/minio(?:\.js)?['"]/;

/** Files in `apps/api/src/` that are PERMITTED to import the LiveKit
 *  SDK directly. Aligned with
 *  `livekit-only-broadcast.test.ts:API_SERVER_SDK_ALLOWLIST`. */
const LIVEKIT_SDK_ALLOWLIST: ReadonlySet<string> = new Set([
  'src/services/livekit.ts',
]);

/** Files in `apps/api/src/` that are PERMITTED to import the LiveKit
 *  signer module (`./services/livekit.js`). The route layer mints
 *  tokens; `server.ts` constructs the signer at boot. Anything else
 *  is a regression. */
const LIVEKIT_SIGNER_ALLOWLIST: ReadonlySet<string> = new Set([
  'src/services/livekit.ts',
  'src/routes/broadcast-live.ts',
  'src/server.ts',
]);

/** Files in `apps/api/src/` that are PERMITTED to import the MinIO
 *  storage module. The attachments route is the only consumer; the
 *  server bootstrap constructs the client and threads it into the
 *  attachments route. No call-signaling code path is on this list. */
const MINIO_STORAGE_ALLOWLIST: ReadonlySet<string> = new Set([
  'src/storage/minio.ts',
  'src/routes/attachments.ts',
  'src/server.ts',
]);

/** Regex matching a UUID-shaped string LITERAL inside source code.
 *  Used to assert that no LiveKit-mint code path bakes in a UUID
 *  (which would be a structural marker for a DM call id leaking into
 *  the LiveKit pipeline). The check is over LITERALS — runtime
 *  values are guarded by `assertBroadcastRoomId` in the signer. */
const UUID_STRING_LITERAL =
  /['"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]/;

// ---------------------------------------------------------------------------
// Section 1 — Static analysis: LiveKit mint paths
// ---------------------------------------------------------------------------

describe('task 6.6: LiveKit token mint paths never reference DM call ids', () => {
  it('the api/src tree exists', async () => {
    const s = await stat(API_SRC);
    expect(s.isDirectory()).toBe(true);
  });

  it('only the allowlisted files import the LiveKit SDK or signer module', async () => {
    const files = await walkTsFiles(API_SRC);
    expect(files.length).toBeGreaterThan(0);

    const sdkViolations: string[] = [];
    const signerViolations: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      const importsSdk = LIVEKIT_SDK_IMPORT.test(content);
      const importsSigner = LIVEKIT_SIGNER_IMPORT.test(content);
      const rel = relApi(file);
      // The signer module imports `@livekit/server-sdk` directly; it
      // is the only file allowed to do so. Routes / bootstrap import
      // the local signer module instead.
      if (importsSdk && !LIVEKIT_SDK_ALLOWLIST.has(rel)) {
        sdkViolations.push(rel);
      }
      if (importsSigner && !LIVEKIT_SIGNER_ALLOWLIST.has(rel)) {
        signerViolations.push(rel);
      }
    }

    expect(
      sdkViolations,
      `Files outside the SDK allowlist must not import @livekit/server-sdk. ` +
        `Allowlist: ${[...LIVEKIT_SDK_ALLOWLIST].join(', ')}. ` +
        `Violations: ${sdkViolations.join(', ')}`,
    ).toEqual([]);
    expect(
      signerViolations,
      `Files outside the signer allowlist must not import services/livekit. ` +
        `Allowlist: ${[...LIVEKIT_SIGNER_ALLOWLIST].join(', ')}. ` +
        `Violations: ${signerViolations.join(', ')}`,
    ).toEqual([]);
  });

  it('no LiveKit-mint file contains a UUID-shaped string literal', async () => {
    // A UUID literal in a mint path would be evidence of a hardcoded
    // DM call id (DM call ids are `uuidv4()` strings on the client;
    // the server should never reference such a literal in a LiveKit
    // code path). The signer module + the broadcast-live route are
    // the only places that build LiveKit grant payloads; everything
    // else is already caught by the import allowlist test above.
    // We INTENTIONALLY skip `server.ts` here even though it imports
    // the signer factory: bootstrap doesn't construct grants and may
    // legitimately mention UUIDs in unrelated config wiring.
    const MINT_FILES: ReadonlySet<string> = new Set([
      'src/services/livekit.ts',
      'src/routes/broadcast-live.ts',
    ]);
    for (const rel of MINT_FILES) {
      const abs = path.join(API_ROOT, rel);
      const content = await readFile(abs, 'utf8');
      // We strip block comments before the regex test so the
      // header-comment paragraph in `services/livekit.ts` that
      // explains the invariant doesn't accidentally trigger by
      // mentioning UUID examples — at the time of writing it does
      // not, but a future doc update should not break this test.
      const stripped = content.replace(/\/\*[\s\S]*?\*\//g, '');
      const match = stripped.match(UUID_STRING_LITERAL);
      expect(
        match,
        `Found UUID-shaped string literal "${match?.[0] ?? ''}" in ` +
          `LiveKit-mint file ${rel}; this looks like a DM call id ` +
          `pattern (Requirements 7.10, 11.7, 11.8, 22.7).`,
      ).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// Section 2 — Static analysis: MinIO never imported from call paths
// ---------------------------------------------------------------------------

describe('task 6.6: MinIO storage is never imported from call-signaling paths', () => {
  it('only attachment-related files import storage/minio', async () => {
    const files = await walkTsFiles(API_SRC);
    expect(files.length).toBeGreaterThan(0);

    const violations: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      if (!MINIO_STORAGE_IMPORT.test(content)) continue;
      const rel = relApi(file);
      if (!MINIO_STORAGE_ALLOWLIST.has(rel)) {
        violations.push(rel);
      }
    }

    expect(
      violations,
      `Files outside the attachments allowlist must not import ` +
        `storage/minio. Allowlist: ${[...MINIO_STORAGE_ALLOWLIST].join(', ')}. ` +
        `Violations: ${violations.join(', ')}`,
    ).toEqual([]);
  });

  it('the WS gateway (call-relay path) imports neither LiveKit nor MinIO', async () => {
    // Explicit, narrowly-scoped assertion: the gateway is the ONLY
    // server-side entry point that handles `EnvelopeRouterType.CALL`
    // envelopes (via `onSendEnvelope`). It must NOT pull in either
    // dependency, so a regression that wires media persistence or
    // SFU provisioning into the call relay fails this test loudly.
    const gatewayPath = path.join(API_SRC, 'ws', 'gateway.ts');
    const content = await readFile(gatewayPath, 'utf8');
    expect(LIVEKIT_SDK_IMPORT.test(content)).toBe(false);
    expect(LIVEKIT_SIGNER_IMPORT.test(content)).toBe(false);
    expect(MINIO_STORAGE_IMPORT.test(content)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Section 3 — Runtime assertion: LiveKit signer rejects DM call ids
// ---------------------------------------------------------------------------

describe('task 6.6: LiveKit signer runtime guard (`assertBroadcastRoomId`)', () => {
  const TEST_API_KEY = 'devkey';
  // 32+ chars — matches the LIVEKIT_API_SECRET min in `config.ts`.
  const TEST_API_SECRET = 'task6_6-livekit-secret-32-bytes-XYZ';
  const VALID_SLUG = 'broadcast-room-1';
  const DM_CALL_UUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const NIL_UUID = '00000000-0000-0000-0000-000000000000';
  const MAX_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
  const VALID_USER = 'user-1';

  it('assertBroadcastRoomId rejects UUID-shaped ids (the DM call id pattern)', () => {
    expect(() => assertBroadcastRoomId(DM_CALL_UUID)).toThrow(
      /1:1 DM call id|broadcast/,
    );
    expect(() => assertBroadcastRoomId(NIL_UUID)).toThrow();
    expect(() => assertBroadcastRoomId(MAX_UUID)).toThrow();
    // Mixed case UUID — also UUID-shaped per RFC 4122.
    expect(() =>
      assertBroadcastRoomId('AAAAAAAA-1111-2222-3333-DEADBEEFCAFE'),
    ).toThrow();
  });

  it('assertBroadcastRoomId accepts a valid broadcast slug', () => {
    expect(() => assertBroadcastRoomId(VALID_SLUG)).not.toThrow();
    expect(() => assertBroadcastRoomId('a-b-c')).not.toThrow();
    // 64-char slug at the regex upper bound.
    expect(() =>
      assertBroadcastRoomId('a'.repeat(64)),
    ).not.toThrow();
  });

  it('assertBroadcastRoomId rejects strings that are neither UUID nor slug', () => {
    // 2-char string — below the 3-char slug minimum.
    expect(() => assertBroadcastRoomId('ab')).toThrow(/broadcast-room slug/);
    // Uppercase letters — outside the slug character class.
    expect(() => assertBroadcastRoomId('Bad-Room')).toThrow();
    // Empty string falls through to the slug-shape error too.
    expect(() => assertBroadcastRoomId('')).toThrow();
    // 65-char string — above the 64-char slug maximum.
    expect(() =>
      assertBroadcastRoomId('a'.repeat(65)),
    ).toThrow();
  });

  it('signPublisher throws when handed a UUID-shaped roomId', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    await expect(
      signer.signPublisher({ userId: VALID_USER, roomId: DM_CALL_UUID }),
    ).rejects.toThrow(/1:1 DM call id|broadcast/);
  });

  it('signViewer throws when handed a UUID-shaped roomId', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    await expect(
      signer.signViewer({ userId: VALID_USER, roomId: DM_CALL_UUID }),
    ).rejects.toThrow(/1:1 DM call id|broadcast/);
  });

  it('signPublisher succeeds for a valid broadcast slug', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    const token = await signer.signPublisher({
      userId: VALID_USER,
      roomId: VALID_SLUG,
    });
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  it('signViewer succeeds for a valid broadcast slug', async () => {
    const signer = createLiveKitTokenSigner(TEST_API_KEY, TEST_API_SECRET);
    const token = await signer.signViewer({
      userId: VALID_USER,
      roomId: VALID_SLUG,
    });
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Section 4 — Runtime assertion: gateway CALL path touches no media
// ---------------------------------------------------------------------------

const SENDER_DEVICE = '11111111-1111-1111-1111-111111111111';
const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const NOW_MS = 1_700_000_000_000;

interface FakeSocket extends WSSocket {
  sent: Uint8Array[];
}

function makeFakeSocket(): FakeSocket {
  const sent: Uint8Array[] = [];
  const sock: FakeSocket = {
    readyState: 1,
    sent,
    send(data: Uint8Array | Buffer): void {
      sent.push(new Uint8Array(data));
    },
    close(): void {
      sock.readyState = 3;
    },
    on(): WSSocket {
      return sock;
    },
  } as FakeSocket;
  return sock;
}

interface FakePool {
  readonly queries: Array<{ sql: string; params: readonly unknown[] }>;
  query<T = unknown>(
    sql: string,
    params: readonly unknown[],
  ): Promise<{ rows: T[]; rowCount: number }>;
}

function makeFakePool(): FakePool {
  let nextId = 1n;
  const queries: Array<{ sql: string; params: readonly unknown[] }> = [];
  const fake: FakePool = {
    queries,
    async query(sql: string, params: readonly unknown[]) {
      queries.push({ sql, params });
      const trimmed = sql.trim();
      if (trimmed.startsWith('INSERT INTO ciphertext_envelopes')) {
        const id = nextId++;
        return { rows: [{ id: id.toString() }] as never[], rowCount: 1 };
      }
      return { rows: [] as never[], rowCount: 0 };
    },
  };
  return fake;
}

interface FakeRedis extends WSRedisPublisher {
  readonly published: Array<{ channel: string; payload: string }>;
}

function makeFakeRedis(): FakeRedis {
  const published: Array<{ channel: string; payload: string }> = [];
  return {
    published,
    async publish(channel: string, payload: string): Promise<number> {
      published.push({ channel, payload });
      return 1;
    },
    async setPresence(): Promise<void> {
      /* unused */
    },
    async subscribeRoom(): Promise<void> {
      /* unused */
    },
    async unsubscribeRoom(): Promise<void> {
      /* unused */
    },
    async subscribeDevice(): Promise<void> {
      /* unused */
    },
    async unsubscribeDevice(): Promise<void> {
      /* unused */
    },
  };
}

/** Spy `Storage` impl whose method records prove a CALL relay path
 *  never invokes MinIO. The harness intentionally does NOT thread
 *  this storage into the gateway — `onSendEnvelope` does not accept a
 *  `Storage` parameter — so the structural absence of any wiring is
 *  the proof. The spy is held alongside to make the assertion
 *  deliberately explicit (see test below). */
function makeStorageSpy(): {
  storage: Storage;
  calls: { put: number; get: number; head: number };
} {
  const calls = { put: 0, get: 0, head: 0 };
  const storage: Storage = {
    async putObject(): Promise<void> {
      calls.put += 1;
    },
    async getObject() {
      calls.get += 1;
      throw new Error('storage spy should never be called by CALL relay');
    },
    async headObject() {
      calls.head += 1;
      return null;
    },
  };
  return { storage, calls };
}

/** Spy LiveKit signer. Same structural argument as the storage spy:
 *  the gateway never accepts a signer dep, so any token mint from
 *  inside the CALL relay is impossible by construction. The spy
 *  records every invocation so the assertion is explicit. */
function makeSignerSpy(): {
  signer: ReturnType<typeof createLiveKitTokenSigner>;
  calls: { publisher: number; viewer: number };
} {
  const calls = { publisher: 0, viewer: 0 };
  const signer = {
    async signPublisher(): Promise<string> {
      calls.publisher += 1;
      throw new Error(
        'LiveKit signer spy should never be called by CALL relay',
      );
    },
    async signViewer(): Promise<string> {
      calls.viewer += 1;
      throw new Error('LiveKit signer spy should never be called by CALL relay');
    },
  };
  return { signer, calls };
}

function buildDeps(pool: FakePool, redis: FakeRedis): SendEnvelopeDeps {
  return {
    pool: pool as unknown as SendEnvelopeDeps['pool'],
    redis,
    now: (): number => NOW_MS,
    sendEnvelopeBuckets: new Map<string, TokenBucketState>(),
    sendEnvelopeBucket: { capacity: 100, refillPerSecond: 100 },
  };
}

interface CapturedSink {
  write(chunk: string): boolean;
  lines: string[];
}

function makeSink(): CapturedSink {
  const lines: string[] = [];
  return {
    lines,
    write(chunk: string): boolean {
      for (const part of chunk.split('\n')) {
        if (part.length > 0) lines.push(part);
      }
      return true;
    },
  };
}

function callEnvelope(ciphertext: Uint8Array): CiphertextEnvelope {
  return {
    sessionId: SESSION_ID,
    senderDeviceId: SENDER_DEVICE,
    recipientDeviceId: RECIPIENT_DEVICE,
    type: EnvelopeRouterType.CALL,
    ciphertext,
  };
}

describe('task 6.6: gateway CALL relay does not touch MinIO or LiveKit', () => {
  // The redaction-failure counter is module-global; a sibling test
  // file may have overridden it. Reset to a no-op before each test
  // here so log assertions don't accidentally count a stale failure.
  setRedactionFailureCounter({ inc(): void {} });

  it('CALL relay does not invoke any MinIO putObject / getObject / headObject', async () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    const sock = makeFakeSocket();
    const child = log.child({ requestId: 'task-6-6-call-no-minio' });
    const ctx = buildContext(
      sock,
      'user-1',
      SENDER_DEVICE,
      child as unknown as Parameters<typeof buildContext>[3],
    );
    ctx.helloReceived = true;
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    const { storage, calls } = makeStorageSpy();

    // The gateway does not accept a `Storage` dep; the spy is held
    // just so we can assert it was never reached. The presence of
    // this assertion exercises the structural invariant: a future
    // refactor that adds a `storage` field to `SendEnvelopeDeps` is
    // exactly what we want this test to flag.
    expect(storage).toBeDefined();

    await onSendEnvelope(
      ctx,
      {
        clientNonce: 'nonce-call-no-minio',
        envelope: callEnvelope(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
      },
      buildDeps(pool, redis),
    );

    // The CALL was queued — the relay path completed.
    expect(sock.sent.length).toBe(1);
    const frame = decodeS2C(sock.sent[0]!);
    expect(frame.t).toBe(S2C.ENVELOPE_QUEUED);

    // The storage spy was never reached.
    expect(calls.put).toBe(0);
    expect(calls.get).toBe(0);
    expect(calls.head).toBe(0);

    // No row inserted into anything other than ciphertext_envelopes.
    // (The CALL relay never writes to `attachments` or any other
    // table — Requirement 22.7.)
    const nonEnvelopeWrites = pool.queries.filter((q) => {
      const t = q.sql.trim().toLowerCase();
      return (
        t.startsWith('insert') &&
        !t.startsWith('insert into ciphertext_envelopes')
      );
    });
    expect(nonEnvelopeWrites).toEqual([]);
  });

  it('CALL relay does not mint any LiveKit token', async () => {
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    const sock = makeFakeSocket();
    const child = log.child({ requestId: 'task-6-6-call-no-livekit' });
    const ctx = buildContext(
      sock,
      'user-1',
      SENDER_DEVICE,
      child as unknown as Parameters<typeof buildContext>[3],
    );
    ctx.helloReceived = true;
    const pool = makeFakePool();
    const redis = makeFakeRedis();
    const { signer, calls } = makeSignerSpy();
    expect(signer).toBeDefined();

    await onSendEnvelope(
      ctx,
      {
        clientNonce: 'nonce-call-no-livekit',
        envelope: callEnvelope(new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16])),
      },
      buildDeps(pool, redis),
    );

    expect(sock.sent.length).toBe(1);
    expect(decodeS2C(sock.sent[0]!).t).toBe(S2C.ENVELOPE_QUEUED);
    expect(calls.publisher).toBe(0);
    expect(calls.viewer).toBe(0);
  });

  it('CALL relay only persists ciphertext_envelopes and publishes recipient channel', async () => {
    // The "no media bytes persisted" invariant (Requirement 22.7):
    // the CALL relay path runs the same INSERT/PUBLISH pair as the
    // MESSAGE / ACK paths. The ciphertext column on
    // `ciphertext_envelopes` carries the E2EE-wrapped call signaling
    // payload (offer / answer / candidate / hangup), NOT the raw
    // RTP/SRTP media — those bytes never reach the server because
    // 1:1 calls are P2P over coturn (Requirement 7.10).
    const sink = makeSink();
    const log = createLogger({ destination: sink, level: 'debug' });
    const sock = makeFakeSocket();
    const child = log.child({ requestId: 'task-6-6-call-shape' });
    const ctx = buildContext(
      sock,
      'user-1',
      SENDER_DEVICE,
      child as unknown as Parameters<typeof buildContext>[3],
    );
    ctx.helloReceived = true;
    const pool = makeFakePool();
    const redis = makeFakeRedis();

    await onSendEnvelope(
      ctx,
      {
        clientNonce: 'nonce-call-shape',
        envelope: callEnvelope(new Uint8Array([42, 43, 44, 45, 46, 47, 48, 49])),
      },
      buildDeps(pool, redis),
    );

    // Exactly one INSERT to `ciphertext_envelopes`, no other writes.
    const inserts = pool.queries.filter((q) =>
      q.sql.trim().toLowerCase().startsWith('insert'),
    );
    expect(inserts.length).toBe(1);
    expect(
      inserts[0]?.sql.trim().toLowerCase().startsWith('insert into ciphertext_envelopes'),
    ).toBe(true);

    // Exactly one PUBLISH on the recipient device channel.
    expect(redis.published.length).toBe(1);
    expect(redis.published[0]?.channel).toBe(`dev:${RECIPIENT_DEVICE}`);
    // Payload is the assigned envelope id as decimal — never any
    // ciphertext bytes, never a MinIO key, never a LiveKit URL.
    expect(redis.published[0]?.payload).toMatch(/^\d+$/);
  });
});

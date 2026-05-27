// apps/api/test/ice-candidate-confidentiality.property.test.ts
//
// Task 6.8 — P23: ICE candidate confidentiality.
//
// Validates Requirements 7.2, 7.3, 21.23:
//
//   - 7.2  : "THE Crypto_Module SHALL wrap each `CALL_OFFER`,
//             `CALL_ANSWER`, and `CALL_ICE_CANDIDATE` inner payload
//             inside a Ciphertext_Envelope before sending it to the
//             API_Gateway."
//   - 7.3  : "THE API_Gateway SHALL relay call signaling
//             Ciphertext_Envelopes between peer devices without
//             decrypting them."
//   - 21.23: "FOR ALL ICE candidates exchanged during one-to-one call
//             signaling, each candidate SHALL travel inside an E2EE
//             envelope, and the API_Gateway log of routed CALL
//             envelopes SHALL contain zero candidate strings in
//             plaintext." *(P23: ICE candidate confidentiality)*
//
// Property under test (P23 wording, also design.md §16):
//
//   For any ICE candidate string `cand` exchanged during one-to-one
//   call signaling, after the Crypto_Module wraps the candidate inside
//   an `EnvelopeRouterType.CALL` Ciphertext_Envelope and the
//   API_Gateway's `onSendEnvelope` routes that envelope:
//
//     (a) The wire-level envelope's `ciphertext` bytes contain neither
//         `cand` nor the literal substring `'candidate:'` under any
//         of {utf-8, latin1, hex, base64} views; the encryption is
//         opaque.
//     (b) The captured pino log lines emitted by the gateway during
//         routing contain zero occurrences of `cand` or `'candidate:'`
//         under any of those encodings (the redaction layer from
//         task 4.9 scrubs the `ciphertext` field by name; the gateway
//         never logs the candidate string in any other position).
//
// Strategy:
//
//   1. Initialise an Alice/Bob ratchet pair via `@konvo/crypto`'s
//      `initSenderRatchet` + `initReceiverRatchet` over a shared
//      32-byte SK and a `generateRatchetDhKeypair` SPK (mirrors the
//      helper in every `packages/crypto/test/p*.property.test.ts`).
//   2. fast-check arbitrary builds an ICE candidate string per RFC
//      5245 / 8445 (foundation, component, transport, priority,
//      address, port, type, optional raddr/rport/generation/ufrag).
//   3. Build the inner payload `{ kind: InnerType.CALL_ICE_CANDIDATE,
//      callId, candidate: { candidate: cand } }`. We msgpack-encode
//      via `@konvo/protocol`'s codec (the protocol package owns the
//      `@msgpack/msgpack` dependency; the api package doesn't import
//      it directly).
//   4. Run `encryptToDevice(alice, plaintext)`. The returned
//      `ciphertext` is the wire-level `ciphertext` field.
//   5. Wrap in `CiphertextEnvelope { type: EnvelopeRouterType.CALL,
//      ciphertext, ... }` and feed through `onSendEnvelope` against
//      a capturing pino sink.
//   6. Assert (a) on the produced ciphertext bytes and (b) on the
//      captured log buffer.
//   7. Sanity check (one-shot, not under fc.assert): decrypt the
//      ciphertext via `decryptFromDevice(bob, ...)` and verify the
//      recovered plaintext bytes contain `cand` — proving the
//      candidate WAS in the plaintext, so the absence-of-leak
//      assertions in (a) and (b) are non-trivial.
//
// Iteration count comes from `test/setup.ts`'s global fast-check
// config (default 100 / nightly 500 via `FAST_CHECK_RUNS`). Per the
// task brief the test must run with ≥ 50 examples; the default 100
// satisfies that comfortably.
//
// The harness reuses the `FakeSocket` / `FakePool` / `FakeRedis` /
// `CapturedSink` shape from `no-dm-call-recording.test.ts` and
// `call-envelope-relay.test.ts` (mirrored inline because the helpers
// are not exported from those test files).

import { Buffer } from 'node:buffer';

import * as fc from 'fast-check';
import { beforeEach, describe, expect, test } from 'vitest';

import {
  decryptFromDevice,
  encryptToDevice,
  generateRatchetDhKeypair,
  initReceiverRatchet,
  initSenderRatchet,
  type RatchetState,
} from '@konvo/crypto';
import {
  EnvelopeRouterType,
  InnerType,
  S2C,
  decodeS2C,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import { createLogger, setRedactionFailureCounter } from '../src/obs/logger.js';
import {
  buildContext,
  fanoutChannelFor,
  onSendEnvelope,
  type SendEnvelopeDeps,
} from '../src/ws/gateway.js';
import type { TokenBucketState } from '../src/ws/rate-limit.js';
import type { WSRedisPublisher, WSSocket } from '../src/ws/types.js';

// ---------------------------------------------------------------------------
// Fixed identifiers (UUIDs satisfy the gateway's deviceId-shape checks)
// ---------------------------------------------------------------------------

const SENDER_DEVICE = '11111111-1111-1111-1111-111111111111';
const RECIPIENT_DEVICE = '22222222-2222-2222-2222-222222222222';
const SESSION_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const CALL_ID = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const NOW_MS = 1_700_000_000_000;

// The ICE-candidate prefix every RFC 5245 / 8445 attribute string starts
// with. The gateway must NEVER emit this substring in any log line that
// originates from a routed CALL envelope.
const CANDIDATE_PREFIX = 'candidate:';

// ---------------------------------------------------------------------------
// Capturing pino destination
// ---------------------------------------------------------------------------

interface CapturedSink {
  write(chunk: string): boolean;
  lines: string[];
  joined(): string;
  clear(): void;
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
    joined(): string {
      return lines.join('\n');
    },
    clear(): void {
      lines.length = 0;
    },
  };
}

// ---------------------------------------------------------------------------
// Socket / pool / redis fakes (mirror call-envelope-relay.test.ts)
// ---------------------------------------------------------------------------

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
  failNext: Error | null;
}

function makeFakeRedis(): FakeRedis {
  const published: Array<{ channel: string; payload: string }> = [];
  const fake: FakeRedis = {
    published,
    failNext: null,
    async publish(channel: string, payload: string): Promise<number> {
      if (fake.failNext !== null) {
        const err = fake.failNext;
        fake.failNext = null;
        throw err;
      }
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
  return fake;
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface Harness {
  ctx: ReturnType<typeof buildContext>;
  sock: FakeSocket;
  sink: CapturedSink;
  pool: FakePool;
  redis: FakeRedis;
  deps: SendEnvelopeDeps;
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

function setupHarness(): Harness {
  const sink = makeSink();
  const log = createLogger({ destination: sink, level: 'debug' });
  const child = log.child({ requestId: 'req-p23' });
  const sock = makeFakeSocket();
  const ctx = buildContext(
    sock,
    'user-1',
    SENDER_DEVICE,
    child as unknown as Parameters<typeof buildContext>[3],
  );
  ctx.helloReceived = true;
  const pool = makeFakePool();
  const redis = makeFakeRedis();
  return { ctx, sock, sink, pool, redis, deps: buildDeps(pool, redis) };
}

beforeEach(() => {
  // Reset to a no-op redaction-failure counter so a sibling test
  // file's installed counter doesn't bleed into our assertions.
  setRedactionFailureCounter({ inc(): void {} });
});

// ---------------------------------------------------------------------------
// Ratchet pair init (mirrors the helper in `packages/crypto/test/...`)
// ---------------------------------------------------------------------------

interface RatchetPair {
  alice: RatchetState;
  bob: RatchetState;
}

function initRatchetPair(): RatchetPair {
  // Shared X3DH-derived root key; here we pick a fresh 32-byte SK
  // since we're only exercising the ratchet itself (the X3DH layer
  // is tested in `packages/crypto/test/p1-e2ee-roundtrip.property.test.ts`
  // and not on the test path for P23). Both peers MUST agree on
  // SK + Bob's SPK pair for the initial chain to align.
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);

  // Bob's "signed prekey" — the receiver's initial DH ratchet keypair.
  // We use `generateRatchetDhKeypair` (the public helper) per the
  // task brief; it returns a matched X25519 priv/pub pair derived
  // through the same `@noble/curves` path the production prekey
  // module uses, so no second derivation is needed here.
  const bobSpk = generateRatchetDhKeypair();

  const alice = initSenderRatchet(sk, bobSpk.pub);
  const bob = initReceiverRatchet(sk, { priv: bobSpk.priv, pub: bobSpk.pub });
  return { alice, bob };
}

// ---------------------------------------------------------------------------
// ICE candidate arbitrary
// ---------------------------------------------------------------------------

/** RFC 5245 / 8445 ICE candidate attribute. Every real candidate has
 *  the prefix `'candidate:'` followed by foundation / component /
 *  transport / priority / connection-address / port / typ <type>
 *  and optional `raddr`/`rport`/`generation`/`ufrag` tail. Examples:
 *
 *    candidate:1 1 udp 2113929471 192.0.2.1 54321 typ host
 *    candidate:7 2 tcp 1518214911 198.51.100.7 9 typ srflx \
 *      raddr 10.0.0.5 rport 50000 generation 0 ufrag abcd
 *
 *  The arbitrary samples a representative subset of the attribute
 *  shape the WebRTC stack actually emits — enough variation to make
 *  any byte-prefix-match heuristic in pino's serialiser surface a
 *  leak across 100 iterations, while staying short enough that the
 *  generated string fits comfortably inside a 1 MiB ws frame. */
const arbIceCandidate: fc.Arbitrary<string> = fc
  .record({
    foundation: fc.integer({ min: 1, max: 4_294_967_295 }).map(String),
    component: fc.constantFrom('1', '2'),
    transport: fc.constantFrom('udp', 'tcp'),
    priority: fc.integer({ min: 1, max: 4_294_967_295 }).map(String),
    address: fc.ipV4(),
    port: fc.integer({ min: 1024, max: 65535 }).map(String),
    typ: fc.constantFrom('host', 'srflx', 'prflx', 'relay'),
    tail: fc.option(
      fc
        .record({
          raddr: fc.ipV4(),
          rport: fc.integer({ min: 1024, max: 65535 }).map(String),
          generation: fc.constantFrom('0', '1'),
          ufrag: fc.stringMatching(/^[A-Za-z0-9]{4,8}$/),
        })
        .map(
          (t) =>
            ` raddr ${t.raddr} rport ${t.rport} generation ${t.generation} ufrag ${t.ufrag}`,
        ),
      { nil: '' },
    ),
  })
  .map((c) => {
    const tail = c.tail ?? '';
    return (
      `${CANDIDATE_PREFIX}${c.foundation} ${c.component} ${c.transport} ` +
      `${c.priority} ${c.address} ${c.port} typ ${c.typ}${tail}`
    );
  });

// ---------------------------------------------------------------------------
// Inner-payload construction
// ---------------------------------------------------------------------------

/** Build the bytes of a `CALL_ICE_CANDIDATE` inner payload that
 *  embeds the candidate string in the position the protocol mandates
 *  (`candidate.candidate`). We don't require msgpack here — any
 *  encoding that reliably embeds the candidate ASCII bytes inside the
 *  plaintext is sufficient for the property under test, because the
 *  property checks the WIRE side (ciphertext + logs) which is
 *  insensitive to the inner encoding. We use a JSON encoding so the
 *  test stays free of `@msgpack/msgpack` (which is a dep of
 *  `@konvo/protocol`, not of `@konvo/api`). The structural fields
 *  match the `InnerType.CALL_ICE_CANDIDATE` variant for documentation
 *  value. */
function buildIceInnerPlaintext(callId: string, cand: string): Uint8Array {
  const inner = {
    kind: InnerType.CALL_ICE_CANDIDATE,
    callId,
    candidate: { candidate: cand },
  };
  return new TextEncoder().encode(JSON.stringify(inner));
}

// ---------------------------------------------------------------------------
// Leak probes
// ---------------------------------------------------------------------------

/** Four byte-views of `needle` a naive serialiser could reach for. The
 *  property must hold against EVERY view — pino's default Buffer
 *  serialiser produces a number-array; a custom toJSON could pick
 *  any encoder; an Error message could carry latin1; a
 *  hand-rolled hex dump is also possible. */
function encodingsOf(needle: string): {
  utf8: string;
  latin1: string;
  hex: string;
  base64: string;
} {
  const buf = Buffer.from(needle, 'utf8');
  return {
    utf8: needle,
    latin1: buf.toString('binary'),
    hex: buf.toString('hex'),
    base64: buf.toString('base64'),
  };
}

/** Assert `haystack` (a string view of bytes or text) contains none
 *  of the encoded forms of `needle`. We skip an encoding when its
 *  rendered length is short enough to collide with random bytes
 *  (the same rule used in `plaintext-non-leakage.property.test.ts`). */
function expectNoLeak(haystack: string, needle: string): void {
  const enc = encodingsOf(needle);
  expect(haystack.includes(enc.utf8)).toBe(false);
  expect(haystack.includes(enc.latin1)).toBe(false);
  if (enc.hex.length >= 16) {
    expect(haystack.includes(enc.hex)).toBe(false);
  }
  if (enc.base64.length >= 12) {
    expect(haystack.includes(enc.base64)).toBe(false);
  }
}

/** Render `bytes` as a single concatenated string-of-views suitable
 *  for substring leak probes. Mirrors the four encodings any naive
 *  JSON serialiser could produce for a Uint8Array. */
function bytesAsAllViews(bytes: Uint8Array): string {
  const buf = Buffer.from(bytes);
  return [
    buf.toString('utf8'),
    buf.toString('binary'),
    buf.toString('hex'),
    buf.toString('base64'),
  ].join('\u0001');
}

// ---------------------------------------------------------------------------
// Envelope construction
// ---------------------------------------------------------------------------

function callEnvelope(ciphertext: Uint8Array): CiphertextEnvelope {
  return {
    sessionId: SESSION_ID,
    senderDeviceId: SENDER_DEVICE,
    recipientDeviceId: RECIPIENT_DEVICE,
    type: EnvelopeRouterType.CALL,
    ciphertext,
  };
}

// ---------------------------------------------------------------------------
// Sanity check — proves the candidate IS in the plaintext
// ---------------------------------------------------------------------------

describe('P23 — sanity: ratchet round-trip recovers the ICE candidate', () => {
  test('encryptToDevice → decryptFromDevice recovers the candidate string', async () => {
    const cand = 'candidate:1 1 udp 2113929471 192.0.2.1 54321 typ host';
    const { alice, bob } = initRatchetPair();

    const plaintext = buildIceInnerPlaintext(CALL_ID, cand);
    const sent = await encryptToDevice(alice, plaintext);
    const recv = await decryptFromDevice(bob, sent.ciphertext, sent.header);

    // Round-trip must succeed; otherwise the property test below is
    // vacuous (we'd be encrypting random bytes that don't actually
    // contain the candidate).
    expect(recv.result.ok).toBe(true);
    if (!recv.result.ok) throw new Error('decrypt failed in sanity check');
    const decoded = new TextDecoder().decode(recv.result.plaintext);
    expect(decoded.includes(cand)).toBe(true);
    expect(decoded.includes(CANDIDATE_PREFIX)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Property A — wire-level ciphertext opaqueness
// ---------------------------------------------------------------------------

describe('P23 — wire-level CALL ciphertext is opaque to the candidate string', () => {
  test('property: ciphertext bytes contain neither `cand` nor `candidate:` (≥100 inputs)', async () => {
    await fc.assert(
      fc.asyncProperty(arbIceCandidate, async (cand) => {
        // Fresh ratchet pair per iteration so AES-GCM nonces (derived
        // from per-message keys) are independent across iterations.
        const { alice } = initRatchetPair();
        const plaintext = buildIceInnerPlaintext(CALL_ID, cand);
        const sent = await encryptToDevice(alice, plaintext);

        // (a) The candidate string must not appear in the ciphertext
        // bytes under any of the four encoding views — this is what
        // "the candidate travels inside an E2EE envelope" (Req 7.2 /
        // 21.23) means at the wire layer. AES-GCM gives us this with
        // negligible probability (< 2^-80 per iteration for an
        // 8-byte string), but we assert it explicitly so the
        // property is checked, not just argued.
        const view = bytesAsAllViews(sent.ciphertext);
        expectNoLeak(view, cand);
        // The ICE prefix is even shorter (10 ASCII chars) — a chance
        // collision is ~2^-80 per iteration too, but worth checking
        // separately because EVERY real candidate carries this
        // exact prefix and a regression that bypassed encryption
        // would surface here first.
        expectNoLeak(view, CANDIDATE_PREFIX);
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Property B — gateway log opaqueness on the happy path
// ---------------------------------------------------------------------------

describe('P23 — gateway routing of CALL envelopes leaks no candidate to logs', () => {
  test('property: happy-path logs contain zero candidate strings (≥100 inputs)', async () => {
    await fc.assert(
      fc.asyncProperty(arbIceCandidate, async (cand) => {
        const h = setupHarness();
        const { alice } = initRatchetPair();
        const plaintext = buildIceInnerPlaintext(CALL_ID, cand);
        const sent = await encryptToDevice(alice, plaintext);

        await onSendEnvelope(
          h.ctx,
          {
            clientNonce: 'nonce-p23-happy',
            envelope: callEnvelope(sent.ciphertext),
          },
          h.deps,
        );

        // The CALL relay path must complete: persist the row,
        // publish the envelope id on the recipient channel, and
        // ack the sender. None of these surfaces may carry the
        // candidate string.
        expect(h.sock.sent.length).toBe(1);
        const ackFrame = decodeS2C(h.sock.sent[0]!);
        expect(ackFrame.t).toBe(S2C.ENVELOPE_QUEUED);

        // The Redis fan-out payload is the assigned envelope id as a
        // decimal string; no ciphertext, no candidate.
        expect(h.redis.published.length).toBe(1);
        const pub = h.redis.published[0]!;
        expect(pub.channel).toBe(fanoutChannelFor(RECIPIENT_DEVICE));
        expect(pub.payload).toMatch(/^\d+$/);
        expectNoLeak(pub.payload, cand);
        expectNoLeak(pub.payload, CANDIDATE_PREFIX);

        // Captured pino log lines: zero matches for the candidate or
        // the literal `'candidate:'` prefix under any of the four
        // byte-view encodings.
        const captured = h.sink.joined();
        expectNoLeak(captured, cand);
        expectNoLeak(captured, CANDIDATE_PREFIX);
      }),
    );
  });

  test('property: redis-publish-failure path logs contain zero candidate strings (≥100 inputs)', async () => {
    // Forces the gateway's `'redis fan-out publish failed; relying on
    // offline replay'` warn-level log path. The structured log fields
    // are `{ err, deviceId, recipientDeviceId }` — none of which
    // legitimately carry the ciphertext bytes; the redaction layer
    // is the safety net.
    await fc.assert(
      fc.asyncProperty(arbIceCandidate, async (cand) => {
        const h = setupHarness();
        h.redis.failNext = new Error('redis: connection refused');
        const { alice } = initRatchetPair();
        const plaintext = buildIceInnerPlaintext(CALL_ID, cand);
        const sent = await encryptToDevice(alice, plaintext);

        await onSendEnvelope(
          h.ctx,
          {
            clientNonce: 'nonce-p23-redis-fail',
            envelope: callEnvelope(sent.ciphertext),
          },
          h.deps,
        );

        // Sender still gets ENVELOPE_QUEUED on a publish failure —
        // the row persisted; offline replay will deliver later.
        expect(h.sock.sent.length).toBe(1);

        const captured = h.sink.joined();
        expectNoLeak(captured, cand);
        expectNoLeak(captured, CANDIDATE_PREFIX);
      }),
    );
  });

  test('property: db-insert-failure path logs contain zero candidate strings (≥100 inputs)', async () => {
    // Forces the gateway's `'ciphertext envelope insert failed'`
    // error-level log path. Same redaction guarantee as the
    // happy-path / redis-failure surfaces.
    await fc.assert(
      fc.asyncProperty(arbIceCandidate, async (cand) => {
        const sink = makeSink();
        const log = createLogger({ destination: sink, level: 'debug' });
        const child = log.child({ requestId: 'req-p23-db-fail' });
        const sock = makeFakeSocket();
        const ctx = buildContext(
          sock,
          'user-1',
          SENDER_DEVICE,
          child as unknown as Parameters<typeof buildContext>[3],
        );
        ctx.helloReceived = true;

        // Pool whose insert always throws — the gateway logs and
        // replies INTERNAL via an ERROR frame.
        const failingPool: FakePool = {
          queries: [],
          async query() {
            throw new Error('connection terminated unexpectedly');
          },
        };
        const redis = makeFakeRedis();
        const deps = buildDeps(failingPool, redis);

        const { alice } = initRatchetPair();
        const plaintext = buildIceInnerPlaintext(CALL_ID, cand);
        const sent = await encryptToDevice(alice, plaintext);

        await onSendEnvelope(
          ctx,
          {
            clientNonce: 'nonce-p23-db-fail',
            envelope: callEnvelope(sent.ciphertext),
          },
          deps,
        );

        // Sender receives an ERROR frame; assert that frame's bytes
        // also carry no candidate string.
        expect(sock.sent.length).toBeGreaterThanOrEqual(1);
        const lastFrame = sock.sent.at(-1)!;
        expectNoLeak(bytesAsAllViews(lastFrame), cand);
        expectNoLeak(bytesAsAllViews(lastFrame), CANDIDATE_PREFIX);

        const captured = sink.joined();
        expectNoLeak(captured, cand);
        expectNoLeak(captured, CANDIDATE_PREFIX);
      }),
    );
  });
});

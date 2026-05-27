// apps/web/test/outbox-coordinator-replay.test.ts
//
// Phase 2 verification gate (task 3.10) — the offline-enqueue
// then reconnect-replay path through the `OutboxCoordinator`.
//
// What this test isolates that other Phase-2 unit tests do NOT:
//   - `outbox.test.ts` covers the Dexie data layer alone (FIFO
//     ordering, capacity + age eviction, idempotent enqueue).
//   - `dm-thread.test.tsx` covers the composer → `'sending'` row
//     → `'delivered'` row transition on a socket that is already
//     in `'ready'` state.
//   - `ws-client.test.ts` covers the reconnect schedule and the
//     `hello_ok` event but not the persisted-outbox drain that
//     follows it.
//
// The full requirement-4.9 contract is end-to-end:
//   "WHEN the Web_Client reconnects, THE Outbox SHALL replay
//    queued envelopes in original enqueue order over the WSS
//    connection."
// The Dexie repo and the WS client each cover half of that
// contract; the `OutboxCoordinator` is the seam that ties them
// together. This test drives a reconnect cycle and asserts the
// drain happens in original-enqueue order (FIFO) on the next
// `hello_ok`, and that each `ENVELOPE_QUEUED` ack deletes the
// corresponding outbox row.
//
// Coverage map:
//   - Requirement 4.8 (FIFO ordering of the persisted queue):
//     `listInOrder` returns rows in insertion order; the
//     coordinator drains in that order.
//   - Requirement 4.9 (replay-on-reconnect): the drain only
//     fires once the WS reaches `'ready'` after a reconnect.
//   - Requirement 12.11 (server-side replay) is exercised on
//     the API side by `apps/api/test/redis-fanout.test.ts` and
//     `apps/api/test/offline-queue-completeness.property.test.ts`;
//     this file complements that with the client-side replay
//     contract.
//
// Implementation note: this test uses an in-memory store stub
// (matching the structural surface `OutboxCoordinator` consumes
// from `DexieOutboxStore`) instead of a real Dexie database.
// The Dexie path is exercised exhaustively in `outbox.test.ts`;
// what we want to isolate here is the coordinator's
// "wait for `hello_ok`, then drain in `listInOrder` order"
// behaviour.

import { describe, expect, it } from 'vitest';

import {
  C2S,
  decodeC2S,
  EnvelopeRouterType,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import {
  type DexieOutboxStore,
  type OutboxEntry,
} from '../src/db/repositories/outbox.js';
import { OutboxCoordinator } from '../src/ws/outbox.js';
import { WsClient, type WebSocketLike } from '../src/ws/client.js';

// ---------------------------------------------------------------------------
// In-memory store stub
// ---------------------------------------------------------------------------

/** Structural stand-in for `DexieOutboxStore`. The coordinator only
 *  calls `enqueue`, `listInOrder`, `deleteByClientNonce`, and
 *  `recordReplayAttempt`. Mirrors the FIFO-by-insertion-order
 *  invariant that `DexieOutboxStore` exposes via primary-key ASC. */
class InMemoryOutboxStore {
  #rows: OutboxEntry[] = [];
  #nextId = 1;

  async enqueue(args: {
    clientNonce: string;
    envelope: CiphertextEnvelope;
    enqueuedAt?: number;
  }): Promise<OutboxEntry> {
    const existing = this.#rows.find(
      (r) => r.clientNonce === args.clientNonce,
    );
    if (existing !== undefined) {
      // Idempotent on duplicate nonce — same shape as
      // `DexieOutboxStore.enqueue`.
      return existing;
    }
    const entry: OutboxEntry = {
      id: this.#nextId++,
      clientNonce: args.clientNonce,
      envelope: args.envelope,
      enqueuedAt: args.enqueuedAt ?? Date.now(),
      retryCount: 0,
    };
    this.#rows.push(entry);
    return entry;
  }

  async listInOrder(): Promise<OutboxEntry[]> {
    // Primary-key ASC — matches `DexieOutboxStore.listInOrder`.
    return this.#rows.slice().sort((a, b) => a.id - b.id);
  }

  async deleteByClientNonce(clientNonce: string): Promise<void> {
    const idx = this.#rows.findIndex((r) => r.clientNonce === clientNonce);
    if (idx >= 0) {
      this.#rows.splice(idx, 1);
    }
  }

  async findByClientNonce(clientNonce: string): Promise<OutboxEntry | null> {
    const found = this.#rows.find((r) => r.clientNonce === clientNonce);
    return found ?? null;
  }

  async count(): Promise<number> {
    return this.#rows.length;
  }

  async recordReplayAttempt(clientNonce: string): Promise<void> {
    const idx = this.#rows.findIndex((r) => r.clientNonce === clientNonce);
    if (idx >= 0) {
      const old = this.#rows[idx]!;
      this.#rows[idx] = {
        ...old,
        retryCount: old.retryCount + 1,
        lastTryAt: Date.now(),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Stub WebSocket
// ---------------------------------------------------------------------------

class StubWebSocket implements WebSocketLike {
  static instances: StubWebSocket[] = [];
  static readonly CLOSED = 3;
  static readonly OPEN = 1;

  readyState = 0;
  binaryType: 'blob' | 'arraybuffer' = 'arraybuffer';
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose:
    | ((ev: { code: number; reason: string; wasClean: boolean }) => void)
    | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  readonly url: string;
  readonly sent: Uint8Array[] = [];

  constructor(url: string) {
    this.url = url;
    StubWebSocket.instances.push(this);
  }

  emitOpen(): void {
    this.readyState = StubWebSocket.OPEN;
    this.onopen?.(undefined);
  }

  emitMessage(payload: unknown): void {
    this.onmessage?.({ data: payload });
  }

  emitClose(code = 1006, reason = 'abnormal', wasClean = false): void {
    this.readyState = StubWebSocket.CLOSED;
    this.onclose?.({ code, reason, wasClean });
  }

  send(data: ArrayBufferView | ArrayBuffer | string): void {
    if (typeof data === 'string') {
      throw new Error('stub: text frames not supported');
    }
    if (data instanceof ArrayBuffer) {
      this.sent.push(new Uint8Array(data));
    } else {
      this.sent.push(
        new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
      );
    }
  }

  close(): void {
    this.readyState = StubWebSocket.CLOSED;
  }
}

// ---------------------------------------------------------------------------
// Stub scheduler
// ---------------------------------------------------------------------------

interface ScheduledTask {
  fn: () => void;
  ms: number;
  fired: boolean;
}

class StubScheduler {
  readonly tasks: ScheduledTask[] = [];
  set(fn: () => void, ms: number): unknown {
    const task: ScheduledTask = { fn, ms, fired: false };
    this.tasks.push(task);
    return task;
  }
  clear(handle: unknown): void {
    const task = handle as ScheduledTask | null;
    if (task !== null && !task.fired) {
      task.fired = true;
      const idx = this.tasks.indexOf(task);
      if (idx >= 0) this.tasks.splice(idx, 1);
    }
  }
  fireNext(): number | null {
    const task = this.tasks.shift();
    if (task === undefined) return null;
    task.fired = true;
    task.fn();
    return task.ms;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SENDER_DEVICE = 'device-self-1111';
const RECIPIENT_DEVICE = 'device-peer-2222';

function makeEnvelope(seed: number): CiphertextEnvelope {
  return {
    sessionId: `session-${seed}`,
    senderDeviceId: SENDER_DEVICE,
    recipientDeviceId: RECIPIENT_DEVICE,
    type: EnvelopeRouterType.MESSAGE,
    ciphertext: new Uint8Array([seed & 0xff]),
  };
}

interface Harness {
  readonly client: WsClient;
  readonly store: InMemoryOutboxStore;
  readonly coordinator: OutboxCoordinator;
  readonly scheduler: StubScheduler;
  readonly newest: () => StubWebSocket;
  readonly socketCount: () => number;
}

async function buildHarness(): Promise<Harness> {
  StubWebSocket.instances.length = 0;
  const scheduler = new StubScheduler();
  const store = new InMemoryOutboxStore();

  const client = new WsClient({
    url: 'wss://example.test',
    deviceId: SENDER_DEVICE,
    tokenProvider: async (): Promise<string> => 'tok',
    WebSocket: StubWebSocket,
    setTimeout: (fn, ms): unknown => scheduler.set(fn, ms),
    clearTimeout: (handle): void => scheduler.clear(handle),
  });
  // The `OutboxCoordinator` only consumes a structural subset of
  // `DexieOutboxStore`; the cast is safe because every method the
  // coordinator calls is implemented on `InMemoryOutboxStore`.
  const coordinator = new OutboxCoordinator({
    client,
    store: store as unknown as DexieOutboxStore,
  });
  coordinator.start();

  return {
    client,
    store,
    coordinator,
    scheduler,
    newest: (): StubWebSocket => {
      const inst =
        StubWebSocket.instances[StubWebSocket.instances.length - 1];
      if (inst === undefined) {
        throw new Error('no socket instance');
      }
      return inst;
    },
    socketCount: (): number => StubWebSocket.instances.length,
  };
}

/** Drain the microtask queue. */
async function flush(): Promise<void> {
  for (let i = 0; i < 10; i += 1) {
    await Promise.resolve();
  }
}

/** Build the HELLO_OK frame as a real msgpack-encoded `S2C` payload
 *  so the WsClient's decode path runs end-to-end. We import the
 *  encoder lazily inside the helper to keep the top-of-file imports
 *  focused on the public surface. */
async function emitHelloOk(
  sock: StubWebSocket,
  serverTimeMs = 1_700_000_000_000,
): Promise<void> {
  const { encodeS2C, S2C } = await import('@konvo/protocol');
  const bytes = encodeS2C({
    t: S2C.HELLO_OK,
    serverTimeMs,
    queuedCount: 0,
  });
  const buffer = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  );
  sock.emitMessage(buffer);
}

async function emitEnvelopeQueued(
  sock: StubWebSocket,
  clientNonce: string,
  envelopeId: bigint,
): Promise<void> {
  const { encodeS2C, S2C } = await import('@konvo/protocol');
  const bytes = encodeS2C({
    t: S2C.ENVELOPE_QUEUED,
    clientNonce,
    envelopeId,
    serverTimeMs: 1_700_000_000_000,
  });
  const buffer = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  );
  sock.emitMessage(buffer);
}

/** Return only the SEND_ENVELOPE frames the client wrote on a
 *  given socket, decoded into their `clientNonce` field. */
function sentNonces(sock: StubWebSocket): string[] {
  const out: string[] = [];
  for (const buf of sock.sent) {
    const frame = decodeC2S(buf);
    if (frame.t === C2S.SEND_ENVELOPE) {
      out.push(frame.clientNonce);
    }
  }
  return out;
}

/** Spin the microtask queue until `pred()` is true or `attempts`
 *  ticks have elapsed. */
async function waitFor(
  pred: () => boolean | Promise<boolean>,
  attempts = 200,
): Promise<void> {
  for (let i = 0; i < attempts; i += 1) {
    if (await pred()) return;
    await Promise.resolve();
  }
  throw new Error('waitFor: predicate never became true');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('OutboxCoordinator — replay on reconnect (Requirement 4.9)', () => {
  it('drains queued rows in original enqueue (FIFO) order on the first hello_ok', async () => {
    const h = await buildHarness();

    // Three enqueues land BEFORE the socket has reached `ready`.
    // Because `OutboxCoordinator.enqueue` only emits a frame when
    // `client.isReady`, all three rows persist into the store and
    // wait for the drain.
    await h.coordinator.enqueue({
      clientNonce: 'nonce-1',
      envelope: makeEnvelope(1),
    });
    await h.coordinator.enqueue({
      clientNonce: 'nonce-2',
      envelope: makeEnvelope(2),
    });
    await h.coordinator.enqueue({
      clientNonce: 'nonce-3',
      envelope: makeEnvelope(3),
    });

    // Sanity: nothing on the wire yet.
    expect(h.socketCount()).toBe(0);
    expect(await h.store.count()).toBe(3);

    // Now drive the connect → handshake.
    await h.client.connect();
    await flush();
    expect(h.socketCount()).toBe(1);
    h.newest().emitOpen();
    await emitHelloOk(h.newest());
    await waitFor(() => h.client.isReady);

    // Wait for the coordinator's async drain to finish writing
    // all three SEND_ENVELOPE frames.
    await waitFor(() => sentNonces(h.newest()).length >= 3);

    // Frames sent on this socket: HELLO followed by SEND_ENVELOPE
    // for each persisted nonce in original enqueue order.
    const nonces = sentNonces(h.newest());
    expect(nonces).toEqual(['nonce-1', 'nonce-2', 'nonce-3']);
  });

  it('replays the residual queue on the next hello_ok after a reconnect', async () => {
    const h = await buildHarness();

    // Cycle 1: connect, ack one, then crash mid-flight.
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    await emitHelloOk(h.newest(), 1);
    await waitFor(() => h.client.isReady);

    // Two enqueues land while ready — they should be sent
    // immediately by the coordinator's ready-path.
    await h.coordinator.enqueue({
      clientNonce: 'nonce-A',
      envelope: makeEnvelope(10),
    });
    await h.coordinator.enqueue({
      clientNonce: 'nonce-B',
      envelope: makeEnvelope(11),
    });
    await waitFor(() => sentNonces(h.newest()).includes('nonce-B'));

    // Server acks A only; B remains in the queue.
    await emitEnvelopeQueued(h.newest(), 'nonce-A', 1n);
    await waitFor(
      async () => (await h.store.findByClientNonce('nonce-A')) === null,
    );
    expect(await h.store.findByClientNonce('nonce-B')).not.toBeNull();

    // One more enqueue lands mid-cycle and ALSO goes on the wire.
    await h.coordinator.enqueue({
      clientNonce: 'nonce-C',
      envelope: makeEnvelope(12),
    });
    await waitFor(() => sentNonces(h.newest()).includes('nonce-C'));

    // Crash the socket. The client schedules a reconnect; B and
    // C remain in the store.
    h.newest().emitClose(1006, 'abnormal', false);
    expect(h.client.isReady).toBe(false);
    expect(await h.store.findByClientNonce('nonce-B')).not.toBeNull();
    expect(await h.store.findByClientNonce('nonce-C')).not.toBeNull();

    // Cycle 2: fire the reconnect timer, complete the handshake.
    h.scheduler.fireNext();
    await flush();
    expect(h.socketCount()).toBe(2);
    const cycle2 = h.newest();
    cycle2.emitOpen();
    await emitHelloOk(cycle2, 3);
    await waitFor(() => h.client.isReady);

    // Wait for the cycle-2 drain to send both residual rows.
    await waitFor(() => sentNonces(cycle2).length >= 2);

    // The drain on cycle 2 must replay B and C in original
    // enqueue order. Frame inspection: ignore HELLO, gather
    // SEND_ENVELOPE nonces.
    const nonces = sentNonces(cycle2);
    expect(nonces).toEqual(['nonce-B', 'nonce-C']);

    // Server acks both; both rows disappear from the store.
    await emitEnvelopeQueued(cycle2, 'nonce-B', 2n);
    await emitEnvelopeQueued(cycle2, 'nonce-C', 3n);
    await waitFor(async () => (await h.store.count()) === 0);
    expect(await h.store.count()).toBe(0);
  });
});

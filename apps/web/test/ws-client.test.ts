// apps/web/test/ws-client.test.ts
//
// Unit tests for `apps/web/src/ws/client.ts` (task 3.7).
//
// Coverage:
//   - HELLO is sent immediately on socket open with `protoVersion: 1`
//     and the deviceId.
//   - HELLO_OK transitions the client into `'ready'` and emits
//     `hello_ok`.
//   - Backoff schedule: the spec-mandated 1s/2s/4s/8s/16s/30s/30s
//     sequence is applied across consecutive failed reconnects.
//   - A successful HELLO_OK resets the backoff index.
//   - `close()` suppresses any further reconnect.
//   - `S2C.ENVELOPE` and `S2C.ENVELOPE_QUEUED` are dispatched as
//     events with the right payload.
//
// We use a stub WebSocket and a stub scheduler instead of real
// timers + jsdom's WebSocket so the tests run fast and don't rely
// on any real network. fake-indexeddb is unaffected (none of these
// tests use Dexie).

import { describe, expect, it } from 'vitest';

import {
  C2S,
  decodeC2S,
  encodeS2C,
  EnvelopeRouterType,
  PROTOCOL_VERSION,
  S2C,
  type CiphertextEnvelope,
  type ServerToClient,
} from '@konvo/protocol';

import {
  RECONNECT_BACKOFF_CAP_MS,
  RECONNECT_BACKOFF_MS,
  WsClient,
  type WebSocketLike,
} from '../src/ws/client.js';

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
  closeArgs: { code?: number; reason?: string } | null = null;

  constructor(url: string) {
    this.url = url;
    StubWebSocket.instances.push(this);
  }

  // Test helpers — drive the stub's lifecycle from the test body.
  emitOpen(): void {
    this.readyState = StubWebSocket.OPEN;
    this.onopen?.(undefined);
  }

  emitMessage(payload: ServerToClient): void {
    const bytes = encodeS2C(payload);
    // Wrap in ArrayBuffer to mirror what a real browser delivers
    // when `binaryType === 'arraybuffer'`.
    const buffer = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    );
    this.onmessage?.({ data: buffer });
  }

  emitClose(code = 1006, reason = 'abnormal', wasClean = false): void {
    this.readyState = StubWebSocket.CLOSED;
    this.onclose?.({ code, reason, wasClean });
  }

  // WebSocketLike surface
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

  close(code?: number, reason?: string): void {
    this.closeArgs = { ...(code !== undefined ? { code } : {}), ...(reason !== undefined ? { reason } : {}) };
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
      task.fired = true; // mark cancelled
      const idx = this.tasks.indexOf(task);
      if (idx >= 0) this.tasks.splice(idx, 1);
    }
  }
  /** Fire the next pending task and return its delay. Returns
   *  null if no task is pending. */
  fireNext(): number | null {
    const task = this.tasks.shift();
    if (task === undefined) return null;
    task.fired = true;
    task.fn();
    return task.ms;
  }
  pendingDelays(): number[] {
    return this.tasks.map((t) => t.ms);
  }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

interface Harness {
  client: WsClient;
  scheduler: StubScheduler;
  newest: () => StubWebSocket;
  socketCount: () => number;
}

function buildHarness(opts?: { reconnectBackoffMs?: readonly number[] }): Harness {
  StubWebSocket.instances.length = 0;
  const scheduler = new StubScheduler();
  const client = new WsClient({
    url: 'wss://example.test',
    deviceId: 'device-1',
    tokenProvider: async (): Promise<string> => 'tok',
    WebSocket: StubWebSocket,
    setTimeout: (fn, ms): unknown => scheduler.set(fn, ms),
    clearTimeout: (handle): void => scheduler.clear(handle),
    ...(opts?.reconnectBackoffMs !== undefined
      ? { reconnectBackoffMs: opts.reconnectBackoffMs }
      : {}),
  });
  return {
    client,
    scheduler,
    newest: (): StubWebSocket => {
      const inst = StubWebSocket.instances[StubWebSocket.instances.length - 1];
      if (inst === undefined) {
        throw new Error('no socket instance yet');
      }
      return inst;
    },
    socketCount: (): number => StubWebSocket.instances.length,
  };
}

async function flush(): Promise<void> {
  // Two ticks — the tokenProvider is async, so connect() awaits one
  // microtask before constructing the socket.
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('WsClient.computeBackoffMs', () => {
  it('matches the spec-mandated schedule', () => {
    const { client } = buildHarness();
    expect(client.computeBackoffMs(0)).toBe(0);
    expect(client.computeBackoffMs(1)).toBe(1_000);
    expect(client.computeBackoffMs(2)).toBe(2_000);
    expect(client.computeBackoffMs(3)).toBe(4_000);
    expect(client.computeBackoffMs(4)).toBe(8_000);
    expect(client.computeBackoffMs(5)).toBe(16_000);
    expect(client.computeBackoffMs(6)).toBe(30_000);
    // Cap: every attempt past the schedule waits the cap.
    expect(client.computeBackoffMs(7)).toBe(RECONNECT_BACKOFF_CAP_MS);
    expect(client.computeBackoffMs(20)).toBe(RECONNECT_BACKOFF_CAP_MS);
  });

  it('exports the expected schedule', () => {
    expect(RECONNECT_BACKOFF_MS).toEqual([
      1_000, 2_000, 4_000, 8_000, 16_000, 30_000,
    ]);
    expect(RECONNECT_BACKOFF_CAP_MS).toBe(30_000);
  });
});

describe('WsClient HELLO handshake', () => {
  it('sends HELLO immediately on socket open with protoVersion=1 and deviceId', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    expect(h.socketCount()).toBe(1);
    h.newest().emitOpen();
    expect(h.newest().sent).toHaveLength(1);
    const decoded = decodeC2S(h.newest().sent[0]!);
    expect(decoded.t).toBe(C2S.HELLO);
    if (decoded.t === C2S.HELLO) {
      expect(decoded.protoVersion).toBe(PROTOCOL_VERSION);
      expect(decoded.deviceId).toBe('device-1');
    }
  });

  it('transitions to ready and emits hello_ok on HELLO_OK', async () => {
    const h = buildHarness();
    const events: { serverTimeMs: number; queuedCount: number }[] = [];
    h.client.on('hello_ok', (ev) => events.push(ev));
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    expect(h.client.state).toBe('authenticating');
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1234,
      queuedCount: 0,
    });
    expect(h.client.state).toBe('ready');
    expect(h.client.isReady).toBe(true);
    expect(events).toEqual([{ serverTimeMs: 1234, queuedCount: 0 }]);
  });

  it('appends the token to the WS URL', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    expect(h.newest().url).toBe('wss://example.test/ws?token=tok');
  });
});

describe('WsClient inbound dispatch', () => {
  it('emits envelope events for S2C.ENVELOPE frames', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1,
      queuedCount: 0,
    });

    const events: CiphertextEnvelope[] = [];
    h.client.on('envelope', (ev) => events.push(ev.envelope));

    const env: CiphertextEnvelope = {
      sessionId: 'sess',
      senderDeviceId: 'sender',
      recipientDeviceId: 'recip',
      type: EnvelopeRouterType.MESSAGE,
      ciphertext: new Uint8Array([1, 2, 3]),
    };
    h.newest().emitMessage({ t: S2C.ENVELOPE, envelope: env });
    expect(events).toHaveLength(1);
    expect(events[0]!.sessionId).toBe('sess');
  });

  it('emits queued events for ENVELOPE_QUEUED frames', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1,
      queuedCount: 0,
    });
    const events: { clientNonce: string; envelopeId: bigint }[] = [];
    h.client.on('queued', (ev) =>
      events.push({ clientNonce: ev.clientNonce, envelopeId: ev.envelopeId }),
    );
    h.newest().emitMessage({
      t: S2C.ENVELOPE_QUEUED,
      clientNonce: 'n1',
      envelopeId: 42n,
      serverTimeMs: 100,
    });
    expect(events).toEqual([{ clientNonce: 'n1', envelopeId: 42n }]);
  });

  it('emits server_error for S2C.ERROR frames', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1,
      queuedCount: 0,
    });
    const errs: { code: number; message: string }[] = [];
    h.client.on('server_error', (ev) =>
      errs.push({ code: ev.code, message: ev.message }),
    );
    h.newest().emitMessage({
      t: S2C.ERROR,
      code: 2,
      message: 'rate-limited',
    });
    expect(errs).toEqual([{ code: 2, message: 'rate-limited' }]);
  });
});

describe('WsClient backoff schedule', () => {
  it('schedules consecutive reconnects at 1s, 2s, 4s, 8s, 16s, 30s, 30s', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();

    const observed: number[] = [];
    const expectedSequence = [
      1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000,
    ];

    for (let i = 0; i < expectedSequence.length; i += 1) {
      // The current attempt's socket is the newest one. Crash it
      // before reaching HELLO_OK to advance the backoff index.
      const sock = h.newest();
      sock.emitClose(1006, 'abnormal', false);

      // A reconnect timer should be scheduled with the next delay.
      const delays = h.scheduler.pendingDelays();
      expect(delays).toHaveLength(1);
      observed.push(delays[0]!);

      // Fire the timer; the client opens the next socket.
      h.scheduler.fireNext();
      await flush();
    }

    expect(observed).toEqual(expectedSequence);
  });

  it('resets the backoff index after a successful HELLO_OK', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();

    // First attempt: succeed.
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1,
      queuedCount: 0,
    });
    expect(h.client.isReady).toBe(true);

    // Disconnect after success — the next attempt should wait 1s
    // (NOT continue from a higher index).
    h.newest().emitClose(1006, 'abnormal', false);
    expect(h.scheduler.pendingDelays()).toEqual([1_000]);

    // Drive the next reconnect, succeed again, then crash again —
    // the next-after-that delay should still start at 1s.
    h.scheduler.fireNext();
    await flush();
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 2,
      queuedCount: 0,
    });
    h.newest().emitClose(1006, 'abnormal', false);
    expect(h.scheduler.pendingDelays()).toEqual([1_000]);
  });
});

describe('WsClient.close', () => {
  it('suppresses any further reconnect attempts', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1,
      queuedCount: 0,
    });

    h.client.close();
    expect(h.client.state).toBe('closed');

    // Even if the socket emits a subsequent close event (e.g. the
    // browser tears down asynchronously), no reconnect timer
    // should be queued.
    h.newest().emitClose(1000, 'normal', true);
    expect(h.scheduler.pendingDelays()).toEqual([]);
  });
});

describe('WsClient.send', () => {
  it('throws when called before HELLO_OK', async () => {
    const h = buildHarness();
    expect(() =>
      h.client.send({
        t: C2S.SEND_ENVELOPE,
        clientNonce: 'n',
        envelope: {
          sessionId: 's',
          senderDeviceId: 'a',
          recipientDeviceId: 'b',
          type: EnvelopeRouterType.MESSAGE,
          ciphertext: new Uint8Array(),
        },
      }),
    ).toThrow();
  });

  it('encodes and forwards a SEND_ENVELOPE frame when ready', async () => {
    const h = buildHarness();
    await h.client.connect();
    await flush();
    h.newest().emitOpen();
    h.newest().emitMessage({
      t: S2C.HELLO_OK,
      serverTimeMs: 1,
      queuedCount: 0,
    });
    // First frame is HELLO; subsequent frames are SEND_ENVELOPE.
    const beforeCount = h.newest().sent.length;
    h.client.send({
      t: C2S.SEND_ENVELOPE,
      clientNonce: 'nonce',
      envelope: {
        sessionId: 'sess',
        senderDeviceId: 'a',
        recipientDeviceId: 'b',
        type: EnvelopeRouterType.MESSAGE,
        ciphertext: new Uint8Array([9, 8, 7]),
      },
    });
    expect(h.newest().sent.length).toBe(beforeCount + 1);
    const decoded = decodeC2S(h.newest().sent[h.newest().sent.length - 1]!);
    expect(decoded.t).toBe(C2S.SEND_ENVELOPE);
    if (decoded.t === C2S.SEND_ENVELOPE) {
      expect(decoded.clientNonce).toBe('nonce');
      expect(decoded.envelope.sessionId).toBe('sess');
    }
  });
});

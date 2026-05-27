// apps/web/src/ws/client.ts
//
// WebSocket transport for the Konvo PWA (task 3.7).
//
// What this module owns:
//   - Opening a WebSocket to the API_Gateway's `/ws` endpoint with
//     the access token attached via the `?token=...` query param
//     (browsers can't set custom WS headers — see
//     `apps/api/src/ws/gateway.ts`).
//   - Sending `HELLO { protoVersion: 1, deviceId }` immediately on
//     `open` and waiting for `HELLO_OK` before reporting "ready".
//   - Encoding outbound `ClientToServer` frames with
//     `@konvo/protocol`'s msgpack codec and decoding inbound binary
//     frames into `ServerToClient`.
//   - Exponential reconnect with the spec-mandated schedule of
//     1s, 2s, 4s, 8s, 16s, 30s (cap), reset on the next successful
//     `HELLO_OK`. (Requirement 4.7 / 4.8 / design.md §13.)
//   - A small typed event surface (`hello_ok`, `envelope`, `queued`,
//     `error`, `disconnect`) so higher-level coordinators (the
//     outbox replayer, the DM thread UI) can wire in without
//     reaching into the underlying socket.
//
// What this module does NOT own:
//   - Outbox storage or replay scheduling (that's
//     `apps/web/src/ws/outbox.ts` plus the Dexie outbox repo).
//   - Decryption or thread-state mutation (the DM feature wires
//     those on top of the `envelope` event).
//   - Token refresh: the token is supplied at construction time
//     and read again from the `tokenProvider` callback on every
//     reconnect attempt. A future task can wire a refresh-on-401
//     loop into the gateway's auth path; this client simply
//     surfaces the close as a `disconnect` event so the consumer
//     can decide what to do.
//
// Design notes:
//   - The reconnect backoff sequence is spec-mandated (requirement
//     4.7 / design.md §13 envelope `WebSocket disconnect` row),
//     so it lives as an exported constant. Tests assert the
//     exact sequence.
//   - The WebSocket constructor is taken at construction time
//     (`opts.WebSocket`) so tests can supply a fake. Defaults to
//     `globalThis.WebSocket`.
//   - The setTimeout scheduler is also injected (`opts.setTimeout`
//     / `opts.clearTimeout`) so tests can drive backoff timing
//     without `vi.useFakeTimers` (which interferes with
//     fake-indexeddb's microtask scheduling).

import {
  C2S,
  decodeS2C,
  encodeC2S,
  PROTOCOL_VERSION,
  S2C,
  type BroadcastPost,
  type CiphertextEnvelope,
  type ClientToServer,
  type ServerToClient,
} from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Minimum surface of `WebSocket` this client uses. The standard
 *  global `WebSocket` matches; tests construct fakes against this
 *  shape.
 *
 *  We type events as `unknown` callbacks because jsdom's `Event`
 *  type and the WHATWG one don't always line up on the `data`
 *  field. The client's actual handlers narrow appropriately. */
export interface WebSocketLike {
  readonly readyState: number;
  send(data: ArrayBufferView | ArrayBuffer | string): void;
  close(code?: number, reason?: string): void;
  binaryType: 'blob' | 'arraybuffer';
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose:
    | ((ev: { code: number; reason: string; wasClean: boolean }) => void)
    | null;
  onerror: ((ev: unknown) => void) | null;
}

/** Constructor signature for `WebSocketLike`. Production code
 *  passes the standard `WebSocket`; tests pass a fake. */
export type WebSocketConstructor = new (url: string) => WebSocketLike;

/** Spec-mandated reconnect schedule (milliseconds). Per
 *  requirement 4.7 / design.md §13:
 *    1s, 2s, 4s, 8s, 16s, 30s (cap)
 *  After the cap is reached every subsequent attempt also waits
 *  30s. The schedule resets on a successful `HELLO_OK`. */
export const RECONNECT_BACKOFF_MS: readonly number[] = [
  1_000, 2_000, 4_000, 8_000, 16_000, 30_000,
];

/** Cap applied beyond the explicit schedule. Equal to the last
 *  entry in `RECONNECT_BACKOFF_MS` but spelled out separately so
 *  callers can read the cap without indexing the array. */
export const RECONNECT_BACKOFF_CAP_MS = 30_000;

/**
 * Connection-state lifecycle. A consumer that just wants
 * "ready / not ready" should listen for `hello_ok` and
 * `disconnect`; the explicit state is exposed for diagnostics
 * (e.g. a connection-status indicator in the UI).
 */
export type WsState =
  | 'idle' // never connected (post-construction, pre-`connect()`)
  | 'connecting' // socket open issued, awaiting `open` + HELLO_OK
  | 'authenticating' // socket open, HELLO sent, awaiting HELLO_OK
  | 'ready' // HELLO_OK received; safe to send envelopes
  | 'disconnected' // socket closed; backoff scheduled
  | 'closed'; // explicitly closed by `close()`; no reconnect

/** Reason an inbound frame couldn't be processed. */
export type WsFrameError =
  | { readonly kind: 'decode'; readonly cause: unknown }
  | { readonly kind: 'unexpected_state'; readonly received: number };

/** Public events emitted by `WsClient`. */
export interface WsEventMap {
  /** Fired after each successful HELLO_OK. Carries the server-supplied
   *  metadata so the consumer can record clock skew / queued count. */
  readonly hello_ok: { readonly serverTimeMs: number; readonly queuedCount: number };
  /** Fired for each inbound `S2C.ENVELOPE` frame. */
  readonly envelope: { readonly envelope: CiphertextEnvelope };
  /** Fired for each inbound `S2C.ENVELOPE_QUEUED` frame. The outbox
   *  coordinator uses this to delete the matching pending row. */
  readonly queued: {
    readonly clientNonce: string;
    readonly envelopeId: bigint;
    readonly serverTimeMs: number;
  };
  /** Fired for each inbound `S2C.ROOM_POST` frame. The broadcast
   *  feature (`apps/web/src/features/broadcast/`) listens here to
   *  render newly-published posts in real time on top of the
   *  paginated REST history (Requirement 10.4 / 10.10 / 10.11). */
  readonly room_post: { readonly post: BroadcastPost };
  /** Fired on a decode failure or any malformed frame. The
   *  connection is NOT torn down — the gateway's spec contract is
   *  that malformed frames close the socket from the server side
   *  (Requirement 12.14); the client logs and continues. */
  readonly frame_error: WsFrameError;
  /** Fired on `S2C.ERROR` frames. The consumer decides whether
   *  the error is fatal. */
  readonly server_error: {
    readonly code: number;
    readonly message: string;
  };
  /** Fired whenever the underlying socket closes. The client
   *  schedules a reconnect automatically unless `close()` was
   *  called explicitly. */
  readonly disconnect: {
    readonly code: number;
    readonly reason: string;
    readonly wasClean: boolean;
    readonly nextAttemptInMs: number | null;
  };
  /** Fired on every state transition. */
  readonly state: { readonly state: WsState };
}

export type WsEventName = keyof WsEventMap;
type Listener<E extends WsEventName> = (payload: WsEventMap[E]) => void;

// ---------------------------------------------------------------------------
// Construction options
// ---------------------------------------------------------------------------

export interface WsClientOptions {
  /** Base URL for the gateway (e.g. `'wss://api.example.com'`).
   *  The client appends `/ws?token=...`. */
  readonly url: string;
  /** Stable device id for this PWA install, sent in the HELLO
   *  frame. Must match the `did` claim of the access token. */
  readonly deviceId: string;
  /** Async callback invoked at connection time (and at each
   *  reconnect) to obtain the current access token. The token is
   *  appended to the WS URL as `?token=<tok>`. */
  readonly tokenProvider: () => Promise<string>;
  /** Override the WebSocket constructor (tests). Defaults to
   *  `globalThis.WebSocket`. */
  readonly WebSocket?: WebSocketConstructor;
  /** Override the timer scheduler (tests). Defaults to the global
   *  `setTimeout` / `clearTimeout`. */
  readonly setTimeout?: (fn: () => void, ms: number) => unknown;
  /** Companion to `setTimeout`. Defaults to global `clearTimeout`. */
  readonly clearTimeout?: (handle: unknown) => void;
  /** Override the reconnect schedule. Tests pass shorter delays.
   *  Production should NOT override this — the spec mandates the
   *  schedule. Defaults to `RECONNECT_BACKOFF_MS`. */
  readonly reconnectBackoffMs?: readonly number[];
  /** Cap applied beyond the schedule. Defaults to
   *  `RECONNECT_BACKOFF_CAP_MS`. */
  readonly reconnectCapMs?: number;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class WsClient {
  readonly #url: string;
  readonly #deviceId: string;
  readonly #tokenProvider: () => Promise<string>;
  readonly #WebSocket: WebSocketConstructor;
  readonly #setTimeoutFn: (fn: () => void, ms: number) => unknown;
  readonly #clearTimeoutFn: (handle: unknown) => void;
  readonly #backoff: readonly number[];
  readonly #backoffCap: number;

  #state: WsState = 'idle';
  #socket: WebSocketLike | null = null;
  /** How many times in a row a connect attempt has failed (i.e. the
   *  connection went `connecting → disconnected` without ever
   *  emitting `hello_ok`). Resets to 0 on each `hello_ok`. The
   *  index into `#backoff` for the next attempt. */
  #attemptCount = 0;
  /** Outstanding reconnect timer handle, if any. */
  #reconnectTimer: unknown = null;
  /** `true` once `close()` has been called explicitly. Suppresses
   *  any pending or future reconnect. */
  #explicitlyClosed = false;
  /** Per-event listener lists. */
  readonly #listeners: { [E in WsEventName]: Listener<E>[] } = {
    hello_ok: [],
    envelope: [],
    queued: [],
    room_post: [],
    frame_error: [],
    server_error: [],
    disconnect: [],
    state: [],
  };

  constructor(opts: WsClientOptions) {
    this.#url = opts.url;
    this.#deviceId = opts.deviceId;
    this.#tokenProvider = opts.tokenProvider;
    const ctor = opts.WebSocket ?? (globalThis as { WebSocket?: WebSocketConstructor }).WebSocket;
    if (ctor === undefined) {
      throw new Error(
        'WsClient: no WebSocket constructor available; supply opts.WebSocket',
      );
    }
    this.#WebSocket = ctor;
    this.#setTimeoutFn =
      opts.setTimeout ??
      ((fn: () => void, ms: number): unknown => globalThis.setTimeout(fn, ms));
    this.#clearTimeoutFn =
      opts.clearTimeout ??
      ((handle: unknown): void => {
        globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>);
      });
    this.#backoff = opts.reconnectBackoffMs ?? RECONNECT_BACKOFF_MS;
    this.#backoffCap = opts.reconnectCapMs ?? RECONNECT_BACKOFF_CAP_MS;
  }

  /** Current state. */
  get state(): WsState {
    return this.#state;
  }

  /** `true` once the most recent connect attempt has reached
   *  HELLO_OK. Flips back to `false` on disconnect. */
  get isReady(): boolean {
    return this.#state === 'ready';
  }

  /** Subscribe to an event. Returns an unsubscribe callback. */
  on<E extends WsEventName>(event: E, listener: Listener<E>): () => void {
    this.#listeners[event].push(listener);
    return (): void => {
      const list = this.#listeners[event];
      const idx = list.indexOf(listener);
      if (idx >= 0) list.splice(idx, 1);
    };
  }

  /**
   * Open the WebSocket. Idempotent: calling `connect()` while
   * already connecting / authenticating / ready / disconnected
   * is a no-op (a `disconnected` state already has a reconnect
   * scheduled).
   */
  async connect(): Promise<void> {
    if (
      this.#state === 'connecting' ||
      this.#state === 'authenticating' ||
      this.#state === 'ready'
    ) {
      return;
    }
    this.#explicitlyClosed = false;
    if (this.#state === 'disconnected' && this.#reconnectTimer !== null) {
      // A reconnect is already in flight; let the timer fire.
      return;
    }
    await this.#openSocket();
  }

  /**
   * Close the connection and suppress any further reconnect
   * attempts. Idempotent.
   */
  close(code = 1000, reason = ''): void {
    this.#explicitlyClosed = true;
    if (this.#reconnectTimer !== null) {
      this.#clearTimeoutFn(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    if (this.#socket !== null) {
      try {
        this.#socket.close(code, reason);
      } catch {
        // Ignore — the close path will run via the socket's own
        // event loop or, if that fails, the client transitions
        // to `'closed'` below regardless.
      }
    }
    this.#setState('closed');
  }

  /**
   * Send a `ClientToServer` frame. Throws if the socket is not in
   * `'ready'` state — callers (specifically the outbox coordinator)
   * must guard on `isReady` and queue otherwise.
   */
  send(msg: ClientToServer): void {
    if (this.#state !== 'ready' || this.#socket === null) {
      throw new Error(`WsClient.send: not ready (state=${this.#state})`);
    }
    const frame = encodeC2S(msg);
    this.#socket.send(frame);
  }

  /**
   * Compute the delay for the (1-based) attempt number. Public so
   * tests can assert the schedule directly.
   *
   * `attempt = 0` returns `0` (the first attempt fires immediately).
   * `attempt = 1` returns `RECONNECT_BACKOFF_MS[0]` (1s).
   * `attempt > schedule.length` returns `RECONNECT_BACKOFF_CAP_MS`.
   */
  computeBackoffMs(attempt: number): number {
    if (attempt <= 0) return 0;
    const idx = attempt - 1;
    if (idx < this.#backoff.length) {
      return this.#backoff[idx]!;
    }
    return this.#backoffCap;
  }

  // ---------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------

  async #openSocket(): Promise<void> {
    this.#setState('connecting');

    let token: string;
    try {
      token = await this.#tokenProvider();
    } catch (err) {
      // Token provider failed — treat as a connect failure so the
      // backoff schedule advances.
      this.#emit('frame_error', { kind: 'decode', cause: err });
      this.#scheduleReconnect();
      return;
    }

    const url = this.#buildUrl(token);
    let socket: WebSocketLike;
    try {
      socket = new this.#WebSocket(url);
    } catch (err) {
      this.#emit('frame_error', { kind: 'decode', cause: err });
      this.#scheduleReconnect();
      return;
    }
    socket.binaryType = 'arraybuffer';
    this.#socket = socket;

    socket.onopen = (): void => {
      this.#setState('authenticating');
      const hello: ClientToServer = {
        t: C2S.HELLO,
        deviceId: this.#deviceId,
        protoVersion: PROTOCOL_VERSION,
      };
      try {
        socket.send(encodeC2S(hello));
      } catch (err) {
        // Send failure on a freshly open socket → tear down and
        // let the close handler schedule reconnect.
        this.#emit('frame_error', { kind: 'decode', cause: err });
        try {
          socket.close();
        } catch {
          // Already closed; the onclose path runs independently.
        }
      }
    };

    socket.onmessage = (ev: { data: unknown }): void => {
      this.#onMessage(ev.data);
    };

    socket.onerror = (): void => {
      // The browser exposes errors only as a generic `ErrorEvent`
      // with no useful payload. The subsequent `onclose` carries
      // the structured close info, so we don't surface this
      // separately — just record it as a frame_error for
      // diagnostics.
      this.#emit('frame_error', { kind: 'decode', cause: 'ws error' });
    };

    socket.onclose = (ev: {
      code: number;
      reason: string;
      wasClean: boolean;
    }): void => {
      this.#socket = null;
      // If we were 'ready' at close time the next attempt should
      // start at the first backoff entry, NOT continue counting
      // from past failed attempts. The `hello_ok` handler reset
      // attemptCount to 0; this matches that contract.
      const wasReady = this.#state === 'ready';
      this.#setState('disconnected');
      const nextDelay = this.#explicitlyClosed
        ? null
        : this.computeBackoffMs(this.#attemptCount + (wasReady ? 1 : 1));
      this.#emit('disconnect', {
        code: ev.code,
        reason: ev.reason,
        wasClean: ev.wasClean,
        nextAttemptInMs: nextDelay,
      });
      if (this.#explicitlyClosed) {
        this.#setState('closed');
        return;
      }
      this.#scheduleReconnect();
    };
  }

  #onMessage(data: unknown): void {
    let bytes: Uint8Array;
    if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (data instanceof Uint8Array) {
      bytes = data;
    } else if (
      typeof Blob !== 'undefined' &&
      data instanceof Blob
    ) {
      // We requested `arraybuffer` binaryType, so this shouldn't
      // happen — but guard defensively.
      this.#emit('frame_error', { kind: 'decode', cause: 'unexpected blob frame' });
      return;
    } else {
      this.#emit('frame_error', {
        kind: 'decode',
        cause: `unexpected frame type: ${typeof data}`,
      });
      return;
    }

    let msg: ServerToClient;
    try {
      msg = decodeS2C(bytes);
    } catch (err) {
      this.#emit('frame_error', { kind: 'decode', cause: err });
      return;
    }

    switch (msg.t) {
      case S2C.HELLO_OK: {
        // Reset the backoff counter on every successful handshake.
        this.#attemptCount = 0;
        this.#setState('ready');
        this.#emit('hello_ok', {
          serverTimeMs: msg.serverTimeMs,
          queuedCount: msg.queuedCount,
        });
        return;
      }
      case S2C.ENVELOPE: {
        if (this.#state !== 'ready') {
          // Per Requirement 12.11 the gateway never sends
          // envelopes pre-HELLO_OK, but tolerate the case
          // defensively.
          this.#emit('frame_error', {
            kind: 'unexpected_state',
            received: msg.t,
          });
          return;
        }
        this.#emit('envelope', { envelope: msg.envelope });
        return;
      }
      case S2C.ENVELOPE_QUEUED: {
        this.#emit('queued', {
          clientNonce: msg.clientNonce,
          envelopeId: msg.envelopeId,
          serverTimeMs: msg.serverTimeMs,
        });
        return;
      }
      case S2C.ROOM_POST: {
        // Broadcast room posts (Requirement 10.4). The broadcast
        // feature attaches a `room_post` listener and runs
        // `verifyBroadcastPost` against each payload before
        // rendering — see `apps/web/src/features/broadcast/`.
        this.#emit('room_post', { post: msg.post });
        return;
      }
      case S2C.ERROR: {
        this.#emit('server_error', { code: msg.code, message: msg.message });
        return;
      }
    }
  }

  #scheduleReconnect(): void {
    if (this.#explicitlyClosed) {
      return;
    }
    if (this.#reconnectTimer !== null) {
      return;
    }
    this.#attemptCount += 1;
    const delay = this.computeBackoffMs(this.#attemptCount);
    const handle = this.#setTimeoutFn(() => {
      this.#reconnectTimer = null;
      void this.#openSocket();
    }, delay);
    this.#reconnectTimer = handle;
  }

  #buildUrl(token: string): string {
    // Append `?token=...` (or `&token=...` if the base URL already
    // carries a query string). Path is always `/ws` per
    // `apps/api/src/server.ts`.
    const base = this.#url.replace(/\/+$/, '');
    const sep = base.includes('?') ? '&' : '?';
    return `${base}/ws${sep}token=${encodeURIComponent(token)}`;
  }

  #setState(next: WsState): void {
    if (this.#state === next) return;
    this.#state = next;
    this.#emit('state', { state: next });
  }

  #emit<E extends WsEventName>(event: E, payload: WsEventMap[E]): void {
    // Snapshot the listener list so an in-flight unsubscribe inside
    // a listener doesn't break iteration.
    const listeners = this.#listeners[event].slice();
    for (const fn of listeners) {
      try {
        fn(payload);
      } catch {
        // Listener errors don't bubble through the event bus —
        // they'd otherwise interleave with other listeners and
        // hide the real failure.
      }
    }
  }
}

// apps/web/src/ws/outbox.ts
//
// Outbox coordinator: bridges the Dexie-backed outbox queue
// (`apps/web/src/db/repositories/outbox.ts`) and the WebSocket
// client (`apps/web/src/ws/client.ts`) for task 3.7.
//
// Responsibilities (requirement 4.7 / 4.8 / 4.9):
//   - On every successful `hello_ok` (initial connect AND any
//     reconnect), replay every pending outbox row in original
//     enqueue order (FIFO via the row's primary-key id).
//   - On each `ENVELOPE_QUEUED` frame, delete the matching
//     pending row by `clientNonce`.
//   - Provide `enqueue(envelope)` that persists into the outbox
//     and, when the WS is in `'ready'` state, immediately sends
//     the frame. When the WS is not ready, the row sits in the
//     outbox for the next replay.
//
// What this module does NOT own:
//   - Encryption (the caller passes a finished `CiphertextEnvelope`),
//   - DM thread-state mutation on `ENVELOPE_QUEUED` (the DM feature
//     wires a parallel listener that flips the `messages` row state),
//   - Retry budget: rows live in the outbox until acknowledged or
//     evicted by the 7-day age sweep. A future task can layer a
//     bounded-retry policy on top of `recordReplayAttempt`.
//
// Concurrency:
//   `replay()` is guarded by a single in-flight flag so a
//   second `hello_ok` arriving mid-replay does not interleave two
//   parallel replay loops over the same rows. The flag is cleared
//   on completion (success or thrown). If a `hello_ok` arrives
//   while replay is in flight, a second pass runs to completion
//   afterward — guarantees that any rows enqueued during the
//   in-flight window are flushed.

import { C2S, type CiphertextEnvelope } from '@konvo/protocol';

import {
  type DexieOutboxStore,
  type OutboxEntry,
} from '../db/repositories/outbox.js';
import type { WsClient } from './client.js';

/**
 * Construction options. All callbacks default to the minimum
 * useful behaviour; tests override them to assert the wiring.
 */
export interface OutboxCoordinatorOptions {
  readonly client: WsClient;
  readonly store: DexieOutboxStore;
  /** Optional callback fired after the coordinator deletes a
   *  pending row in response to `ENVELOPE_QUEUED`. The DM thread
   *  state flipper hooks in here. */
  readonly onAck?: (info: {
    readonly clientNonce: string;
    readonly envelopeId: bigint;
    readonly serverTimeMs: number;
  }) => void;
  /** Optional error sink for unexpected failures during enqueue or
   *  replay. Defaults to `console.warn`. */
  readonly onError?: (err: unknown) => void;
}

/**
 * Coordinates the persisted outbox with the live WS connection.
 *
 * Construct one of these per signed-in session, after both the
 * `WsClient` and the `DexieOutboxStore` are alive. Call `start()`
 * to wire the event subscriptions; call `stop()` to tear them
 * down on logout.
 */
export class OutboxCoordinator {
  readonly #client: WsClient;
  readonly #store: DexieOutboxStore;
  readonly #onAck?: (info: {
    readonly clientNonce: string;
    readonly envelopeId: bigint;
    readonly serverTimeMs: number;
  }) => void;
  readonly #onError: (err: unknown) => void;

  /** Unsubscribe handles for the `WsClient` listeners we register. */
  readonly #unsubscribes: (() => void)[] = [];
  #replayInFlight = false;
  #replayPending = false;
  #started = false;

  constructor(opts: OutboxCoordinatorOptions) {
    this.#client = opts.client;
    this.#store = opts.store;
    if (opts.onAck !== undefined) {
      this.#onAck = opts.onAck;
    }
    this.#onError =
      opts.onError ??
      ((err: unknown): void => {
        // eslint-disable-next-line no-console
        console.warn('outbox-coordinator:', err);
      });
  }

  /**
   * Wire the WS event subscriptions. Idempotent: `start()` is a
   * no-op after the first call. The bound listeners survive
   * multiple `disconnect`/`reconnect` cycles.
   */
  start(): void {
    if (this.#started) return;
    this.#started = true;

    this.#unsubscribes.push(
      this.#client.on('hello_ok', (): void => {
        void this.#kickReplay();
      }),
      this.#client.on('queued', (info): void => {
        void this.#handleQueued(info).catch((err) => this.#onError(err));
      }),
    );

    // If the client is already in `'ready'` state at start time
    // (consumer constructed us after a successful handshake), kick
    // an immediate replay too.
    if (this.#client.isReady) {
      void this.#kickReplay();
    }
  }

  /** Unsubscribe from the WS client. The Dexie store is left intact. */
  stop(): void {
    for (const off of this.#unsubscribes) {
      off();
    }
    this.#unsubscribes.length = 0;
    this.#started = false;
  }

  /**
   * Persist an envelope to the outbox AND, if the WS is ready,
   * immediately send it. The persistence comes first so a
   * crash-or-disconnect mid-send leaves a row that will be
   * replayed on the next `hello_ok`.
   *
   * Returns the persisted `OutboxEntry`. Idempotent in the same
   * sense as `DexieOutboxStore.enqueue`: the same `clientNonce`
   * resolves to the same row.
   */
  async enqueue(args: {
    clientNonce: string;
    envelope: CiphertextEnvelope;
    enqueuedAt?: number;
  }): Promise<OutboxEntry> {
    const persistArgs: {
      clientNonce: string;
      envelope: CiphertextEnvelope;
      enqueuedAt?: number;
    } = {
      clientNonce: args.clientNonce,
      envelope: args.envelope,
      ...(args.enqueuedAt !== undefined ? { enqueuedAt: args.enqueuedAt } : {}),
    };
    const entry = await this.#store.enqueue(persistArgs);
    if (this.#client.isReady) {
      try {
        this.#sendFrame(entry);
      } catch (err) {
        // The row stays in the outbox for the next replay. We
        // surface the failure to the error sink for diagnostics.
        this.#onError(err);
      }
    }
    return entry;
  }

  /**
   * Replay every pending row in FIFO order. Public so callers can
   * trigger a manual flush (e.g. after the user presses a "retry"
   * button); the normal driver is the `hello_ok` event.
   *
   * Concurrency-safe: a re-entrant call queues a second pass that
   * fires after the in-flight one resolves. This guarantees rows
   * enqueued mid-replay are still flushed promptly.
   */
  async replay(): Promise<void> {
    return this.#kickReplay();
  }

  // ---------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------

  async #kickReplay(): Promise<void> {
    if (this.#replayInFlight) {
      this.#replayPending = true;
      return;
    }
    this.#replayInFlight = true;
    try {
      do {
        this.#replayPending = false;
        await this.#runReplay();
      } while (this.#replayPending);
    } finally {
      this.#replayInFlight = false;
    }
  }

  async #runReplay(): Promise<void> {
    if (!this.#client.isReady) {
      // The WS dropped mid-replay; bail. The next `hello_ok` will
      // re-enter this loop. The unsent rows remain in the outbox.
      return;
    }
    const pending = await this.#store.listInOrder();
    for (const entry of pending) {
      if (!this.#client.isReady) {
        // Mid-loop disconnect: stop sending; the next `hello_ok`
        // will pick up where we left off (rows not deleted yet).
        return;
      }
      try {
        this.#sendFrame(entry);
        await this.#store.recordReplayAttempt(entry.clientNonce);
      } catch (err) {
        // A send failure is unusual on a `'ready'` socket. We
        // surface it and bail; the next `hello_ok` retries.
        this.#onError(err);
        return;
      }
    }
  }

  async #handleQueued(info: {
    readonly clientNonce: string;
    readonly envelopeId: bigint;
    readonly serverTimeMs: number;
  }): Promise<void> {
    await this.#store.deleteByClientNonce(info.clientNonce);
    if (this.#onAck !== undefined) {
      try {
        this.#onAck(info);
      } catch (err) {
        this.#onError(err);
      }
    }
  }

  #sendFrame(entry: OutboxEntry): void {
    this.#client.send({
      t: C2S.SEND_ENVELOPE,
      clientNonce: entry.clientNonce,
      envelope: entry.envelope,
    });
  }
}

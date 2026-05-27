// apps/web/src/features/dm/controller.ts
//
// DM state controller (task 3.8 + task 4.7).
//
// Task 4.7 — wire libsignal ciphertext through the DM path:
//   - Send-side: every plaintext goes through
//     `@konvo/crypto`'s `encryptToDevice` against the
//     persisted ratchet session loaded from the
//     `SignalProtocolStore` (Dexie-backed). The resulting
//     ratchet state is committed back to storage before the
//     outbox row is created, so a crash mid-send leaves a
//     consistent ratchet state on disk.
//   - Multi-device fan-out: `RecipientDeviceIdsResolver`
//     returns the full device array for a peer; the controller
//     emits exactly one `CiphertextEnvelope` per device, each
//     under its own per-device `clientNonce`. All envelopes
//     share the single local `MessageRow`'s base nonce as a
//     prefix so the `ENVELOPE_QUEUED` ack flow can flip the
//     row to `'delivered'` on the first ack received.
//   - Receive-side (`handleInbound`): the wire ciphertext is
//     split into the ratchet header + AES-GCM body, the
//     sender's session is loaded, `decryptFromDevice` is
//     invoked, and the result is fanned to one of three
//     outcomes:
//       * `ok: true` → insert a `'delivered'` message row
//         with the recovered plaintext.
//       * `error.kind === 'invalid_message'` → insert a
//         `'tampered'` placeholder row carrying the inert
//         "message couldn't be decrypted (tampered or
//         corrupted)" UTF-8 bytes (req 4.11). The ratchet
//         function preserves the input state on this path,
//         so the persisted session is unchanged.
//       * `error.kind === 'duplicate'` → no-op. No row is
//         inserted and no UI duplicate is shown (req 4.12).
//         The ratchet preserves state on this path too.
//       * `error.kind === 'message_lost'` → the ratchet
//         advanced state past the over-cap position
//         (req 9.5). We persist the advanced state and skip
//         the row insert; surfacing "messages were lost" to
//         the UI is out of scope for task 4.7 and lives on
//         the post-Phase-3 backlog.
//
// What this module does NOT own:
//   - X3DH session establishment. The session for each peer
//     device must already exist in the `SignalProtocolStore`
//     before `sendMessage` / `handleInbound` runs. In
//     production this is wired through the prekey-bundle
//     fetch + `establishSession` / `acceptSession` flow
//     (tasks 4.2 + 4.5); the test harness for task 4.7
//     pre-seeds sessions directly via
//     `initSenderRatchet` / `initReceiverRatchet`.
//   - WebSocket transport (`apps/web/src/ws/client.ts`).
//   - Outbox replay scheduling
//     (`apps/web/src/ws/outbox.ts` — `OutboxCoordinator`).
//
// Concurrency / ordering:
//   - The send-side encrypt + saveSession sequence runs once
//     per recipient device, sequentially. The Phase-3 ratchet
//     advances the sending chain by exactly one message per
//     `encryptToDevice` call, so two concurrent sends to the
//     same peer device would race on the chain counter — we
//     serialise per-device by simply iterating the recipients
//     array.
//   - The `'queued'` listener is registered exactly once via
//     `start()` and unregistered via `stop()`. Multiple
//     `'queued'` events on the same logical message (one per
//     recipient device) all flip the row to `'delivered'` —
//     the second and subsequent flips are no-ops because the
//     state-machine guard rejects already-`'delivered'` rows.

import {
  decryptFromDevice,
  deserializeRatchetState,
  encryptToDevice,
  serializeRatchetState,
  type SignalProtocolStore,
} from '@konvo/crypto';
import {
  EnvelopeRouterType,
  type CiphertextEnvelope,
} from '@konvo/protocol';

import type {
  DexieMessagesStore,
  Message,
} from '../../db/repositories/messages.js';
import type {
  DexieThreadsStore,
  Thread,
} from '../../db/repositories/threads.js';
import type { WsClient } from '../../ws/client.js';
import type { OutboxCoordinator } from '../../ws/outbox.js';

import {
  decodeWireCiphertext,
  encodeWireCiphertext,
  TAMPERED_PLACEHOLDER_TEXT,
} from './wire.js';

/** A change notification fired by the controller after a
 *  user-visible state mutation lands. Components subscribe to
 *  this to know when to re-read threads / messages from the
 *  Dexie repositories. The payload identifies the affected
 *  thread (if any) so a future optimisation can scope updates;
 *  for now subscribers always re-read. */
export interface DmChange {
  readonly kind:
    | 'message_inserted'
    | 'message_state_changed'
    | 'thread_updated';
  readonly threadId?: string;
  readonly messageId?: number;
}

export type DmChangeListener = (change: DmChange) => void;

/** Resolver hook for the recipient device IDs of a peer user.
 *  Phase-3 multi-device fan-out (req 4.5): the controller emits
 *  one envelope per id returned here. The resolver MUST return a
 *  non-empty array — `sendMessage` rejects an empty array as a
 *  programmer error (the directory should never report a peer
 *  with zero enrolled devices, since at least one device must
 *  have published a prekey bundle for the user to be reachable).
 *
 *  In production this is wired through the `/users/:handle`
 *  directory response. Tests inject a static array. */
export type RecipientDeviceIdsResolver = (
  peerUserId: string,
) => Promise<readonly string[]>;

/** Resolver hook for the per-peer session id. The Phase-2
 *  envelope `sessionId` is a stable opaque string the server
 *  uses for routing only; for Phase 3 it becomes the libsignal
 *  X3DH session id. Defaults to `peerUserId` so single-device
 *  Phase-2 traffic works without any caller wiring. */
export type SessionIdResolver = (peerUserId: string) => Promise<string>;

/** Resolver hook for inbound envelope routing. The WS gateway
 *  hands us a `CiphertextEnvelope` whose `senderDeviceId` is
 *  the peer device that sent us the message; the
 *  `SignalProtocolStore` is keyed on
 *  `(peerUserId, peerDeviceId)`, so we need a way to map the
 *  device id back to the owning user. Phase 3 wires this
 *  through a directory cache; tests inject a static map. */
export type SenderUserIdResolver = (
  envelope: CiphertextEnvelope,
) => Promise<string | null>;

export interface DmControllerOptions {
  readonly threads: DexieThreadsStore;
  readonly messages: DexieMessagesStore;
  readonly outbox: OutboxCoordinator;
  /** WS client whose `'queued'` event drives the
   *  `'sending' → 'delivered'` transition and whose `'envelope'`
   *  event is routed through `handleInbound`. The controller
   *  does not own the client's lifecycle. */
  readonly client: WsClient;
  /** Persisted Double-Ratchet store (task 4.4) used by both
   *  the send and receive paths. */
  readonly sessionStore: SignalProtocolStore;
  /** Stable device id of *this* browser. Stamped on every
   *  outbound envelope's `senderDeviceId`. */
  readonly senderDeviceId: string;
  readonly resolveRecipientDeviceIds: RecipientDeviceIdsResolver;
  /** Optional override; defaults to identity (`peerUserId`). */
  readonly resolveSessionId?: SessionIdResolver;
  /** Resolves the inbound envelope's sender user id. */
  readonly resolveSenderUserId: SenderUserIdResolver;
  /** Optional override for `clientNonce` generation. Defaults
   *  to `crypto.randomUUID()`. */
  readonly nonceFactory?: () => string;
  /** Optional override for the wall clock. Defaults to
   *  `Date.now`. */
  readonly now?: () => number;
}

/**
 * Tiny ad-hoc event bus + DM controller. The class is small
 * enough that wiring `zustand` would obscure rather than
 * clarify the data flow; `useSyncExternalStore` in the React
 * components plus `subscribe()` here is the React-recommended
 * shape for an external store of this scope.
 */
export class DmController {
  readonly #threads: DexieThreadsStore;
  readonly #messages: DexieMessagesStore;
  readonly #outbox: OutboxCoordinator;
  readonly #client: WsClient;
  readonly #sessionStore: SignalProtocolStore;
  readonly #senderDeviceId: string;
  readonly #resolveRecipientDeviceIds: RecipientDeviceIdsResolver;
  readonly #resolveSessionId: SessionIdResolver;
  readonly #resolveSenderUserId: SenderUserIdResolver;
  readonly #nonceFactory: () => string;
  readonly #now: () => number;

  readonly #listeners: DmChangeListener[] = [];
  #unsubscribeQueued: (() => void) | null = null;
  #unsubscribeEnvelope: (() => void) | null = null;
  #started = false;

  constructor(opts: DmControllerOptions) {
    this.#threads = opts.threads;
    this.#messages = opts.messages;
    this.#outbox = opts.outbox;
    this.#client = opts.client;
    this.#sessionStore = opts.sessionStore;
    this.#senderDeviceId = opts.senderDeviceId;
    this.#resolveRecipientDeviceIds = opts.resolveRecipientDeviceIds;
    this.#resolveSessionId =
      opts.resolveSessionId ??
      ((peerUserId: string): Promise<string> => Promise.resolve(peerUserId));
    this.#resolveSenderUserId = opts.resolveSenderUserId;
    this.#nonceFactory = opts.nonceFactory ?? defaultNonce;
    this.#now = opts.now ?? ((): number => Date.now());
  }

  /** Wire the WS event subscriptions. Idempotent. */
  start(): void {
    if (this.#started) return;
    this.#started = true;
    this.#unsubscribeQueued = this.#client.on('queued', (info): void => {
      void this.#handleQueued(info.clientNonce).catch(() => {
        // Errors during the state flip are not user-visible —
        // the row stays in `'sending'` and a future ack /
        // reconnect will retry the flip. Surfacing a loud
        // failure here would interrupt the WS dispatch loop.
      });
    });
    this.#unsubscribeEnvelope = this.#client.on('envelope', (info): void => {
      void this.handleInbound(info.envelope).catch(() => {
        // Inbound errors are likewise non-fatal at the
        // dispatch loop level. The envelope will not be
        // retried by the gateway (transport ack happens
        // independently), so a controller-internal failure
        // simply means the message is lost on this client —
        // matching the requirement-4.11 contract for
        // unrecoverable inbound bytes.
      });
    });
  }

  /** Drop the WS subscription. Idempotent. */
  stop(): void {
    if (this.#unsubscribeQueued !== null) {
      this.#unsubscribeQueued();
      this.#unsubscribeQueued = null;
    }
    if (this.#unsubscribeEnvelope !== null) {
      this.#unsubscribeEnvelope();
      this.#unsubscribeEnvelope = null;
    }
    this.#started = false;
  }

  // ---------------------------------------------------------------------
  // Subscription
  // ---------------------------------------------------------------------

  /** Register a change listener. Returns an unsubscribe
   *  callback. Listener errors do not propagate — they're
   *  swallowed so a misbehaving subscriber can't break the
   *  fan-out to the others. */
  subscribe(listener: DmChangeListener): () => void {
    this.#listeners.push(listener);
    return (): void => {
      const idx = this.#listeners.indexOf(listener);
      if (idx >= 0) this.#listeners.splice(idx, 1);
    };
  }

  // ---------------------------------------------------------------------
  // Read accessors (thin pass-throughs to repositories)
  // ---------------------------------------------------------------------

  async listThreads(): Promise<readonly Thread[]> {
    return this.#threads.list();
  }

  async listMessagesForThread(
    threadId: string,
    limit?: number,
  ): Promise<readonly Message[]> {
    return this.#messages.listForThread(threadId, limit);
  }

  // ---------------------------------------------------------------------
  // Send path
  // ---------------------------------------------------------------------

  /**
   * Compose-and-send. The full data path is:
   *   1. Resolve the recipient device id list and per-peer
   *      session id.
   *   2. Insert ONE `'sending'` `MessageRow` (auto-id assigned)
   *      with a fresh base `clientNonce`.
   *   3. For each recipient device:
   *      a. Load the persisted ratchet session.
   *      b. Run `encryptToDevice(state, plaintext)`; the
   *         returned `state` is the post-advance ratchet state.
   *      c. Save the advanced state back via `saveSession`.
   *      d. Encode the wire ciphertext (header || AES-GCM
   *         body) and persist + send it via the
   *         `OutboxCoordinator` under the per-device nonce
   *         `${baseNonce}:${deviceId}`.
   *   4. Bump the thread's `lastMessageAt` (and lazily create
   *      the row on first send to a peer).
   *
   * Returns the persisted message so the composer can clear
   * its draft on the canonical id.
   *
   * Throws if:
   *   - the resolver returns an empty device array (the peer
   *     is unreachable — a programmer error at this slice),
   *   - any recipient device has no persisted ratchet session
   *     (X3DH must have run beforehand for this slice).
   */
  async sendMessage(args: {
    readonly peerUserId: string;
    readonly peerHandle?: string;
    readonly body: Uint8Array;
  }): Promise<Message> {
    const recipientDeviceIds = await this.#resolveRecipientDeviceIds(
      args.peerUserId,
    );
    if (recipientDeviceIds.length === 0) {
      throw new Error(
        `sendMessage: peer ${args.peerUserId} has no recipient devices`,
      );
    }
    const sessionId = await this.#resolveSessionId(args.peerUserId);
    const baseClientNonce = this.#nonceFactory();
    const now = this.#now();

    // Insert the local message row before fanning out to the
    // wire. The row carries the plaintext bytes only on this
    // local device — the wire envelopes that follow carry
    // libsignal ciphertext per req 4.4. Storing the plaintext
    // locally is intentional: requirement 4.6 wants the
    // composer to render its own send immediately, and the
    // message row is the source of truth for that render.
    const message = await this.#messages.insertOutgoing({
      threadId: args.peerUserId,
      senderDeviceId: this.#senderDeviceId,
      recipientDeviceId: recipientDeviceIds[0]!, // primary device for display
      body: args.body,
      clientNonce: baseClientNonce,
      createdAt: now,
    });
    this.#emit({
      kind: 'message_inserted',
      threadId: args.peerUserId,
      messageId: message.id,
    });

    // Fan out: encrypt + enqueue once per recipient device.
    // We iterate sequentially so two parallel encrypts to the
    // same peer device cannot race on the ratchet's send
    // counter (the Phase-3 ratchet advances the sending chain
    // by exactly one step per call — concurrent encrypts on
    // the same state would derive the same chain key twice,
    // breaking the AES-GCM single-use-key invariant).
    for (const recipientDeviceId of recipientDeviceIds) {
      const wireCiphertext = await this.#encryptForDevice(
        args.peerUserId,
        recipientDeviceId,
        args.body,
      );
      const envelope: CiphertextEnvelope = {
        sessionId,
        senderDeviceId: this.#senderDeviceId,
        recipientDeviceId,
        type: EnvelopeRouterType.MESSAGE,
        ciphertext: wireCiphertext,
      };
      const perDeviceNonce = `${baseClientNonce}:${recipientDeviceId}`;
      await this.#outbox.enqueue({
        clientNonce: perDeviceNonce,
        envelope,
        enqueuedAt: now,
      });
    }

    const upsertArgs: Parameters<DexieThreadsStore['upsert']>[0] = {
      peerUserId: args.peerUserId,
      lastMessageAt: now,
      now,
      ...(args.peerHandle !== undefined ? { peerHandle: args.peerHandle } : {}),
    };
    await this.#threads.upsert(upsertArgs);
    this.#emit({ kind: 'thread_updated', threadId: args.peerUserId });

    return message;
  }

  /**
   * Re-attempt delivery of a `'failed'` row. The envelope is
   * re-encrypted from the persisted plaintext body and
   * re-fanned to every current recipient device. The row is
   * flipped back to `'sending'` so the ticker immediately
   * reflects the retry.
   *
   * NOTE: re-encrypting (rather than replaying the cached
   * ciphertext) means the ratchet advances one more step per
   * recipient device for each retry. This is the correct
   * behaviour: the previous send's chain keys may have been
   * scrubbed (req 9.1), so we cannot replay the prior
   * ciphertext bytes. The peer's ratchet handles the
   * re-encrypted message as a new in-order arrival.
   *
   * Returns the updated row, or `null` if no message with
   * that id exists.
   */
  async retry(messageId: number): Promise<Message | null> {
    const flipped = await this.#messages.updateState(messageId, 'sending');
    if (flipped === null) return null;

    const recipientDeviceIds = await this.#resolveRecipientDeviceIds(
      flipped.threadId,
    );
    if (recipientDeviceIds.length === 0) {
      // Can't deliver. Mark failed again and surface to caller.
      await this.#messages.updateState(messageId, 'failed');
      this.#emit({
        kind: 'message_state_changed',
        threadId: flipped.threadId,
        messageId: flipped.id,
      });
      return flipped;
    }
    const sessionId = await this.#resolveSessionId(flipped.threadId);

    for (const recipientDeviceId of recipientDeviceIds) {
      const wireCiphertext = await this.#encryptForDevice(
        flipped.threadId,
        recipientDeviceId,
        flipped.body,
      );
      const envelope: CiphertextEnvelope = {
        sessionId,
        senderDeviceId: flipped.senderDeviceId,
        recipientDeviceId,
        type: EnvelopeRouterType.MESSAGE,
        ciphertext: wireCiphertext,
      };
      const perDeviceNonce = `${flipped.clientNonce}:${recipientDeviceId}`;
      await this.#outbox.enqueue({
        clientNonce: perDeviceNonce,
        envelope,
        enqueuedAt: this.#now(),
      });
    }

    this.#emit({
      kind: 'message_state_changed',
      threadId: flipped.threadId,
      messageId: flipped.id,
    });
    return flipped;
  }

  /**
   * Mark a `'sending'` row as `'failed'`. This is the seam a
   * future timeout / retry-budget scheduler hooks into; for
   * the Phase-2 slice the only caller is the unit tests
   * exercising the retry path.
   *
   * Returns the updated row, or `null` if no message with
   * that id exists.
   */
  async markFailed(messageId: number): Promise<Message | null> {
    const updated = await this.#messages.updateState(messageId, 'failed');
    if (updated !== null) {
      this.#emit({
        kind: 'message_state_changed',
        threadId: updated.threadId,
        messageId: updated.id,
      });
    }
    return updated;
  }

  // ---------------------------------------------------------------------
  // Receive path
  // ---------------------------------------------------------------------

  /**
   * Route an inbound `CiphertextEnvelope` through the ratchet.
   *
   * Public so the WS-driven path inside `start()` can call it
   * AND so tests can drive it directly without spinning up a
   * stub WebSocket.
   *
   * The four branches mirror the documented `decryptFromDevice`
   * outcomes; see the file header for the per-branch contract.
   */
  async handleInbound(envelope: CiphertextEnvelope): Promise<void> {
    if (envelope.type !== EnvelopeRouterType.MESSAGE) {
      // ACK / CALL envelopes are routed elsewhere; only DM
      // payloads land in the messages store. Phase-3 wires
      // ACKs through a parallel listener; for now we ignore.
      return;
    }
    const peerUserId = await this.#resolveSenderUserId(envelope);
    if (peerUserId === null) {
      // Unknown sender device — we cannot key into the session
      // store. Drop the envelope rather than render a
      // tampered placeholder under an unknown peer.
      return;
    }
    const senderDeviceId = envelope.senderDeviceId;

    let header;
    let body;
    try {
      const decoded = decodeWireCiphertext(envelope.ciphertext);
      header = decoded.header;
      body = decoded.body;
    } catch {
      // Frame too short to even fit the ratchet header. Treat
      // the same as an AES-GCM tag failure — render the inert
      // placeholder, persist no plaintext, leave any existing
      // ratchet state alone.
      await this.#insertTamperedRow(peerUserId, senderDeviceId, envelope);
      return;
    }

    const persisted = await this.#sessionStore.loadSession(
      peerUserId,
      senderDeviceId,
    );
    if (persisted === null) {
      // No session yet — X3DH didn't run. For task 4.7's
      // slice we surface this as a tamper-equivalent
      // placeholder rather than crash the WS dispatch loop.
      // The post-Phase-3 backlog wires X3DH-on-first-inbound
      // here.
      await this.#insertTamperedRow(peerUserId, senderDeviceId, envelope);
      return;
    }

    const inputState = deserializeRatchetState(persisted);
    const { state: nextState, result } = await decryptFromDevice(
      inputState,
      body,
      header,
    );

    // Persist the post-call state regardless of outcome.
    // For 'invalid_message' and 'duplicate' the ratchet
    // returns the input state ref unchanged, so this is a
    // semantic no-op (last-write-wins overwrites with the
    // same bytes). For 'message_lost' and 'ok' the state has
    // advanced and MUST be persisted before we surface the
    // user-visible row, otherwise a crash between insert and
    // save would replay the same envelope and append a
    // duplicate row on next boot.
    await this.#sessionStore.saveSession(
      peerUserId,
      senderDeviceId,
      serializeRatchetState(nextState),
    );

    if (result.ok) {
      const inserted = await this.#messages.insertIncoming({
        threadId: peerUserId,
        senderDeviceId,
        recipientDeviceId: this.#senderDeviceId,
        body: result.plaintext,
        clientNonce: this.#inboundNonce(envelope),
        createdAt: this.#now(),
      });
      await this.#threads.recordIncoming(peerUserId, inserted.createdAt);
      this.#emit({
        kind: 'message_inserted',
        threadId: peerUserId,
        messageId: inserted.id,
      });
      this.#emit({ kind: 'thread_updated', threadId: peerUserId });
      return;
    }

    if (result.error.kind === 'invalid_message') {
      await this.#insertTamperedRow(peerUserId, senderDeviceId, envelope);
      return;
    }
    if (result.error.kind === 'duplicate') {
      // No-op: req 4.12 / task 4.7 brief — "no UI duplicate
      // is shown".
      return;
    }
    // 'message_lost': req 9.5. State already advanced + saved
    // above; no row inserted in this slice. A future task can
    // surface a non-blocking notice here.
  }

  // ---------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------

  /**
   * Encrypt `plaintext` to the supplied recipient device using
   * its persisted ratchet session. Advances + persists the
   * ratchet state, returns the wire-encoded ciphertext (header
   * || AES-GCM body). Throws if no session exists for the
   * device.
   */
  async #encryptForDevice(
    peerUserId: string,
    peerDeviceId: string,
    plaintext: Uint8Array,
  ): Promise<Uint8Array> {
    const persisted = await this.#sessionStore.loadSession(
      peerUserId,
      peerDeviceId,
    );
    if (persisted === null) {
      throw new Error(
        `sendMessage: no ratchet session for peer ${peerUserId} device ${peerDeviceId}`,
      );
    }
    const inputState = deserializeRatchetState(persisted);
    const { state: nextState, ciphertext: body, header } = await encryptToDevice(
      inputState,
      plaintext,
    );
    await this.#sessionStore.saveSession(
      peerUserId,
      peerDeviceId,
      serializeRatchetState(nextState),
    );
    return encodeWireCiphertext(header, body);
  }

  /**
   * Persist the inert placeholder row for an inbound envelope
   * the ratchet rejected (`invalid_message`) or that we could
   * not even attempt (no session, malformed frame).
   *
   * The row's `body` carries the inert UTF-8 placeholder text
   * directly — `ThreadView`'s body decoder renders it as if
   * it were a regular plaintext message. The row's `state` is
   * `'tampered'` so the `StateTicker` renders the warning
   * glyph and screen readers announce the matching label.
   *
   * Per requirement 4.11 the row carries no bytes derived
   * from the attacker-controlled ciphertext; the persisted
   * payload is a fixed string constant.
   */
  async #insertTamperedRow(
    peerUserId: string,
    senderDeviceId: string,
    envelope: CiphertextEnvelope,
  ): Promise<void> {
    const placeholder = new TextEncoder().encode(TAMPERED_PLACEHOLDER_TEXT);
    const inserted = await this.#messages.insertIncoming({
      threadId: peerUserId,
      senderDeviceId,
      recipientDeviceId: this.#senderDeviceId,
      body: placeholder,
      clientNonce: this.#inboundNonce(envelope),
      createdAt: this.#now(),
    });
    // Inbound rows land in 'delivered' by the repository;
    // flip to 'tampered' so the UI renders the warning ticker.
    await this.#messages.updateState(inserted.id, 'tampered');
    await this.#threads.recordIncoming(peerUserId, inserted.createdAt);
    this.#emit({
      kind: 'message_inserted',
      threadId: peerUserId,
      messageId: inserted.id,
    });
    this.#emit({ kind: 'thread_updated', threadId: peerUserId });
  }

  /**
   * Synthesise a unique `clientNonce` for an inbound message
   * row. Inbound envelopes don't carry the C2S `clientNonce`
   * field — the natural identifier is the server's
   * monotonic `envelope.id`, with a fresh-uuid fallback when
   * the gateway omits it (e.g. tests that fabricate envelopes
   * directly).
   *
   * The `inbound-` prefix keeps the namespace disjoint from
   * outbound nonces (which are uuids or
   * `${uuid}:${deviceId}` per-device shards) so a future
   * lookup that scans across both shapes can demux without
   * ambiguity.
   */
  #inboundNonce(envelope: CiphertextEnvelope): string {
    if (envelope.id !== undefined) {
      return `inbound-${envelope.id.toString()}`;
    }
    return `inbound-${this.#nonceFactory()}`;
  }

  async #handleQueued(clientNonce: string): Promise<void> {
    // The wire-level `clientNonce` is the per-device shard
    // (`${baseNonce}:${recipientDeviceId}`). The local
    // `MessageRow` is keyed by the bare base nonce. Strip
    // the device suffix to find the matching row.
    const baseNonce = stripDeviceShardSuffix(clientNonce);
    const existing = await this.#messages.findByClientNonce(baseNonce);
    if (existing === null) return;
    if (existing.state !== 'sending') return;
    const updated = await this.#messages.setStateByClientNonce(
      baseNonce,
      'delivered',
    );
    if (updated !== null) {
      this.#emit({
        kind: 'message_state_changed',
        threadId: updated.threadId,
        messageId: updated.id,
      });
    }
  }

  #emit(change: DmChange): void {
    // Snapshot to avoid an in-flight unsubscribe inside a
    // listener mutating the iteration.
    const snapshot = this.#listeners.slice();
    for (const fn of snapshot) {
      try {
        fn(change);
      } catch {
        // Listener errors are swallowed — see class header.
      }
    }
  }
}

/**
 * The wire `clientNonce` for an outbound envelope is
 * `${baseNonce}:${recipientDeviceId}` — see `sendMessage` and
 * `retry`. The local `MessageRow` is keyed by the bare base
 * nonce, so a `'queued'` ack must be demuxed: split on the
 * first `:` and take the prefix as the row key.
 *
 * UUIDs (the default base nonce shape) and device ids do not
 * contain `:`, so the split is unambiguous. If a future
 * change introduces a non-UUID base nonce shape that contains
 * `:`, the encoding here must be revisited (and the codec
 * function in `sendMessage` along with it).
 */
function stripDeviceShardSuffix(clientNonce: string): string {
  const idx = clientNonce.indexOf(':');
  if (idx < 0) return clientNonce;
  return clientNonce.slice(0, idx);
}

function defaultNonce(): string {
  // `crypto.randomUUID` is available in Node 20 (via
  // `globalThis.crypto`) and every modern browser. The test
  // setup binds Node's WebCrypto onto `globalThis.crypto`.
  if (
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.randomUUID === 'function'
  ) {
    return globalThis.crypto.randomUUID();
  }
  // Last-resort fallback. Not cryptographically rigorous;
  // only reached on a runtime that lacks WebCrypto, which we
  // don't support but tolerate rather than crash.
  return `nonce-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 12)}`;
}

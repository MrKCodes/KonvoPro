// apps/web/src/features/dm/plaintext-controller.ts
//
// Phase-2 plaintext DM controller (transitional).
//
// This is the minimum send/receive path the SPA needs to actually
// exchange messages between two signed-in users today. It uses the
// existing WebSocket gateway, persisted outbox, and Dexie thread /
// message repositories — but does NOT run libsignal. Messages
// travel through the wire envelope as UTF-8 plaintext bytes inside
// `CiphertextEnvelope.ciphertext`.
//
// This is the design's documented Phase-2 intermediate state ("DMs
// over WSS, plaintext"). The fully E2EE `DmController` in
// `controller.ts` is the Phase-3+ replacement once X3DH bootstrap
// + per-peer-device session bring-up is wired into the SPA. This
// controller and that one share the same `Thread` / `Message`
// repositories and the same `WsClient` / `OutboxCoordinator`, so a
// future swap is local: replace the `enqueue` / `handleInbound`
// bodies; everything else (composer UI, ticker, thread list)
// stays.
//
// SECURITY POSTURE:
//   - Server stores `CiphertextEnvelope.ciphertext` as opaque
//     bytes per design.md §10. With this controller in place the
//     server is therefore observing plaintext bodies in the bytea
//     column. This is acceptable for self-hosted single-tenant
//     deploys but MUST NOT be left in place for any production
//     multi-tenant deploy.
//   - The wire transport itself is still WSS (TLS 1.3) so a
//     network observer cannot read the bodies. The threat being
//     accepted here is "operator can read DMs" — the same threat
//     model as a stock Slack / Discord deployment.

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

/** Change-stream payload mirrors the Phase-3 controller's shape so
 *  React hooks (`useDmStore`) can be reused unchanged. */
export interface DmChange {
  readonly kind:
    | 'message_inserted'
    | 'message_state_changed'
    | 'thread_updated';
  readonly threadId?: string;
  readonly messageId?: number;
}

export type DmChangeListener = (change: DmChange) => void;

/** Recipient-device resolver. The DM composer hands a `peerUserId`
 *  to `sendMessage`; we look up the peer's enrolled devices from
 *  the server directory (`/users/:handle`) once and remember them
 *  for the session. */
export type RecipientDeviceIdsResolver = (
  peerUserId: string,
) => Promise<readonly string[]>;

/** Resolver to map an inbound envelope's `senderDeviceId` back to
 *  its owning user. The controller persists messages keyed by
 *  `peerUserId`, so this is needed to land an inbound message in
 *  the right thread. */
export type SenderUserIdResolver = (
  envelope: CiphertextEnvelope,
) => Promise<string | null>;

export interface PlaintextDmControllerOptions {
  readonly threads: DexieThreadsStore;
  readonly messages: DexieMessagesStore;
  readonly outbox: OutboxCoordinator;
  readonly client: WsClient;
  readonly senderDeviceId: string;
  readonly resolveRecipientDeviceIds: RecipientDeviceIdsResolver;
  readonly resolveSenderUserId: SenderUserIdResolver;
  /** Optional override for `clientNonce` generation. Defaults to
   *  `crypto.randomUUID()`. */
  readonly nonceFactory?: () => string;
  /** Optional wall-clock override (tests). Defaults to
   *  `Date.now`. */
  readonly now?: () => number;
}

export class PlaintextDmController {
  readonly #threads: DexieThreadsStore;
  readonly #messages: DexieMessagesStore;
  readonly #outbox: OutboxCoordinator;
  readonly #client: WsClient;
  readonly #senderDeviceId: string;
  readonly #resolveRecipientDeviceIds: RecipientDeviceIdsResolver;
  readonly #resolveSenderUserId: SenderUserIdResolver;
  readonly #nonceFactory: () => string;
  readonly #now: () => number;

  readonly #listeners: DmChangeListener[] = [];
  #unsubscribeQueued: (() => void) | null = null;
  #unsubscribeEnvelope: (() => void) | null = null;
  #started = false;

  constructor(opts: PlaintextDmControllerOptions) {
    this.#threads = opts.threads;
    this.#messages = opts.messages;
    this.#outbox = opts.outbox;
    this.#client = opts.client;
    this.#senderDeviceId = opts.senderDeviceId;
    this.#resolveRecipientDeviceIds = opts.resolveRecipientDeviceIds;
    this.#resolveSenderUserId = opts.resolveSenderUserId;
    this.#nonceFactory = opts.nonceFactory ?? defaultNonce;
    this.#now = opts.now ?? ((): number => Date.now());
  }

  start(): void {
    if (this.#started) return;
    this.#started = true;
    this.#unsubscribeQueued = this.#client.on('queued', (info): void => {
      void this.#handleQueued(info.clientNonce).catch(() => {
        // The row stays in 'sending' and the next ack will retry the flip.
      });
    });
    this.#unsubscribeEnvelope = this.#client.on('envelope', (info): void => {
      void this.handleInbound(info.envelope).catch(() => {
        // Inbound errors are non-fatal at the dispatch loop level.
      });
    });
  }

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

  subscribe(listener: DmChangeListener): () => void {
    this.#listeners.push(listener);
    return (): void => {
      const idx = this.#listeners.indexOf(listener);
      if (idx >= 0) this.#listeners.splice(idx, 1);
    };
  }

  async listThreads(): Promise<readonly Thread[]> {
    return this.#threads.list();
  }

  async listMessagesForThread(
    threadId: string,
    limit?: number,
  ): Promise<readonly Message[]> {
    return this.#messages.listForThread(threadId, limit);
  }

  /**
   * Compose-and-send. Plaintext bytes are placed in the wire
   * envelope's ciphertext field; one envelope per recipient device.
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
    const sessionId = args.peerUserId; // any stable opaque routing id
    const baseClientNonce = this.#nonceFactory();
    const now = this.#now();

    const message = await this.#messages.insertOutgoing({
      threadId: args.peerUserId,
      senderDeviceId: this.#senderDeviceId,
      recipientDeviceId: recipientDeviceIds[0]!,
      body: args.body,
      clientNonce: baseClientNonce,
      createdAt: now,
    });
    this.#emit({
      kind: 'message_inserted',
      threadId: args.peerUserId,
      messageId: message.id,
    });

    for (const recipientDeviceId of recipientDeviceIds) {
      const envelope: CiphertextEnvelope = {
        sessionId,
        senderDeviceId: this.#senderDeviceId,
        recipientDeviceId,
        type: EnvelopeRouterType.MESSAGE,
        ciphertext: new Uint8Array(args.body),
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
   * Re-enqueue a `'failed'` row for delivery. The plaintext body
   * is replayed through every current recipient device.
   */
  async retry(messageId: number): Promise<Message | null> {
    const flipped = await this.#messages.updateState(messageId, 'sending');
    if (flipped === null) return null;

    const recipientDeviceIds = await this.#resolveRecipientDeviceIds(
      flipped.threadId,
    );
    if (recipientDeviceIds.length === 0) {
      await this.#messages.updateState(messageId, 'failed');
      this.#emit({
        kind: 'message_state_changed',
        threadId: flipped.threadId,
        messageId: flipped.id,
      });
      return flipped;
    }
    const sessionId = flipped.threadId;
    for (const recipientDeviceId of recipientDeviceIds) {
      const envelope: CiphertextEnvelope = {
        sessionId,
        senderDeviceId: flipped.senderDeviceId,
        recipientDeviceId,
        type: EnvelopeRouterType.MESSAGE,
        ciphertext: new Uint8Array(flipped.body),
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

  /** Inbound dispatch — the wire `ciphertext` is the plaintext body. */
  async handleInbound(envelope: CiphertextEnvelope): Promise<void> {
    if (envelope.type !== EnvelopeRouterType.MESSAGE) {
      return;
    }
    const peerUserId = await this.#resolveSenderUserId(envelope);
    if (peerUserId === null) {
      return;
    }
    const inserted = await this.#messages.insertIncoming({
      threadId: peerUserId,
      senderDeviceId: envelope.senderDeviceId,
      recipientDeviceId: this.#senderDeviceId,
      body: new Uint8Array(envelope.ciphertext),
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
  }

  // ---------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------

  #inboundNonce(envelope: CiphertextEnvelope): string {
    if (envelope.id !== undefined) {
      return `inbound-${envelope.id.toString()}`;
    }
    return `inbound-${this.#nonceFactory()}`;
  }

  async #handleQueued(clientNonce: string): Promise<void> {
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
    const snapshot = this.#listeners.slice();
    for (const fn of snapshot) {
      try {
        fn(change);
      } catch {
        // listener errors don't propagate
      }
    }
  }
}

function stripDeviceShardSuffix(clientNonce: string): string {
  const idx = clientNonce.indexOf(':');
  if (idx < 0) return clientNonce;
  return clientNonce.slice(0, idx);
}

function defaultNonce(): string {
  if (
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.randomUUID === 'function'
  ) {
    return globalThis.crypto.randomUUID();
  }
  return `nonce-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 12)}`;
}

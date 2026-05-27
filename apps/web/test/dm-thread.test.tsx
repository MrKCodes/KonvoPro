// apps/web/test/dm-thread.test.tsx
//
// Unit tests for the DM thread UI feature (task 3.8 — surface for
// requirement 4.6).
//
// Coverage map:
//   - `StateTicker` renders the right glyph and `data-state`
//     attribute for each of the four message states.
//   - `Composer.send` inserts a `'sending'` `MessageRow` AND
//     enqueues the corresponding envelope into the persisted
//     outbox.
//   - On `WsClient.queued` (i.e. the API gateway's
//     `ENVELOPE_QUEUED` ack), the matching `'sending'` row in
//     the local store flips to `'delivered'`.
//   - A `'failed'` row's "Retry" button re-enqueues the same
//     envelope and flips the row back to `'sending'`.
//
// Framework choices mirror `in-call-safety-number.test.tsx`:
//   - jsdom + fake-indexeddb (see `test/setup.ts`).
//   - `react-dom/client.createRoot` (no `@testing-library/react`).
//   - `act` wrappers around every render / event so React's
//     internal effect queue flushes before we read the DOM.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  encodeS2C,
  EnvelopeRouterType,
  S2C,
  type CiphertextEnvelope,
  type ServerToClient,
} from '@konvo/protocol';

import {
  generateRatchetDhKeypair,
  initReceiverRatchet,
  initSenderRatchet,
  serializeRatchetState,
} from '@konvo/crypto';

import { DexieMessagesStore } from '../src/db/repositories/messages.js';
import { DexieOutboxStore } from '../src/db/repositories/outbox.js';
import { DexieSessionsStore } from '../src/db/repositories/sessions.js';
import { DexieThreadsStore } from '../src/db/repositories/threads.js';
import { KonvoDb } from '../src/db/schema.js';
import {
  Composer,
  decodeWireCiphertext,
  DmController,
  StateTicker,
  ThreadView,
  TICKER_GLYPH,
  TICKER_LABEL,
} from '../src/features/dm/index.js';
import {
  WsClient,
  type WebSocketLike,
  type WebSocketConstructor,
} from '../src/ws/client.js';
import { OutboxCoordinator } from '../src/ws/outbox.js';

// ---------------------------------------------------------------------------
// Test harness — DOM mount / unmount
// ---------------------------------------------------------------------------

interface Mounted {
  readonly container: HTMLDivElement;
  readonly root: Root;
}

let mounted: Mounted | null = null;

function mount(node: React.ReactNode): Mounted {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(node);
  });
  const m: Mounted = { container, root };
  mounted = m;
  return m;
}

function unmount(): void {
  if (mounted === null) return;
  act(() => {
    mounted!.root.unmount();
  });
  mounted.container.remove();
  mounted = null;
}

afterEach(async () => {
  unmount();
  if (activeDb !== null) {
    activeDb.close();
    await activeDb.delete();
    activeDb = null;
  }
});

let activeDb: KonvoDb | null = null;
function freshDb(): KonvoDb {
  const name = `konvo-test-dm-${Math.random().toString(36).slice(2)}`;
  activeDb = new KonvoDb(name);
  return activeDb;
}

/** Spin the microtask queue under `act` until the predicate is
 *  true or `attempts` ticks have elapsed. Mirrors the helper in
 *  `in-call-safety-number.test.tsx`. */
async function waitFor(
  pred: () => boolean,
  attempts = 100,
): Promise<void> {
  for (let i = 0; i < attempts; i += 1) {
    let ok = false;
    await act(async () => {
      await Promise.resolve();
      ok = pred();
    });
    if (ok) return;
  }
  throw new Error('waitFor: predicate never became true');
}

// ---------------------------------------------------------------------------
// Stub WebSocket — copied/trimmed from `ws-client.test.ts`
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

  emitMessage(payload: ServerToClient): void {
    const bytes = encodeS2C(payload);
    const buffer = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    );
    this.onmessage?.({ data: buffer });
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
// Test harness — DM controller wired to a stub WS + Dexie repos
// ---------------------------------------------------------------------------

const SENDER_DEVICE = 'device-self-0001';
const RECIPIENT_DEVICE = 'device-peer-0002';
const PEER_USER_ID = 'peer-uuid-0001';

interface DmHarness {
  readonly db: KonvoDb;
  readonly threads: DexieThreadsStore;
  readonly messages: DexieMessagesStore;
  readonly outbox: DexieOutboxStore;
  readonly client: WsClient;
  readonly coordinator: OutboxCoordinator;
  readonly controller: DmController;
  readonly socket: StubWebSocket;
  /** Drive a HELLO_OK so the WS client moves into `'ready'`. */
  readonly handshake: () => Promise<void>;
  /** Push a queued ack for the given client nonce. */
  readonly emitQueued: (clientNonce: string) => Promise<void>;
}

async function buildDmHarness(opts?: {
  readonly nonceFactory?: () => string;
}): Promise<DmHarness> {
  StubWebSocket.instances.length = 0;
  const db = freshDb();
  const threads = new DexieThreadsStore(db);
  const messages = new DexieMessagesStore(db);
  const outbox = new DexieOutboxStore(db);
  const sessionStore = new DexieSessionsStore(db);

  // Pre-seed a libsignal session so encryptToDevice has
  // something to advance on the send path.
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);
  const peerSpk = generateRatchetDhKeypair();
  const senderRatchet = initSenderRatchet(sk, peerSpk.pub);
  await sessionStore.saveSession(
    PEER_USER_ID,
    RECIPIENT_DEVICE,
    serializeRatchetState(senderRatchet),
  );
  // The peer-side ratchet is staged here for tests that drive
  // the inbound path; receive-side tests live in the dedicated
  // dm-ciphertext suite.
  void initReceiverRatchet(sk, { priv: peerSpk.priv, pub: peerSpk.pub });

  const client = new WsClient({
    url: 'wss://example.test',
    deviceId: SENDER_DEVICE,
    tokenProvider: async (): Promise<string> => 'tok',
    WebSocket: StubWebSocket as unknown as WebSocketConstructor,
    setTimeout: (fn): unknown => fn,
    clearTimeout: (): void => {},
  });
  const coordinator = new OutboxCoordinator({ client, store: outbox });
  coordinator.start();

  const controller = new DmController({
    threads,
    messages,
    outbox: coordinator,
    client,
    sessionStore,
    senderDeviceId: SENDER_DEVICE,
    resolveRecipientDeviceIds: async (): Promise<readonly string[]> => [
      RECIPIENT_DEVICE,
    ],
    resolveSenderUserId: async (): Promise<string> => PEER_USER_ID,
    ...(opts?.nonceFactory !== undefined
      ? { nonceFactory: opts.nonceFactory }
      : {}),
  });
  controller.start();

  await client.connect();
  // Two ticks: tokenProvider resolves on tick 1; the socket is
  // constructed on tick 2.
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  const socket = StubWebSocket.instances[StubWebSocket.instances.length - 1];
  if (socket === undefined) {
    throw new Error('harness: no socket instance constructed');
  }

  return {
    db,
    threads,
    messages,
    outbox,
    client,
    coordinator,
    controller,
    socket,
    handshake: async (): Promise<void> => {
      socket.emitOpen();
      // Let the HELLO send run.
      await Promise.resolve();
      socket.emitMessage({
        t: S2C.HELLO_OK,
        serverTimeMs: 1_700_000_000_000,
        queuedCount: 0,
      });
      await Promise.resolve();
      await Promise.resolve();
    },
    emitQueued: async (clientNonce: string): Promise<void> => {
      socket.emitMessage({
        t: S2C.ENVELOPE_QUEUED,
        clientNonce,
        envelopeId: 1n,
        serverTimeMs: 1_700_000_000_000,
      });
      // Drain enough microtasks for the chained async work
      // (WsClient dispatch → DmController.#handleQueued →
      //  Dexie find + update transactions) to settle. Each
      // Dexie call resolves on a microtask boundary, so a
      // generous count covers the find + setStateByClientNonce
      // round-trip even on slower CI runners.
      for (let i = 0; i < 50; i += 1) {
        await Promise.resolve();
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Tests — `StateTicker`
// ---------------------------------------------------------------------------

describe('StateTicker', () => {
  it.each(['sending', 'delivered', 'read', 'failed', 'tampered'] as const)(
    'renders the right glyph + a11y label for state=%s',
    (state) => {
      const m = mount(<StateTicker state={state} />);
      const span = m.container.querySelector('[data-testid="dm-state-ticker"]');
      expect(span).not.toBeNull();
      expect(span!.getAttribute('data-state')).toBe(state);
      expect(span!.textContent).toBe(TICKER_GLYPH[state]);
      expect(span!.getAttribute('aria-label')).toBe(TICKER_LABEL[state]);
    },
  );
});

// ---------------------------------------------------------------------------
// Tests — `Composer.send` insert + outbox enqueue
// ---------------------------------------------------------------------------

describe('Composer.send', () => {
  it('inserts a sending message AND enqueues the envelope into the outbox', async () => {
    const h = await buildDmHarness({ nonceFactory: () => 'nonce-fixed-1' });

    let sentInfo: { messageId: number; clientNonce: string } | null = null;
    const m = mount(
      <Composer
        controller={h.controller}
        peerUserId={PEER_USER_ID}
        peerHandle="peer"
        onSent={(info): void => {
          sentInfo = info;
        }}
      />,
    );

    // Type into the textarea. React tracks the input value via a
    // hidden tracker, so a plain `textarea.value = ...` assignment
    // gets ignored on the next event. Use the prototype's native
    // setter so the React tracker observes the new value.
    const textarea = m.container.querySelector<HTMLTextAreaElement>(
      '[data-testid="dm-composer-input"]',
    );
    expect(textarea).not.toBeNull();
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype,
      'value',
    )!.set!;
    act(() => {
      nativeSetter.call(textarea!, 'hello world');
      textarea!.dispatchEvent(new Event('input', { bubbles: true }));
    });

    // Click send.
    const sendBtn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="dm-composer-send"]',
    );
    expect(sendBtn).not.toBeNull();
    act(() => {
      sendBtn!.click();
    });

    await waitFor(() => sentInfo !== null);

    // 1. A `'sending'` row exists in the messages store with the
    //    expected body and clientNonce.
    const persisted = await h.messages.findByClientNonce('nonce-fixed-1');
    expect(persisted).not.toBeNull();
    expect(persisted!.state).toBe('sending');
    expect(persisted!.threadId).toBe(PEER_USER_ID);
    expect(persisted!.senderDeviceId).toBe(SENDER_DEVICE);
    expect(persisted!.recipientDeviceId).toBe(RECIPIENT_DEVICE);
    // The local message row carries the plaintext body (so the
    // composer can render its own send immediately). The wire
    // envelope below carries libsignal ciphertext.
    expect(new TextDecoder().decode(persisted!.body)).toBe('hello world');

    // 2. An outbox row exists for the per-device-shard nonce
    //    `${baseNonce}:${recipientDeviceId}`. The envelope's
    //    `ciphertext` field now carries libsignal ciphertext —
    //    decoding it as UTF-8 must NOT recover the plaintext.
    const perDeviceNonce = `nonce-fixed-1:${RECIPIENT_DEVICE}`;
    const outboxRow = await h.outbox.findByClientNonce(perDeviceNonce);
    expect(outboxRow).not.toBeNull();
    expect(outboxRow!.envelope.senderDeviceId).toBe(SENDER_DEVICE);
    expect(outboxRow!.envelope.recipientDeviceId).toBe(RECIPIENT_DEVICE);
    expect(outboxRow!.envelope.type).toBe(EnvelopeRouterType.MESSAGE);
    // The wire ciphertext begins with a 40-byte ratchet header,
    // not the plaintext bytes — it is at minimum 40 + 16 (GCM
    // tag) bytes long.
    expect(outboxRow!.envelope.ciphertext.length).toBeGreaterThanOrEqual(56);
    expect(new TextDecoder('utf-8', { fatal: false }).decode(
      outboxRow!.envelope.ciphertext,
    )).not.toContain('hello world');
    // Splitting back into header + body: the header decodes
    // cleanly but contains no plaintext.
    const decoded = decodeWireCiphertext(outboxRow!.envelope.ciphertext);
    expect(decoded.header.dhPub.length).toBe(32);
    expect(decoded.body.length).toBeGreaterThan(0);
    expect(new TextDecoder('utf-8', { fatal: false }).decode(decoded.body)).not.toContain(
      'hello world',
    );

    // 3. The thread row exists with the peer handle.
    const thread = await h.threads.get(PEER_USER_ID);
    expect(thread).not.toBeNull();
    expect(thread!.peerHandle).toBe('peer');
    expect(thread!.lastMessageAt).toBeGreaterThan(0);

    // 4. The composer cleared its draft after a successful send.
    expect(textarea!.value).toBe('');
  });
});

// ---------------------------------------------------------------------------
// Tests — `ENVELOPE_QUEUED` flips sending → delivered
// ---------------------------------------------------------------------------

describe('DmController on `queued`', () => {
  it('flips the matching sending row to delivered on ENVELOPE_QUEUED', async () => {
    const h = await buildDmHarness({ nonceFactory: () => 'nonce-q-1' });
    await h.handshake();

    // Insert via the controller so the WS path is exercised end-
    // to-end (composer → controller → outbox → WS send).
    const message = await h.controller.sendMessage({
      peerUserId: PEER_USER_ID,
      body: new TextEncoder().encode('hi'),
    });
    expect(message.state).toBe('sending');

    // The outbox sent the envelope to the open socket.
    expect(h.socket.sent.length).toBeGreaterThanOrEqual(2); // HELLO + SEND

    // Server acks under the per-device-shard nonce. The DM
    // controller's listener strips the device suffix and
    // flips the matching row to 'delivered' on the next
    // microtask.
    await h.emitQueued(`nonce-q-1:${RECIPIENT_DEVICE}`);

    // Poll for the state flip (Dexie's promise chain may still
    // be in flight when emitQueued returns).
    let after: Awaited<ReturnType<typeof h.messages.findByClientNonce>> = null;
    for (let i = 0; i < 100; i += 1) {
      after = await h.messages.findByClientNonce('nonce-q-1');
      if (after !== null && after.state === 'delivered') break;
      await Promise.resolve();
    }
    expect(after).not.toBeNull();
    expect(after!.state).toBe('delivered');
  });

  it('renders the delivered glyph after ENVELOPE_QUEUED', async () => {
    const h = await buildDmHarness({ nonceFactory: () => 'nonce-q-2' });
    await h.handshake();

    // Send a message via the controller.
    const message = await h.controller.sendMessage({
      peerUserId: PEER_USER_ID,
      body: new TextEncoder().encode('rendered'),
    });

    // Mount the thread view so we can read the rendered ticker.
    const m = mount(
      <ThreadView
        controller={h.controller}
        threadId={PEER_USER_ID}
        senderDeviceId={SENDER_DEVICE}
      />,
    );

    // First state the row paints with: 'sending'.
    await waitFor(
      () =>
        m.container.querySelector(
          `[data-testid="dm-message-${message.id}"]`,
        ) !== null,
    );
    const initialRow = m.container.querySelector(
      `[data-testid="dm-message-${message.id}"]`,
    );
    expect(initialRow!.getAttribute('data-message-state')).toBe('sending');

    // Server acks; the controller flips state and the
    // useDmMessages subscriber re-pulls the row.
    await act(async () => {
      await h.emitQueued(`nonce-q-2:${RECIPIENT_DEVICE}`);
    });

    await waitFor(() => {
      const row = m.container.querySelector(
        `[data-testid="dm-message-${message.id}"]`,
      );
      return row?.getAttribute('data-message-state') === 'delivered';
    });

    const ticker = m.container
      .querySelector(`[data-testid="dm-message-${message.id}"]`)!
      .querySelector('[data-testid="dm-state-ticker"]');
    expect(ticker?.getAttribute('data-state')).toBe('delivered');
    expect(ticker?.textContent).toBe(TICKER_GLYPH.delivered);
  });
});

// ---------------------------------------------------------------------------
// Tests — Retry on `'failed'`
// ---------------------------------------------------------------------------

describe('failed message retry', () => {
  it('re-enqueues the envelope with the same clientNonce and flips state back to sending', async () => {
    const h = await buildDmHarness({ nonceFactory: () => 'nonce-fail-1' });
    await h.handshake();

    // 1. Send and then mark failed (simulates a transport timeout
    //    in the absence of a real retry-budget scheduler).
    const sent = await h.controller.sendMessage({
      peerUserId: PEER_USER_ID,
      body: new TextEncoder().encode('please retry'),
    });
    await h.controller.markFailed(sent.id);

    const beforeRetry = await h.messages.findByClientNonce('nonce-fail-1');
    expect(beforeRetry!.state).toBe('failed');

    // 2. Mount the thread view; the failed row should expose a
    //    retry button.
    const m = mount(
      <ThreadView
        controller={h.controller}
        threadId={PEER_USER_ID}
        senderDeviceId={SENDER_DEVICE}
      />,
    );
    await waitFor(
      () =>
        m.container.querySelector(
          `[data-testid="dm-message-retry-${sent.id}"]`,
        ) !== null,
    );

    // Spy on the outbox enqueue path through the coordinator.
    const enqueueSpy = vi.spyOn(h.coordinator, 'enqueue');

    // 3. Click retry.
    const retryBtn = m.container.querySelector<HTMLButtonElement>(
      `[data-testid="dm-message-retry-${sent.id}"]`,
    );
    expect(retryBtn).not.toBeNull();
    act(() => {
      retryBtn!.click();
    });

    // 4. Wait for the row to flip back to 'sending' and the
    //    coordinator to have been invoked with the same nonce.
    await waitFor(() => enqueueSpy.mock.calls.length > 0);
    await waitFor(async () => {
      const row = await h.messages.findByClientNonce('nonce-fail-1');
      return row?.state === 'sending';
    });

    expect(enqueueSpy).toHaveBeenCalledTimes(1);
    const enqueueArg = enqueueSpy.mock.calls[0]![0] as {
      clientNonce: string;
      envelope: CiphertextEnvelope;
    };
    // The retry path enqueues under the per-device-shard
    // nonce just like the initial send.
    expect(enqueueArg.clientNonce).toBe(`nonce-fail-1:${RECIPIENT_DEVICE}`);
    expect(enqueueArg.envelope.recipientDeviceId).toBe(RECIPIENT_DEVICE);
    // Retry re-encrypts (it does not replay the prior wire
    // bytes), so the envelope's ciphertext is libsignal-shaped
    // and does NOT contain the plaintext.
    expect(
      new TextDecoder('utf-8', { fatal: false }).decode(
        enqueueArg.envelope.ciphertext,
      ),
    ).not.toContain('please retry');

    // 5. The outbox itself only carries one row (idempotency
    //    by clientNonce — see DexieOutboxStore.enqueue).
    expect(await h.outbox.count()).toBe(1);
  });
});

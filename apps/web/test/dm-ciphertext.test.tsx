// apps/web/test/dm-ciphertext.test.tsx
//
// Unit tests for task 4.7: replace plaintext DM payloads with
// libsignal ciphertext.
//
// Coverage map vs the task brief:
//   1. Send routes through encrypt; the outbox envelope's
//      `ciphertext` field is NOT plaintext.
//   2. Inbound envelope routes through decrypt; the matching
//      plaintext appears in the persisted message row.
//   3. Tamper test: flipping a byte of the wire ciphertext
//      surfaces the inert "couldn't be decrypted" placeholder
//      and does NOT reveal the plaintext anywhere on the row.
//      Ratchet state is unchanged on this branch
//      (decryptFromDevice contract).
//   4. Duplicate inbound: receiving the same envelope twice
//      results in exactly one persisted row.
//   5. Multi-device fan-out: two recipient devices for a peer
//      produce two outbox rows for one logical message.
//
// All tests run against the real Phase-3 ratchet from
// `@konvo/crypto` (no mocks): each test stages a sender +
// receiver session pair via `initSenderRatchet` /
// `initReceiverRatchet`, persists them through the
// Dexie-backed `SignalProtocolStore`, and lets the
// `DmController` drive the encrypt / decrypt seams.
//
// jsdom + fake-indexeddb (`test/setup.ts`) provide the WebCrypto
// + IndexedDB primitives the ratchet and Dexie need.

import { afterEach, describe, expect, it } from 'vitest';

import {
  EnvelopeRouterType,
  type CiphertextEnvelope,
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
  DmController,
  TAMPERED_PLACEHOLDER_TEXT,
} from '../src/features/dm/index.js';
import {
  WsClient,
  type WebSocketLike,
  type WebSocketConstructor,
} from '../src/ws/client.js';
import { OutboxCoordinator } from '../src/ws/outbox.js';

// ---------------------------------------------------------------------------
// Stub WebSocket — the controller only needs `client.on('queued', ...)` to
// fire on outbox-ack and `client.on('envelope', ...)` to deliver inbound.
// We never open a real socket; tests drive the controller's `handleInbound`
// directly for the receive-side cases and only enqueue (no replay) for the
// send-side cases.
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
// Fixture
// ---------------------------------------------------------------------------

const SENDER_DEVICE = 'device-self-aaaa';
const RECIPIENT_DEVICE = 'device-peer-bbbb';
const RECIPIENT_DEVICE_2 = 'device-peer-cccc';
const PEER_USER_ID = 'peer-uuid-0001';

let activeDb: KonvoDb | null = null;
function freshDb(): KonvoDb {
  const name = `konvo-test-dm-ct-${Math.random().toString(36).slice(2)}`;
  activeDb = new KonvoDb(name);
  return activeDb;
}

afterEach(async () => {
  if (activeDb !== null) {
    activeDb.close();
    await activeDb.delete();
    activeDb = null;
  }
});

interface SessionSeed {
  /** Sender-side ratchet to encrypt to the recipient. */
  readonly senderToRecipient: ReturnType<typeof initSenderRatchet>;
  /** Recipient-side ratchet to decrypt envelopes from the
   *  sender. The harness uses this to fabricate inbound
   *  envelopes the controller's `handleInbound` will route. */
  readonly recipientFromSender: ReturnType<typeof initReceiverRatchet>;
  /** Reverse-direction ratchets (recipient is the sender, our
   *  test client is the receiver). Used only by the receive-side
   *  cases. */
  readonly recipientToSender: ReturnType<typeof initSenderRatchet>;
  readonly senderFromRecipient: ReturnType<typeof initReceiverRatchet>;
}

function freshSessionSeed(): SessionSeed {
  // Forward direction: our local client → peer device.
  const skFwd = new Uint8Array(32);
  crypto.getRandomValues(skFwd);
  const peerSpk = generateRatchetDhKeypair();
  const senderToRecipient = initSenderRatchet(skFwd, peerSpk.pub);
  const recipientFromSender = initReceiverRatchet(skFwd, {
    priv: peerSpk.priv,
    pub: peerSpk.pub,
  });

  // Reverse direction: peer device → our local client. Used by
  // the receive-side cases. Independent X3DH outputs (separate
  // SK + SPK).
  const skRev = new Uint8Array(32);
  crypto.getRandomValues(skRev);
  const ourSpk = generateRatchetDhKeypair();
  const recipientToSender = initSenderRatchet(skRev, ourSpk.pub);
  const senderFromRecipient = initReceiverRatchet(skRev, {
    priv: ourSpk.priv,
    pub: ourSpk.pub,
  });

  return {
    senderToRecipient,
    recipientFromSender,
    recipientToSender,
    senderFromRecipient,
  };
}

interface Harness {
  readonly db: KonvoDb;
  readonly threads: DexieThreadsStore;
  readonly messages: DexieMessagesStore;
  readonly outbox: DexieOutboxStore;
  readonly sessionStore: DexieSessionsStore;
  readonly client: WsClient;
  readonly coordinator: OutboxCoordinator;
  readonly controller: DmController;
}

async function buildHarness(opts: {
  readonly recipientDeviceIds: readonly string[];
  /** Pre-seed the persisted ratchet store so encrypt /
   *  decrypt have something to advance on. The map keys are
   *  `${peerUserId}:${peerDeviceId}` and the values are the
   *  ratchet states our local client's view of that peer
   *  starts from (i.e. the sender-side state for outbound
   *  encrypt; the receiver-side state for inbound decrypt). */
  readonly seedSessions: ReadonlyMap<
    string,
    ReturnType<typeof initSenderRatchet>
  >;
  /** Optional override for `clientNonce` generation. */
  readonly nonceFactory?: () => string;
}): Promise<Harness> {
  StubWebSocket.instances.length = 0;
  const db = freshDb();
  const threads = new DexieThreadsStore(db);
  const messages = new DexieMessagesStore(db);
  const outbox = new DexieOutboxStore(db);
  const sessionStore = new DexieSessionsStore(db);

  for (const [key, state] of opts.seedSessions) {
    const [peerUserId, peerDeviceId] = key.split(':');
    if (peerUserId === undefined || peerDeviceId === undefined) {
      throw new Error(`bad seed key: ${key}`);
    }
    await sessionStore.saveSession(
      peerUserId,
      peerDeviceId,
      serializeRatchetState(state),
    );
  }

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
    resolveRecipientDeviceIds: async (): Promise<readonly string[]> =>
      opts.recipientDeviceIds,
    resolveSenderUserId: async (): Promise<string> => PEER_USER_ID,
    ...(opts.nonceFactory !== undefined
      ? { nonceFactory: opts.nonceFactory }
      : {}),
  });
  controller.start();

  return {
    db,
    threads,
    messages,
    outbox,
    sessionStore,
    client,
    coordinator,
    controller,
  };
}

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);

// ---------------------------------------------------------------------------
// Tests — send-side
// ---------------------------------------------------------------------------

describe('send routes through encryptToDevice (req 4.4 / 4.10)', () => {
  it('the outbox envelope ciphertext is NOT plaintext bytes', async () => {
    const seed = freshSessionSeed();
    const h = await buildHarness({
      recipientDeviceIds: [RECIPIENT_DEVICE],
      seedSessions: new Map([
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE}`, seed.senderToRecipient],
      ]),
      nonceFactory: () => 'nonce-send-1',
    });

    const plaintext = 'super secret canary string';
    const message = await h.controller.sendMessage({
      peerUserId: PEER_USER_ID,
      body: enc(plaintext),
    });
    expect(message.state).toBe('sending');

    // The outbox row for this device shard carries libsignal
    // ciphertext, not the plaintext bytes.
    const perDeviceNonce = `nonce-send-1:${RECIPIENT_DEVICE}`;
    const row = await h.outbox.findByClientNonce(perDeviceNonce);
    expect(row).not.toBeNull();
    const wire = row!.envelope.ciphertext;

    // 1. Wire frame is at minimum 40 (header) + 16 (GCM tag)
    //    bytes — never just the plaintext length.
    expect(wire.length).toBeGreaterThanOrEqual(40 + 16);

    // 2. The plaintext substring must NOT appear anywhere in
    //    the wire bytes — search the raw byte buffer for the
    //    canary pattern.
    const wireAsLatin1 = String.fromCharCode(...wire);
    expect(wireAsLatin1.includes(plaintext)).toBe(false);

    // 3. The envelope's router type is MESSAGE.
    expect(row!.envelope.type).toBe(EnvelopeRouterType.MESSAGE);
    expect(row!.envelope.recipientDeviceId).toBe(RECIPIENT_DEVICE);
    expect(row!.envelope.senderDeviceId).toBe(SENDER_DEVICE);
  });
});

describe('multi-device fan-out (req 4.5)', () => {
  it('a peer with 2 enrolled devices yields 2 outbox rows for one logical message', async () => {
    // Two independent sessions — one per recipient device.
    const seedA = freshSessionSeed();
    const seedB = freshSessionSeed();
    const h = await buildHarness({
      recipientDeviceIds: [RECIPIENT_DEVICE, RECIPIENT_DEVICE_2],
      seedSessions: new Map([
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE}`, seedA.senderToRecipient],
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE_2}`, seedB.senderToRecipient],
      ]),
      nonceFactory: () => 'nonce-fanout-1',
    });

    const message = await h.controller.sendMessage({
      peerUserId: PEER_USER_ID,
      body: enc('hi everyone'),
    });

    // Exactly one local message row.
    const rows = await h.messages.listForThread(PEER_USER_ID);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.id).toBe(message.id);

    // Two outbox rows — one per recipient device. They share
    // the base nonce as a prefix and key their per-device
    // shard suffix off the device id.
    const all = await h.outbox.listInOrder();
    expect(all).toHaveLength(2);

    const recipients = new Set(all.map((r) => r.envelope.recipientDeviceId));
    expect(recipients).toEqual(
      new Set([RECIPIENT_DEVICE, RECIPIENT_DEVICE_2]),
    );

    const nonces = new Set(all.map((r) => r.clientNonce));
    expect(nonces).toEqual(
      new Set([
        `nonce-fanout-1:${RECIPIENT_DEVICE}`,
        `nonce-fanout-1:${RECIPIENT_DEVICE_2}`,
      ]),
    );

    // The two ciphertexts are distinct — each was produced
    // by an independent sending chain.
    const cts = all.map((r) => r.envelope.ciphertext);
    expect(cts[0]!.length).toBeGreaterThanOrEqual(40 + 16);
    expect(cts[1]!.length).toBeGreaterThanOrEqual(40 + 16);
    const a = String.fromCharCode(...cts[0]!);
    const b = String.fromCharCode(...cts[1]!);
    expect(a).not.toBe(b);
    expect(a.includes('hi everyone')).toBe(false);
    expect(b.includes('hi everyone')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests — receive-side
// ---------------------------------------------------------------------------

/**
 * Construct the wire-ciphertext envelope a peer would send, by
 * driving the peer's sender-side ratchet directly. Returns the
 * envelope plus the post-encrypt sender state so callers can
 * thread it forward for a second send.
 */
async function fabricateInboundEnvelope(
  peerSenderState: ReturnType<typeof initSenderRatchet>,
  plaintext: string,
): Promise<{
  envelope: CiphertextEnvelope;
  nextState: ReturnType<typeof initSenderRatchet>;
}> {
  const { encryptToDevice } = await import('@konvo/crypto');
  const { encodeWireCiphertext } = await import('../src/features/dm/wire.js');
  const { state: nextState, ciphertext, header } = await encryptToDevice(
    peerSenderState,
    enc(plaintext),
  );
  const wire = encodeWireCiphertext(header, ciphertext);
  const envelope: CiphertextEnvelope = {
    sessionId: PEER_USER_ID,
    senderDeviceId: RECIPIENT_DEVICE, // peer sent it
    recipientDeviceId: SENDER_DEVICE, // we received it
    type: EnvelopeRouterType.MESSAGE,
    ciphertext: wire,
  };
  return { envelope, nextState };
}

describe('inbound routes through decryptFromDevice (req 4.10)', () => {
  it('a successful inbound envelope persists the matching plaintext', async () => {
    const seed = freshSessionSeed();
    const h = await buildHarness({
      recipientDeviceIds: [RECIPIENT_DEVICE],
      // The receive-side state our local client uses to decrypt
      // envelopes from the peer device.
      seedSessions: new Map([
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE}`, seed.senderFromRecipient],
      ]),
    });

    const plaintext = 'hello from the peer';
    const { envelope } = await fabricateInboundEnvelope(
      seed.recipientToSender,
      plaintext,
    );

    await h.controller.handleInbound(envelope);

    const rows = await h.messages.listForThread(PEER_USER_ID);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.state).toBe('delivered');
    expect(rows[0]!.senderDeviceId).toBe(RECIPIENT_DEVICE);
    expect(rows[0]!.recipientDeviceId).toBe(SENDER_DEVICE);
    expect(dec(rows[0]!.body)).toBe(plaintext);
  });
});

describe('tamper rejection (req 4.11)', () => {
  it('flipping a byte of the wire ciphertext renders the inert placeholder + leaks no plaintext', async () => {
    const seed = freshSessionSeed();
    const h = await buildHarness({
      recipientDeviceIds: [RECIPIENT_DEVICE],
      seedSessions: new Map([
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE}`, seed.senderFromRecipient],
      ]),
    });

    const plaintext = 'this should never reach the row';
    const { envelope } = await fabricateInboundEnvelope(
      seed.recipientToSender,
      plaintext,
    );

    // Capture the persisted ratchet state before the tamper
    // attempt — req 4.11 says it must remain unchanged.
    const before = await h.sessionStore.loadSession(
      PEER_USER_ID,
      RECIPIENT_DEVICE,
    );
    expect(before).not.toBeNull();

    // Flip a byte in the AES-GCM body section (after the 40-
    // byte header). This is the canonical "single byte
    // mutation" of req 4.11.
    const tampered = new Uint8Array(envelope.ciphertext);
    tampered[50] = (tampered[50]! ^ 0x01) & 0xff;
    const tamperedEnvelope: CiphertextEnvelope = {
      ...envelope,
      ciphertext: tampered,
    };

    await h.controller.handleInbound(tamperedEnvelope);

    // 1. Exactly one row was inserted: the inert placeholder.
    const rows = await h.messages.listForThread(PEER_USER_ID);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.state).toBe('tampered');
    expect(dec(rows[0]!.body)).toBe(TAMPERED_PLACEHOLDER_TEXT);

    // 2. The plaintext does NOT appear anywhere on the row's
    //    bytes — the only stored body is the fixed placeholder
    //    string.
    expect(dec(rows[0]!.body)).not.toContain(plaintext);
    expect(dec(rows[0]!.body)).not.toContain(plaintext.split(' ')[0]!);

    // 3. The persisted ratchet state is byte-equal to the pre-
    //    tamper state (req 4.11: "ratchet state SHALL remain
    //    unchanged"). The Phase-3 ratchet's `decryptFromDevice`
    //    returns the input state ref on `invalid_message`; the
    //    controller saves *that* ref, which is structurally
    //    equivalent to the pre-call state.
    const after = await h.sessionStore.loadSession(
      PEER_USER_ID,
      RECIPIENT_DEVICE,
    );
    expect(after).not.toBeNull();
    expect(Array.from(after!.rootKey)).toEqual(Array.from(before!.rootKey));
    expect(after!.receivingMessageNumber).toBe(before!.receivingMessageNumber);
  });

  it('after a tampered inbound, a subsequent untampered inbound still decrypts cleanly', async () => {
    // Direct corollary of "ratchet state unchanged on tamper":
    // the next legitimate envelope from the peer must work.
    const seed = freshSessionSeed();
    const h = await buildHarness({
      recipientDeviceIds: [RECIPIENT_DEVICE],
      seedSessions: new Map([
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE}`, seed.senderFromRecipient],
      ]),
    });

    const fab1 = await fabricateInboundEnvelope(
      seed.recipientToSender,
      'first (will be tampered)',
    );
    const fab2 = await fabricateInboundEnvelope(
      fab1.nextState,
      'second (clean)',
    );

    // Tamper the first.
    const tampered = new Uint8Array(fab1.envelope.ciphertext);
    tampered[45] = (tampered[45]! ^ 0xff) & 0xff;
    await h.controller.handleInbound({
      ...fab1.envelope,
      ciphertext: tampered,
    });
    // Send the second envelope clean.
    await h.controller.handleInbound(fab2.envelope);

    const rows = await h.messages.listForThread(PEER_USER_ID);
    // 2 rows: one tampered placeholder, one clean delivered.
    expect(rows.length).toBe(2);
    const tamperedRows = rows.filter((r) => r.state === 'tampered');
    const deliveredRows = rows.filter((r) => r.state === 'delivered');
    expect(tamperedRows).toHaveLength(1);
    expect(deliveredRows).toHaveLength(1);
    expect(dec(deliveredRows[0]!.body)).toBe('second (clean)');

    // The tampered row's body is the inert placeholder only.
    expect(dec(tamperedRows[0]!.body)).toBe(TAMPERED_PLACEHOLDER_TEXT);
    expect(dec(tamperedRows[0]!.body)).not.toContain('first');
  });
});

describe('duplicate inbound (req 4.12)', () => {
  it('receiving the same envelope twice persists exactly one row', async () => {
    const seed = freshSessionSeed();
    const h = await buildHarness({
      recipientDeviceIds: [RECIPIENT_DEVICE],
      seedSessions: new Map([
        [`${PEER_USER_ID}:${RECIPIENT_DEVICE}`, seed.senderFromRecipient],
      ]),
    });

    const { envelope } = await fabricateInboundEnvelope(
      seed.recipientToSender,
      'send this once',
    );

    // First delivery: one row inserted.
    await h.controller.handleInbound(envelope);
    let rows = await h.messages.listForThread(PEER_USER_ID);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.state).toBe('delivered');
    expect(dec(rows[0]!.body)).toBe('send this once');

    // Second delivery of the SAME envelope: duplicate path.
    // The ratchet returns `{ ok: false, error: { kind:
    // 'duplicate' } }` and the controller inserts no row.
    await h.controller.handleInbound(envelope);
    rows = await h.messages.listForThread(PEER_USER_ID);
    expect(rows).toHaveLength(1);

    // Third delivery: still no duplicate.
    await h.controller.handleInbound(envelope);
    rows = await h.messages.listForThread(PEER_USER_ID);
    expect(rows).toHaveLength(1);
  });
});

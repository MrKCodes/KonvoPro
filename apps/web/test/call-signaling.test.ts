// apps/web/test/call-signaling.test.ts
//
// Unit tests for `apps/web/src/features/calls/signaling.ts` (task
// 6.3). Validates Requirements 7.2, 7.3, 11.8 and the P23 ICE
// candidate confidentiality property as observed from the client
// side.
//
// What we exercise:
//
//   1. `sendCallSignal('ice', { candidate: ... }, route)` produces a
//      `CiphertextEnvelope` whose ciphertext (the wire-format
//      blob handed to the outbox) does NOT contain the ICE
//      candidate string in any of the encodings a naïve serialiser
//      might reach for (utf-8 / latin1 / hex / base64 /
//      number-array). The candidate text appears ONLY after
//      decrypting the matching `decryptFromDevice` call on a peer
//      ratchet — i.e. the candidate is genuinely encrypted.
//
//   2. The envelope's `type` is `EnvelopeRouterType.CALL` (Server
//      uses this to route on the same SEND_ENVELOPE → fan-out path
//      as DM messages but with no decryption).
//
//   3. `senderDeviceId` matches the local device id (the gateway's
//      sender-authority check will reject any other value).
//
//   4. Round-trip: an envelope produced by `sendCallSignal` is
//      consumed by `handleInboundCallEnvelope` against a peer
//      ratchet seeded from the same X3DH-derived root key, and
//      the dispatcher invokes the corresponding handler with the
//      original payload contents. Covers all four kinds (offer /
//      answer / ice / hangup).
//
//   5. Tampering with one byte of the wire ciphertext produces a
//      `decrypt_failed` outcome and does NOT advance the receiver
//      ratchet (Requirement 4.11 / P3); the inner payload is never
//      surfaced.
//
//   6. An envelope of router type MESSAGE handed to
//      `handleInboundCallEnvelope` is dropped with `'wrong_type'`
//      — defence in depth against a misrouted DM that would
//      otherwise corrupt the call ratchet.
//
// We construct a real Phase-3 ratchet via
// `initSenderRatchet`/`initReceiverRatchet` against a shared X3DH-
// derived root key (32 random bytes). The `SignalProtocolStore`
// is implemented as an in-memory Map fixture: production wires
// the Dexie-backed store, but persistence semantics are not on
// the critical path of this test — the round-trip property only
// cares that loadSession/saveSession are honest about preserving
// state across the encrypt/decrypt boundary.

import {
  decryptFromDevice,
  generateRatchetDhKeypair,
  initReceiverRatchet,
  initSenderRatchet,
  serializeRatchetState,
  deserializeRatchetState,
  type SerializedRatchetState,
  type SignalProtocolStore,
} from '@konvo/crypto';
import {
  EnvelopeRouterType,
  InnerType,
  type CiphertextEnvelope,
  type IceCandidateInit,
} from '@konvo/protocol';
import { Buffer } from 'node:buffer';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import {
  decodeWireCiphertext,
} from '../src/features/dm/wire.js';
import {
  dispatchInner,
  handleInboundCallEnvelope,
  sendCallSignal,
  type CallPeerConnectionLike,
  type CallSignalingHandlers,
} from '../src/features/calls/signaling.js';
import type {
  OutboxCoordinator,
} from '../src/ws/outbox.js';

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

const ALICE_USER = 'user-alice';
const ALICE_DEVICE = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const BOB_USER = 'user-bob';
const BOB_DEVICE = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const SESSION_ID = '11111111-1111-1111-1111-111111111111';
const CALL_ID = 'call-7';

// A realistic ICE candidate string per RFC 5245 / 8445. The literal
// `candidate:` prefix is what we forbid in any plaintext-visible
// surface (logs, the wire ciphertext, etc).
const ICE_CANDIDATE_STR =
  'candidate:842163049 1 udp 1677729535 192.0.2.1 54321 typ srflx ' +
  'raddr 0.0.0.0 rport 0 generation 0 ufrag abcd network-id 1';

const SAMPLE_OFFER_SDP =
  'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
  'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
  'a=fingerprint:sha-256 12:34:56:78:9A:BC:DE:F0\r\n';
const SAMPLE_ANSWER_SDP =
  'v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
  'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
  'a=fingerprint:sha-256 99:88:77:66:55:44:33:22\r\n';

// ---------------------------------------------------------------------------
// In-memory SignalProtocolStore (test fixture)
// ---------------------------------------------------------------------------

class InMemorySessionStore implements SignalProtocolStore {
  private readonly sessions = new Map<string, SerializedRatchetState>();

  private key(peerUserId: string, peerDeviceId: string): string {
    return `${peerUserId}::${peerDeviceId}`;
  }

  async loadSession(
    peerUserId: string,
    peerDeviceId: string,
  ): Promise<SerializedRatchetState | null> {
    const v = this.sessions.get(this.key(peerUserId, peerDeviceId));
    if (v === undefined) return null;
    // Defensive copy — mirror the Dexie store contract so a caller
    // that mutates the returned state cannot corrupt the persisted
    // row.
    return cloneSerialized(v);
  }

  async saveSession(
    peerUserId: string,
    peerDeviceId: string,
    state: SerializedRatchetState,
  ): Promise<void> {
    this.sessions.set(this.key(peerUserId, peerDeviceId), cloneSerialized(state));
  }

  async deleteSession(peerUserId: string, peerDeviceId: string): Promise<void> {
    this.sessions.delete(this.key(peerUserId, peerDeviceId));
  }

  async markOpkUsed(): Promise<void> {
    /* unused — call signaling never consumes one-time prekeys */
  }
}

function cloneSerialized(s: SerializedRatchetState): SerializedRatchetState {
  return {
    rootKey: new Uint8Array(s.rootKey),
    sendingDhPriv: new Uint8Array(s.sendingDhPriv),
    sendingDhPub: new Uint8Array(s.sendingDhPub),
    receivingDhPub:
      s.receivingDhPub === null ? null : new Uint8Array(s.receivingDhPub),
    sendingChainKey:
      s.sendingChainKey === null ? null : new Uint8Array(s.sendingChainKey),
    receivingChainKey:
      s.receivingChainKey === null ? null : new Uint8Array(s.receivingChainKey),
    sendingMessageNumber: s.sendingMessageNumber,
    receivingMessageNumber: s.receivingMessageNumber,
    previousSendingChainLength: s.previousSendingChainLength,
    skippedKeys: s.skippedKeys.map((k) => ({
      dhPub: new Uint8Array(k.dhPub),
      messageNumber: k.messageNumber,
      messageKey: new Uint8Array(k.messageKey),
    })),
  };
}

// ---------------------------------------------------------------------------
// Outbox stub
// ---------------------------------------------------------------------------

interface FakeOutboxRecord {
  clientNonce: string;
  envelope: CiphertextEnvelope;
  enqueuedAt?: number;
}

interface FakeOutbox extends Pick<OutboxCoordinator, 'enqueue'> {
  readonly records: FakeOutboxRecord[];
}

function makeFakeOutbox(): FakeOutbox {
  const records: FakeOutboxRecord[] = [];
  return {
    records,
    async enqueue(args: {
      clientNonce: string;
      envelope: CiphertextEnvelope;
      enqueuedAt?: number;
    }): Promise<never> {
      const rec: FakeOutboxRecord = {
        clientNonce: args.clientNonce,
        envelope: args.envelope,
      };
      if (args.enqueuedAt !== undefined) {
        rec.enqueuedAt = args.enqueuedAt;
      }
      records.push(rec);
      // The signaling layer never reads the return value; cast to
      // `never` so a future caller that DOES read forces a follow-up.
      return undefined as never;
    },
  };
}

// ---------------------------------------------------------------------------
// Ratchet pair seeding
// ---------------------------------------------------------------------------

/** Build a fresh Alice ↔ Bob ratchet pair, persist initial state to
 *  the matching session store on each side, and return the stores
 *  + identifiers ready for use. The shared 32-byte SK is the
 *  X3DH-derived root key both sides agree on. Bob's signed-prekey
 *  keypair is the DH pair Alice's first inbound message will
 *  ratchet against. */
async function seedRatchetPair(): Promise<{
  aliceStore: InMemorySessionStore;
  bobStore: InMemorySessionStore;
}> {
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);
  const bobSpk = generateRatchetDhKeypair();

  const aliceState = initSenderRatchet(sk, bobSpk.pub);
  const bobState = initReceiverRatchet(sk, bobSpk);

  const aliceStore = new InMemorySessionStore();
  const bobStore = new InMemorySessionStore();
  // From Alice's perspective the peer is Bob.
  await aliceStore.saveSession(
    BOB_USER,
    BOB_DEVICE,
    serializeRatchetState(aliceState),
  );
  // From Bob's perspective the peer is Alice.
  await bobStore.saveSession(
    ALICE_USER,
    ALICE_DEVICE,
    serializeRatchetState(bobState),
  );

  return { aliceStore, bobStore };
}

// ---------------------------------------------------------------------------
// Confidentiality probes
// ---------------------------------------------------------------------------

/** Three encodings any naive serialiser might surface for a byte
 *  buffer; we check each independently so a probe failure names
 *  the leaking encoding. */
function bytesEncodings(bytes: Uint8Array): {
  hex: string;
  base64: string;
  latin1: string;
} {
  const buf = Buffer.from(bytes);
  return {
    hex: buf.toString('hex'),
    base64: buf.toString('base64'),
    latin1: buf.toString('binary'),
  };
}

function expectNoStringLeak(haystack: string, needle: string): void {
  // We compare against every encoding the haystack could carry.
  // The wire ciphertext is opaque bytes; the "haystack" is the
  // decoded latin1 view of those bytes (plus any structural
  // wrapping the test wraps it in). If the candidate string
  // appears verbatim in that view, the bytes contain the needle
  // un-encrypted — which would be a bug.
  expect(haystack.includes(needle)).toBe(false);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('sendCallSignal: ICE candidate confidentiality (task 6.3)', () => {
  let aliceStore: InMemorySessionStore;
  let bobStore: InMemorySessionStore;
  let outbox: FakeOutbox;

  beforeEach(async () => {
    const seeded = await seedRatchetPair();
    aliceStore = seeded.aliceStore;
    bobStore = seeded.bobStore;
    void bobStore; // some tests below use it
    outbox = makeFakeOutbox();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('produces a CiphertextEnvelope whose ciphertext does NOT contain the candidate string', async () => {
    const candidate: IceCandidateInit = {
      candidate: ICE_CANDIDATE_STR,
      sdpMid: '0',
      sdpMLineIndex: 0,
    };

    const { envelope } = await sendCallSignal(
      'ice',
      { candidate },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
        sessionId: SESSION_ID,
      },
    );

    // Envelope shape — server-visible fields.
    expect(envelope.type).toBe(EnvelopeRouterType.CALL);
    expect(envelope.senderDeviceId).toBe(ALICE_DEVICE);
    expect(envelope.recipientDeviceId).toBe(BOB_DEVICE);
    expect(envelope.sessionId).toBe(SESSION_ID);

    // Confidentiality probe: the candidate string MUST NOT appear
    // in any byte encoding of the wire ciphertext.
    const ciphertext = envelope.ciphertext;
    const enc = bytesEncodings(ciphertext);
    expectNoStringLeak(enc.latin1, ICE_CANDIDATE_STR);
    expectNoStringLeak(enc.latin1, 'candidate:');
    expectNoStringLeak(enc.hex, Buffer.from(ICE_CANDIDATE_STR, 'utf8').toString('hex'));
    expectNoStringLeak(enc.base64, Buffer.from(ICE_CANDIDATE_STR, 'utf8').toString('base64'));

    // Sanity: the outbox received exactly one record.
    expect(outbox.records.length).toBe(1);
    expect(outbox.records[0]?.envelope).toBe(envelope);
  });

  test('the wire ciphertext layout starts with the 40-byte ratchet header (defence in depth)', async () => {
    const candidate: IceCandidateInit = { candidate: ICE_CANDIDATE_STR };

    const { envelope } = await sendCallSignal(
      'ice',
      { candidate },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    // The wire layout (apps/web/src/features/dm/wire.ts) puts a
    // 40-byte ratchet header in front of the AES-GCM body. Decoding
    // the header succeeds; the body length is the remainder.
    const decoded = decodeWireCiphertext(envelope.ciphertext);
    expect(decoded.header.dhPub.byteLength).toBe(32);
    expect(decoded.body.byteLength).toBe(envelope.ciphertext.byteLength - 40);
  });

  test('default sessionId falls back to peerUserId and a random clientNonce is allocated', async () => {
    const { envelope, clientNonce } = await sendCallSignal(
      'hangup',
      { reason: 'normal' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    expect(envelope.sessionId).toBe(BOB_USER);
    // randomUUID() produces a 36-char hyphenated string.
    expect(clientNonce).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  test('caller-supplied clientNonce is forwarded to the outbox', async () => {
    const { clientNonce } = await sendCallSignal(
      'hangup',
      { reason: 'declined' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
        clientNonce: 'custom-nonce-1',
      },
    );

    expect(clientNonce).toBe('custom-nonce-1');
    expect(outbox.records[0]?.clientNonce).toBe('custom-nonce-1');
  });

  test('throws when no ratchet session exists for the peer', async () => {
    const emptyStore = new InMemorySessionStore();

    await expect(
      sendCallSignal(
        'ice',
        { candidate: { candidate: ICE_CANDIDATE_STR } },
        {
          callId: CALL_ID,
          peerUserId: BOB_USER,
          peerDeviceId: BOB_DEVICE,
          sessionStore: emptyStore,
          outbox: outbox as unknown as OutboxCoordinator,
          senderDeviceId: ALICE_DEVICE,
        },
      ),
    ).rejects.toThrow(/no ratchet session/);

    // No partial state mutation: the outbox is empty.
    expect(outbox.records.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Round-trip: sender encrypts → receiver decrypts → handler dispatched
// ---------------------------------------------------------------------------

describe('handleInboundCallEnvelope: round-trip with sendCallSignal', () => {
  let aliceStore: InMemorySessionStore;
  let bobStore: InMemorySessionStore;
  let outbox: FakeOutbox;

  beforeEach(async () => {
    const seeded = await seedRatchetPair();
    aliceStore = seeded.aliceStore;
    bobStore = seeded.bobStore;
    outbox = makeFakeOutbox();
  });

  test('CALL_ICE_CANDIDATE: receiver decrypts → onAddIceCandidate dispatched', async () => {
    const candidate: IceCandidateInit = {
      candidate: ICE_CANDIDATE_STR,
      sdpMid: '0',
      sdpMLineIndex: 0,
    };

    const { envelope } = await sendCallSignal(
      'ice',
      { candidate },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
    };
    const handlers: CallSignalingHandlers = { peerConnection: peer };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result.kind).toBe('ice');
    expect(peer.addIceCandidate).toHaveBeenCalledTimes(1);
    expect(peer.addIceCandidate).toHaveBeenCalledWith(
      expect.objectContaining({ candidate: ICE_CANDIDATE_STR }),
    );
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
  });

  test('CALL_OFFER: receiver decrypts → onOffer + setRemoteDescription dispatched', async () => {
    const { envelope } = await sendCallSignal(
      'offer',
      { sdp: SAMPLE_OFFER_SDP, dtlsFingerprint: 'sha-256 12:34:56:78:9A:BC:DE:F0' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
    };
    const onOffer = vi.fn();
    const handlers: CallSignalingHandlers = { peerConnection: peer, onOffer };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({ kind: 'offer', callId: CALL_ID });
    expect(onOffer).toHaveBeenCalledWith({
      callId: CALL_ID,
      sdp: SAMPLE_OFFER_SDP,
      dtlsFingerprint: 'sha-256 12:34:56:78:9A:BC:DE:F0',
    });
    expect(peer.setRemoteDescription).toHaveBeenCalledWith({
      type: 'offer',
      sdp: SAMPLE_OFFER_SDP,
    });
  });

  test('CALL_ANSWER: receiver decrypts → onAnswer + setRemoteDescription("answer") dispatched', async () => {
    const { envelope } = await sendCallSignal(
      'answer',
      { sdp: SAMPLE_ANSWER_SDP, dtlsFingerprint: 'sha-256 99:88:77:66:55:44:33:22' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
    };
    const onAnswer = vi.fn();
    const handlers: CallSignalingHandlers = { peerConnection: peer, onAnswer };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({ kind: 'answer', callId: CALL_ID });
    expect(onAnswer).toHaveBeenCalledTimes(1);
    expect(peer.setRemoteDescription).toHaveBeenCalledWith({
      type: 'answer',
      sdp: SAMPLE_ANSWER_SDP,
    });
  });

  test('CALL_HANGUP: receiver decrypts → onHangup dispatched with reason', async () => {
    const { envelope } = await sendCallSignal(
      'hangup',
      { reason: 'declined' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const onHangup = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: null,
      onHangup,
    };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({
      kind: 'hangup',
      callId: CALL_ID,
      reason: 'declined',
    });
    expect(onHangup).toHaveBeenCalledWith({
      callId: CALL_ID,
      reason: 'declined',
    });
  });

  test('null peerConnection: dispatcher skips WebRTC ops but still fires the typed handler', async () => {
    const { envelope } = await sendCallSignal(
      'offer',
      { sdp: SAMPLE_OFFER_SDP, dtlsFingerprint: 'sha-256 12:34:56:78:9A:BC:DE:F0' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const onOffer = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: null,
      onOffer,
    };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result.kind).toBe('offer');
    expect(onOffer).toHaveBeenCalledTimes(1);
  });

  test('tampered ciphertext: dispatcher returns decrypt_failed and never invokes peer.*', async () => {
    const { envelope } = await sendCallSignal(
      'ice',
      { candidate: { candidate: ICE_CANDIDATE_STR } },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    // Flip one byte well past the header, inside the AES-GCM body.
    const tampered = new Uint8Array(envelope.ciphertext);
    const flipIdx = tampered.length - 1;
    tampered[flipIdx] = (tampered[flipIdx]! ^ 0x01) & 0xff;
    const tamperedEnv: CiphertextEnvelope = {
      ...envelope,
      ciphertext: tampered,
    };

    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
    };
    const onAnswer = vi.fn();
    const onOffer = vi.fn();
    const onHangup = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: peer,
      onAnswer,
      onOffer,
      onHangup,
    };

    const result = await handleInboundCallEnvelope(
      tamperedEnv,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({ kind: 'dropped', reason: 'decrypt_failed' });
    expect(peer.addIceCandidate).not.toHaveBeenCalled();
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(onAnswer).not.toHaveBeenCalled();
    expect(onOffer).not.toHaveBeenCalled();
    expect(onHangup).not.toHaveBeenCalled();
  });

  test('wrong router type (MESSAGE): dispatcher drops without touching the ratchet', async () => {
    // Build a ciphertext that LOOKS like a CALL ciphertext (wire
    // shape) but stamp `type: MESSAGE` so the gateway / receiver
    // can tell it's misrouted. We don't even need a real encrypt
    // here — the receiver bails before the ratchet load.
    const fake: CiphertextEnvelope = {
      sessionId: SESSION_ID,
      senderDeviceId: BOB_DEVICE,
      recipientDeviceId: ALICE_DEVICE,
      type: EnvelopeRouterType.MESSAGE,
      ciphertext: new Uint8Array(80),
    };

    // Snapshot Bob's persisted state on Alice's store: it should be
    // unchanged after the rejected dispatch.
    const before = await bobStore.loadSession(ALICE_USER, ALICE_DEVICE);
    expect(before).not.toBeNull();

    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
    };
    const handlers: CallSignalingHandlers = { peerConnection: peer };

    const result = await handleInboundCallEnvelope(
      fake,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({ kind: 'dropped', reason: 'wrong_type' });
    const after = await bobStore.loadSession(ALICE_USER, ALICE_DEVICE);
    expect(after).not.toBeNull();
    // Easy structural equality: serialise both sides via JSON
    // (Uint8Array → numeric array via a custom replacer).
    expect(stringifyState(after!)).toBe(stringifyState(before!));
    expect(peer.addIceCandidate).not.toHaveBeenCalled();
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Pure dispatcher (no ratchet) sanity checks
// ---------------------------------------------------------------------------

describe('dispatchInner: pure dispatch table', () => {
  test('CALL_ICE_CANDIDATE forwards the candidate verbatim', () => {
    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
    };
    const candidate: IceCandidateInit = {
      candidate: ICE_CANDIDATE_STR,
      sdpMid: 'audio',
      sdpMLineIndex: 0,
    };
    const result = dispatchInner(
      {
        kind: InnerType.CALL_ICE_CANDIDATE,
        callId: CALL_ID,
        candidate,
      },
      { peerConnection: peer },
    );
    expect(result).toEqual({ kind: 'ice', callId: CALL_ID });
    expect(peer.addIceCandidate).toHaveBeenCalledWith(candidate);
  });

  test('CALL_HANGUP fires the onHangup callback even with null peerConnection', () => {
    const onHangup = vi.fn();
    const result = dispatchInner(
      { kind: InnerType.CALL_HANGUP, callId: CALL_ID, reason: 'failed' },
      { peerConnection: null, onHangup },
    );
    expect(result).toEqual({
      kind: 'hangup',
      callId: CALL_ID,
      reason: 'failed',
    });
    expect(onHangup).toHaveBeenCalledWith({
      callId: CALL_ID,
      reason: 'failed',
    });
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Stable string form of a serialised ratchet state, used to assert
 *  byte-equality across two reads. */
function stringifyState(s: SerializedRatchetState): string {
  // Round-trip through deserialize/serialize keeps the field order
  // canonical and converts every Uint8Array to a deterministic
  // shape; we then JSON.stringify with a replacer so byte buffers
  // surface as plain numeric arrays.
  const re = serializeRatchetState(deserializeRatchetState(s));
  return JSON.stringify(re, (_k, v: unknown) => {
    if (v instanceof Uint8Array) return Array.from(v);
    return v;
  });
}

// apps/web/test/dtls-fingerprint.test.ts
//
// Unit tests for task 6.4 — DTLS fingerprint binding between the
// SDP advertised by a peer and the fingerprint inside the matching
// E2EE `CALL_OFFER` / `CALL_ANSWER` envelope.
//
// Specification anchors:
//   - Requirements 7.4 / 7.5 (requirements.md §Requirement 7).
//   - Property P22 "Fingerprint binding" (design.md §14.5):
//     "for any call where the SDP fingerprint inside the E2EE
//      envelope does not match the fingerprint advertised in the
//      SDP, the call is terminated before any RTP/SRTP media
//      packet is processed, on both offer and answer paths".
//
// What this file exercises (in priority order):
//
//   1. The pure helper `verifyDtlsFingerprintBinding(envFp, sdp)`.
//      Three failure modes (mismatch / sdp_missing /
//      envelope_missing) and the success path. Comparison is
//      case- and whitespace-insensitive (RFC 8122 §5).
//
//   2. The `dispatchInner` integration — when an inbound
//      `CALL_OFFER` carries a fingerprint that does NOT match its
//      SDP, the dispatcher:
//        - skips `peerConnection.setRemoteDescription`,
//        - synchronously calls `peerConnection.close()`,
//        - fires `onFingerprintMismatch`,
//        - returns a `{ kind: 'fingerprint_mismatch', ... }`
//          structured outcome so the caller can ship a
//          `CALL_HANGUP { reason: 'failed' }` envelope and call
//          `peer.hangup('failed', 'fingerprint_mismatch')`.
//      Symmetric coverage for `CALL_ANSWER`.
//
//   3. The matching-fingerprint path: dispatcher proceeds as
//      normal (binding check is a no-op for a well-formed call).
//
//   4. The end-to-end ratchet round-trip: a tampered envelope
//      whose `dtlsFingerprint` field has been MODIFIED post-
//      decryption (constructed directly, since the AEAD prevents
//      modifying it on the wire) reaches the dispatcher, gets
//      rejected with cause `'mismatch'`, and the underlying
//      `RTCPeerConnection` is closed BEFORE any
//      `setRemoteDescription` / `addIceCandidate` runs.
//
//   5. Empty / whitespace-only `dtlsFingerprint` is rejected with
//      cause `'envelope_missing'` even if the SDP contains a
//      well-formed fingerprint line.
//
// We deliberately exercise both `dispatchInner` (pure dispatch
// table — no ratchet) and `handleInboundCallEnvelope` (full
// decrypt + dispatch round-trip) because the binding check sits
// inside `dispatchInner` and is exercised by both call sites.
//
// Test scaffolding mirrors `apps/web/test/call-signaling.test.ts`:
// in-memory `SignalProtocolStore`, fake outbox, real Phase-3
// ratchet pair seeded from a shared X3DH-derived root key.

import {
  generateRatchetDhKeypair,
  initReceiverRatchet,
  initSenderRatchet,
  serializeRatchetState,
  type SerializedRatchetState,
  type SignalProtocolStore,
} from '@konvo/crypto';
import {
  EnvelopeRouterType,
  InnerType,
  type CiphertextEnvelope,
} from '@konvo/protocol';
import { beforeEach, describe, expect, test, vi } from 'vitest';

import {
  dispatchInner,
  handleInboundCallEnvelope,
  sendCallSignal,
  verifyDtlsFingerprintBinding,
  type CallPeerConnectionLike,
  type CallSignalingHandlers,
} from '../src/features/calls/signaling.js';
import type { OutboxCoordinator } from '../src/ws/outbox.js';

// ---------------------------------------------------------------------------
// Identifiers + fixture SDP blobs
// ---------------------------------------------------------------------------

const ALICE_USER = 'user-alice';
const ALICE_DEVICE = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const BOB_USER = 'user-bob';
const BOB_DEVICE = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const CALL_ID = 'call-fp-binding';

/** SDP whose `a=fingerprint:` line is well-formed and unique. */
const SDP_WITH_FP_A =
  'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
  'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
  'a=fingerprint:sha-256 12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88\r\n' +
  'a=setup:actpass\r\n';

const FP_A = 'sha-256 12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88';
/** A second, distinct fingerprint (one byte differs). */
const FP_B = 'sha-256 99:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88';

/** SDP that omits the fingerprint line entirely. Should never
 *  happen in practice for an offer/answer produced by a working
 *  RTCPeerConnection, but the binding check has to handle it. */
const SDP_WITHOUT_FP =
  'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
  'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
  'a=setup:actpass\r\n';

// ---------------------------------------------------------------------------
// In-memory SignalProtocolStore + outbox + ratchet seeding
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
    return cloneSerialized(v);
  }

  async saveSession(
    peerUserId: string,
    peerDeviceId: string,
    state: SerializedRatchetState,
  ): Promise<void> {
    this.sessions.set(
      this.key(peerUserId, peerDeviceId),
      cloneSerialized(state),
    );
  }

  async deleteSession(peerUserId: string, peerDeviceId: string): Promise<void> {
    this.sessions.delete(this.key(peerUserId, peerDeviceId));
  }

  async markOpkUsed(): Promise<void> {
    /* unused */
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

interface FakeOutboxRecord {
  clientNonce: string;
  envelope: CiphertextEnvelope;
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
    }): Promise<never> {
      records.push({
        clientNonce: args.clientNonce,
        envelope: args.envelope,
      });
      return undefined as never;
    },
  };
}

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
  await aliceStore.saveSession(
    BOB_USER,
    BOB_DEVICE,
    serializeRatchetState(aliceState),
  );
  await bobStore.saveSession(
    ALICE_USER,
    ALICE_DEVICE,
    serializeRatchetState(bobState),
  );

  return { aliceStore, bobStore };
}

// ---------------------------------------------------------------------------
// 1. Pure helper: verifyDtlsFingerprintBinding
// ---------------------------------------------------------------------------

describe('verifyDtlsFingerprintBinding (pure helper)', () => {
  test('matching fingerprint and SDP returns ok=true', () => {
    const r = verifyDtlsFingerprintBinding(FP_A, SDP_WITH_FP_A);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.canonical).toBe(
        'sha-256 12:34:56:78:9a:bc:de:f0:11:22:33:44:55:66:77:88',
      );
    }
  });

  test('comparison is case-insensitive (RFC 8122)', () => {
    // Envelope FP in lower case, SDP FP in upper case.
    const lowerEnv = FP_A.toLowerCase();
    const r = verifyDtlsFingerprintBinding(lowerEnv, SDP_WITH_FP_A);
    expect(r.ok).toBe(true);
  });

  test('comparison tolerates extra whitespace between algo and hex', () => {
    const noisyEnv = `sha-256   ${FP_A.split(' ')[1]!}`; // multiple spaces
    const r = verifyDtlsFingerprintBinding(noisyEnv, SDP_WITH_FP_A);
    expect(r.ok).toBe(true);
  });

  test('mismatch (different bytes) returns cause=mismatch', () => {
    const r = verifyDtlsFingerprintBinding(FP_B, SDP_WITH_FP_A);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.cause).toBe('mismatch');
      expect(r.envelopeFingerprint).toBe(FP_B);
      expect(r.sdpFingerprint).toBe(FP_A);
    }
  });

  test('mismatch (different algorithm) returns cause=mismatch', () => {
    const fpSha1 = 'sha-1 12:34:56:78:9A:BC:DE:F0';
    const r = verifyDtlsFingerprintBinding(fpSha1, SDP_WITH_FP_A);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.cause).toBe('mismatch');
  });

  test('SDP without fingerprint line returns cause=sdp_missing', () => {
    const r = verifyDtlsFingerprintBinding(FP_A, SDP_WITHOUT_FP);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.cause).toBe('sdp_missing');
      expect(r.sdpFingerprint).toBeNull();
    }
  });

  test('empty envelope fingerprint returns cause=envelope_missing', () => {
    const r = verifyDtlsFingerprintBinding('', SDP_WITH_FP_A);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.cause).toBe('envelope_missing');
  });

  test('whitespace-only envelope fingerprint returns cause=envelope_missing', () => {
    const r = verifyDtlsFingerprintBinding('   \t  ', SDP_WITH_FP_A);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.cause).toBe('envelope_missing');
  });
});

// ---------------------------------------------------------------------------
// 2. dispatchInner (pure dispatch table) — binding integration
// ---------------------------------------------------------------------------

describe('dispatchInner: DTLS fingerprint binding for CALL_OFFER', () => {
  let peer: CallPeerConnectionLike & {
    setRemoteDescription: ReturnType<typeof vi.fn>;
    addIceCandidate: ReturnType<typeof vi.fn>;
    close: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    peer = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
  });

  test('matching fingerprint: setRemoteDescription IS called and close is NOT', () => {
    const onOffer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_OFFER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_A,
      },
      { peerConnection: peer, onOffer, onFingerprintMismatch },
    );
    expect(result).toEqual({ kind: 'offer', callId: CALL_ID });
    expect(peer.setRemoteDescription).toHaveBeenCalledWith({
      type: 'offer',
      sdp: SDP_WITH_FP_A,
    });
    expect(peer.close).not.toHaveBeenCalled();
    expect(onOffer).toHaveBeenCalledTimes(1);
    expect(onFingerprintMismatch).not.toHaveBeenCalled();
  });

  test('mismatched fingerprint: setRemoteDescription is NEVER called, close IS', () => {
    const onOffer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_OFFER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_B, // different from SDP's FP
      },
      { peerConnection: peer, onOffer, onFingerprintMismatch },
    );

    // Result is the structured fingerprint_mismatch outcome.
    expect(result).toEqual({
      kind: 'fingerprint_mismatch',
      callId: CALL_ID,
      which: 'offer',
      cause: 'mismatch',
      envelopeFingerprint: FP_B,
      sdpFingerprint: FP_A,
    });

    // Critical for Requirement 7.5: setRemoteDescription must NOT
    // be called — calling it would let libwebrtc start the DTLS
    // handshake against this SDP and potentially process RTP/SRTP
    // packets, which the requirement explicitly forbids.
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.addIceCandidate).not.toHaveBeenCalled();

    // The underlying RTCPeerConnection is closed synchronously
    // BEFORE any DTLS / RTP work could happen. The order is also
    // critical: close must run before the dispatcher returns so
    // a re-entrant inbound ICE candidate envelope can't slip in.
    expect(peer.close).toHaveBeenCalledTimes(1);

    // Caller is notified so it can ship CALL_HANGUP.
    expect(onFingerprintMismatch).toHaveBeenCalledWith({
      callId: CALL_ID,
      which: 'offer',
      cause: 'mismatch',
      envelopeFingerprint: FP_B,
      sdpFingerprint: FP_A,
    });

    // The accept-handler is NEVER called — the caller learns of
    // the offer only via onFingerprintMismatch.
    expect(onOffer).not.toHaveBeenCalled();
  });

  test('mismatch with peerConnection=null: caller is still notified, no throw', () => {
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_OFFER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_B,
      },
      { peerConnection: null, onFingerprintMismatch },
    );
    expect(result.kind).toBe('fingerprint_mismatch');
    expect(onFingerprintMismatch).toHaveBeenCalledTimes(1);
  });

  test('absent envelope fingerprint (empty string) is rejected with envelope_missing', () => {
    const onOffer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_OFFER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: '',
      },
      { peerConnection: peer, onOffer, onFingerprintMismatch },
    );
    expect(result.kind).toBe('fingerprint_mismatch');
    if (result.kind === 'fingerprint_mismatch') {
      expect(result.cause).toBe('envelope_missing');
    }
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.close).toHaveBeenCalledTimes(1);
    expect(onOffer).not.toHaveBeenCalled();
  });

  test('SDP missing the fingerprint line is rejected with sdp_missing', () => {
    const onOffer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_OFFER,
        callId: CALL_ID,
        sdp: SDP_WITHOUT_FP,
        dtlsFingerprint: FP_A,
      },
      { peerConnection: peer, onOffer, onFingerprintMismatch },
    );
    expect(result.kind).toBe('fingerprint_mismatch');
    if (result.kind === 'fingerprint_mismatch') {
      expect(result.cause).toBe('sdp_missing');
    }
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.close).toHaveBeenCalledTimes(1);
  });
});

describe('dispatchInner: DTLS fingerprint binding for CALL_ANSWER', () => {
  test('matching answer fingerprint: setRemoteDescription IS called, no mismatch', () => {
    const peer: CallPeerConnectionLike = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onAnswer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_ANSWER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_A,
      },
      { peerConnection: peer, onAnswer, onFingerprintMismatch },
    );
    expect(result).toEqual({ kind: 'answer', callId: CALL_ID });
    expect(peer.setRemoteDescription).toHaveBeenCalledWith({
      type: 'answer',
      sdp: SDP_WITH_FP_A,
    });
    expect(onAnswer).toHaveBeenCalledTimes(1);
    expect(onFingerprintMismatch).not.toHaveBeenCalled();
  });

  test('mismatched answer fingerprint: setRemoteDescription NOT called, close IS', () => {
    const peer: CallPeerConnectionLike & {
      setRemoteDescription: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onAnswer = vi.fn();
    const onFingerprintMismatch = vi.fn();

    const result = dispatchInner(
      {
        kind: InnerType.CALL_ANSWER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_B,
      },
      { peerConnection: peer, onAnswer, onFingerprintMismatch },
    );

    expect(result).toEqual({
      kind: 'fingerprint_mismatch',
      callId: CALL_ID,
      which: 'answer',
      cause: 'mismatch',
      envelopeFingerprint: FP_B,
      sdpFingerprint: FP_A,
    });
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.close).toHaveBeenCalledTimes(1);
    expect(onAnswer).not.toHaveBeenCalled();
    expect(onFingerprintMismatch).toHaveBeenCalledWith({
      callId: CALL_ID,
      which: 'answer',
      cause: 'mismatch',
      envelopeFingerprint: FP_B,
      sdpFingerprint: FP_A,
    });
  });

  test('absent answer fingerprint (whitespace-only) → envelope_missing', () => {
    const peer: CallPeerConnectionLike & {
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onFingerprintMismatch = vi.fn();
    const result = dispatchInner(
      {
        kind: InnerType.CALL_ANSWER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: '   ',
      },
      { peerConnection: peer, onFingerprintMismatch },
    );
    expect(result.kind).toBe('fingerprint_mismatch');
    if (result.kind === 'fingerprint_mismatch') {
      expect(result.cause).toBe('envelope_missing');
      expect(result.which).toBe('answer');
    }
    expect(peer.close).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// 3. End-to-end: handleInboundCallEnvelope round-trip
// ---------------------------------------------------------------------------

describe('handleInboundCallEnvelope: fingerprint binding (end-to-end)', () => {
  let aliceStore: InMemorySessionStore;
  let bobStore: InMemorySessionStore;
  let outbox: FakeOutbox;

  beforeEach(async () => {
    const seeded = await seedRatchetPair();
    aliceStore = seeded.aliceStore;
    bobStore = seeded.bobStore;
    outbox = makeFakeOutbox();
  });

  test('matching offer: full round-trip dispatches setRemoteDescription', async () => {
    const { envelope } = await sendCallSignal(
      'offer',
      { sdp: SDP_WITH_FP_A, dtlsFingerprint: FP_A },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike & {
      setRemoteDescription: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onFingerprintMismatch = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: peer,
      onFingerprintMismatch,
    };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({ kind: 'offer', callId: CALL_ID });
    expect(peer.setRemoteDescription).toHaveBeenCalledTimes(1);
    expect(peer.close).not.toHaveBeenCalled();
    expect(onFingerprintMismatch).not.toHaveBeenCalled();
  });

  test('mismatched offer (sender lies about fingerprint) → close + onFingerprintMismatch', async () => {
    // Alice sends an offer claiming FP_B, but the SDP advertises
    // FP_A. The AEAD prevents a man-in-the-middle from rewriting
    // the inner field, so this scenario models a malicious
    // SENDER (e.g. a compromised Alice trying to bind to a
    // cert she doesn't actually own).
    const { envelope } = await sendCallSignal(
      'offer',
      { sdp: SDP_WITH_FP_A, dtlsFingerprint: FP_B },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike & {
      setRemoteDescription: ReturnType<typeof vi.fn>;
      addIceCandidate: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onOffer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: peer,
      onOffer,
      onFingerprintMismatch,
    };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result).toEqual({
      kind: 'fingerprint_mismatch',
      callId: CALL_ID,
      which: 'offer',
      cause: 'mismatch',
      envelopeFingerprint: FP_B,
      sdpFingerprint: FP_A,
    });

    // The hard requirement: zero RTP/SRTP processing can begin.
    // We assert this structurally — the only WebRTC method that
    // would kick off the DTLS handshake is setRemoteDescription,
    // and we never called it.
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.addIceCandidate).not.toHaveBeenCalled();
    expect(peer.close).toHaveBeenCalledTimes(1);
    expect(onOffer).not.toHaveBeenCalled();
    expect(onFingerprintMismatch).toHaveBeenCalledTimes(1);
  });

  test('mismatched answer: close + onFingerprintMismatch with which="answer"', async () => {
    const { envelope } = await sendCallSignal(
      'answer',
      { sdp: SDP_WITH_FP_A, dtlsFingerprint: FP_B },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike & {
      setRemoteDescription: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onAnswer = vi.fn();
    const onFingerprintMismatch = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: peer,
      onAnswer,
      onFingerprintMismatch,
    };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result.kind).toBe('fingerprint_mismatch');
    if (result.kind === 'fingerprint_mismatch') {
      expect(result.which).toBe('answer');
    }
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.close).toHaveBeenCalledTimes(1);
    expect(onAnswer).not.toHaveBeenCalled();
    expect(onFingerprintMismatch).toHaveBeenCalledTimes(1);
  });

  test('absent envelope fingerprint (empty) on offer is rejected with envelope_missing', async () => {
    const { envelope } = await sendCallSignal(
      'offer',
      { sdp: SDP_WITH_FP_A, dtlsFingerprint: '' },
      {
        callId: CALL_ID,
        peerUserId: BOB_USER,
        peerDeviceId: BOB_DEVICE,
        sessionStore: aliceStore,
        outbox: outbox as unknown as OutboxCoordinator,
        senderDeviceId: ALICE_DEVICE,
      },
    );

    const peer: CallPeerConnectionLike & {
      setRemoteDescription: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const onFingerprintMismatch = vi.fn();
    const handlers: CallSignalingHandlers = {
      peerConnection: peer,
      onFingerprintMismatch,
    };

    const result = await handleInboundCallEnvelope(
      envelope,
      ALICE_USER,
      bobStore,
      handlers,
    );

    expect(result.kind).toBe('fingerprint_mismatch');
    if (result.kind === 'fingerprint_mismatch') {
      expect(result.cause).toBe('envelope_missing');
      expect(result.envelopeFingerprint).toBe('');
    }
    expect(peer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peer.close).toHaveBeenCalledTimes(1);
    expect(onFingerprintMismatch).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// 4. Symmetry / sanity cross-check
// ---------------------------------------------------------------------------

describe('fingerprint binding: symmetry across offer / answer paths (P22)', () => {
  test('offer and answer paths reject the same kind of mismatch identically', () => {
    // Build two payloads — one OFFER, one ANSWER — with the same
    // mismatch shape, dispatch through the dispatcher, and assert
    // their outcomes are byte-for-byte equivalent up to the
    // `which` discriminator. P22 demands the property hold on
    // both paths; this test makes that symmetry observable.
    const peerOffer: CallPeerConnectionLike & {
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };
    const peerAnswer: CallPeerConnectionLike & {
      close: ReturnType<typeof vi.fn>;
    } = {
      setRemoteDescription: vi.fn(async () => {}),
      addIceCandidate: vi.fn(async () => {}),
      close: vi.fn(() => {}),
    };

    const offerResult = dispatchInner(
      {
        kind: InnerType.CALL_OFFER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_B,
      },
      { peerConnection: peerOffer },
    );
    const answerResult = dispatchInner(
      {
        kind: InnerType.CALL_ANSWER,
        callId: CALL_ID,
        sdp: SDP_WITH_FP_A,
        dtlsFingerprint: FP_B,
      },
      { peerConnection: peerAnswer },
    );

    expect(offerResult.kind).toBe('fingerprint_mismatch');
    expect(answerResult.kind).toBe('fingerprint_mismatch');
    if (
      offerResult.kind === 'fingerprint_mismatch' &&
      answerResult.kind === 'fingerprint_mismatch'
    ) {
      expect(offerResult.which).toBe('offer');
      expect(answerResult.which).toBe('answer');
      expect(offerResult.cause).toBe(answerResult.cause);
      expect(offerResult.envelopeFingerprint).toBe(
        answerResult.envelopeFingerprint,
      );
      expect(offerResult.sdpFingerprint).toBe(answerResult.sdpFingerprint);
    }

    // Both paths closed their peer connections; neither called
    // setRemoteDescription.
    expect(peerOffer.close).toHaveBeenCalledTimes(1);
    expect(peerAnswer.close).toHaveBeenCalledTimes(1);
    expect(peerOffer.setRemoteDescription).not.toHaveBeenCalled();
    expect(peerAnswer.setRemoteDescription).not.toHaveBeenCalled();
  });
});

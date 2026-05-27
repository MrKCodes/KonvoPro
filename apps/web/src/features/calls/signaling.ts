// apps/web/src/features/calls/signaling.ts
//
// E2EE call-signaling envelope wrapper (task 6.3).
//
// Responsibilities — design.md §13.5 + Requirements 7.2, 7.3, 11.8,
// and the P23 property "ICE candidate confidentiality":
//
//   - Wrap each `CALL_OFFER`, `CALL_ANSWER`, `CALL_ICE_CANDIDATE`,
//     and `CALL_HANGUP` inner payload in a `CiphertextEnvelope` so
//     the server (`apps/api/src/ws/gateway.ts`) only ever sees
//     opaque ratchet ciphertext bytes. The server routes such
//     envelopes through the same SEND_ENVELOPE / Redis fan-out
//     path as DM messages but with `type: EnvelopeRouterType.CALL`,
//     never decrypting and never logging the candidate strings
//     (the obs/logger.ts redaction layer also blocks `ciphertext`
//     and `body` fields at any depth as defense-in-depth).
//
//   - On the receive side, ratchet-decrypt the inbound CALL
//     envelope, parse the inner shape by discriminator, and
//     dispatch to the supplied `RTCPeerConnection`-shaped target:
//       * `CALL_OFFER`  → setRemoteDescription({ type: 'offer',  sdp }).
//       * `CALL_ANSWER` → setRemoteDescription({ type: 'answer', sdp }).
//       * `CALL_ICE_CANDIDATE` → addIceCandidate(candidate).
//       * `CALL_HANGUP` → hangup callback + close peer connection.
//
// Why a standalone module (not folded into peer.ts):
//   peer.ts (task 6.2) is a pure WebRTC primitive — it owns the
//   `RTCPeerConnection`, the watchdog timers, and the local
//   getUserMedia stream. It deliberately knows NOTHING about the
//   ratchet, the `CiphertextEnvelope` shape, or msgpack. Wrapping
//   the signaling here keeps the ratchet/transport coupling on
//   the call-feature side of the package boundary, mirroring how
//   DM uses `dm/controller.ts` + `dm/wire.ts` to bridge between
//   `peer`-equivalent storage primitives and the WS transport.
//
// What this module does NOT do:
//   - Encryption parameter selection (we always use the persisted
//     ratchet for `(peerUserId, peerDeviceId)`).
//   - Session establishment. The caller MUST have run X3DH
//     beforehand so `sessionStore.loadSession(...)` resolves to a
//     non-null state. A null session at send time is a programmer
//     error and is surfaced as a thrown `Error`.
//   - DTLS fingerprint binding (task 6.4) — that's a downstream
//     check the caller performs against the inner payload after
//     `handleInboundCallEnvelope` resolves.
//   - Hangup transport. `peer.ts:hangup()` is the renderer-side
//     teardown; this module only ships the `CALL_HANGUP` envelope
//     to the peer. The two are sequenced by the call UI (send the
//     envelope first, then call `peer.hangup()`), per
//     Requirement 7.16.

import {
  encryptToDevice,
  decryptFromDevice,
  deserializeRatchetState,
  serializeRatchetState,
  type SignalProtocolStore,
} from '@konvo/crypto';
import {
  EnvelopeRouterType,
  InnerType,
  type CiphertextEnvelope,
  type IceCandidateInit,
  type InnerPayload,
} from '@konvo/protocol';
import { decode as mpDecode, encode as mpEncode } from '@msgpack/msgpack';

import type { OutboxCoordinator } from '../../ws/outbox.js';

import { decodeWireCiphertext, encodeWireCiphertext } from '../dm/wire.js';
import { extractDtlsFingerprint } from './peer.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Discriminator selecting which `InnerType.CALL_*` shape to build.
 *
 *  Using a string-literal union (rather than the underlying
 *  `InnerType` numeric enum) keeps the public API of `sendCallSignal`
 *  readable — call sites in CallScreen.tsx will read
 *  `sendCallSignal('ice', ...)` rather than
 *  `sendCallSignal(InnerType.CALL_ICE_CANDIDATE, ...)`. The
 *  translation table to the wire enum is `KIND_TO_INNER_TYPE` below;
 *  any addition here must also be added there. */
export type CallSignalKind = 'offer' | 'answer' | 'ice' | 'hangup';

/** Per-kind payload shape accepted by `sendCallSignal`. The discriminator
 *  is implicit in the `CallSignalKind` argument; we keep these as a
 *  closed record so a typo in `kind` produces a compile error rather
 *  than a runtime "missing field" surprise. */
export interface CallSignalPayloads {
  offer: { readonly sdp: string; readonly dtlsFingerprint: string };
  answer: { readonly sdp: string; readonly dtlsFingerprint: string };
  ice: { readonly candidate: IceCandidateInit };
  hangup: { readonly reason: 'normal' | 'busy' | 'declined' | 'failed' };
}

/** Common arguments to every signaling send. Carrying these as a
 *  positional record (rather than spreading into the function) keeps
 *  call sites readable when the kind argument is one slot away from
 *  the peer ids and shrinks the diff for any future field. */
export interface CallSignalRoute {
  readonly callId: string;
  readonly peerUserId: string;
  readonly peerDeviceId: string;
  readonly sessionStore: SignalProtocolStore;
  readonly outbox: OutboxCoordinator;
  /** Stable device id of the *local* browser. Stamped on the
   *  envelope's `senderDeviceId` so the gateway's
   *  `envelope.senderDeviceId === ctx.deviceId` authority check
   *  (Requirement 12.3 / P17) passes. */
  readonly senderDeviceId: string;
  /** Opaque server-routing session id. Mirrors the DM controller's
   *  `resolveSessionId` shape; defaults to `peerUserId` when omitted
   *  so single-device wiring works without further setup. */
  readonly sessionId?: string;
  /** Optional override for the per-envelope `clientNonce`. Defaults
   *  to `crypto.randomUUID()`. The outbox de-duplicates on this
   *  value, so a deliberate retry with a stable nonce produces a
   *  single ciphertext row server-side (Requirement 12.9 / P13). */
  readonly clientNonce?: string;
  /** Optional wall-clock override for the outbox `enqueuedAt`
   *  field. Defaults to `Date.now`. */
  readonly now?: () => number;
}

// ---------------------------------------------------------------------------
// Inner-type translation
// ---------------------------------------------------------------------------

/** String-kind → `InnerType` numeric discriminator. Kept module-local
 *  so the only place a caller passes a numeric InnerType is the
 *  protocol/envelopes shape itself. */
const KIND_TO_INNER_TYPE: Readonly<Record<CallSignalKind, InnerType>> = {
  offer: InnerType.CALL_OFFER,
  answer: InnerType.CALL_ANSWER,
  ice: InnerType.CALL_ICE_CANDIDATE,
  hangup: InnerType.CALL_HANGUP,
};

/** Build the typed `InnerPayload` for the supplied kind + payload.
 *
 *  Why this lives in a single switch rather than four sibling
 *  factories: the four `InnerType.CALL_*` shapes share zero fields
 *  beyond `callId`, so a unified factory would not save any code
 *  duplication. Keeping them inline makes the kind-to-shape mapping
 *  trivially auditable in one place. */
function buildInnerPayload<K extends CallSignalKind>(
  kind: K,
  callId: string,
  payload: CallSignalPayloads[K],
): InnerPayload {
  switch (kind) {
    case 'offer': {
      const p = payload as CallSignalPayloads['offer'];
      return {
        kind: InnerType.CALL_OFFER,
        callId,
        sdp: p.sdp,
        dtlsFingerprint: p.dtlsFingerprint,
      };
    }
    case 'answer': {
      const p = payload as CallSignalPayloads['answer'];
      return {
        kind: InnerType.CALL_ANSWER,
        callId,
        sdp: p.sdp,
        dtlsFingerprint: p.dtlsFingerprint,
      };
    }
    case 'ice': {
      const p = payload as CallSignalPayloads['ice'];
      return {
        kind: InnerType.CALL_ICE_CANDIDATE,
        callId,
        candidate: p.candidate,
      };
    }
    case 'hangup': {
      const p = payload as CallSignalPayloads['hangup'];
      return {
        kind: InnerType.CALL_HANGUP,
        callId,
        reason: p.reason,
      };
    }
    default: {
      // Exhaustiveness guard: any addition to `CallSignalKind`
      // without a case here is a compile error.
      const _exhaustive: never = kind;
      throw new Error(`buildInnerPayload: unknown kind ${String(_exhaustive)}`);
    }
  }
}

// Re-export so the InnerType lookup is stable across the call feature.
export { KIND_TO_INNER_TYPE };

// ---------------------------------------------------------------------------
// msgpack encoding
// ---------------------------------------------------------------------------

/** Encode an inner payload to a msgpack byte buffer suitable for
 *  feeding into `encryptToDevice`.
 *
 *  We bypass `@konvo/protocol`'s codec because that codec is
 *  scoped to the wire-format envelopes / WS frames. Encoding the
 *  inner payload is intentionally straight msgpack — the bytes are
 *  about to be encrypted, the receiver decrypts them, and only
 *  then is the structural shape examined. The msgpack codec's
 *  shape validators (`validateEnvelopeShape` etc.) intentionally
 *  reject unknown discriminators, which would prevent us from
 *  encoding a `CALL_*` inner type that the codec doesn't model.
 *
 *  `useBigInt64` matches the protocol codec for consistency, even
 *  though no `bigint` survives in `InnerPayload` shapes today. */
function encodeInnerPayload(inner: InnerPayload): Uint8Array {
  return mpEncode(inner, { useBigInt64: true });
}

/** Decode an inner payload from a msgpack byte buffer. Returns
 *  `null` if the bytes are malformed. We deliberately do NOT
 *  re-validate the shape here; the call-side `dispatch` switch
 *  is the gating layer. */
function decodeInnerPayload(bytes: Uint8Array): InnerPayload | null {
  try {
    const v = mpDecode(bytes, { useBigInt64: true }) as unknown;
    if (!isCallInnerPayload(v)) return null;
    return v;
  } catch {
    return null;
  }
}

/** Narrow an arbitrary `unknown` to one of the four `InnerType.CALL_*`
 *  payload shapes. Anything outside the call-signaling slice
 *  (TEXT / VOICE_NOTE / ATTACHMENT / ACK_* / TYPING) is rejected
 *  even if msgpack decoded a structurally valid object — the call
 *  receive path must never accept a DM payload pretending to be a
 *  signaling message.
 *
 *  Failure to narrow drops the envelope on the floor (the `dispatch`
 *  caller logs nothing, mirroring the DM controller's "tampered ⇒
 *  inert placeholder" discipline so we don't leak signal about
 *  partial decode states). */
function isCallInnerPayload(v: unknown): v is InnerPayload {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as { kind?: unknown };
  switch (o.kind) {
    case InnerType.CALL_OFFER:
    case InnerType.CALL_ANSWER: {
      const p = v as { callId?: unknown; sdp?: unknown; dtlsFingerprint?: unknown };
      return (
        typeof p.callId === 'string' &&
        typeof p.sdp === 'string' &&
        typeof p.dtlsFingerprint === 'string'
      );
    }
    case InnerType.CALL_ICE_CANDIDATE: {
      const p = v as { callId?: unknown; candidate?: unknown };
      return typeof p.callId === 'string' && typeof p.candidate === 'object';
    }
    case InnerType.CALL_HANGUP: {
      const p = v as { callId?: unknown; reason?: unknown };
      return (
        typeof p.callId === 'string' &&
        (p.reason === 'normal' ||
          p.reason === 'busy' ||
          p.reason === 'declined' ||
          p.reason === 'failed')
      );
    }
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------------

/**
 * Encrypt and enqueue a call-signaling envelope.
 *
 * The data flow:
 *   1. Build the typed `InnerPayload` for `kind` + `payload`.
 *   2. msgpack-encode it.
 *   3. Load the persisted ratchet state for `(peerUserId,
 *      peerDeviceId)`. Throws if no session exists — call signaling
 *      cannot bootstrap a session, the caller must run X3DH first.
 *   4. `encryptToDevice(state, msgpackBytes)` → advances the chain;
 *      we persist the new state IMMEDIATELY so a crash mid-fanout
 *      leaves a consistent ratchet on disk (mirrors the DM controller
 *      contract).
 *   5. Splice the ratchet header onto the AES-GCM body via
 *      `encodeWireCiphertext` (the same wire format DMs use, so the
 *      server's ciphertext column carries one uniform layout
 *      regardless of envelope router type).
 *   6. Build a `CiphertextEnvelope` with `type:
 *      EnvelopeRouterType.CALL` and enqueue via the outbox. The
 *      outbox persists the row before sending, so a transient WS
 *      disconnect mid-send leaves the envelope queued for replay
 *      after the next `HELLO_OK` (Requirement 4.7 / 4.8).
 *
 * Idempotency: the outbox de-duplicates on `clientNonce`. A retry
 * with the same nonce sends a single ciphertext to the server, but
 * the ratchet has already advanced — the second `encryptToDevice`
 * would consume a second message key. To support deliberate retries
 * the caller MUST capture and re-pass the original nonce; we do
 * NOT auto-retry from this layer. (DM `retry()` re-encrypts on
 * purpose, accepting an extra ratchet step; for call signaling
 * the latency budget is shorter and we keep this layer minimal.)
 */
export async function sendCallSignal<K extends CallSignalKind>(
  kind: K,
  payload: CallSignalPayloads[K],
  route: CallSignalRoute,
): Promise<{ readonly clientNonce: string; readonly envelope: CiphertextEnvelope }> {
  const inner = buildInnerPayload(kind, route.callId, payload);
  const innerBytes = encodeInnerPayload(inner);

  const persisted = await route.sessionStore.loadSession(
    route.peerUserId,
    route.peerDeviceId,
  );
  if (persisted === null) {
    // The DM controller surfaces this as a tamper-equivalent inbound
    // placeholder (the inbound side is best-effort), but for
    // outbound signaling there's no fallback — without an
    // established ratchet we cannot encrypt at all.
    throw new Error(
      `sendCallSignal: no ratchet session for peer ${route.peerUserId}` +
        ` device ${route.peerDeviceId} — establish via X3DH first`,
    );
  }
  const inputState = deserializeRatchetState(persisted);
  const { state: nextState, ciphertext: body, header } = await encryptToDevice(
    inputState,
    innerBytes,
  );
  await route.sessionStore.saveSession(
    route.peerUserId,
    route.peerDeviceId,
    serializeRatchetState(nextState),
  );

  const wireCiphertext = encodeWireCiphertext(header, body);
  const envelope: CiphertextEnvelope = {
    sessionId: route.sessionId ?? route.peerUserId,
    senderDeviceId: route.senderDeviceId,
    recipientDeviceId: route.peerDeviceId,
    type: EnvelopeRouterType.CALL,
    ciphertext: wireCiphertext,
  };

  const clientNonce = route.clientNonce ?? defaultNonce();
  const enqueueArgs: Parameters<OutboxCoordinator['enqueue']>[0] = {
    clientNonce,
    envelope,
    ...(route.now !== undefined ? { enqueuedAt: route.now() } : {}),
  };
  await route.outbox.enqueue(enqueueArgs);

  return { clientNonce, envelope };
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

/** Minimal `RTCPeerConnection`-shaped surface dispatched into by
 *  `handleInboundCallEnvelope`. Kept as a structural type so tests
 *  can supply a plain object literal of `vi.fn`s without
 *  constructing a real `RTCPeerConnection`. The methods are the
 *  exact subset of WebRTC 1.0 we touch on the inbound path.
 *
 *  `close` is optional because the `IncomingRing` flow uses
 *  `peerConnection: null` and has nothing to close; for an active
 *  call the caller MUST supply a peer that exposes `close()` so
 *  the fingerprint-binding check (task 6.4) can synchronously
 *  tear the underlying connection down BEFORE the dispatcher
 *  would otherwise have called `setRemoteDescription` and
 *  triggered DTLS handshake / RTP flow. */
export interface CallPeerConnectionLike {
  setRemoteDescription(desc: RTCSessionDescriptionInit): Promise<void>;
  addIceCandidate(candidate: RTCIceCandidateInit): Promise<void>;
  close?(): void;
}

/** Bag of dispatch hooks invoked by `handleInboundCallEnvelope`.
 *
 *  All callbacks are fire-and-forget; the dispatcher does NOT await
 *  return values from `onHangup`. Throwing is treated as a
 *  programmer error and surfaces via the unhandled-rejection
 *  channel — we deliberately don't swallow it. */
export interface CallSignalingHandlers {
  /** `RTCPeerConnection`-like dispatch target. May be `null` when
   *  the local renderer has not yet constructed a peer (e.g. an
   *  `IncomingRing` state where the user has not accepted the
   *  call). In that case `setRemoteDescription` and
   *  `addIceCandidate` envelopes are buffered by the caller. */
  readonly peerConnection: CallPeerConnectionLike | null;
  /** Invoked when a `CALL_HANGUP` envelope is decrypted. The
   *  caller MUST tear down its `CallPeer` (peer.ts) and render the
   *  hangup UI. Receives the reason verbatim from the inner
   *  payload so the UI can branch on `'declined'` vs `'failed'`. */
  readonly onHangup?: (
    args: { readonly callId: string; readonly reason: 'normal' | 'busy' | 'declined' | 'failed' },
  ) => void;
  /** Invoked when an inbound CALL_OFFER decrypts. The caller
   *  decides whether to accept (and only then construct a peer
   *  + call `setRemoteDescription` + `createAnswer`). Receives
   *  the verbatim inner-payload fingerprint so the caller can
   *  enforce the binding check (task 6.4 / Requirement 7.5). */
  readonly onOffer?: (
    args: {
      readonly callId: string;
      readonly sdp: string;
      readonly dtlsFingerprint: string;
    },
  ) => void;
  /** Invoked when an inbound CALL_ANSWER decrypts. The caller
   *  is expected to call `setRemoteDescription` on its existing
   *  `RTCPeerConnection` after asserting the fingerprint binding
   *  (task 6.4). */
  readonly onAnswer?: (
    args: {
      readonly callId: string;
      readonly sdp: string;
      readonly dtlsFingerprint: string;
    },
  ) => void;
  /** Invoked when the dispatcher detects a DTLS fingerprint
   *  binding violation on a CALL_OFFER or CALL_ANSWER envelope
   *  (task 6.4 / Requirement 7.5). The dispatcher has ALREADY
   *  called `peerConnection.close()` (if a peer connection was
   *  attached) and skipped `setRemoteDescription`, so by the time
   *  this callback fires no DTLS / SRTP handshake can complete.
   *
   *  The caller MUST:
   *    1. Send an E2EE `CALL_HANGUP` envelope with
   *       `{ reason: 'failed' }` so the peer learns about the
   *       teardown.
   *    2. Call `peer.hangup('failed', 'fingerprint_mismatch')`
   *       on its `CallPeer` (peer.ts) to release media resources
   *       and surface the local subreason to the UI.
   *
   *  The `cause` field discriminates the three failure modes the
   *  binding check distinguishes:
   *    - `'mismatch'`     : envelope FP and SDP FP both present
   *                         but differ.
   *    - `'sdp_missing'`  : envelope carried a fingerprint but
   *                         the SDP has no `a=fingerprint:` line
   *                         — should be impossible for a working
   *                         RTCPeerConnection but we treat it as
   *                         a binding failure rather than crash.
   *    - `'envelope_missing'` : envelope inner payload had an
   *                         empty / whitespace-only fingerprint
   *                         field. (The envelope shape itself
   *                         requires a string; this catches a
   *                         peer that strips the value to bypass
   *                         the binding.) */
  readonly onFingerprintMismatch?: (
    args: {
      readonly callId: string;
      readonly which: 'offer' | 'answer';
      readonly cause: 'mismatch' | 'sdp_missing' | 'envelope_missing';
      readonly envelopeFingerprint: string;
      readonly sdpFingerprint: string | null;
    },
  ) => void;
}

/** Outcome of `handleInboundCallEnvelope`. Surfaces the dispatched
 *  inner-payload kind so the caller can correlate against UI
 *  state, and a `dropped` flag for the cases where the envelope
 *  was rejected (decrypt failure, malformed shape, wrong router
 *  type, fingerprint binding violation). */
export type HandleInboundCallResult =
  | { readonly kind: 'offer'; readonly callId: string }
  | { readonly kind: 'answer'; readonly callId: string }
  | { readonly kind: 'ice'; readonly callId: string }
  | { readonly kind: 'hangup'; readonly callId: string; readonly reason: 'normal' | 'busy' | 'declined' | 'failed' }
  | { readonly kind: 'dropped'; readonly reason: 'wrong_type' | 'no_session' | 'decrypt_failed' | 'malformed' }
  | {
      readonly kind: 'fingerprint_mismatch';
      readonly callId: string;
      readonly which: 'offer' | 'answer';
      readonly cause: 'mismatch' | 'sdp_missing' | 'envelope_missing';
      readonly envelopeFingerprint: string;
      readonly sdpFingerprint: string | null;
    };

/** Outcome of the binding check between an envelope-carried DTLS
 *  fingerprint (`dtlsFingerprint` field of `CALL_OFFER` /
 *  `CALL_ANSWER`) and the fingerprint advertised in the SDP itself.
 *
 *  The four states are mutually exclusive; `ok` is true iff both
 *  fingerprints are present and equal under the canonicalisation
 *  documented in `verifyDtlsFingerprintBinding`. */
export type FingerprintBindingResult =
  | { readonly ok: true; readonly canonical: string }
  | {
      readonly ok: false;
      readonly cause: 'mismatch' | 'sdp_missing' | 'envelope_missing';
      readonly envelopeFingerprint: string;
      readonly sdpFingerprint: string | null;
    };

/** Canonicalise a fingerprint string for case-insensitive,
 *  whitespace-tolerant comparison.
 *
 *  RFC 8122 §5: the algorithm token (`sha-256`, `sha-1`, …) is
 *  case-insensitive; the colon-separated hex bytes are
 *  case-insensitive. Browsers normalise to upper-case hex per
 *  the spec, but we don't rely on either side doing the same —
 *  lowering everything and trimming the leading `<algo> ` join
 *  gives a single comparable string. */
function canonicaliseFingerprint(fp: string): string {
  // Collapse internal whitespace runs (some SDPs use a single
  // space, others a tab) so `"sha-256\t12:34"` and
  // `"sha-256 12:34"` compare equal.
  return fp.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Compare the DTLS fingerprint claimed inside the decrypted E2EE
 * `CALL_OFFER` / `CALL_ANSWER` payload against the fingerprint the
 * peer's SDP actually advertises (Requirement 7.4 / 7.5, task 6.4).
 *
 * The check is the lynchpin of E2EE call security: an attacker who
 * can flip ciphertext at the gateway cannot mutate the inner
 * fingerprint (libsignal AEAD blocks tamper, P3) and cannot mutate
 * the SDP (it's inside the same encrypted payload), but COULD in
 * principle intercept the underlying DTLS handshake and substitute
 * a different certificate — hence the binding: the SDP fingerprint
 * the peer's RTCPeerConnection actually sees must equal the
 * fingerprint the peer advertised inside the E2EE envelope.
 *
 * Comparison rules:
 *   - both inputs are canonicalised via `canonicaliseFingerprint`
 *     (lower-case, single-space algo separator) — RFC 8122 makes
 *     fingerprint strings case-insensitive,
 *   - an empty / whitespace-only `envelopeFingerprint` is rejected
 *     as `'envelope_missing'`,
 *   - an SDP that does not contain an `a=fingerprint:` line is
 *     rejected as `'sdp_missing'`.
 *
 * Exported for unit tests + for any future call-control surface
 * that wants to run the check without going through the dispatcher.
 */
export function verifyDtlsFingerprintBinding(
  envelopeFingerprint: string,
  sdp: string,
): FingerprintBindingResult {
  const trimmedEnv = envelopeFingerprint.trim();
  if (trimmedEnv === '') {
    return {
      ok: false,
      cause: 'envelope_missing',
      envelopeFingerprint,
      sdpFingerprint: extractDtlsFingerprint(sdp),
    };
  }
  const sdpFp = extractDtlsFingerprint(sdp);
  if (sdpFp === null) {
    return {
      ok: false,
      cause: 'sdp_missing',
      envelopeFingerprint,
      sdpFingerprint: null,
    };
  }
  const canonEnv = canonicaliseFingerprint(envelopeFingerprint);
  const canonSdp = canonicaliseFingerprint(sdpFp);
  if (canonEnv !== canonSdp) {
    return {
      ok: false,
      cause: 'mismatch',
      envelopeFingerprint,
      sdpFingerprint: sdpFp,
    };
  }
  return { ok: true, canonical: canonEnv };
}

/**
 * Decrypt an inbound `EnvelopeRouterType.CALL` envelope and dispatch
 * to the supplied handlers.
 *
 * The four branches mirror `decryptFromDevice`:
 *   - `result.ok === true` → parse the inner payload, route by
 *     `kind`, return the structured result.
 *   - `error.kind === 'invalid_message'` → drop with
 *     `'decrypt_failed'`. The ratchet preserves state on this path
 *     (Requirement 4.11 / P3), so the persisted session is
 *     unchanged and a retry from the peer will decrypt cleanly if
 *     the bytes were corrupted in transit.
 *   - `error.kind === 'duplicate'` → drop with `'decrypt_failed'`
 *     (Requirement 4.12). A duplicate `CALL_*` envelope is benign
 *     — the gateway's idempotent-insert guarantee means the same
 *     row was redelivered after a transient disconnect.
 *   - `error.kind === 'message_lost'` → drop with `'decrypt_failed'`
 *     (Requirement 9.5). The skipped-keys store overflowed; for
 *     call signaling the loss is unrecoverable but the call may
 *     still be salvageable if subsequent envelopes decrypt — the
 *     caller's watchdog timers (peer.ts) will eventually terminate
 *     the call if media never flows.
 *
 * The post-call ratchet state IS persisted regardless of result
 * (matching DM controller discipline) so a `'message_lost'` outcome
 * advances state cleanly past the over-cap position.
 *
 * Type filter: envelopes whose `type` is not
 * `EnvelopeRouterType.CALL` are silently dropped with `'wrong_type'`
 * — call signaling and DM messages are routed by the WS dispatch
 * layer, but a robust receive path checks again here so a
 * misrouted envelope can't corrupt the call ratchet by accident.
 */
export async function handleInboundCallEnvelope(
  envelope: CiphertextEnvelope,
  peerUserId: string,
  sessionStore: SignalProtocolStore,
  handlers: CallSignalingHandlers,
): Promise<HandleInboundCallResult> {
  if (envelope.type !== EnvelopeRouterType.CALL) {
    return { kind: 'dropped', reason: 'wrong_type' };
  }

  let header;
  let body;
  try {
    const decoded = decodeWireCiphertext(envelope.ciphertext);
    header = decoded.header;
    body = decoded.body;
  } catch {
    return { kind: 'dropped', reason: 'malformed' };
  }

  const persisted = await sessionStore.loadSession(
    peerUserId,
    envelope.senderDeviceId,
  );
  if (persisted === null) {
    return { kind: 'dropped', reason: 'no_session' };
  }
  const inputState = deserializeRatchetState(persisted);
  const { state: nextState, result } = await decryptFromDevice(
    inputState,
    body,
    header,
  );

  // Persist post-call state regardless of outcome so 'message_lost'
  // advances ratchet correctly. For 'invalid_message' / 'duplicate'
  // the ratchet returned the input state unchanged; the save is a
  // semantic no-op (overwrite with equivalent bytes).
  await sessionStore.saveSession(
    peerUserId,
    envelope.senderDeviceId,
    serializeRatchetState(nextState),
  );

  if (!result.ok) {
    return { kind: 'dropped', reason: 'decrypt_failed' };
  }

  const inner = decodeInnerPayload(result.plaintext);
  if (inner === null) {
    return { kind: 'dropped', reason: 'malformed' };
  }

  return dispatchInner(inner, handlers);
}

/** Route a successfully-decrypted `InnerPayload.CALL_*` to the
 *  matching handler. Pulled out of `handleInboundCallEnvelope` so
 *  tests can call it directly with a hand-built inner payload
 *  (skipping the ratchet) when exercising the dispatch table.
 *
 *  DTLS fingerprint binding (task 6.4 / Requirement 7.5):
 *    For `CALL_OFFER` and `CALL_ANSWER` we run
 *    `verifyDtlsFingerprintBinding(inner.dtlsFingerprint, inner.sdp)`
 *    BEFORE invoking `setRemoteDescription`. On a mismatch we:
 *      1. Skip `setRemoteDescription` so libwebrtc never starts
 *         the DTLS handshake against this SDP — no RTP/SRTP
 *         packet can be processed.
 *      2. Synchronously call `peerConnection.close()` (when the
 *         caller supplied a peer connection that exposes it) so
 *         the underlying `RTCPeerConnection` is torn down before
 *         any further dispatcher work runs.
 *      3. Fire `onFingerprintMismatch` so the caller can send the
 *         `CALL_HANGUP { reason: 'failed' }` envelope and call
 *         `peer.hangup('failed', 'fingerprint_mismatch')` on its
 *         `CallPeer` to release media resources and surface the
 *         subreason to the UI.
 *      4. Return `{ kind: 'fingerprint_mismatch', ... }` so the
 *         caller of `handleInboundCallEnvelope` can correlate the
 *         outcome with its own UI state.
 *    The flow is symmetric: each peer runs the check on its own
 *    decryption path, so a tamper detected on one side terminates
 *    that side independently of the other side. */
export function dispatchInner(
  inner: InnerPayload,
  handlers: CallSignalingHandlers,
): HandleInboundCallResult {
  switch (inner.kind) {
    case InnerType.CALL_OFFER: {
      const binding = verifyDtlsFingerprintBinding(
        inner.dtlsFingerprint,
        inner.sdp,
      );
      if (!binding.ok) {
        return rejectFingerprintBinding(inner.callId, 'offer', binding, handlers);
      }
      handlers.onOffer?.({
        callId: inner.callId,
        sdp: inner.sdp,
        dtlsFingerprint: inner.dtlsFingerprint,
      });
      // Default behaviour: also feed the SDP into the existing
      // peer connection if one is attached. The caller may opt
      // out by providing `peerConnection: null` (e.g. the
      // IncomingRing state where the local peer hasn't been
      // constructed yet — the caller will set the description
      // after the user accepts).
      if (handlers.peerConnection !== null) {
        void handlers.peerConnection.setRemoteDescription({
          type: 'offer',
          sdp: inner.sdp,
        });
      }
      return { kind: 'offer', callId: inner.callId };
    }
    case InnerType.CALL_ANSWER: {
      const binding = verifyDtlsFingerprintBinding(
        inner.dtlsFingerprint,
        inner.sdp,
      );
      if (!binding.ok) {
        return rejectFingerprintBinding(inner.callId, 'answer', binding, handlers);
      }
      handlers.onAnswer?.({
        callId: inner.callId,
        sdp: inner.sdp,
        dtlsFingerprint: inner.dtlsFingerprint,
      });
      if (handlers.peerConnection !== null) {
        void handlers.peerConnection.setRemoteDescription({
          type: 'answer',
          sdp: inner.sdp,
        });
      }
      return { kind: 'answer', callId: inner.callId };
    }
    case InnerType.CALL_ICE_CANDIDATE: {
      if (handlers.peerConnection !== null) {
        // RTCIceCandidateInit and our protocol's IceCandidateInit
        // are structurally identical (the protocol type is
        // declared independently so the package stays Node-safe);
        // a plain assignment is sufficient at the wire boundary.
        void handlers.peerConnection.addIceCandidate(
          inner.candidate as RTCIceCandidateInit,
        );
      }
      return { kind: 'ice', callId: inner.callId };
    }
    case InnerType.CALL_HANGUP: {
      handlers.onHangup?.({ callId: inner.callId, reason: inner.reason });
      return { kind: 'hangup', callId: inner.callId, reason: inner.reason };
    }
    default: {
      // The narrowing in `isCallInnerPayload` ensures we never
      // reach this branch with a non-CALL inner type, but keep an
      // exhaustive `dropped` for any future protocol additions
      // (e.g. CALL_RENEGOTIATE) that haven't grown a handler yet.
      return { kind: 'dropped', reason: 'malformed' };
    }
  }
}

/** Internal helper for `dispatchInner` — encapsulates the four
 *  steps of the fingerprint-binding rejection path so the OFFER
 *  and ANSWER branches don't drift apart over time. */
function rejectFingerprintBinding(
  callId: string,
  which: 'offer' | 'answer',
  binding: Extract<FingerprintBindingResult, { ok: false }>,
  handlers: CallSignalingHandlers,
): HandleInboundCallResult {
  // Step 1: never call setRemoteDescription with this SDP — done
  // implicitly by returning before that branch runs.

  // Step 2: tear the peer connection down synchronously so no
  // further ICE / DTLS / RTP work happens. We guard with a try
  // because some test fakes don't expose `close`; the contract
  // for production peers (peer.ts) is that they DO.
  if (handlers.peerConnection !== null && handlers.peerConnection.close) {
    try {
      handlers.peerConnection.close();
    } catch {
      // Spec'd to not throw; ignore so the rejection completes.
    }
  }

  // Step 3: notify the caller so it can ship CALL_HANGUP and
  // call `peer.hangup('failed', 'fingerprint_mismatch')`.
  handlers.onFingerprintMismatch?.({
    callId,
    which,
    cause: binding.cause,
    envelopeFingerprint: binding.envelopeFingerprint,
    sdpFingerprint: binding.sdpFingerprint,
  });

  // Step 4: structured outcome for the dispatcher caller.
  return {
    kind: 'fingerprint_mismatch',
    callId,
    which,
    cause: binding.cause,
    envelopeFingerprint: binding.envelopeFingerprint,
    sdpFingerprint: binding.sdpFingerprint,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Mirror of `dm/controller.ts:defaultNonce`. Kept local rather than
 *  imported so the call feature has no source-level dependency on
 *  the DM feature beyond the shared wire-codec helper. */
function defaultNonce(): string {
  if (
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.randomUUID === 'function'
  ) {
    return globalThis.crypto.randomUUID();
  }
  return `call-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 12)}`;
}

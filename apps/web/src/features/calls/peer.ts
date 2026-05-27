// apps/web/src/features/calls/peer.ts
//
// Low-level WebRTC peer-connection wrapper for one-to-one E2EE calls.
//
// Scope (task 6.2):
//   This module owns the RTCPeerConnection lifecycle, the local
//   getUserMedia stream, and every call-watchdog timer the requirements
//   pin to a wall-clock deadline (ICE gathering, unanswered offer, lost
//   connection). It is deliberately decoupled from:
//
//     - WebSocket transport. ICE candidates and SDP descriptions are
//       handed to a caller-supplied callback; the caller is the one
//       that wraps them in a `CiphertextEnvelope` per requirement 7.2
//       and pushes them through `apps/web/src/ws/client.ts`.
//     - Crypto. We never touch identity keys, ratchets, or
//       safety-numbers from here; that lives behind `@konvo/crypto`.
//     - React. peer.ts is a plain class so it can be unit-tested
//       without a renderer; UI bindings live in a sibling file.
//
// Why a class with callbacks (and not e.g. an EventTarget):
//   The WebRTC primitives we wrap are themselves callback-shaped
//   (`pc.onicecandidate`, `pc.ontrack`, ...), so a class with a
//   `CallEvents` bag mirrors them 1:1 without forcing the caller to
//   subscribe/unsubscribe. The shape is also trivial to fake in tests:
//   we hand the constructor a plain object literal of vi.fn()s.
//
// Requirement → behavior map (cited inline at each enforcement site
// below, kept here as an index):
//   - 7.1   ICE candidate preference: callers wire host > srflx > relay
//           by ordering `iceServers`; we don't override.
//   - 7.7   48 kHz mono Opus / 1280×720@30 — see `mediaConstraints()`.
//   - 7.8   Mute/camera toggle without renegotiation — see
//           `setSenderTrackEnabled()`.
//   - 7.9   Reversible audio-only switch — see `switchToAudioOnly()` /
//           `resumeVideo()`.
//   - 7.13  >10 s lost connection ⇒ terminate('failed') — see
//           `handleConnectionStateChange()`.
//   - 7.14  45 s unanswered offer ⇒ terminate — see `armOfferTimer()`.
//   - 7.15  Permission denied at start ⇒ permission-required prompt,
//           do not initiate — see `start()`.
//   - 7.16  Hangup tears down within 500 ms — `hangup()` is fully
//           synchronous; the only async work is best-effort.
//   - 7.17  ICE gathering >10 s ⇒ terminate('failed', 'ice_timeout')
//           — see `armIceGatheringTimer()`.

/* eslint-disable @typescript-eslint/no-empty-function */

/** Constants pinned by requirement 7. Exposed for tests; not for tuning. */
export const ICE_GATHERING_TIMEOUT_MS = 10_000; // 7.17
export const UNANSWERED_OFFER_TIMEOUT_MS = 45_000; // 7.14
export const CONNECTION_LOST_TIMEOUT_MS = 10_000; // 7.13

/** Reasons the call was terminated. Mirrors the `reason` field of
 *  `InnerType.CALL_HANGUP` in `@konvo/protocol` so the UI can forward
 *  it directly into a `CALL_HANGUP` envelope without translation. */
export type TerminateReason = 'normal' | 'busy' | 'declined' | 'failed';

/** Construction-time configuration. */
export interface CallOptions {
  /** Stable call identifier shared by both peers; only used in logs. */
  readonly callId: string;
  /** ICE servers to hand to RTCPeerConnection. The caller is responsible
   *  for ordering host > srflx > relay per requirement 7.1; this module
   *  does not reorder or filter the list. */
  readonly iceServers: readonly RTCIceServer[];
  /** Whether to request a video track at start. Audio is always on. */
  readonly withVideo: boolean;
}

/** Callback bag invoked on peer-connection events.
 *
 *  All callbacks are fire-and-forget; CallPeer ignores any return value
 *  and does NOT await them. Throwing inside a callback is treated as a
 *  programmer error and surfaces via the unhandled rejection / error
 *  channel — peer.ts does not swallow it. */
export interface CallEvents {
  /** Local ICE candidate produced by the peer connection. A `null`
   *  candidate signals end-of-candidates (per WebRTC 1.0). The caller
   *  wraps this in an E2EE `CALL_ICE_CANDIDATE` envelope. */
  onIceCandidate(candidate: RTCIceCandidate | null): void;
  /** Mirrors `RTCPeerConnection.onconnectionstatechange`. */
  onConnectionStateChange(state: RTCPeerConnectionState): void;
  /** Remote media track + the streams it belongs to. */
  onRemoteTrack(track: MediaStreamTrack, streams: readonly MediaStream[]): void;
  /** Fires once after `createOffer` / `createAnswer` resolves and the
   *  local SDP is set. The string is `"<algo> <hex:hex:...>"` exactly
   *  as it appears in `a=fingerprint:` (e.g.
   *  `"sha-256 12:34:..."`). The caller embeds this in the
   *  `CALL_OFFER` / `CALL_ANSWER` E2EE payload (requirement 7.4). */
  onLocalDtlsFingerprint(fingerprint: string): void;
  /** Terminal — fires exactly once. After this, the peer is dead and
   *  no further callbacks will be invoked. `subreason` is provided
   *  when peer.ts has a more specific cause (`'permission_denied'`,
   *  `'ice_timeout'`, `'connection_lost'`, `'unanswered'`); it's
   *  absent when the caller hung up normally. */
  onTerminated(reason: TerminateReason, subreason?: string): void;
}

/** Subreason strings emitted by peer.ts and the call signaling
 *  layer. Kept as a string-literal union rather than an enum so
 *  callers can extend the set without a code change here.
 *
 *  Provenance:
 *   - `permission_denied` / `media_error`     ← peer.ts:start()
 *   - `ice_timeout`                            ← peer.ts:armIceGatheringTimer
 *   - `connection_lost`                        ← peer.ts:armConnectionLostTimer
 *   - `unanswered`                             ← peer.ts:armOfferTimer
 *   - `fingerprint_mismatch`                   ← signaling.ts (task 6.4)
 *                                                Fired when the SDP DTLS
 *                                                fingerprint advertised
 *                                                by the peer does not
 *                                                match the value carried
 *                                                inside the decrypted
 *                                                E2EE CALL_OFFER /
 *                                                CALL_ANSWER envelope. */
export type PeerSubreason =
  | 'permission_denied'
  | 'ice_timeout'
  | 'connection_lost'
  | 'unanswered'
  | 'media_error'
  | 'fingerprint_mismatch';

// ---------------------------------------------------------------------------
// SDP fingerprint extraction
// ---------------------------------------------------------------------------

/** Match the first `a=fingerprint:<algo> <colon-hex>` line in an SDP.
 *
 *  RFC 8122 §5: the line is session-level OR media-level. Either is
 *  acceptable for our purposes — both peers use a single DTLS context
 *  per `RTCPeerConnection`, so the algorithm + bytes are identical
 *  across every fingerprint line in the SDP. We grab the first one and
 *  trust libwebrtc to keep them consistent. */
const FINGERPRINT_RE = /^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]+)/m;

/** Extract the DTLS fingerprint from an SDP blob.
 *
 *  Returns `"<algo> <hex:hex:...>"` (e.g. `"sha-256 12:34:..."`) when a
 *  fingerprint line is present, or `null` when the SDP omits it (which
 *  should never happen for an offer/answer produced by a working
 *  `RTCPeerConnection`, but we don't crash if it does — the caller
 *  decides whether to terminate the call).
 *
 *  Exported for unit tests and for the envelope-binding layer (task
 *  6.3) which uses it to bind the peer's advertised SDP fingerprint
 *  to the value carried inside the E2EE `CALL_OFFER` / `CALL_ANSWER`
 *  payload (requirement 7.5). */
export function extractDtlsFingerprint(sdp: string): string | null {
  const m = FINGERPRINT_RE.exec(sdp);
  if (!m) return null;
  // `noUncheckedIndexedAccess` makes capture groups `string | undefined`.
  // Both groups are required by the regex to match, but the type system
  // can't see that, so we narrow defensively.
  const algo = m[1];
  const hex = m[2];
  if (!algo || !hex) return null;
  return `${algo} ${hex}`;
}

// ---------------------------------------------------------------------------
// CallPeer
// ---------------------------------------------------------------------------

/** Lifecycle states (informational; not exposed). */
type PeerState = 'idle' | 'started' | 'terminated';

/** Build the getUserMedia constraints pinned by requirement 7.7. */
function mediaConstraints(withVideo: boolean): MediaStreamConstraints {
  // 48 kHz mono Opus is enforced via the `audio` track constraints.
  // Browsers honor `sampleRate` and `channelCount` on a best-effort
  // basis (Chrome + Firefox both do at the time of writing). Opus is
  // the default codec selected by the SDP munger; we don't pin it
  // explicitly because doing so would require renegotiation tweaks
  // we explicitly avoid per requirement 7.8.
  const audio: MediaTrackConstraints = {
    sampleRate: 48_000,
    channelCount: 1,
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
  };
  if (!withVideo) {
    return { audio, video: false };
  }
  // Requirement 7.7: 1280×720@30 when video is enabled.
  const video: MediaTrackConstraints = {
    width: { ideal: 1280 },
    height: { ideal: 720 },
    frameRate: { ideal: 30 },
  };
  return { audio, video };
}

/** Wraps a single `RTCPeerConnection` and the timers/state that the
 *  call-acceptance criteria require.
 *
 *  Lifecycle:
 *    new CallPeer(opts, events)
 *      -> await peer.start()                            // [idle -> started]
 *           triggers getUserMedia, creates RTCPeerConnection, wires events.
 *           Permission denial transitions [started -> terminated].
 *      -> await peer.createOffer() OR peer.createAnswer(remoteOffer)
 *           produces local SDP, captures DTLS fingerprint, arms timers.
 *      -> peer.setRemoteDescription(answer)             // for caller side
 *           clears the unanswered-offer timer.
 *      -> peer.addRemoteIceCandidate(c)                 // 0..N times
 *      -> peer.toggleAudio / toggleVideo / switchToAudioOnly / resumeVideo
 *      -> peer.hangup('normal') OR auto-terminate from a watchdog timer
 *                                                       // [-> terminated]
 *
 *  Threading: every public method is intended to be called from the
 *  same JS event loop turn (i.e. the renderer thread). No locking is
 *  needed because RTCPeerConnection is single-threaded by spec. */
export class CallPeer {
  private readonly opts: CallOptions;
  private readonly events: CallEvents;

  private state: PeerState = 'idle';
  private pc: RTCPeerConnection | null = null;
  private localStream: MediaStream | null = null;
  private localFingerprint: string | null = null;

  // Watchdog timers. Each is an opaque ReturnType<typeof setTimeout>
  // because Node and the DOM disagree on the exact return type
  // (`Timeout` vs `number`); the helper conditional avoids the mismatch.
  private iceGatheringTimer: ReturnType<typeof setTimeout> | null = null;
  private offerTimer: ReturnType<typeof setTimeout> | null = null;
  private connectionLostTimer: ReturnType<typeof setTimeout> | null = null;

  /** Set to true after `setRemoteDescription` is called with an answer.
   *  Suppresses the unanswered-offer watchdog. */
  private remoteAnswered = false;

  constructor(opts: CallOptions, events: CallEvents) {
    this.opts = opts;
    this.events = events;
  }

  // -------------------------------------------------------------------------
  // Setup
  // -------------------------------------------------------------------------

  /**
   * Acquire the local media stream and construct the
   * `RTCPeerConnection`. Must be called exactly once before any of
   * `createOffer` / `createAnswer` / `setRemoteDescription`.
   *
   * On `NotAllowedError` (microphone or camera permission denied,
   * requirement 7.15) the peer enters `terminated` with reason
   * `failed` / subreason `permission_denied` and the original error
   * is re-thrown so the UI can render the permission-required prompt
   * AND know not to send any signaling envelopes.
   *
   * On any other getUserMedia rejection (no device, OS-level lock,
   * etc.) we terminate with subreason `media_error` and re-throw.
   */
  async start(): Promise<void> {
    if (this.state !== 'idle') {
      throw new Error('CallPeer.start() called more than once');
    }

    // Capture media first; if this rejects we never construct the
    // RTCPeerConnection, so there's nothing to clean up.
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia(
        mediaConstraints(this.opts.withVideo),
      );
    } catch (err) {
      this.state = 'started'; // so terminate() doesn't short-circuit
      const subreason = isPermissionDenied(err)
        ? 'permission_denied'
        : 'media_error';
      this.terminate('failed', subreason);
      throw err;
    }

    this.localStream = stream;
    this.state = 'started';

    const pc = new RTCPeerConnection({
      iceServers: [...this.opts.iceServers],
    });
    this.pc = pc;

    for (const track of stream.getTracks()) {
      pc.addTrack(track, stream);
    }

    pc.onicecandidate = (ev: RTCPeerConnectionIceEvent): void => {
      this.events.onIceCandidate(ev.candidate);
    };
    pc.ontrack = (ev: RTCTrackEvent): void => {
      this.events.onRemoteTrack(ev.track, ev.streams);
    };
    pc.onconnectionstatechange = (): void => {
      this.handleConnectionStateChange();
    };
    pc.onicegatheringstatechange = (): void => {
      this.handleIceGatheringStateChange();
    };
    pc.oniceconnectionstatechange = (): void => {
      // ICE state is a finer-grained signal than connection state and
      // is also covered by the >10s lost-connection rule. We funnel
      // through the same handler so the timer logic lives in one place.
      this.handleConnectionStateChange();
    };
  }

  // -------------------------------------------------------------------------
  // Signaling
  // -------------------------------------------------------------------------

  /**
   * Caller side: produce a local SDP offer, set it as the local
   * description, capture the DTLS fingerprint, and arm:
   *   - the 10 s ICE-gathering watchdog (req 7.17)
   *   - the 45 s unanswered-offer watchdog (req 7.14)
   *
   * The caller wraps the returned SDP in an E2EE `CALL_OFFER` envelope.
   */
  async createOffer(): Promise<RTCSessionDescriptionInit> {
    const pc = this.requirePc('createOffer');
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this.captureLocalFingerprint(offer.sdp);
    this.armIceGatheringTimer();
    this.armOfferTimer();
    return offer;
  }

  /**
   * Callee side: ingest the remote offer, produce a local SDP answer,
   * set it as the local description, capture the DTLS fingerprint,
   * and arm the ICE-gathering watchdog.
   *
   * The unanswered-offer watchdog does NOT apply on this side — the
   * remote peer has already sent the offer, so there's nothing to time
   * out for the answer.
   */
  async createAnswer(
    remoteOffer: RTCSessionDescriptionInit,
  ): Promise<RTCSessionDescriptionInit> {
    const pc = this.requirePc('createAnswer');
    await pc.setRemoteDescription(remoteOffer);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    this.captureLocalFingerprint(answer.sdp);
    this.armIceGatheringTimer();
    return answer;
  }

  /**
   * Caller side: ingest the peer's `CALL_ANSWER` SDP. Clears the
   * unanswered-offer watchdog (req 7.14) since we now have an answer.
   */
  async setRemoteDescription(desc: RTCSessionDescriptionInit): Promise<void> {
    const pc = this.requirePc('setRemoteDescription');
    await pc.setRemoteDescription(desc);
    this.remoteAnswered = true;
    this.clearTimer('offerTimer');
  }

  /**
   * Add a remote ICE candidate. The caller is expected to feed every
   * candidate received via `CALL_ICE_CANDIDATE` envelopes through here
   * in arrival order.
   */
  async addRemoteIceCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    const pc = this.requirePc('addRemoteIceCandidate');
    await pc.addIceCandidate(candidate);
  }

  // -------------------------------------------------------------------------
  // Mute / camera / audio-only toggles  (req 7.8, 7.9)
  // -------------------------------------------------------------------------

  /** Mute or unmute the outbound audio track without renegotiating. */
  toggleAudio(enabled: boolean): void {
    this.setSenderTrackEnabled('audio', enabled);
  }

  /** Enable or disable the outbound video track without renegotiating. */
  toggleVideo(enabled: boolean): void {
    this.setSenderTrackEnabled('video', enabled);
  }

  /** Disable the outbound video track. Idempotent.
   *
   *  Reversibility (req 7.9): this method only flips
   *  `RTCRtpSender.track.enabled`; it does NOT remove the sender,
   *  replace the track, or call `pc.removeTrack`. As a result,
   *  `resumeVideo()` re-enables the same track without renegotiating
   *  the peer connection identity (no new SDP exchange, no new DTLS
   *  handshake, no new fingerprint). */
  switchToAudioOnly(): void {
    this.toggleVideo(false);
  }

  /** Re-enable the outbound video track previously disabled by
   *  `switchToAudioOnly`. Idempotent and renegotiation-free. */
  resumeVideo(): void {
    this.toggleVideo(true);
  }

  // -------------------------------------------------------------------------
  // Termination
  // -------------------------------------------------------------------------

  /**
   * User-initiated hangup (requirement 7.16).
   *
   * Tears down synchronously: stops local tracks, closes the
   * `RTCPeerConnection`, clears every watchdog timer, and fires
   * `onTerminated`. The 500 ms budget cited in the requirement is
   * trivially met because no async work happens here — the only
   * `await`-able call (`pc.close`) is synchronous in the spec.
   *
   * The caller is responsible for sending the E2EE `CALL_HANGUP`
   * envelope BEFORE calling `hangup()` so the peer learns about the
   * teardown; peer.ts has no transport of its own.
   *
   * `subreason` is an OPTIONAL local-only label propagated to the
   * `onTerminated` callback so the UI can branch on the cause
   * (e.g. `'fingerprint_mismatch'` from the task 6.4 binding check;
   * the wire `CALL_HANGUP` envelope intentionally has no
   * `subreason` field because fingerprint binding is symmetric —
   * each side independently runs the check on its own ratchet
   * decryption and surfaces the same subreason locally).
   */
  hangup(reason: TerminateReason = 'normal', subreason?: string): void {
    if (subreason !== undefined) {
      this.terminate(reason, subreason);
    } else {
      this.terminate(reason);
    }
  }

  /** Returns the local DTLS fingerprint advertised in the most recent
   *  local SDP (offer or answer), or `null` if no SDP has been set
   *  yet. The format is `"<algo> <hex:hex:...>"`. */
  getDtlsFingerprint(): string | null {
    return this.localFingerprint;
  }

  /** Underlying peer connection — exposed for the envelope-binding
   *  layer (task 6.3) and for tests. Don't call lifecycle-mutating
   *  methods on it directly; route them through CallPeer. */
  getPeerConnection(): RTCPeerConnection | null {
    return this.pc;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private requirePc(op: string): RTCPeerConnection {
    if (this.state === 'terminated') {
      throw new Error(`CallPeer.${op}() after terminate`);
    }
    if (!this.pc) {
      throw new Error(`CallPeer.${op}() before start()`);
    }
    return this.pc;
  }

  private setSenderTrackEnabled(
    kind: 'audio' | 'video',
    enabled: boolean,
  ): void {
    if (!this.pc) return;
    for (const sender of this.pc.getSenders()) {
      const track = sender.track;
      if (track && track.kind === kind) {
        track.enabled = enabled;
      }
    }
  }

  private captureLocalFingerprint(sdp: string | undefined): void {
    if (!sdp) return;
    const fp = extractDtlsFingerprint(sdp);
    if (!fp) return;
    this.localFingerprint = fp;
    this.events.onLocalDtlsFingerprint(fp);
  }

  // ---- Timers ------------------------------------------------------------

  private armIceGatheringTimer(): void {
    // If gathering has already completed (small networks frequently
    // produce candidates synchronously), don't start the watchdog.
    if (this.pc && this.pc.iceGatheringState === 'complete') return;
    this.clearTimer('iceGatheringTimer');
    this.iceGatheringTimer = setTimeout(() => {
      this.iceGatheringTimer = null;
      // Requirement 7.17: ICE gathering > 10 s without a viable pair
      // ⇒ terminate('failed', 'ice_timeout').
      this.terminate('failed', 'ice_timeout');
    }, ICE_GATHERING_TIMEOUT_MS);
  }

  private armOfferTimer(): void {
    this.clearTimer('offerTimer');
    this.offerTimer = setTimeout(() => {
      this.offerTimer = null;
      if (this.remoteAnswered) return;
      // Requirement 7.14: 45 s unanswered offer ⇒ terminate. We pick
      // 'failed' as the reason because peer.ts has no way to tell
      // whether the silence was a network failure or a user decline;
      // higher layers may translate to 'declined' if they observe a
      // remote-side hangup envelope first.
      this.terminate('failed', 'unanswered');
    }, UNANSWERED_OFFER_TIMEOUT_MS);
  }

  private armConnectionLostTimer(): void {
    if (this.connectionLostTimer !== null) return; // already armed
    this.connectionLostTimer = setTimeout(() => {
      this.connectionLostTimer = null;
      // Requirement 7.13: connection state remained lost for >10 s.
      this.terminate('failed', 'connection_lost');
    }, CONNECTION_LOST_TIMEOUT_MS);
  }

  private clearTimer(
    name: 'iceGatheringTimer' | 'offerTimer' | 'connectionLostTimer',
  ): void {
    const t = this[name];
    if (t !== null) {
      clearTimeout(t);
      this[name] = null;
    }
  }

  private clearAllTimers(): void {
    this.clearTimer('iceGatheringTimer');
    this.clearTimer('offerTimer');
    this.clearTimer('connectionLostTimer');
  }

  // ---- Connection state machine -----------------------------------------

  private handleIceGatheringStateChange(): void {
    if (!this.pc) return;
    if (this.pc.iceGatheringState === 'complete') {
      this.clearTimer('iceGatheringTimer');
    }
  }

  private handleConnectionStateChange(): void {
    if (!this.pc) return;
    const cs = this.pc.connectionState;
    this.events.onConnectionStateChange(cs);

    switch (cs) {
      case 'connected':
        this.clearTimer('connectionLostTimer');
        break;
      case 'disconnected':
      case 'failed':
        // Requirement 7.13: debounce — wait 10 s for recovery before
        // pulling the plug. 'failed' is technically terminal in the
        // WebRTC spec, but giving the renderer a chance to observe
        // the same 10 s window across either flavour keeps the
        // user-visible behavior uniform.
        this.armConnectionLostTimer();
        break;
      case 'closed':
        this.clearTimer('connectionLostTimer');
        break;
      // 'new' and 'connecting' are intermediate; do nothing.
      default:
        break;
    }
  }

  // ---- Termination -------------------------------------------------------

  /** Idempotent terminal teardown. Safe to call from any state.
   *
   *  Order matters here:
   *    1. Mark the state first so re-entrant timer fires (e.g. a
   *       connection-lost timer that ticks while we're inside
   *       `pc.close()`) bail out at the top.
   *    2. Cancel timers before stopping tracks so we don't fire a
   *       redundant terminate() against an already-terminated peer.
   *    3. Stop local tracks (releases the camera/mic LED).
   *    4. Close the peer connection.
   *    5. Fire onTerminated last so the caller sees a fully-cleaned
   *       peer if it inspects state from inside the callback. */
  private terminate(reason: TerminateReason, subreason?: string): void {
    if (this.state === 'terminated') return;
    this.state = 'terminated';

    this.clearAllTimers();

    // Detach handlers first so closing the pc doesn't fire late
    // connectionstatechange events into the renderer.
    if (this.pc) {
      this.pc.onicecandidate = null;
      this.pc.ontrack = null;
      this.pc.onconnectionstatechange = null;
      this.pc.onicegatheringstatechange = null;
      this.pc.oniceconnectionstatechange = null;
    }

    if (this.localStream) {
      for (const track of this.localStream.getTracks()) {
        try {
          track.stop();
        } catch {
          // MediaStreamTrack.stop() is spec'd to not throw, but some
          // test fakes do; ignore so we keep tearing down.
        }
      }
      this.localStream = null;
    }

    if (this.pc) {
      try {
        this.pc.close();
      } catch {
        // RTCPeerConnection.close() is spec'd to not throw either,
        // but test fakes occasionally do; ignore.
      }
      this.pc = null;
    }

    if (subreason !== undefined) {
      this.events.onTerminated(reason, subreason);
    } else {
      this.events.onTerminated(reason);
    }
  }
}

// ---------------------------------------------------------------------------
// Error classification helpers
// ---------------------------------------------------------------------------

/** Detect getUserMedia permission-denial errors across browsers.
 *
 *  Spec name: `NotAllowedError`. Older Firefox + Safari variants used
 *  `PermissionDeniedError`; we accept either. We don't use
 *  `instanceof DOMException` because some test environments stub
 *  errors with plain objects that carry only a `.name`. */
function isPermissionDenied(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const name = (err as { name?: unknown }).name;
  return name === 'NotAllowedError' || name === 'PermissionDeniedError';
}

// apps/web/test/calls-peer.test.ts
//
// Unit tests for `apps/web/src/features/calls/peer.ts`.
//
// jsdom does not ship `RTCPeerConnection` or `navigator.mediaDevices`,
// so these tests install minimal fakes on `globalThis` and tear them
// down per-test. The fakes are deliberately incomplete — they
// implement only the surface peer.ts touches and nothing more — so
// changes in peer.ts that start using a new WebRTC method will fail
// loudly here rather than silently no-op.
//
// Coverage map:
//   - DTLS fingerprint extraction from a known SDP string.
//   - withVideo=false skips the video constraint in getUserMedia.
//   - Permission denial path (NotAllowedError) → terminates with
//     subreason `permission_denied` and re-throws.
//   - Hangup tears down within 500 ms (requirement 7.16).
//   - ICE gathering > 10 s → terminate('failed', 'ice_timeout')
//     (requirement 7.17).
//   - Unanswered offer 45 s → terminate (requirement 7.14).
//   - Connection lost > 10 s → terminate (requirement 7.13).
//   - toggleAudio / switchToAudioOnly flip `track.enabled` without
//     renegotiating (requirement 7.8, 7.9).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CallPeer,
  type CallEvents,
  CONNECTION_LOST_TIMEOUT_MS,
  extractDtlsFingerprint,
  ICE_GATHERING_TIMEOUT_MS,
  UNANSWERED_OFFER_TIMEOUT_MS,
} from '../src/features/calls/peer.js';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface FakeTrack {
  kind: 'audio' | 'video';
  enabled: boolean;
  stopped: boolean;
  stop(): void;
}

function makeTrack(kind: 'audio' | 'video'): FakeTrack {
  return {
    kind,
    enabled: true,
    stopped: false,
    stop(): void {
      this.stopped = true;
    },
  };
}

interface FakeStream {
  tracks: FakeTrack[];
  getTracks(): FakeTrack[];
}

function makeStream(tracks: FakeTrack[]): FakeStream {
  return {
    tracks,
    getTracks(): FakeTrack[] {
      return this.tracks;
    },
  };
}

interface FakeSender {
  track: FakeTrack | null;
}

const SAMPLE_SDP =
  'v=0\r\n' +
  'o=- 1 1 IN IP4 127.0.0.1\r\n' +
  's=-\r\n' +
  't=0 0\r\n' +
  'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
  'c=IN IP4 0.0.0.0\r\n' +
  'a=fingerprint:sha-256 12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88\r\n' +
  'a=setup:actpass\r\n';

class FakePeerConnection {
  static instances: FakePeerConnection[] = [];
  iceServers: readonly RTCIceServer[];
  connectionState: RTCPeerConnectionState = 'new';
  iceGatheringState: RTCIceGatheringState = 'new';
  iceConnectionState: RTCIceConnectionState = 'new';
  closed = false;

  onicecandidate:
    | ((ev: { candidate: RTCIceCandidate | null }) => void)
    | null = null;
  ontrack: ((ev: { track: FakeTrack; streams: FakeStream[] }) => void) | null =
    null;
  onconnectionstatechange: (() => void) | null = null;
  onicegatheringstatechange: (() => void) | null = null;
  oniceconnectionstatechange: (() => void) | null = null;

  private senders: FakeSender[] = [];

  constructor(config: RTCConfiguration) {
    this.iceServers = config.iceServers ?? [];
    FakePeerConnection.instances.push(this);
  }

  addTrack(track: FakeTrack, _stream: FakeStream): FakeSender {
    const sender: FakeSender = { track };
    this.senders.push(sender);
    return sender;
  }

  getSenders(): FakeSender[] {
    return this.senders;
  }

  async createOffer(): Promise<{ type: 'offer'; sdp: string }> {
    return { type: 'offer', sdp: SAMPLE_SDP };
  }

  async createAnswer(): Promise<{ type: 'answer'; sdp: string }> {
    return { type: 'answer', sdp: SAMPLE_SDP };
  }

  async setLocalDescription(_d: RTCSessionDescriptionInit): Promise<void> {
    /* no-op */
  }

  async setRemoteDescription(_d: RTCSessionDescriptionInit): Promise<void> {
    /* no-op */
  }

  async addIceCandidate(_c: RTCIceCandidateInit): Promise<void> {
    /* no-op */
  }

  close(): void {
    this.closed = true;
    this.connectionState = 'closed';
  }

  /** Test helper: simulate connection-state transition. */
  setConnectionState(s: RTCPeerConnectionState): void {
    this.connectionState = s;
    this.onconnectionstatechange?.();
  }

  /** Test helper: simulate ICE-gathering state transition. */
  setIceGatheringState(s: RTCIceGatheringState): void {
    this.iceGatheringState = s;
    this.onicegatheringstatechange?.();
  }
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface Harness {
  events: CallEvents & {
    onIceCandidate: ReturnType<typeof vi.fn>;
    onConnectionStateChange: ReturnType<typeof vi.fn>;
    onRemoteTrack: ReturnType<typeof vi.fn>;
    onLocalDtlsFingerprint: ReturnType<typeof vi.fn>;
    onTerminated: ReturnType<typeof vi.fn>;
  };
  getUserMedia: ReturnType<typeof vi.fn>;
}

function installFakes(opts: {
  withVideo: boolean;
  /** Override getUserMedia to throw with the given DOMException-ish name. */
  permissionError?: string;
}): Harness {
  const events = {
    onIceCandidate: vi.fn(),
    onConnectionStateChange: vi.fn(),
    onRemoteTrack: vi.fn(),
    onLocalDtlsFingerprint: vi.fn(),
    onTerminated: vi.fn(),
  };

  const getUserMedia = vi.fn(async () => {
    if (opts.permissionError !== undefined) {
      const err = new Error('denied');
      err.name = opts.permissionError;
      throw err;
    }
    const tracks: FakeTrack[] = [makeTrack('audio')];
    if (opts.withVideo) tracks.push(makeTrack('video'));
    return makeStream(tracks);
  });

  // Install on globalThis (jsdom doesn't have these).
  (globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection =
    FakePeerConnection as unknown;
  (globalThis as unknown as { navigator: { mediaDevices: unknown } }).navigator =
    {
      ...(globalThis as unknown as { navigator?: object }).navigator,
      mediaDevices: { getUserMedia },
    } as { mediaDevices: unknown };

  return { events, getUserMedia };
}

function uninstallFakes(): void {
  FakePeerConnection.instances = [];
  delete (globalThis as unknown as { RTCPeerConnection?: unknown })
    .RTCPeerConnection;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('extractDtlsFingerprint', () => {
  it('returns "<algo> <hex>" for a well-formed SDP', () => {
    expect(extractDtlsFingerprint(SAMPLE_SDP)).toBe(
      'sha-256 12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88',
    );
  });

  it('returns null when no fingerprint line is present', () => {
    expect(extractDtlsFingerprint('v=0\r\nm=audio 9\r\n')).toBeNull();
  });

  it('matches a session-level fingerprint at the top of the SDP', () => {
    const sdp =
      'v=0\r\n' +
      'a=fingerprint:sha-1 AA:BB:CC:DD\r\n' +
      'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n';
    expect(extractDtlsFingerprint(sdp)).toBe('sha-1 AA:BB:CC:DD');
  });
});

describe('CallPeer', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    uninstallFakes();
  });

  it('skips the video constraint when withVideo=false', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c1', iceServers: [], withVideo: false },
      h.events,
    );

    await peer.start();

    expect(h.getUserMedia).toHaveBeenCalledTimes(1);
    const call = h.getUserMedia.mock.calls[0]?.[0] as MediaStreamConstraints;
    expect(call.audio).toMatchObject({ sampleRate: 48_000, channelCount: 1 });
    expect(call.video).toBe(false);
  });

  it('requests 1280x720@30 video when withVideo=true', async () => {
    const h = installFakes({ withVideo: true });
    const peer = new CallPeer(
      { callId: 'c2', iceServers: [], withVideo: true },
      h.events,
    );

    await peer.start();

    const call = h.getUserMedia.mock.calls[0]?.[0] as MediaStreamConstraints;
    expect(call.video).toMatchObject({
      width: { ideal: 1280 },
      height: { ideal: 720 },
      frameRate: { ideal: 30 },
    });
  });

  it('terminates with permission_denied and re-throws on NotAllowedError', async () => {
    const h = installFakes({
      withVideo: false,
      permissionError: 'NotAllowedError',
    });
    const peer = new CallPeer(
      { callId: 'c3', iceServers: [], withVideo: false },
      h.events,
    );

    await expect(peer.start()).rejects.toThrow();

    expect(h.events.onTerminated).toHaveBeenCalledTimes(1);
    expect(h.events.onTerminated).toHaveBeenCalledWith(
      'failed',
      'permission_denied',
    );
    // No RTCPeerConnection was ever constructed.
    expect(FakePeerConnection.instances.length).toBe(0);
  });

  it('emits the local DTLS fingerprint after createOffer', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c4', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();
    await peer.createOffer();

    expect(h.events.onLocalDtlsFingerprint).toHaveBeenCalledWith(
      'sha-256 12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88',
    );
    expect(peer.getDtlsFingerprint()).toBe(
      'sha-256 12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88',
    );
  });

  it('hangup tears down synchronously and stops local tracks', async () => {
    const h = installFakes({ withVideo: true });
    const peer = new CallPeer(
      { callId: 'c5', iceServers: [], withVideo: true },
      h.events,
    );
    await peer.start();

    const pc = FakePeerConnection.instances[0];
    expect(pc).toBeDefined();
    if (!pc) throw new Error('pc');

    const stream = (peer as unknown as { localStream: FakeStream | null })
      .localStream;
    expect(stream).not.toBeNull();
    const tracks = stream?.tracks ?? [];

    const t0 = Date.now();
    peer.hangup('normal');
    const elapsed = Date.now() - t0;

    // 7.16: tear down within 500 ms. The wall-clock budget is trivial
    // here because hangup is synchronous, but we assert on it
    // explicitly so the test fails loudly if anyone introduces an
    // await in the teardown path later.
    expect(elapsed).toBeLessThan(500);
    expect(pc.closed).toBe(true);
    for (const track of tracks) {
      expect(track.stopped).toBe(true);
    }
    expect(h.events.onTerminated).toHaveBeenCalledWith('normal');
  });

  it('terminates with ice_timeout after 10 s of no gathering progress', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c6', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();
    await peer.createOffer();

    // Just before the deadline: no termination yet.
    vi.advanceTimersByTime(ICE_GATHERING_TIMEOUT_MS - 1);
    expect(h.events.onTerminated).not.toHaveBeenCalled();

    // Cross the deadline.
    vi.advanceTimersByTime(1);
    expect(h.events.onTerminated).toHaveBeenCalledWith('failed', 'ice_timeout');
  });

  it('clears ICE gathering timer when state reaches "complete"', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c7', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();
    await peer.createOffer();

    const pc = FakePeerConnection.instances[0];
    if (!pc) throw new Error('pc');
    pc.setIceGatheringState('complete');

    vi.advanceTimersByTime(ICE_GATHERING_TIMEOUT_MS + 1);
    expect(h.events.onTerminated).not.toHaveBeenCalled();
  });

  it('terminates after 45 s if the offer is unanswered', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c8', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();
    await peer.createOffer();

    // Suppress the ICE-gathering watchdog by completing gathering up
    // front; otherwise it fires at 10 s and masks the 45 s timer
    // we're trying to assert on.
    const pc = FakePeerConnection.instances[0];
    if (!pc) throw new Error('pc');
    pc.setIceGatheringState('complete');

    vi.advanceTimersByTime(UNANSWERED_OFFER_TIMEOUT_MS - 1);
    expect(h.events.onTerminated).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(h.events.onTerminated).toHaveBeenCalledWith('failed', 'unanswered');
  });

  it('clears the unanswered-offer timer once setRemoteDescription resolves', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c9', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();
    await peer.createOffer();
    await peer.setRemoteDescription({ type: 'answer', sdp: SAMPLE_SDP });

    vi.advanceTimersByTime(UNANSWERED_OFFER_TIMEOUT_MS + 1);
    // ICE-gathering watchdog still arms after createOffer; suppress
    // it by only checking the unanswered subreason explicitly.
    const subreasons = h.events.onTerminated.mock.calls.map(
      (c: unknown[]) => c[1],
    );
    expect(subreasons).not.toContain('unanswered');
  });

  it('terminates after 10 s of disconnected connection state', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c10', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();

    const pc = FakePeerConnection.instances[0];
    if (!pc) throw new Error('pc');
    pc.setConnectionState('disconnected');

    vi.advanceTimersByTime(CONNECTION_LOST_TIMEOUT_MS - 1);
    expect(h.events.onTerminated).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(h.events.onTerminated).toHaveBeenCalledWith(
      'failed',
      'connection_lost',
    );
  });

  it('clears the connection-lost timer when state recovers to connected', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c11', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();

    const pc = FakePeerConnection.instances[0];
    if (!pc) throw new Error('pc');
    pc.setConnectionState('disconnected');
    vi.advanceTimersByTime(CONNECTION_LOST_TIMEOUT_MS - 100);
    pc.setConnectionState('connected');
    vi.advanceTimersByTime(CONNECTION_LOST_TIMEOUT_MS);

    expect(h.events.onTerminated).not.toHaveBeenCalled();
  });

  it('toggleAudio flips RTCRtpSender.track.enabled without closing the pc', async () => {
    const h = installFakes({ withVideo: true });
    const peer = new CallPeer(
      { callId: 'c12', iceServers: [], withVideo: true },
      h.events,
    );
    await peer.start();

    const pc = FakePeerConnection.instances[0];
    if (!pc) throw new Error('pc');
    const audioSender = pc.getSenders().find((s) => s.track?.kind === 'audio');
    expect(audioSender?.track?.enabled).toBe(true);

    peer.toggleAudio(false);
    expect(audioSender?.track?.enabled).toBe(false);
    expect(pc.closed).toBe(false);

    peer.toggleAudio(true);
    expect(audioSender?.track?.enabled).toBe(true);
  });

  it('switchToAudioOnly disables video, resumeVideo re-enables the same track', async () => {
    const h = installFakes({ withVideo: true });
    const peer = new CallPeer(
      { callId: 'c13', iceServers: [], withVideo: true },
      h.events,
    );
    await peer.start();

    const pc = FakePeerConnection.instances[0];
    if (!pc) throw new Error('pc');
    const videoSender = pc.getSenders().find((s) => s.track?.kind === 'video');
    expect(videoSender?.track?.enabled).toBe(true);

    peer.switchToAudioOnly();
    expect(videoSender?.track?.enabled).toBe(false);

    // Same track instance is re-enabled — no new sender, no
    // renegotiation. (Requirement 7.9.)
    const videoSenderAfter = pc
      .getSenders()
      .find((s) => s.track?.kind === 'video');
    expect(videoSenderAfter).toBe(videoSender);

    peer.resumeVideo();
    expect(videoSender?.track?.enabled).toBe(true);
  });

  it('does not deliver callbacks after terminate()', async () => {
    const h = installFakes({ withVideo: false });
    const peer = new CallPeer(
      { callId: 'c14', iceServers: [], withVideo: false },
      h.events,
    );
    await peer.start();
    peer.hangup('normal');
    h.events.onTerminated.mockClear();

    // Subsequent timers/state changes must not produce more events.
    vi.advanceTimersByTime(60_000);
    expect(h.events.onTerminated).not.toHaveBeenCalled();
  });
});

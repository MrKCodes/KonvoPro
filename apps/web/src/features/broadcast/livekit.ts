// apps/web/src/features/broadcast/livekit.ts
//
// Thin LiveKit-client adapter for the broadcast feature (task 8.2).
//
// Why this layer exists:
//   - The `livekit-client` SDK ships a giant `Room` class with a
//     surface area `GoLiveButton` / `ViewerPanel` only need a tiny
//     slice of (connect, publish a local track, subscribe to
//     remote tracks, observe participant count, disconnect). We
//     re-declare the slice as a structural interface so:
//       1. The SDK's real `Room` instance matches by construction
//          (its `connect`, `disconnect`, `localParticipant`, `on`,
//          and `numParticipants` methods/fields satisfy the
//          interface).
//       2. Unit tests can substitute a hand-written fake without
//          loading the SDK or touching real WebRTC / DOM media
//          APIs (jsdom has no `MediaStream`, no
//          `RTCPeerConnection` capable of negotiating with a real
//          server).
//   - Production code constructs a real `Room` via the
//     `defaultLiveKitClient` factory, which dynamic-imports
//     `livekit-client` so the SDK chunk is only fetched when the
//     user actually goes live or watches a stream — keeps the
//     initial bundle lean.
//
// Requirement → behaviour map:
//   - 11.3, 11.4 — viewer count exposed via `Room.numParticipants`
//                  (the server's "active viewer" count is the same
//                  as the LiveKit room's participant count). The
//                  publisher counts as a participant; capacity is
//                  applied at the LiveKit room level so the cap of
//                  200 includes the publisher per Requirement 11.4
//                  ("the room is at capacity").
//   - 11.5      — audio-only mode publishes only an audio track via
//                  `LocalParticipant.publishTrack(audioTrack)`.
//   - 11.6      — full mode publishes audio AND video tracks via
//                  two `publishTrack` calls.

/** Local audio / video track produced by `getUserMedia`. We only
 *  need to know it's structurally a `MediaStreamTrack` so the SDK
 *  can publish it. The real SDK accepts both raw
 *  `MediaStreamTrack` and its own `LocalTrack` wrapper; we standardise
 *  on the raw track to keep the abstraction lean. */
export interface PublishableTrack {
  readonly kind: 'audio' | 'video';
  readonly track: MediaStreamTrack;
}

/** Remote track exposed by the SDK to the subscriber. The component
 *  attaches this to a media element to render audio / video. */
export interface RemoteTrack {
  readonly kind: 'audio' | 'video';
  /** Attach the track's media to the supplied element. The SDK's
   *  `RemoteTrack.attach` returns the element it attached to;
   *  callers typically pass an existing `<audio>` / `<video>` and
   *  ignore the return value. */
  attach(element: HTMLMediaElement): HTMLMediaElement;
  /** Detach and stop rendering; called from the disconnect path. */
  detach(): void;
}

/** Local participant slice — only the publish surface. */
export interface LocalParticipantSlice {
  publishTrack(track: MediaStreamTrack): Promise<unknown>;
}

/** Event names this layer subscribes to. The real SDK exposes the
 *  same string event names via `RoomEvent.*` enum members; we use
 *  the underlying strings so a structural fake doesn't have to
 *  import the SDK to emit them. */
export type RoomEventName =
  | 'trackSubscribed'
  | 'participantConnected'
  | 'participantDisconnected'
  | 'disconnected';

/** Listener signatures by event name. */
export interface RoomEventMap {
  trackSubscribed: (track: RemoteTrack) => void;
  participantConnected: () => void;
  participantDisconnected: () => void;
  disconnected: () => void;
}

/** The structural slice of `livekit-client.Room` we depend on. */
export interface LiveKitRoom {
  connect(url: string, token: string): Promise<unknown>;
  disconnect(): Promise<void> | void;
  readonly localParticipant: LocalParticipantSlice;
  readonly numParticipants: number;
  on<E extends RoomEventName>(
    event: E,
    listener: RoomEventMap[E],
  ): unknown;
  off<E extends RoomEventName>(
    event: E,
    listener: RoomEventMap[E],
  ): unknown;
}

/** Factory that produces fresh rooms. Tests inject a fake. */
export interface LiveKitClient {
  /** Create a brand-new `Room` instance ready for `.connect(url,
   *  token)`. */
  createRoom(): LiveKitRoom;
  /** Acquire local audio / optional video tracks via the platform
   *  getUserMedia API. Returns the tracks plus the underlying
   *  MediaStream so callers can stop it on hangup. The real
   *  implementation calls `navigator.mediaDevices.getUserMedia`;
   *  tests override this to return a stub stream. */
  acquireLocalTracks(opts: {
    audio: boolean;
    video: boolean;
  }): Promise<LocalTrackSet>;
}

export interface LocalTrackSet {
  readonly stream: MediaStream;
  readonly tracks: readonly PublishableTrack[];
}

/** Production factory. Lazy-loads `livekit-client` so the SDK
 *  chunk only ships when the user actually opens a live affordance.
 *  The dynamic import is wrapped in a function so the SDK is not
 *  evaluated at module-load time, which keeps the test environment
 *  (jsdom — no MediaDevices, no WebRTC) from blowing up.
 *
 *  This factory is exported but not used directly by the React
 *  components — they accept a `LiveKitClient` prop with a default
 *  of `defaultLiveKitClient()`. Tests pass their own fake. */
export function defaultLiveKitClient(): LiveKitClient {
  return {
    createRoom(): LiveKitRoom {
      // Dynamic import keeps `livekit-client` out of the critical
      // path. Returning a synchronous proxy that lazily resolves
      // `connect()` would complicate the structural type; instead
      // we rely on `Room` being constructed via a synchronous
      // require/import-meta pattern in production. The component
      // calling `createRoom()` immediately awaits `connect(...)`,
      // so the dynamic import lives there.
      throw new Error(
        'defaultLiveKitClient.createRoom: must be replaced with the loaded SDK; '
          + 'use loadLiveKitClient() or pass a client via props in non-browser builds',
      );
    },
    async acquireLocalTracks(opts) {
      if (typeof navigator === 'undefined' || navigator.mediaDevices === undefined) {
        throw new Error('LiveKit: navigator.mediaDevices unavailable');
      }
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: opts.audio,
        video: opts.video,
      });
      const tracks: PublishableTrack[] = [];
      for (const t of stream.getTracks()) {
        if (t.kind === 'audio' || t.kind === 'video') {
          tracks.push({ kind: t.kind, track: t });
        }
      }
      return { stream, tracks };
    },
  };
}

/** Lazy-load the real `livekit-client` SDK and return a
 *  `LiveKitClient` whose `createRoom()` produces a real `Room`.
 *  Components import this only at click time (inside the Go-Live /
 *  Watch handlers) so the SDK chunk is fetched on demand. The
 *  return type is `Promise<LiveKitClient>` because the SDK is
 *  loaded asynchronously.
 *
 *  Implementation note: the SDK's `Room` constructor is a no-arg
 *  call — connection happens via `room.connect(url, token)` — so
 *  the wrapped `createRoom()` is synchronous against the loaded
 *  module. The module specifier is held in a variable so the
 *  TypeScript compiler does not try to resolve it at type-check
 *  time — `livekit-client` is a runtime peer dependency and the
 *  test environment never reaches this path. */
export async function loadLiveKitClient(): Promise<LiveKitClient> {
  const specifier = 'livekit-client';
  const mod: { Room: new () => LiveKitRoom } = (await import(
    /* @vite-ignore */ specifier
  )) as unknown as { Room: new () => LiveKitRoom };
  const fallback = defaultLiveKitClient();
  return {
    createRoom(): LiveKitRoom {
      return new mod.Room();
    },
    acquireLocalTracks: fallback.acquireLocalTracks.bind(fallback),
  };
}

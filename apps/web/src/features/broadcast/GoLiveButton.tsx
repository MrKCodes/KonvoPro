// apps/web/src/features/broadcast/GoLiveButton.tsx
//
// Admin "Go Live" affordance for a broadcast room (task 8.2).
//
// User flow:
//   1. Admin clicks one of the two mode buttons:
//        - "Go Live (Audio)"          → audio-only publish (Req 11.5)
//        - "Go Live (Audio + Video)"  → audio + video publish (Req 11.6)
//   2. Component POSTs `/rooms/:slug/live` and receives a
//      `LiveKitTokenResponse` (`{ token, url, role: 'publisher' }`).
//      A 403 from the server (non-admin) surfaces as an inline error
//      message; the UI re-enables the buttons so the user can react
//      to the explanation. Server is the authoritative role gate
//      (Requirement 11.1) — the prop-level `isAdmin` flag below is
//      a UX hint only.
//   3. Component connects to LiveKit via the supplied
//      `LiveKitClient`, acquires local tracks via `getUserMedia`,
//      and publishes them on the connected room. Audio-only mode
//      requests just an audio track; full mode requests both.
//   4. While live the component renders a "Live" indicator plus a
//      "Stop" button that disconnects, stops local tracks, and
//      re-shows the mode selectors.
//
// Role enforcement:
//   - The server is the authoritative gate (Requirement 11.1);
//     `isAdmin` is a UX hint only. Non-admin sessions get the
//     buttons hidden by default. Tests assert both branches:
//     admin sees the buttons, non-admin does not.
//
// Dependency injection:
//   - `api` (BroadcastApiClient) — token issuance + REST shape.
//   - `client` (LiveKitClient) — the structural SDK adapter from
//     `./livekit.ts`. Default factory dynamic-loads the real SDK at
//     click time so the bundle stays lean and the test environment
//     never imports the SDK.

import { useCallback, useRef, useState } from 'react';

import {
  BroadcastApiClient,
  broadcastApi,
  BroadcastApiError,
} from './api.js';
import {
  defaultLiveKitClient,
  loadLiveKitClient,
  type LiveKitClient,
  type LiveKitRoom,
  type LocalTrackSet,
} from './livekit.js';

/** Mode the publisher chose. */
export type GoLiveMode = 'audio' | 'full';

export interface GoLiveButtonProps {
  /** Slug of the room the admin wants to go live in. */
  readonly slug: string;
  /** UX-level admin hint. The component renders nothing when this
   *  is `false`. The server is still the authoritative role gate
   *  (Requirement 11.1). */
  readonly isAdmin: boolean;
  /** Override the broadcast API client (tests). */
  readonly api?: BroadcastApiClient;
  /** Override the LiveKit client (tests). When omitted, the real
   *  SDK is dynamic-imported on first click. */
  readonly client?: LiveKitClient;
  /** Notified after the publisher successfully connects. The parent
   *  can react to this (e.g. surface a top-level "you are live"
   *  toast); the component itself owns the in-flow indicator. */
  readonly onConnected?: () => void;
  /** Notified after the publisher disconnects. */
  readonly onDisconnected?: () => void;
}

interface ActiveSession {
  readonly room: LiveKitRoom;
  readonly localTracks: LocalTrackSet;
  readonly mode: GoLiveMode;
}

export function GoLiveButton(props: GoLiveButtonProps): JSX.Element | null {
  const api = props.api ?? broadcastApi;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<ActiveSession | null>(null);

  // We hold the in-flight session in a ref alongside state so the
  // stop handler can read it synchronously without going through a
  // re-render cycle.
  const sessionRef = useRef<ActiveSession | null>(null);
  sessionRef.current = session;

  const startLive = useCallback(
    async (mode: GoLiveMode) => {
      setError(null);
      setBusy(true);
      let started: ActiveSession | null = null;
      try {
        // 1. Issue publisher token (also provisions the LiveKit
        //    room server-side per Requirement 11.1).
        const tokenResp = await api.startLive(props.slug);

        // 2. Resolve the LiveKit client. Lazy-loads the real SDK
        //    when no test override was supplied.
        const client = props.client ?? (await loadLiveKitClient());

        // 3. Connect a fresh Room.
        const room = client.createRoom();
        await room.connect(tokenResp.url, tokenResp.token);

        // 4. Acquire and publish local tracks.
        const localTracks = await client.acquireLocalTracks({
          audio: true,
          video: mode === 'full',
        });
        for (const t of localTracks.tracks) {
          // Audio-only mode never has a video track in the set
          // because `acquireLocalTracks({ video: false })` doesn't
          // request one. Defensive `kind` check below covers any
          // platform-specific extras (e.g. captions tracks).
          if (mode === 'audio' && t.kind !== 'audio') continue;
          await room.localParticipant.publishTrack(t.track);
        }

        started = { room, localTracks, mode };
        setSession(started);
        props.onConnected?.();
      } catch (err) {
        // Best-effort cleanup if we partially set up.
        if (started !== null) {
          await tearDownSession(started);
        }
        setError(humaniseError(err));
      } finally {
        setBusy(false);
      }
    },
    [api, props],
  );

  const stopLive = useCallback(async () => {
    const current = sessionRef.current;
    if (current === null) return;
    setBusy(true);
    try {
      await tearDownSession(current);
    } finally {
      sessionRef.current = null;
      setSession(null);
      setBusy(false);
      props.onDisconnected?.();
    }
  }, [props]);

  if (!props.isAdmin) {
    // UX gate. The server enforces the real role check
    // (Requirement 11.1); rendering nothing here is just to keep
    // the affordance out of non-admin sessions.
    return null;
  }

  if (session !== null) {
    return (
      <div data-testid="go-live-active">
        <span data-testid="go-live-indicator" role="status">
          ● Live ({session.mode === 'audio' ? 'audio' : 'audio + video'})
        </span>
        <button
          type="button"
          data-testid="go-live-stop"
          onClick={() => {
            void stopLive();
          }}
          disabled={busy}
        >
          Stop
        </button>
      </div>
    );
  }

  return (
    <div data-testid="go-live-controls">
      <button
        type="button"
        data-testid="go-live-audio"
        onClick={() => {
          void startLive('audio');
        }}
        disabled={busy}
      >
        Go Live (Audio)
      </button>
      <button
        type="button"
        data-testid="go-live-full"
        onClick={() => {
          void startLive('full');
        }}
        disabled={busy}
      >
        Go Live (Audio + Video)
      </button>
      {error !== null ? (
        <p
          role="alert"
          data-testid="go-live-error"
          style={{ color: 'red' }}
        >
          {error}
        </p>
      ) : null}
    </div>
  );
}

async function tearDownSession(s: ActiveSession): Promise<void> {
  // Stop local capture first so the browser camera/mic indicator
  // turns off promptly even if `disconnect()` hangs.
  for (const t of s.localTracks.tracks) {
    try {
      t.track.stop();
    } catch {
      // ignore — best effort
    }
  }
  try {
    s.localTracks.stream.getTracks().forEach((t) => {
      try {
        t.stop();
      } catch {
        // ignore
      }
    });
  } catch {
    // ignore
  }
  try {
    const out = s.room.disconnect();
    if (out instanceof Promise) {
      await out;
    }
  } catch {
    // ignore — best effort
  }
}

function humaniseError(err: unknown): string {
  if (err instanceof BroadcastApiError) {
    if (err.status === 403) {
      return 'Forbidden: only room admins may start a live session.';
    }
    if (err.status === 404) {
      return 'Room not found.';
    }
    return err.serverError ?? `HTTP ${err.status ?? '?'}`;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return 'Unable to go live.';
}

// Re-export the default factory so callers that want to construct a
// stub-friendly client without dynamic-importing the SDK have a
// stable reference.
export { defaultLiveKitClient };

// apps/web/src/features/broadcast/ViewerPanel.tsx
//
// Viewer-side affordance for live broadcast sessions (task 8.2).
//
// User flow:
//   1. The component renders a "Watch live" button. Clicking it
//      requests a viewer token via `GET /rooms/:slug/live/viewer-token`
//      (Requirement 11.2).
//   2. On token success the component connects a LiveKit room and
//      subscribes to remote tracks. Each subscribed track is
//      attached to the corresponding `<audio>` / `<video>` element.
//   3. The viewer count (LiveKit `Room.numParticipants`) is
//      displayed in the header. The component refreshes its view
//      of the count on `participantConnected` and
//      `participantDisconnected` events.
//   4. Per Requirement 11.4, when the LiveKit room reports 200
//      active viewers the component does NOT join — it shows
//      "Room at capacity (200 viewers)" and the join button is
//      replaced. We rely on the server-driven viewer count via the
//      LiveKit room's participant tally; the same value is checked
//      after the room connects (the SDK reports
//      `numParticipants` post-connect) and the component
//      disconnects immediately if the cap was already reached
//      between the click and the `connect()` resolving.
//
// Capacity probing without joining:
//   The original spec line ("when room is at 200 active viewers,
//   show capacity message and do not join") suggests we know the
//   count BEFORE deciding to join. The viewer-token route doesn't
//   return that count today, so we apply the cap in two places:
//     - Pre-join: the component accepts an optional
//       `viewerCount` prop the parent can pass when it has a more
//       up-to-date hint (e.g. from a server-pushed event in a
//       follow-up task). When that hint is ≥ 200 the join button
//       is hidden and the capacity message renders synchronously
//       without ever calling `getViewerToken`.
//     - Post-connect: immediately after `room.connect(...)`
//       resolves we check `room.numParticipants`. If the count is
//       ≥ 200 we disconnect, surface the capacity message, and
//       discard the connection. This keeps the cap honest even
//       when the parent doesn't pass a count hint.
//
//   Either path satisfies Requirement 11.4: the user sees a
//   capacity message and the client does not maintain a
//   subscription.

import { useCallback, useEffect, useRef, useState } from 'react';

import {
  BroadcastApiClient,
  broadcastApi,
  BroadcastApiError,
} from './api.js';
import {
  loadLiveKitClient,
  type LiveKitClient,
  type LiveKitRoom,
  type RemoteTrack,
} from './livekit.js';

/** Capacity cap from Requirement 11.3 / 11.4. The constant is
 *  centralised here so the component and tests share one source
 *  of truth. The server enforces the same cap; we mirror it on
 *  the client to refuse to join. */
export const VIEWER_CAPACITY_CAP = 200;

export interface ViewerPanelProps {
  /** Slug of the room to watch. */
  readonly slug: string;
  /** Optional pre-known viewer count (e.g. from a future
   *  server-pushed event). When ≥ `VIEWER_CAPACITY_CAP` the
   *  component refuses to join and renders the capacity message
   *  synchronously. */
  readonly viewerCount?: number;
  /** Override the broadcast API client (tests). */
  readonly api?: BroadcastApiClient;
  /** Override the LiveKit client (tests). */
  readonly client?: LiveKitClient;
}

interface ActiveView {
  readonly room: LiveKitRoom;
  readonly attachedTracks: RemoteTrack[];
  readonly participantCount: number;
}

export function ViewerPanel(props: ViewerPanelProps): JSX.Element {
  const api = props.api ?? broadcastApi;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [atCapacity, setAtCapacity] = useState<boolean>(
    (props.viewerCount ?? 0) >= VIEWER_CAPACITY_CAP,
  );
  const [view, setView] = useState<ActiveView | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  // Sync prop-supplied count into the capacity flag without
  // discarding a "we connected and discovered the count was high"
  // message.
  useEffect(() => {
    if ((props.viewerCount ?? 0) >= VIEWER_CAPACITY_CAP) {
      setAtCapacity(true);
    }
  }, [props.viewerCount]);

  const watch = useCallback(async () => {
    if (atCapacity) return;
    setError(null);
    setBusy(true);
    let connectedRoom: LiveKitRoom | null = null;
    try {
      const tokenResp = await api.getViewerToken(props.slug);
      const client = props.client ?? (await loadLiveKitClient());
      const room = client.createRoom();
      // Subscribe to remote tracks before connecting so we don't
      // miss the publisher's `trackSubscribed` event for tracks
      // that arrive immediately on join.
      const attachedTracks: RemoteTrack[] = [];
      const onTrack = (track: RemoteTrack): void => {
        attachedTracks.push(track);
        if (track.kind === 'audio' && audioRef.current !== null) {
          track.attach(audioRef.current);
        } else if (track.kind === 'video' && videoRef.current !== null) {
          track.attach(videoRef.current);
        }
      };
      room.on('trackSubscribed', onTrack);
      room.on('participantConnected', () => {
        setView((prev) =>
          prev === null
            ? prev
            : { ...prev, participantCount: room.numParticipants },
        );
      });
      room.on('participantDisconnected', () => {
        setView((prev) =>
          prev === null
            ? prev
            : { ...prev, participantCount: room.numParticipants },
        );
      });
      room.on('disconnected', () => {
        setView(null);
      });

      await room.connect(tokenResp.url, tokenResp.token);
      connectedRoom = room;

      // Post-connect capacity check (covers the race where the
      // room filled between click and connect resolution).
      if (room.numParticipants >= VIEWER_CAPACITY_CAP) {
        await safeDisconnect(room);
        setAtCapacity(true);
        connectedRoom = null;
        return;
      }

      setView({
        room,
        attachedTracks,
        participantCount: room.numParticipants,
      });
    } catch (err) {
      if (connectedRoom !== null) {
        await safeDisconnect(connectedRoom);
      }
      setError(humaniseError(err));
    } finally {
      setBusy(false);
    }
  }, [api, props, atCapacity]);

  const stop = useCallback(async () => {
    if (view === null) return;
    setBusy(true);
    try {
      for (const t of view.attachedTracks) {
        try {
          t.detach();
        } catch {
          // ignore
        }
      }
      await safeDisconnect(view.room);
    } finally {
      setView(null);
      setBusy(false);
    }
  }, [view]);

  if (atCapacity) {
    return (
      <div data-testid="viewer-panel">
        <p data-testid="viewer-capacity-message">
          Room at capacity ({VIEWER_CAPACITY_CAP} viewers)
        </p>
      </div>
    );
  }

  if (view !== null) {
    return (
      <div data-testid="viewer-panel-active">
        <header>
          <span data-testid="viewer-count">
            {view.participantCount} viewer
            {view.participantCount === 1 ? '' : 's'}
          </span>
          <button
            type="button"
            data-testid="viewer-stop"
            onClick={() => {
              void stop();
            }}
            disabled={busy}
          >
            Leave
          </button>
        </header>
        <audio ref={audioRef} data-testid="viewer-audio" autoPlay />
        <video
          ref={videoRef}
          data-testid="viewer-video"
          autoPlay
          playsInline
        />
      </div>
    );
  }

  return (
    <div data-testid="viewer-panel">
      <button
        type="button"
        data-testid="viewer-watch"
        onClick={() => {
          void watch();
        }}
        disabled={busy}
      >
        Watch live
      </button>
      {error !== null ? (
        <p
          role="alert"
          data-testid="viewer-error"
          style={{ color: 'red' }}
        >
          {error}
        </p>
      ) : null}
    </div>
  );
}

async function safeDisconnect(room: LiveKitRoom): Promise<void> {
  try {
    const out = room.disconnect();
    if (out instanceof Promise) {
      await out;
    }
  } catch {
    // ignore — best effort
  }
}

function humaniseError(err: unknown): string {
  if (err instanceof BroadcastApiError) {
    if (err.status === 404) {
      return 'Room not found.';
    }
    if (err.status === 401) {
      return 'Sign in to watch this live session.';
    }
    return err.serverError ?? `HTTP ${err.status ?? '?'}`;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return 'Unable to join live session.';
}

// apps/web/test/go-live.test.tsx
//
// Unit tests for the broadcast Go-Live and viewer flows (task 8.2).
//
// Coverage:
//   - GoLiveButton renders the mode buttons only when `isAdmin`
//     is true. Non-admin sessions render nothing.
//   - Clicking "Go Live (Audio)" issues `POST /rooms/:slug/live`
//     against the broadcast API client, then connects to the
//     mocked LiveKit `Room` and publishes ONLY an audio track.
//   - ViewerPanel refuses to join when `viewerCount >= 200`,
//     surfaces the capacity message, and never calls
//     `getViewerToken`.
//
// LiveKit isolation:
//   The real `livekit-client` SDK is never imported by these
//   tests. We construct a `LiveKitClient` stub that satisfies the
//   structural interface from
//   `apps/web/src/features/broadcast/livekit.ts` and pass it into
//   the components via the `client` prop. The stub records every
//   `createRoom`, `connect`, `publishTrack`, `acquireLocalTracks`
//   call so assertions have full visibility into the wire flow.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  GoLiveButton,
  ViewerPanel,
  VIEWER_CAPACITY_CAP,
  BroadcastApiClient,
  type LiveKitClient,
  type LiveKitRoom,
  type LocalParticipantSlice,
  type LocalTrackSet,
  type PublishableTrack,
  type RoomEventMap,
  type RoomEventName,
} from '../src/features/broadcast/index.js';

// ---------------------------------------------------------------------------
// Test harness
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

afterEach(() => {
  unmount();
  vi.restoreAllMocks();
});

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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

interface FakeRoomLog {
  readonly connectCalls: Array<{ url: string; token: string }>;
  readonly publishedKinds: string[];
  disconnected: boolean;
}

/** Hand-rolled `LiveKitRoom` matching the structural interface.
 *  Records every call into the `log` so tests can assert the wire
 *  flow without touching real WebRTC. */
function makeFakeRoom(opts: {
  log: FakeRoomLog;
  numParticipants: number;
}): LiveKitRoom {
  const listeners: Partial<{
    [K in RoomEventName]: Array<RoomEventMap[K]>;
  }> = {};
  const localParticipant: LocalParticipantSlice = {
    publishTrack: vi.fn(async (track: MediaStreamTrack) => {
      opts.log.publishedKinds.push(track.kind);
    }),
  };
  const room: LiveKitRoom = {
    async connect(url, token) {
      opts.log.connectCalls.push({ url, token });
    },
    disconnect() {
      opts.log.disconnected = true;
    },
    localParticipant,
    get numParticipants() {
      return opts.numParticipants;
    },
    on<E extends RoomEventName>(event: E, listener: RoomEventMap[E]) {
      const arr = listeners[event] ?? [];
      arr.push(listener);
      (listeners as Record<string, unknown>)[event] = arr;
      return room;
    },
    off<E extends RoomEventName>(event: E, listener: RoomEventMap[E]) {
      const arr = listeners[event];
      if (arr === undefined) return room;
      const idx = arr.indexOf(listener);
      if (idx >= 0) arr.splice(idx, 1);
      return room;
    },
  };
  return room;
}

/** Build a `MediaStreamTrack`-like object. jsdom does not provide
 *  the real DOM type, so we construct a minimal stub with the
 *  fields the production code reads. */
function fakeMediaStreamTrack(kind: 'audio' | 'video'): MediaStreamTrack {
  const t = {
    kind,
    enabled: true,
    stop: vi.fn(),
  };
  return t as unknown as MediaStreamTrack;
}

function fakeMediaStream(tracks: MediaStreamTrack[]): MediaStream {
  return {
    getTracks: () => tracks,
    getAudioTracks: () => tracks.filter((t) => t.kind === 'audio'),
    getVideoTracks: () => tracks.filter((t) => t.kind === 'video'),
  } as unknown as MediaStream;
}

/** Build a `LiveKitClient` stub with deterministic behaviour. The
 *  factory returns the stub plus a handle to the room log so the
 *  test can inspect it. */
function makeFakeClient(opts: { numParticipants: number }): {
  client: LiveKitClient;
  log: FakeRoomLog;
  acquireCalls: Array<{ audio: boolean; video: boolean }>;
} {
  const log: FakeRoomLog = {
    connectCalls: [],
    publishedKinds: [],
    disconnected: false,
  };
  const acquireCalls: Array<{ audio: boolean; video: boolean }> = [];
  const client: LiveKitClient = {
    createRoom(): LiveKitRoom {
      return makeFakeRoom({ log, numParticipants: opts.numParticipants });
    },
    async acquireLocalTracks(o): Promise<LocalTrackSet> {
      acquireCalls.push({ audio: o.audio, video: o.video });
      const tracks: PublishableTrack[] = [];
      const rawTracks: MediaStreamTrack[] = [];
      if (o.audio) {
        const at = fakeMediaStreamTrack('audio');
        tracks.push({ kind: 'audio', track: at });
        rawTracks.push(at);
      }
      if (o.video) {
        const vt = fakeMediaStreamTrack('video');
        tracks.push({ kind: 'video', track: vt });
        rawTracks.push(vt);
      }
      return { stream: fakeMediaStream(rawTracks), tracks };
    },
  };
  return { client, log, acquireCalls };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const SLUG = 'announcements';
const LIVEKIT_URL = 'wss://livekit.konvo.local';
const PUBLISHER_TOKEN = 'publisher.jwt.payload';
const VIEWER_TOKEN = 'viewer.jwt.payload';

describe('GoLiveButton', () => {
  it('renders nothing for non-admin sessions', () => {
    const { client } = makeFakeClient({ numParticipants: 1 });
    const api = new BroadcastApiClient({
      fetchImpl: vi.fn() as unknown as typeof fetch,
      baseUrl: '',
    });
    const m = mount(
      <GoLiveButton
        slug={SLUG}
        isAdmin={false}
        api={api}
        client={client}
      />,
    );
    expect(
      m.container.querySelector('[data-testid="go-live-controls"]'),
    ).toBeNull();
    expect(
      m.container.querySelector('[data-testid="go-live-audio"]'),
    ).toBeNull();
  });

  it('renders both mode buttons for admin sessions', () => {
    const { client } = makeFakeClient({ numParticipants: 1 });
    const api = new BroadcastApiClient({
      fetchImpl: vi.fn() as unknown as typeof fetch,
      baseUrl: '',
    });
    const m = mount(
      <GoLiveButton
        slug={SLUG}
        isAdmin={true}
        api={api}
        client={client}
      />,
    );
    expect(
      m.container.querySelector('[data-testid="go-live-audio"]'),
    ).not.toBeNull();
    expect(
      m.container.querySelector('[data-testid="go-live-full"]'),
    ).not.toBeNull();
  });

  it('clicking "Go Live (Audio)" issues POST /rooms/:slug/live and connects audio-only', async () => {
    const { client, log, acquireCalls } = makeFakeClient({
      numParticipants: 1,
    });

    let postedToLive = false;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === `/rooms/${SLUG}/live` && init?.method === 'POST') {
        postedToLive = true;
        return jsonResponse(200, {
          token: PUBLISHER_TOKEN,
          url: LIVEKIT_URL,
          role: 'publisher',
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const api = new BroadcastApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      baseUrl: '',
    });

    const onConnected = vi.fn();
    const m = mount(
      <GoLiveButton
        slug={SLUG}
        isAdmin={true}
        api={api}
        client={client}
        onConnected={onConnected}
      />,
    );

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="go-live-audio"]',
    );
    expect(btn).not.toBeNull();
    await act(async () => {
      btn!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    await waitFor(() => onConnected.mock.calls.length > 0);

    // POST issued.
    expect(postedToLive).toBe(true);

    // LiveKit connect happened with the URL/token from the API.
    expect(log.connectCalls).toEqual([
      { url: LIVEKIT_URL, token: PUBLISHER_TOKEN },
    ]);

    // Audio-only mode: only an audio track was acquired and
    // published.
    expect(acquireCalls).toEqual([{ audio: true, video: false }]);
    expect(log.publishedKinds).toEqual(['audio']);

    // The active session UI rendered.
    expect(
      m.container.querySelector('[data-testid="go-live-active"]'),
    ).not.toBeNull();
    expect(
      m.container.querySelector('[data-testid="go-live-indicator"]')
        ?.textContent ?? '',
    ).toContain('Live');
  });

  it('"Go Live (Audio + Video)" publishes both audio and video tracks', async () => {
    const { client, log, acquireCalls } = makeFakeClient({
      numParticipants: 1,
    });

    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, {
        token: PUBLISHER_TOKEN,
        url: LIVEKIT_URL,
        role: 'publisher',
      }),
    );
    const api = new BroadcastApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      baseUrl: '',
    });

    const m = mount(
      <GoLiveButton
        slug={SLUG}
        isAdmin={true}
        api={api}
        client={client}
      />,
    );
    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="go-live-full"]',
    );
    await act(async () => {
      btn!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="go-live-active"]',
        ) !== null,
    );

    expect(acquireCalls).toEqual([{ audio: true, video: true }]);
    expect(log.publishedKinds.sort()).toEqual(['audio', 'video']);
  });
});

describe('ViewerPanel', () => {
  it('shows the capacity message and does NOT connect when viewerCount >= 200', () => {
    const { client } = makeFakeClient({ numParticipants: 200 });
    const fetchImpl = vi.fn();
    const api = new BroadcastApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      baseUrl: '',
    });
    const m = mount(
      <ViewerPanel
        slug={SLUG}
        api={api}
        client={client}
        viewerCount={VIEWER_CAPACITY_CAP}
      />,
    );

    // Capacity message rendered, watch button absent.
    expect(
      m.container.querySelector(
        '[data-testid="viewer-capacity-message"]',
      ),
    ).not.toBeNull();
    expect(
      m.container.querySelector('[data-testid="viewer-watch"]'),
    ).toBeNull();

    // No fetch was issued — the viewer-token endpoint must not be
    // called when we already know the room is full.
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('clicking "Watch live" requests a viewer token and joins when below capacity', async () => {
    const { client, log } = makeFakeClient({ numParticipants: 5 });
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === `/rooms/${SLUG}/live/viewer-token`) {
        return jsonResponse(200, {
          token: VIEWER_TOKEN,
          url: LIVEKIT_URL,
          role: 'subscriber',
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const api = new BroadcastApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      baseUrl: '',
    });

    const m = mount(
      <ViewerPanel slug={SLUG} api={api} client={client} viewerCount={5} />,
    );
    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="viewer-watch"]',
    );
    await act(async () => {
      btn!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="viewer-panel-active"]',
        ) !== null,
    );

    expect(log.connectCalls).toEqual([
      { url: LIVEKIT_URL, token: VIEWER_TOKEN },
    ]);
    const countText =
      m.container.querySelector('[data-testid="viewer-count"]')?.textContent ?? '';
    expect(countText).toContain('5');
  });

  it('disconnects post-connect when participant count is at capacity', async () => {
    // Hand a stub whose connected room reports 200 participants
    // even though the prop hint was undefined. The component must
    // notice the post-connect race and bail out.
    const { client, log } = makeFakeClient({
      numParticipants: VIEWER_CAPACITY_CAP,
    });
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, {
        token: VIEWER_TOKEN,
        url: LIVEKIT_URL,
        role: 'subscriber',
      }),
    );
    const api = new BroadcastApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      baseUrl: '',
    });

    const m = mount(
      <ViewerPanel slug={SLUG} api={api} client={client} />,
    );
    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="viewer-watch"]',
    );
    await act(async () => {
      btn!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="viewer-capacity-message"]',
        ) !== null,
    );

    // Connection was attempted but the room was disconnected
    // immediately after the over-capacity check.
    expect(log.connectCalls.length).toBe(1);
    expect(log.disconnected).toBe(true);
  });
});

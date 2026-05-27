// apps/web/src/features/broadcast/RoomView.tsx
//
// Renders the paginated post history of a single broadcast room plus
// real-time updates pushed via the WS `room_post` event.
//
// Data flow:
//   1. Fetch `GET /rooms/:slug` for the room metadata (name, roomId,
//      ownerHandle). Public read; no auth required (Requirement 10.2).
//      The roomId is required to verify post signatures
//      (`canonicalBroadcastMessage` covers `body || roomId ||
//      createdAtMs`).
//   2. Fetch `GET /rooms/:slug/messages?limit=50` for the initial
//      page. For each post, run `verifyBroadcastPost(body, roomId,
//      createdAtMs, signature, authorIdentityPub)`. Persist the post
//      + verified flag into the local `roomPosts` Dexie cache so a
//      reload renders without re-running verification.
//   3. (Optional) Subscribe to the WS `room_post` event so newly-
//      published posts appear without a refetch (Requirement 10.4
//      live fan-out path). Each post is verified before render in
//      exactly the same way.
//
// Verification badge contract (Requirements 10.10, 10.11):
//   - Verified posts render with a "verified author" badge
//     (`data-testid="room-post-badge-verified"`).
//   - Unverified posts render with a red "unverified" badge
//     (`data-testid="room-post-badge-unverified"`). Per Requirement
//     10.11 the post itself is NOT hidden — the user can still read
//     the body and decide for themselves.
//
// Read-only mode:
//   - The public `/r/:slug` route renders this component with no
//     `wsClient`. Pagination, history, and the verified/unverified
//     badges still work because they only need the public REST
//     surface.

import { useEffect, useMemo, useState } from 'react';

import { verifyBroadcastPost } from '@konvo/crypto';
import type { BroadcastPost } from '@konvo/protocol';

import { db } from '../../db/schema.js';
import { DexieRoomPostsStore } from '../../db/repositories/roomPosts.js';
import { DexieRoomsStore } from '../../db/repositories/rooms.js';
import {
  BroadcastApiClient,
  broadcastApi,
  BroadcastApiError,
  type RoomDto,
} from './api.js';
import { GoLiveButton } from './GoLiveButton.js';
import type { LiveKitClient } from './livekit.js';
import { ViewerPanel } from './ViewerPanel.js';

/** Structurally typed WS subscription source. The production
 *  `WsClient` (`apps/web/src/ws/client.ts`) matches by construction;
 *  tests pass a stub implementing only this method. */
export interface RoomViewWsLike {
  on(
    event: 'room_post',
    listener: (payload: { post: BroadcastPost }) => void,
  ): () => void;
}

export interface RoomViewProps {
  readonly slug: string;
  /** Override the broadcast API client (tests). */
  readonly api?: BroadcastApiClient;
  /** Override the rooms store (tests). */
  readonly roomsStore?: DexieRoomsStore;
  /** Override the roomPosts store (tests). */
  readonly roomPostsStore?: DexieRoomPostsStore;
  /** Optional WS client subscription source. When supplied the view
   *  listens for `room_post` events and renders new posts in real
   *  time. Read-only routes (e.g. public `/r/:slug`) pass nothing. */
  readonly wsClient?: RoomViewWsLike;
  /** Read-only mode renders an explicit "public read-only view"
   *  banner. The view itself never renders composer UI — that's
   *  composed by the caller (see `App.tsx`). */
  readonly readOnly?: boolean;
  /** When true, render the admin "Go Live" affordance for the
   *  authed user. The server-side role check at
   *  `POST /rooms/:slug/live` is the authoritative gate
   *  (Requirement 11.1); this prop is a UX hint only. Defaults to
   *  false. */
  readonly isAdmin?: boolean;
  /** Override the LiveKit client used by the live affordances
   *  (tests). When omitted the affordances dynamic-load the real
   *  SDK at click time. */
  readonly liveKitClient?: LiveKitClient;
  /** Optional pre-known viewer count, forwarded to `ViewerPanel`
   *  to enable the synchronous capacity-message path. */
  readonly viewerCount?: number;
}

interface RenderedPost {
  readonly key: string; // `${slug}:${postId}` — stable under re-render
  readonly postId: string;
  readonly body: string;
  readonly authorHandle: string;
  readonly createdAt: number;
  readonly verified: boolean;
}

export function RoomView(props: RoomViewProps): JSX.Element {
  // CRITICAL: stabilise the default-store / default-api references
  // across renders. Allocating fresh instances inline (`?? new
  // DexieRoomsStore(db)`) mutated the dependency identities of the
  // fetch effect on every render, which triggered an infinite
  // refetch loop on any 404 (every error → setError → re-render →
  // new instances → effect re-runs → 404 → setError …). Memoising
  // the defaults — and including the *prop overrides* in the deps,
  // not the resolved instances — keeps the effect stable for the
  // common no-overrides path while still letting tests inject a
  // stub by passing a stable reference.
  const api = useMemo(
    () => props.api ?? broadcastApi,
    [props.api],
  );
  const roomsStore = useMemo(
    () => props.roomsStore ?? new DexieRoomsStore(db),
    [props.roomsStore],
  );
  const roomPostsStore = useMemo(
    () => props.roomPostsStore ?? new DexieRoomPostsStore(db),
    [props.roomPostsStore],
  );
  const { slug } = props;

  const [room, setRoom] = useState<RoomDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [posts, setPosts] = useState<RenderedPost[]>([]);
  const [loading, setLoading] = useState(true);

  // ------------------------------------------------------------------
  // 1. Fetch room metadata + initial message page
  // ------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setErrorStatus(null);

    void (async () => {
      try {
        const roomDto = await api.getRoom(slug);
        if (cancelled) return;
        setRoom(roomDto);

        // Mirror room metadata into the local cache so RoomList
        // includes it next time. We don't flip `subscribed` here —
        // public reads must never assert subscription state.
        await roomsStore.upsert({
          slug: roomDto.slug,
          roomId: roomDto.id,
          name: roomDto.name,
          ownerHandle: roomDto.ownerHandle,
          createdAt: Date.parse(roomDto.createdAt),
        });

        const page = await api.listMessages(slug, { limit: 50 });
        if (cancelled) return;

        const rendered: RenderedPost[] = [];
        const persistBatch: Array<Parameters<DexieRoomPostsStore['upsert']>[0]> = [];
        for (const post of page.messages) {
          const verified = verifyBroadcastPost(
            post.body,
            roomDto.id,
            post.createdAtMs,
            post.signature,
            post.authorIdentityPub,
          );
          rendered.push({
            key: `${slug}:${post.postId}`,
            postId: post.postId,
            body: post.body,
            authorHandle: post.authorHandle,
            createdAt: post.createdAtMs,
            verified,
          });
          persistBatch.push({
            roomSlug: slug,
            postId: post.postId,
            body: post.body,
            authorHandle: post.authorHandle,
            authorIdentityPub: post.authorIdentityPub,
            signature: post.signature,
            createdAt: post.createdAtMs,
            verified,
          });
        }
        // Best-effort persistence; cache misses are recoverable.
        for (const p of persistBatch) {
          try {
            await roomPostsStore.upsert(p);
          } catch {
            // Local cache hiccup is non-fatal — the UI already
            // verified each post and rendered the result.
          }
        }
        if (cancelled) return;
        // History is returned newest-first; sort chronologically
        // (oldest first) for the conventional "feed" ordering.
        rendered.sort((a, b) => a.createdAt - b.createdAt);
        setPosts(rendered);
      } catch (err) {
        if (cancelled) return;
        const status =
          err instanceof BroadcastApiError ? err.status ?? null : null;
        const msg =
          err instanceof BroadcastApiError
            ? err.serverError ?? `HTTP ${err.status ?? '?'}`
            : (err as Error).message;
        setErrorStatus(status);
        setError(msg);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [slug, api, roomsStore, roomPostsStore]);

  // ------------------------------------------------------------------
  // 2. Subscribe to live `room_post` events
  // ------------------------------------------------------------------
  useEffect(() => {
    const ws = props.wsClient;
    if (ws === undefined || room === null) return;
    const off = ws.on('room_post', (payload) => {
      const post = payload.post;
      // Filter out events for other rooms — the WS gateway fans out
      // to every subscribed connection regardless of slug, so the
      // client must drop foreign-room events itself.
      if (post.roomId !== room.id) return;
      const verified = verifyBroadcastPost(
        post.body,
        post.roomId,
        post.createdAt,
        post.authorSignature,
        post.authorIdentityPub,
      );
      const postId = post.id.toString();
      void roomPostsStore
        .upsert({
          roomSlug: slug,
          postId,
          body: post.body,
          authorHandle: post.authorHandle,
          authorIdentityPub: post.authorIdentityPub,
          signature: post.authorSignature,
          createdAt: post.createdAt,
          verified,
        })
        .catch(() => {
          // Cache hiccup — the UI render below is the source of
          // truth for this session.
        });
      const rendered: RenderedPost = {
        key: `${slug}:${postId}`,
        postId,
        body: post.body,
        authorHandle: post.authorHandle,
        createdAt: post.createdAt,
        verified,
      };
      setPosts((prev) => {
        if (prev.some((p) => p.key === rendered.key)) return prev;
        return [...prev, rendered].sort((a, b) => a.createdAt - b.createdAt);
      });
    });
    return off;
  }, [props.wsClient, room, slug, roomPostsStore]);

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------
  const headingId = useMemo(() => `room-view-heading-${slug}`, [slug]);

  if (loading) {
    return (
      <section data-testid="room-view" aria-busy="true">
        <p>Loading room…</p>
      </section>
    );
  }
  if (error !== null) {
    if (errorStatus === 404) {
      return (
        <section data-testid="room-view" data-room-status="not-found">
          <div className="empty">
            <h3>Room not found</h3>
            <p>
              No broadcast room with the slug <code>{slug}</code>{' '}
              exists on this server. Double-check the link, or pick
              one from the rooms list.
            </p>
          </div>
        </section>
      );
    }
    return (
      <section data-testid="room-view" role="alert">
        <p>Couldn’t load room: {error}</p>
      </section>
    );
  }
  if (room === null) {
    return (
      <section data-testid="room-view">
        <p>Room not found.</p>
      </section>
    );
  }

  return (
    <section
      data-testid="room-view"
      data-room-slug={slug}
      data-room-id={room.id}
      aria-labelledby={headingId}
    >
      <header>
        <h1 id={headingId}>{room.name}</h1>
        <p>
          @{room.slug} · by @{room.ownerHandle}
        </p>
        {props.readOnly === true ? (
          <p data-testid="room-view-readonly-banner">
            Public read-only view
          </p>
        ) : null}
        {props.readOnly !== true ? (
          <div data-testid="room-view-live-controls">
            <GoLiveButton
              slug={room.slug}
              isAdmin={props.isAdmin === true}
              {...(props.api !== undefined ? { api: props.api } : {})}
              {...(props.liveKitClient !== undefined
                ? { client: props.liveKitClient }
                : {})}
            />
            <ViewerPanel
              slug={room.slug}
              {...(props.api !== undefined ? { api: props.api } : {})}
              {...(props.liveKitClient !== undefined
                ? { client: props.liveKitClient }
                : {})}
              {...(props.viewerCount !== undefined
                ? { viewerCount: props.viewerCount }
                : {})}
            />
          </div>
        ) : null}
      </header>
      <ul data-testid="room-view-posts">
        {posts.length === 0 ? (
          <li>
            <em>No posts yet.</em>
          </li>
        ) : (
          posts.map((post) => (
            <li key={post.key} data-testid={`room-post-${post.postId}`}>
              <article>
                <header>
                  <strong>@{post.authorHandle}</strong>{' '}
                  <time dateTime={new Date(post.createdAt).toISOString()}>
                    {new Date(post.createdAt).toLocaleString()}
                  </time>{' '}
                  {post.verified ? (
                    <span
                      className="verified"
                      data-testid="room-post-badge-verified"
                    >
                      verified author
                    </span>
                  ) : (
                    <span
                      className="unverified"
                      data-testid="room-post-badge-unverified"
                      style={{ color: 'red' }}
                    >
                      unverified
                    </span>
                  )}
                </header>
                <p>{post.body}</p>
              </article>
            </li>
          ))
        )}
      </ul>
    </section>
  );
}

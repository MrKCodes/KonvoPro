// apps/web/src/features/broadcast/RoomList.tsx
//
// Renders the list of broadcast rooms the user can interact with.
// Sources:
//
//   1. The local `rooms` Dexie cache (rooms the user has created,
//      subscribed to, or visited via `/r/:slug`). Always shown.
//   2. `GET /rooms` server listing (recently-created public rooms).
//      Merged in on top of the cache so a fresh user has something
//      to discover even if their Dexie is empty.
//
// Each row carries a "subscribed" indicator (from the local cache;
// rows known only to the server show "discover"). Picking a row
// invokes `onSelect(slug)` and lets the parent route to `RoomView`.
//
// We intentionally do NOT auto-subscribe a discovery click: the
// subscribe call requires auth + a CSRF token and is a deliberate
// user action. The user can subscribe explicitly inside the room
// view later. Visiting an unsubscribed room is fine — the read
// endpoints are public.

import { useEffect, useMemo, useState } from 'react';

import { db } from '../../db/schema.js';
import { DexieRoomsStore, type Room } from '../../db/repositories/rooms.js';
import { broadcastApi, type BroadcastApiClient, type RoomDto } from './api.js';

export interface RoomListProps {
  /** Override the rooms store (tests). Defaults to the production
   *  singleton against the shared `db`. */
  readonly roomsStore?: DexieRoomsStore;
  /** Override the broadcast API client (tests). */
  readonly api?: BroadcastApiClient;
  /** Called when the user picks a room. The slug is the canonical
   *  routing identifier. */
  readonly onSelect?: (slug: string) => void;
}

interface DisplayRow {
  readonly slug: string;
  readonly name: string;
  readonly ownerHandle: string;
  readonly source: 'local' | 'discover';
  readonly subscribed: boolean;
}

export function RoomList(props: RoomListProps): JSX.Element {
  const store = useMemo(
    () => props.roomsStore ?? new DexieRoomsStore(db),
    [props.roomsStore],
  );
  const api = useMemo(() => props.api ?? broadcastApi, [props.api]);

  const [local, setLocal] = useState<Room[] | null>(null);
  const [discover, setDiscover] = useState<readonly RoomDto[] | null>(null);
  const [discoverError, setDiscoverError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const list = await store.list();
      if (!cancelled) setLocal(list);
    })();
    return () => {
      cancelled = true;
    };
  }, [store]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const r = await api.listRooms();
        if (!cancelled) setDiscover(r.rooms);
      } catch (err) {
        if (cancelled) return;
        // Non-fatal — local cache still renders.
        setDiscoverError((err as Error).message);
        setDiscover([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api]);

  // Merge discover into local. A slug that appears in both is shown
  // once with its local row (the local one knows the `subscribed`
  // bit). Newer-first sort by createdAt is approximated by the
  // server's response order for discover rows; local rows already
  // arrive sorted DESC by createdAt.
  const rows: DisplayRow[] = useMemo(() => {
    const out: DisplayRow[] = [];
    const seen = new Set<string>();
    for (const r of local ?? []) {
      out.push({
        slug: r.slug,
        name: r.name,
        ownerHandle: r.ownerHandle,
        source: 'local',
        subscribed: r.subscribed,
      });
      seen.add(r.slug);
    }
    for (const r of discover ?? []) {
      if (seen.has(r.slug)) continue;
      out.push({
        slug: r.slug,
        name: r.name,
        ownerHandle: r.ownerHandle,
        source: 'discover',
        subscribed: false,
      });
    }
    return out;
  }, [local, discover]);

  if (local === null && discover === null) {
    return (
      <section data-testid="room-list" aria-busy="true">
        <p>Loading rooms…</p>
      </section>
    );
  }

  if (rows.length === 0) {
    return (
      <section data-testid="room-list">
        <p>No rooms yet. Create one or open a public room link.</p>
        {discoverError !== null ? (
          <p role="status" style={{ color: 'var(--color-fg-muted)' }}>
            (couldn't fetch room directory: {discoverError})
          </p>
        ) : null}
      </section>
    );
  }

  return (
    <section data-testid="room-list">
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {rows.map((row) => (
          <li
            key={row.slug}
            data-testid={`room-list-item-${row.slug}`}
            data-source={row.source}
          >
            <button
              type="button"
              onClick={() => props.onSelect?.(row.slug)}
              style={{
                width: '100%',
                textAlign: 'left',
                padding: 'var(--space-2) var(--space-3)',
                display: 'flex',
                flexDirection: 'column',
                gap: '2px',
                marginBottom: 'var(--space-1)',
              }}
            >
              <span style={{ fontWeight: 500 }}>{row.name}</span>
              <span
                style={{
                  fontSize: 'var(--type-12)',
                  color: 'var(--color-fg-muted)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                }}
              >
                <span>@{row.slug}</span>
                <span style={{ opacity: 0.7 }}>by @{row.ownerHandle}</span>
                {row.subscribed ? (
                  <span
                    className="pill pill--success"
                    data-testid="room-list-subscribed-badge"
                  >
                    subscribed
                  </span>
                ) : (
                  <span className="pill" style={{ opacity: 0.7 }}>
                    {row.source === 'local' ? 'visited' : 'discover'}
                  </span>
                )}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

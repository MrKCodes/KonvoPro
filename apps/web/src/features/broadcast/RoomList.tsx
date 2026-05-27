// apps/web/src/features/broadcast/RoomList.tsx
//
// Renders the list of broadcast rooms the user has interacted with.
//
// Data source:
//   - Reads from the local `rooms` Dexie cache via `DexieRoomsStore`.
//     Rooms enter the cache through any of the room-touching paths:
//     creating a room (`POST /rooms`), subscribing (`POST /rooms/:slug/subscribe`),
//     viewing a public room (`GET /rooms/:slug`), or receiving a fan-out
//     (`S2C.ROOM_POST`) on a room whose row was previously persisted.
//   - The server does not expose a `GET /rooms` listing endpoint
//     (the API surface in `apps/api/src/routes/broadcast.ts` only
//     supports per-slug lookups), so the local cache is the source
//     of truth for "rooms I know about". A future task can add a
//     server-side listing and merge it in here without changing the
//     component's public props.
//
// Selection:
//   - The component takes an optional `onSelect(slug)` so a parent
//     can route to `RoomView` for the chosen slug. It deliberately
//     does NOT own the routing decision itself — `RoomView`,
//     `AdminComposer`, and `PublicRoomRoute` are composed by the
//     caller (see `App.tsx` for the live route wiring).

import { useEffect, useState } from 'react';

import { db } from '../../db/schema.js';
import { DexieRoomsStore, type Room } from '../../db/repositories/rooms.js';

export interface RoomListProps {
  /** Override the rooms store (tests). Defaults to the production
   *  singleton against the shared `db`. */
  readonly roomsStore?: DexieRoomsStore;
  /** Called when the user picks a room. The slug is the canonical
   *  routing identifier. */
  readonly onSelect?: (slug: string) => void;
}

export function RoomList(props: RoomListProps): JSX.Element {
  const store = props.roomsStore ?? new DexieRoomsStore(db);
  const [rooms, setRooms] = useState<Room[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const list = await store.list();
      if (!cancelled) setRooms(list);
    })();
    return () => {
      cancelled = true;
    };
  }, [store]);

  if (rooms === null) {
    return (
      <section data-testid="room-list" aria-busy="true">
        <p>Loading rooms…</p>
      </section>
    );
  }

  if (rooms.length === 0) {
    return (
      <section data-testid="room-list">
        <p>No rooms yet. Create one or open a public room link.</p>
      </section>
    );
  }

  return (
    <section data-testid="room-list">
      <ul>
        {rooms.map((room) => (
          <li key={room.slug} data-testid={`room-list-item-${room.slug}`}>
            <button
              type="button"
              onClick={() => props.onSelect?.(room.slug)}
            >
              <span>{room.name}</span>
              <span>@{room.slug}</span>
              {room.subscribed ? (
                <span data-testid="room-list-subscribed-badge">subscribed</span>
              ) : null}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

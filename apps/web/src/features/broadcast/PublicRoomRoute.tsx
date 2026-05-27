// apps/web/src/features/broadcast/PublicRoomRoute.tsx
//
// Standalone host for the `/r/:slug` public-read route. Renders
// `RoomView` in read-only mode without an auth-required guard, so
// unauthenticated visitors can read a broadcast room (Requirement
// 10.2: `GET /rooms/:slug` and `GET /rooms/:slug/messages` are
// public).
//
// Why a separate component:
//   - The room URL is a permalink anyone can open. The component
//     must work even when the auth store has no access token —
//     `RoomView` already handles that path because the broadcast
//     API client only sends `Authorization` when an in-memory
//     token is present, and the public REST routes don't require
//     one.
//   - Wiring the route this way keeps the read-only invariant
//     visible in code review: the component never composes
//     `AdminComposer`, never calls `roomsStore.markSubscribed`,
//     never runs role-dependent logic. Anything that requires
//     auth lives elsewhere.
//
// Slug parsing:
//   - The component takes the slug as a prop so the parent owns
//     route parsing. `App.tsx` wires the `window.location.pathname`
//     pattern `/r/:slug` and strips the `/r/` prefix before
//     instantiating this component. A real router can replace the
//     `App.tsx` plumbing without touching this file.

import { RoomView } from './RoomView.js';
import type { BroadcastApiClient } from './api.js';
import type { DexieRoomPostsStore } from '../../db/repositories/roomPosts.js';
import type { DexieRoomsStore } from '../../db/repositories/rooms.js';

export interface PublicRoomRouteProps {
  /** Slug parsed from the `/r/:slug` URL path. */
  readonly slug: string;
  /** Override the broadcast API client (tests). Mirrors the test
   *  seam exposed by `RoomView` so a unit test can drive
   *  `PublicRoomRoute` end-to-end with a stub fetch. */
  readonly api?: BroadcastApiClient;
  /** Override the rooms store (tests). */
  readonly roomsStore?: DexieRoomsStore;
  /** Override the roomPosts store (tests). */
  readonly roomPostsStore?: DexieRoomPostsStore;
}

export function PublicRoomRoute(props: PublicRoomRouteProps): JSX.Element {
  return (
    <main data-testid="public-room-route">
      <RoomView
        slug={props.slug}
        readOnly
        {...(props.api !== undefined ? { api: props.api } : {})}
        {...(props.roomsStore !== undefined
          ? { roomsStore: props.roomsStore }
          : {})}
        {...(props.roomPostsStore !== undefined
          ? { roomPostsStore: props.roomPostsStore }
          : {})}
      />
    </main>
  );
}

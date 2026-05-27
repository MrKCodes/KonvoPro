// apps/web/src/features/broadcast/index.ts
//
// Public surface of the broadcast feature module (task 7.4).

export { RoomList, type RoomListProps } from './RoomList.js';
export {
  RoomView,
  type RoomViewProps,
  type RoomViewWsLike,
} from './RoomView.js';
export {
  AdminComposer,
  type AdminComposerProps,
  type IdentityLoader,
} from './AdminComposer.js';
export {
  PublicRoomRoute,
  type PublicRoomRouteProps,
} from './PublicRoomRoute.js';
export {
  GoLiveButton,
  type GoLiveButtonProps,
  type GoLiveMode,
} from './GoLiveButton.js';
export {
  ViewerPanel,
  type ViewerPanelProps,
  VIEWER_CAPACITY_CAP,
} from './ViewerPanel.js';
export {
  defaultLiveKitClient,
  loadLiveKitClient,
  type LiveKitClient,
  type LiveKitRoom,
  type LocalParticipantSlice,
  type LocalTrackSet,
  type PublishableTrack,
  type RemoteTrack,
  type RoomEventMap,
  type RoomEventName,
} from './livekit.js';
export {
  BroadcastApiClient,
  BroadcastApiError,
  broadcastApi,
  type BroadcastApiClientOptions,
  type BroadcastApiErrorKind,
  type BroadcastPostDto,
  type ListMessagesResponse,
  type RoomDto,
} from './api.js';

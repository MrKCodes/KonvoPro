// apps/web/src/pwa/index.ts
//
// Barrel for the PWA layer (task 9.1). Callers that want to wire
// the SW registration + reconnect hook from `main.tsx` (or a
// React effect in `App.tsx`) import everything from
// `./pwa` and don't have to reach into the individual modules.

export {
  consoleSink,
  pwaLog,
  resetPwaLogSink,
  setPwaLogSink,
  type PwaLogLevel,
  type PwaLogRecord,
  type PwaLogSink,
} from './logger.js';

export {
  DEFAULT_SW_URL,
  RECONNECT_EVENT_NAME,
  installReconnectHook,
  onReconnect,
  registerServiceWorker,
  type ReconnectHookOptions,
  type RegisterOptions,
  type RegisterResult,
} from './register.js';

export {
  MAX_MESSAGES_PER_CONVERSATION,
  PRECACHE_RETENTION_WINDOW_MS,
  diffEviction,
  selectMessagesToRetain,
  selectRetentionByConversation,
  type PrecacheCandidate,
} from './precache-messages.js';

export { InstallPrompt } from './InstallPrompt.js';
export type {
  BeforeInstallPromptEventLike,
  InstallPromptProps,
} from './InstallPrompt.js';

export {
  FALLBACK_GENERIC_BODY,
  GENERIC_BODIES,
  defaultThreadUrlFor,
  genericBodyFor,
  handleNotificationClick,
  handlePushEvent,
  parsePushPayload,
  type ClientLike,
  type ClientsLike,
  type DecryptEnvelopeForNotification,
  type DecryptEnvelopeResult,
  type EnvelopeForNotification,
  type FetchLatestEnvelope,
  type FetchLatestEnvelopeResult,
  type NavigateMessage,
  type NotificationClickDeps,
  type NotificationData,
  type PushHandlerDeps,
  type PushPayload,
  type ShowNotificationLike,
} from './sw-push-handler.js';

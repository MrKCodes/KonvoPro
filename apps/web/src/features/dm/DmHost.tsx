// apps/web/src/features/dm/DmHost.tsx
//
// Per-session host for the DM machinery. Composes the WebSocket
// client, the persisted outbox coordinator, and the
// `PlaintextDmController` (Phase-2 transitional) into one React
// context that the DM screen consumes.
//
// The host is mounted by `Shell.tsx` exactly once per signed-in
// session. On unmount (logout / sign-out / hard navigation) it
// closes the WS, drops the controller subscriptions, and lets the
// Dexie repos live on (subsequent sign-ins reuse them).

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import { authApi, AuthApiError, getAuthState, useAuthStore } from '../auth/index.js';
import { db } from '../../db/schema.js';
import { DexieMessagesStore } from '../../db/repositories/messages.js';
import { DexieThreadsStore } from '../../db/repositories/threads.js';
import { DexieOutboxStore } from '../../db/repositories/outbox.js';
import { WsClient } from '../../ws/client.js';
import { OutboxCoordinator } from '../../ws/outbox.js';
import { readStoredDeviceId } from '../devices/enrollment.js';

import { PlaintextDmController } from './plaintext-controller.js';

export interface DmHostHandle {
  /** Active controller bound to the current session. `null` while
   *  the WS is still connecting / authenticating; the screen
   *  renders a "Connecting…" state until this becomes non-null. */
  readonly controller: PlaintextDmController | null;
  /** Stable device id of THIS browser. Threaded through to
   *  `ThreadView` for outbound/inbound differentiation. */
  readonly senderDeviceId: string | null;
  /** Look up a peer by handle and remember the (deviceId →
   *  userId/handle) mapping so subsequent inbound sends can
   *  resolve the sender quickly. */
  readonly resolvePeerByHandle: (handle: string) => Promise<{
    userId: string;
    handle: string;
    deviceIds: readonly string[];
  } | null>;
  /** Connection-state hint for diagnostics. */
  readonly connectionState: 'connecting' | 'ready' | 'reconnecting' | 'closed';
}

const DmHostContext = createContext<DmHostHandle | null>(null);

/** React hook to access the controller from inside the DM screen. */
export function useDmHost(): DmHostHandle {
  const ctx = useContext(DmHostContext);
  if (ctx === null) {
    throw new Error('useDmHost: must be used inside <DmHost>');
  }
  return ctx;
}

interface DmHostProps {
  readonly children: ReactNode;
}

/**
 * Mount once per signed-in session. Owns the `WsClient`,
 * `OutboxCoordinator`, and `PlaintextDmController`, exposes them
 * via context, and tears everything down on unmount.
 */
export function DmHost({ children }: DmHostProps): JSX.Element {
  const userId = useAuthStore((s) => s.user?.id ?? null);
  const senderDeviceId = userId === null ? null : readStoredDeviceId();
  const [controller, setController] = useState<PlaintextDmController | null>(null);
  const [connectionState, setConnectionState] = useState<
    'connecting' | 'ready' | 'reconnecting' | 'closed'
  >('connecting');

  // Cache `(deviceId → { userId, handle })` so inbound dispatch can
  // resolve a sender without a server round-trip after the first
  // mention. Survives controller restarts as long as the host stays
  // mounted.
  const deviceOwnerCacheRef = useRef<Map<string, { userId: string; handle: string }>>(
    new Map(),
  );

  // Same for `(userId → readonly deviceIds[])` — populated on the
  // first handle-lookup for a peer; refreshed by `resolvePeerByHandle`.
  const userDevicesCacheRef = useRef<Map<string, readonly string[]>>(new Map());

  // Resolver used by the controller for outbound: look up the
  // peer's enrolled devices. Cached to avoid a directory hit on
  // every send.
  const resolveRecipientDeviceIds = useMemo(
    () =>
      async (peerUserId: string): Promise<readonly string[]> => {
        const cached = userDevicesCacheRef.current.get(peerUserId);
        if (cached !== undefined) return cached;
        // We only know the peer by userId here — the directory
        // endpoint takes a handle. The DM composer flow caches
        // the mapping at handle-lookup time (via
        // `resolvePeerByHandle` below); if we're hitting this path
        // we already had the userId but never visited the handle
        // form (e.g. inbound message from a stranger). In that
        // case we cannot send back — return empty so the controller
        // surfaces "no recipient devices".
        return [];
      },
    [],
  );

  // Resolver for inbound: map `senderDeviceId` back to its owning
  // user. We hit `/devices/:id/owner` once per unseen device, then
  // serve from the cache.
  const resolveSenderUserId = useMemo(
    () =>
      async (envelope: import('@konvo/protocol').CiphertextEnvelope): Promise<string | null> => {
        const cached = deviceOwnerCacheRef.current.get(envelope.senderDeviceId);
        if (cached !== undefined) return cached.userId;
        try {
          const owner = await authApi.lookupDeviceOwner(envelope.senderDeviceId);
          deviceOwnerCacheRef.current.set(envelope.senderDeviceId, {
            userId: owner.userId,
            handle: owner.handle,
          });
          // Fold the device-id into the user's known-devices list
          // so a future outbound reply can fan out to the same id.
          const existing = userDevicesCacheRef.current.get(owner.userId) ?? [];
          if (!existing.includes(envelope.senderDeviceId)) {
            userDevicesCacheRef.current.set(owner.userId, [
              ...existing,
              envelope.senderDeviceId,
            ]);
          }
          return owner.userId;
        } catch {
          return null;
        }
      },
    [],
  );

  // Build the controller + transport when a session lands. Tear it
  // down when the user logs out OR the device id rolls.
  useEffect(() => {
    if (userId === null || senderDeviceId === null) {
      setController(null);
      setConnectionState('closed');
      return;
    }

    setConnectionState('connecting');

    // wss:// in production (Caddy fronts both); ws:// in dev
    // (Vite proxies /ws to localhost:3000 via its HTTP upgrade
    // path).
    const proto =
      typeof window !== 'undefined' && window.location.protocol === 'https:'
        ? 'wss'
        : 'ws';
    const host =
      typeof window !== 'undefined' ? window.location.host : 'localhost:5173';
    const url = `${proto}://${host}`;

    const client = new WsClient({
      url,
      deviceId: senderDeviceId,
      tokenProvider: async (): Promise<string> => {
        const t = getAuthState().accessToken;
        if (t === null || t.length === 0) {
          throw new Error('DmHost: no access token in memory');
        }
        return t;
      },
    });
    const messagesStore = new DexieMessagesStore(db);
    const threadsStore = new DexieThreadsStore(db);
    const outboxStore = new DexieOutboxStore(db);
    const outbox = new OutboxCoordinator({ client, store: outboxStore });

    const ctrl = new PlaintextDmController({
      threads: threadsStore,
      messages: messagesStore,
      outbox,
      client,
      senderDeviceId,
      resolveRecipientDeviceIds,
      resolveSenderUserId,
    });

    const offState = client.on('state', (info) => {
      if (info.state === 'ready') setConnectionState('ready');
      else if (info.state === 'connecting' || info.state === 'authenticating') {
        setConnectionState('connecting');
      } else if (info.state === 'disconnected') setConnectionState('reconnecting');
      else if (info.state === 'closed') setConnectionState('closed');
    });

    outbox.start();
    ctrl.start();
    void client.connect();

    setController(ctrl);

    return () => {
      offState();
      ctrl.stop();
      outbox.stop();
      client.close();
      setController(null);
      setConnectionState('closed');
    };
  }, [userId, senderDeviceId, resolveRecipientDeviceIds, resolveSenderUserId]);

  const resolvePeerByHandle = useMemo(
    () =>
      async (handle: string): Promise<{
        userId: string;
        handle: string;
        deviceIds: readonly string[];
      } | null> => {
        try {
          const dto = await authApi.lookupUser(handle);
          const deviceIds = dto.devices.map((d) => d.deviceId);
          userDevicesCacheRef.current.set(dto.userId, deviceIds);
          for (const d of dto.devices) {
            deviceOwnerCacheRef.current.set(d.deviceId, {
              userId: dto.userId,
              handle: dto.handle,
            });
          }
          return {
            userId: dto.userId,
            handle: dto.handle,
            deviceIds,
          };
        } catch (err) {
          if (err instanceof AuthApiError && err.status === 404) {
            return null;
          }
          throw err;
        }
      },
    [],
  );

  const value: DmHostHandle = useMemo(
    () => ({
      controller,
      senderDeviceId,
      resolvePeerByHandle,
      connectionState,
    }),
    [controller, senderDeviceId, resolvePeerByHandle, connectionState],
  );

  return <DmHostContext.Provider value={value}>{children}</DmHostContext.Provider>;
}

// apps/api/src/ws/redis-publisher.ts
//
// Thin adapter wrapping `ioredis` as a `WSRedisPublisher`. Created in
// `server.ts` at boot and threaded into `wsRoutes` so the gateway has
// no compile-time dependency on `ioredis` — the rest of the WS layer
// only sees the structural `WSRedisPublisher` surface from
// `apps/api/src/ws/types.ts`. This keeps unit tests injecting a plain
// in-memory mock without pulling `ioredis` into the test bundle, and
// keeps the door open for a future swap to a different Redis client
// without touching the gateway.
//
// The constructor takes the validated `REDIS_URL` from `config.ts`
// (regex-checked to start with `redis://` or `rediss://`). On startup
// we lazily-import `ioredis` so this module remains tree-shakeable from
// any consumer that doesn't bring up the WS gateway (e.g. a future
// CLI worker for migration backfill).
//
// Two clients are constructed:
//
//   - `publisher`  — issues `PUBLISH` and `SET … EX` against Redis.
//                    Used by `onSendEnvelope` (task 3.4) and
//                    `onPresencePing` (task 3.6).
//   - `subscriber` — issues `SUBSCRIBE` / `UNSUBSCRIBE` and dispatches
//                    `'message'` events to per-channel listeners. ioredis
//                    requires a dedicated client for subscriptions
//                    because subscribed connections cannot issue other
//                    commands (Redis pub/sub is connection-local).
//                    Used by `onSubscribeRoom` and `onUnsubscribeRoom`
//                    (task 3.6) for the `room:{slug}` channels, and by
//                    `attachInbox` (task 3.5) for the per-device
//                    `dev:{deviceId}` fan-out channels.
//
// Listener refcounting:
//   Multiple WS contexts can subscribe to the same `room:{slug}`. The
//   adapter maintains a per-channel `Set<RoomMessageListener>` and
//   only issues a real `SUBSCRIBE` to ioredis when the set transitions
//   from empty to non-empty, and a real `UNSUBSCRIBE` when it
//   transitions back to empty. This keeps the upstream Redis traffic
//   proportional to room-count, not connection-count.

import type {
  DeviceMessageListener,
  RoomMessageListener,
  WSRedisPublisher,
} from './types.js';

/** Minimal subset of the `ioredis` client API the publisher uses.
 *  Restated structurally so a test or future client swap doesn't have
 *  to satisfy `ioredis`'s full ~200-method surface. */
interface RedisLike {
  publish(channel: string, message: string): Promise<number>;
  /** ioredis `set(key, value, 'EX', ttlSec)` overload. We constrain
   *  the third argument to the literal `'EX'` so a typo can't
   *  silently produce a no-TTL key. */
  set(key: string, value: string, mode: 'EX', ttlSec: number): Promise<unknown>;
  /** Subscribe to one channel. Resolves after the SUBSCRIBE completes. */
  subscribe(channel: string): Promise<unknown>;
  /** Unsubscribe from one channel. Resolves after the UNSUBSCRIBE
   *  completes. */
  unsubscribe(channel: string): Promise<unknown>;
  /** Register a `'message'` event listener that fires for every
   *  message published on a channel this client is subscribed to. */
  on(event: 'message', listener: (channel: string, message: string) => void): unknown;
  off(event: 'message', listener: (channel: string, message: string) => void): unknown;
  quit(): Promise<unknown>;
}

/** The room channel name for a given slug. Centralised so the
 *  gateway and the publisher can never disagree on the prefix. */
export function roomChannelFor(slug: string): string {
  return `room:${slug}`;
}

/** The per-device fan-out channel name. Centralised here so this
 *  module, `redis-fanout.ts`, and `gateway.ts` (`fanoutChannelFor`)
 *  can never drift on the prefix. The gateway re-exports its own
 *  `fanoutChannelFor` for backwards-compat with the existing tests
 *  in `ws-gateway.test.ts`; both helpers must produce the same
 *  string for any given device id. */
export function deviceChannelFor(deviceId: string): string {
  return `dev:${deviceId}`;
}

/** The presence key name for a given device id. SET with EX 30s by
 *  `onPresencePing`; consulted by `routeOutboundEnvelope` (design.md
 *  §13.6) before scheduling a Web Push for an offline recipient. */
export function presenceKeyFor(deviceId: string): string {
  return `presence:${deviceId}`;
}

/** Constructed `WSRedisPublisher` plus a `close()` hook the server
 *  bootstrap registers in `app.addHook('onClose', ...)` so SIGTERM
 *  drains the Redis connections alongside the pg pool. */
export interface WSRedisHandle {
  readonly publisher: WSRedisPublisher;
  close(): Promise<void>;
}

/** Create a `WSRedisPublisher` backed by `ioredis`. The `ioredis`
 *  package is loaded via dynamic import so a build that excludes the
 *  WS gateway (none today, but kept open for future refactors) does
 *  not pull the client into its bundle.
 *
 *  Parameters:
 *    - `url`: a validated `redis://` or `rediss://` URL.
 *    - `clientFactory`: optional override for tests; lets a unit test
 *      inject a `RedisLike` mock without monkey-patching the dynamic
 *      import. Defaults to constructing real `ioredis.Redis` clients.
 *      The factory is invoked TWICE on first call — once for the
 *      publish client and once for the subscribe client — because
 *      ioredis requires distinct connections for each role. */
export async function createWsRedisPublisher(
  url: string,
  clientFactory?: (url: string) => Promise<RedisLike> | RedisLike,
): Promise<WSRedisHandle> {
  const factory = clientFactory ?? defaultClientFactory;
  const pubClient: RedisLike = await factory(url);
  const subClient: RedisLike = await factory(url);

  // Per-channel listener registry. Keyed by full channel name
  // (`room:{slug}`) so the lookup matches the channel string
  // emitted by ioredis on `'message'`. We use an Array (not Set)
  // because the same listener function MAY be attached twice — the
  // gateway uses one listener per WSContext per slug, but a future
  // refactor that registers idempotently shouldn't change semantics.
  const channelListeners = new Map<string, RoomMessageListener[]>();

  // Single `'message'` handler on the subscribe client — fanned out
  // in JS to whichever listeners are registered for the channel. ioredis
  // delivers `(channel, message)` for `'message'` events.
  subClient.on('message', (channel, message) => {
    const listeners = channelListeners.get(channel);
    if (listeners === undefined || listeners.length === 0) return;
    // Snapshot so a listener that mutates the array (e.g. unsubscribes
    // itself) doesn't reorder dispatch within the same tick.
    for (const fn of listeners.slice()) {
      try {
        fn(message);
      } catch {
        // A throwing listener must not interrupt sibling listeners
        // for the same channel. We deliberately swallow here rather
        // than logging because each WSContext owns its own log
        // binding and surfacing the throw inside the publisher would
        // bypass that binding.
      }
    }
  });

  return {
    publisher: {
      async publish(channel: string, payload: string): Promise<number> {
        return pubClient.publish(channel, payload);
      },
      async setPresence(deviceId: string, ttlSec: number): Promise<void> {
        await pubClient.set(presenceKeyFor(deviceId), '1', 'EX', ttlSec);
      },
      async subscribeRoom(
        slug: string,
        listener: RoomMessageListener,
      ): Promise<void> {
        await addChannelListener(roomChannelFor(slug), listener);
      },
      async unsubscribeRoom(
        slug: string,
        listener: RoomMessageListener,
      ): Promise<void> {
        await removeChannelListener(roomChannelFor(slug), listener);
      },
      async subscribeDevice(
        deviceId: string,
        listener: DeviceMessageListener,
      ): Promise<void> {
        await addChannelListener(deviceChannelFor(deviceId), listener);
      },
      async unsubscribeDevice(
        deviceId: string,
        listener: DeviceMessageListener,
      ): Promise<void> {
        await removeChannelListener(deviceChannelFor(deviceId), listener);
      },
    },
    async close(): Promise<void> {
      await Promise.allSettled([pubClient.quit(), subClient.quit()]);
    },
  };

  /** Refcounted attach. The empty → non-empty transition issues a
   *  real upstream `SUBSCRIBE`; subsequent attaches just push into
   *  the listener array so a single ioredis subscription fans out
   *  to N WS contexts in JS. */
  async function addChannelListener(
    channel: string,
    listener: (payload: string) => void,
  ): Promise<void> {
    let listeners = channelListeners.get(channel);
    if (listeners === undefined) {
      listeners = [];
      channelListeners.set(channel, listeners);
      await subClient.subscribe(channel);
    }
    listeners.push(listener);
  }

  /** Refcounted detach. The non-empty → empty transition issues a
   *  real upstream `UNSUBSCRIBE`; intermediate detaches just splice
   *  the listener out. */
  async function removeChannelListener(
    channel: string,
    listener: (payload: string) => void,
  ): Promise<void> {
    const listeners = channelListeners.get(channel);
    if (listeners === undefined) return;
    const idx = listeners.indexOf(listener);
    if (idx >= 0) listeners.splice(idx, 1);
    if (listeners.length === 0) {
      channelListeners.delete(channel);
      await subClient.unsubscribe(channel);
    }
  }
}

async function defaultClientFactory(url: string): Promise<RedisLike> {
  // `ioredis` ships both CJS and ESM entry points; the ESM entry
  // exports the constructor as the default export. CJS interop wraps
  // it under `.default` under our `"type": "module"` setup.
  const mod = (await import('ioredis')) as unknown as {
    default?: { new (url: string): RedisLike };
    Redis?: { new (url: string): RedisLike };
  };
  const Ctor = mod.default ?? mod.Redis;
  if (typeof Ctor !== 'function') {
    throw new Error('ioredis module did not export a constructor');
  }
  return new Ctor(url);
}

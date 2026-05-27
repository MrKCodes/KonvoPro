// apps/api/src/ws/types.ts
//
// WebSocket gateway types per design.md §10 and Requirements 12.1, 12.2,
// 12.3, 12.4, 12.9, 12.13, 12.14, 12.15.
//
// `WSContext` is the per-connection state passed to every handler in
// `gateway.ts`. The brief for tasks 3.3–3.4 specifies the shape
// verbatim; design.md §10 lists a narrower set of `readonly` fields
// plus a `tokenBucket`. The bucket is per-device (50 burst / 10
// sustained per second per Requirement 19.4) and is therefore looked
// up by `deviceId` in a module-level map inside `gateway.ts` rather
// than allocated per-connection — a re-connect from the same device
// must not reset the bucket or it would be trivially defeated by
// disconnect/reconnect storms.
//
// `WSSocket` is the structural subset of the `ws` WebSocket API the
// gateway actually uses. `@fastify/websocket` v11 hands us an instance
// of `ws.WebSocket`, which already satisfies this interface; declaring
// the surface structurally keeps `gateway.ts` free of any
// `@fastify/websocket`-specific types so its tests can exercise the
// handler with a plain object mock and no transitive dependencies.

import type { FastifyBaseLogger } from 'fastify';

import type { ServerToClient } from '@konvo/protocol';

/**
 * Minimal WebSocket-like surface used by the gateway. Compatible with
 * `ws.WebSocket` (the runtime type exposed by `@fastify/websocket`).
 *
 * Only the operations the gateway actually performs are listed:
 * `send` (binary frames produced by `encodeS2C`), `close` (normal
 * closure on auth/HELLO failures), and the three `on(...)` event
 * subscriptions (`message`, `close`, `error`). `readyState` is exposed
 * so handlers can avoid sending into a closing socket.
 *
 * The `data` argument of the `'message'` listener is typed as
 * `Buffer | Uint8Array` rather than the union the `ws` types actually
 * emit (`Buffer | ArrayBuffer | Buffer[]`) because `@fastify/websocket`
 * is configured with the default options that always deliver a single
 * `Buffer`. The gateway normalizes either shape via `Uint8Array.from`
 * before passing to the codec.
 */
export interface WSSocket {
  send(data: Uint8Array | Buffer): void;
  close(code?: number, reason?: string): void;
  on(event: 'message', listener: (data: Buffer | Uint8Array) => void): WSSocket;
  on(event: 'close', listener: () => void): WSSocket;
  on(event: 'error', listener: (err: Error) => void): WSSocket;
  readyState: number;
}

/**
 * Listener invoked by `WSRedisPublisher.subscribeRoom` when a message
 * arrives on the subscribed `room:{slug}` channel. The string payload
 * is whatever the publishing endpoint wrote to Redis (Phase 7 will
 * publish a msgpack-encoded `BroadcastPost`; for now the listener is
 * a thin forwarder that decodes and pushes via `ctx.send`).
 */
export type RoomMessageListener = (payload: string) => void;

/**
 * Listener invoked by `WSRedisPublisher.subscribeDevice` when a message
 * arrives on the subscribed `dev:{deviceId}` fan-out channel. The
 * payload is the decimal string form of the envelope id assigned by
 * `onSendEnvelope` in `gateway.ts`. Listeners are registered by
 * `attachInbox` in `redis-fanout.ts` (task 3.5); the listener SELECTs
 * the envelope row by id and forwards it to the connected recipient
 * via `ctx.send` as an `S2C.ENVELOPE` frame.
 */
export type DeviceMessageListener = (payload: string) => void;

/**
 * Minimal Redis surface used by the WS gateway. Exposed structurally
 * so unit tests can inject a plain-object mock and so the gateway has
 * no compile-time dependency on `ioredis`. The concrete client is
 * wired in `apps/api/src/server.ts` via `createWsRedisPublisher` (a
 * thin adapter around `ioredis`).
 *
 * Operations:
 *   - `publish` — task 3.4 SEND_ENVELOPE fan-out on `dev:{recipient}`.
 *   - `setPresence` — task 3.6 PRESENCE_PING; SET `presence:{deviceId} = 1`
 *     with EX = `ttlSec` (typically 30s per Requirement 12.2 and
 *     design.md §13.6 `presence:` key check). Re-issued every PING so
 *     the key behaves as a 30s sliding-window TTL.
 *   - `subscribeRoom` — task 3.6 SUBSCRIBE_ROOM; subscribes the
 *     listener to `room:{slug}`. Multiple slugs per connection are
 *     supported (a context tracks its own active set in
 *     `WSContext.subscribedRooms`). The listener is invoked on the
 *     ioredis `'message'` event for that channel.
 *   - `unsubscribeRoom` — task 3.6 UNSUBSCRIBE_ROOM; removes the
 *     listener for `room:{slug}` and unsubscribes from the channel
 *     iff no other listeners remain (the publisher implementation
 *     owns refcounting).
 */
export interface WSRedisPublisher {
  /** Publish `payload` on Redis channel `channel`. Returns the number
   *  of subscribers that received the message (only used for logging;
   *  the gateway never branches on the count). */
  publish(channel: string, payload: string): Promise<number>;
  /** SET `presence:{deviceId} = "1"` with EX = `ttlSec`. Idempotent.
   *  Used by `onPresencePing` to maintain the per-device presence key
   *  consulted by `routeOutboundEnvelope` (design.md §13.6) before
   *  scheduling a Web Push notification for an offline recipient. */
  setPresence(deviceId: string, ttlSec: number): Promise<void>;
  /** SUBSCRIBE Redis channel `room:{slug}` and route every published
   *  message to `listener`. The publisher implementation MUST handle
   *  multiple subscribers per channel (a single api process running
   *  many connections all watching the same room). Resolves once the
   *  subscription is registered. */
  subscribeRoom(slug: string, listener: RoomMessageListener): Promise<void>;
  /** UNSUBSCRIBE the previously registered `listener` from `room:{slug}`.
   *  When the last listener for a given slug detaches the publisher
   *  also issues a real `UNSUBSCRIBE` to the upstream Redis client. */
  unsubscribeRoom(slug: string, listener: RoomMessageListener): Promise<void>;
  /** SUBSCRIBE Redis channel `dev:{deviceId}` and route every published
   *  envelope-id payload to `listener`. Used by `attachInbox` in
   *  `redis-fanout.ts` (task 3.5) to deliver inbound envelopes to a
   *  connected recipient. Each WS connection registers exactly one
   *  listener for its own device id; the publisher implementation
   *  MUST gracefully handle multiple connections to the same device
   *  (e.g. a transient overlap during reconnect) by maintaining a
   *  per-channel listener set. Resolves once the subscription is
   *  registered with upstream Redis. */
  subscribeDevice(deviceId: string, listener: DeviceMessageListener): Promise<void>;
  /** UNSUBSCRIBE the previously registered `listener` from
   *  `dev:{deviceId}`. When the last listener for a given device
   *  detaches the publisher also issues a real `UNSUBSCRIBE` to the
   *  upstream Redis client. */
  unsubscribeDevice(deviceId: string, listener: DeviceMessageListener): Promise<void>;
}

/**
 * Per-connection context handed to every WS handler.
 *
 * Mutability:
 *   - `socket`, `userId`, `deviceId`, `log` are set once at connection
 *     time and never reassigned.
 *   - `authenticated` and `helloReceived` are flipped during the
 *     handshake state machine: `authenticated` becomes `true` after
 *     the access-token verify succeeds; `helloReceived` becomes `true`
 *     after the HELLO frame validates and HELLO_OK has been queued.
 *
 * `send` and `close` are bound to `socket` at construction so handlers
 * never have to reach into the underlying ws instance directly. `send`
 * msgpack-encodes via `encodeS2C` from `@konvo/protocol`; `close` is
 * a thin wrapper that swallows errors from a socket already in
 * CLOSING / CLOSED so concurrent close paths don't crash.
 */
export interface WSContext {
  socket: WSSocket;
  userId: string;
  deviceId: string;
  authenticated: boolean;
  helloReceived: boolean;
  log: FastifyBaseLogger;
  /**
   * Set of `broadcast_rooms.slug` values this connection has
   * subscribed to via `SUBSCRIBE_ROOM`. Mutated by the WS handlers in
   * `gateway.ts` (`onSubscribeRoom` adds; `onUnsubscribeRoom` removes;
   * the connection-close path drains every entry). Module-level
   * design.md §10 calls this the "subscription record"; we keep it
   * in-memory because broadcast subscriptions exist only for the
   * lifetime of the socket — durable membership lives in
   * `broadcast_members` and is independent of WS state.
   */
  subscribedRooms: Set<string>;
  send(msg: ServerToClient): void;
  close(code: number, reason: string): void;
}

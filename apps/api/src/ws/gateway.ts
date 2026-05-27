// apps/api/src/ws/gateway.ts
//
// WebSocket gateway — tasks 3.3 (authentication + HELLO handshake),
// 3.4 (SEND_ENVELOPE handler with idempotency and rate limit), and
// 3.6 (ENVELOPE_RECEIVED, PRESENCE_PING, SUBSCRIBE_ROOM, UNSUBSCRIBE_ROOM).
//
// Realizes Requirements 4.7, 10.3, 12.1–12.4, 12.9, 12.12–12.15, 19.4
// and design.md §10 / §13.6.
//
//   - 12.1  : the WS gateway authenticates every connection via a 15-min
//             HS256 access token whose remaining lifetime is at least 600s.
//             Tokens are read from `?token=...` (browsers cannot set
//             custom headers on a WebSocket upgrade) OR from a
//             `Sec-WebSocket-Protocol` style `Authorization: Bearer ...`
//             header for non-browser clients. Per the task brief the
//             header path is preferred when available.
//   - 12.2  : a connection that fails to send a valid HELLO within 5s
//             is closed. HELLO must carry `protoVersion: 1` and a
//             `deviceId` matching the access-token `did` claim.
//   - 12.13 : on success the server replies with `HELLO_OK { serverTimeMs,
//             queuedCount }` where `queuedCount` is the count of envelopes
//             addressed to this device with `delivered_at IS NULL`,
//             capped at 10000 (so a flood of undelivered envelopes
//             doesn't leak an unbounded integer to the client).
//   - 12.14 : on invalid/expired token, missing HELLO, or `protoVersion`
//             other than 1, the gateway sends an `ERROR` frame
//             (`ErrorCode.AUTH_REQUIRED` or `ErrorCode.INVALID_PAYLOAD`)
//             and closes the socket with the WebSocket 1000 (Normal
//             Closure) code. We DO NOT use a custom close code because
//             RFC 6455 §7.4.2 reserves the 4xxx range for application
//             use and we want browsers to surface a generic close to
//             the JS client; the ERROR frame carries the structured
//             reason for application-layer logging.
//
// What this module does NOT do:
//   - The Redis-backed inbox subscription (`attachInbox`) and offline
//     replay land in task 3.5. This module only PUBLISHES on the
//     dev:{deviceId} fan-out channel; subscriptions are wired
//     elsewhere.
//   - Task 7.3 wires `makeRoomListener` to decode the JSON
//     `BroadcastPostFanoutPayload` published by
//     `apps/api/src/routes/broadcast.ts` and forward it as an
//     `S2C.ROOM_POST` frame; see `makeRoomListener` below.
//
// Implementation notes:
//
//   - The access-token check enforces "at least 600s of remaining
//     lifetime" by re-reading the verified `exp` claim and comparing
//     against `now + 600`. Tokens with less than 600s left are
//     rejected so a brand-new connection can survive a full 10-minute
//     window without re-auth (matches the tradeoff in design.md
//     §17.6).
//   - The HELLO timer is started in `handleConnection` before any
//     `message` listener fires; if the first frame received is not a
//     valid HELLO the connection is torn down. We also guard against
//     a double-HELLO race (the timer fires while the message listener
//     is mid-parse) by checking `ctx.helloReceived` inside the timer
//     callback.
//   - msgpack frames larger than 1 MiB throw `CodecError('malformed')`
//     in `decodeC2S`; we catch that and surface `INVALID_PAYLOAD` so
//     the client can distinguish protocol violations from network
//     failures.
//   - SEND_ENVELOPE idempotency is enforced at the database layer via
//     a UNIQUE index on `ciphertext_envelopes(sender_device,
//     client_nonce)` (see infra/postgres/init.sql). The handler uses
//     `INSERT ... ON CONFLICT DO NOTHING RETURNING id` so a retry
//     consumes no extra row; on a conflict-no-row outcome we re-read
//     the existing id with a SELECT and return that. This single-
//     authority approach satisfies P13 (exactly one row, exactly one
//     fan-out publish) without any application-side cache that would
//     have to be kept consistent across api replicas.
//   - SEND_ENVELOPE rate limiting is in-process per-device via
//     `./rate-limit.ts`. The bucket survives socket reconnect because
//     the map is module-level and keyed by `deviceId` — Requirement
//     12.4 / property P16 require the limit to hold "per device", not
//     "per connection".
//
// The exported `registerWsRoute` plugin is wired into `apps/api/src/server.ts`
// AFTER the auth routes so a 401 on token verification can be raised
// independently of any side effects from auth-route registration.

import type {
  FastifyBaseLogger,
  FastifyInstance,
  FastifyPluginAsync,
  FastifyRequest,
} from 'fastify';
import type pg from 'pg';

import {
  CodecError,
  decodeC2S,
  encodeS2C,
  ErrorCode,
  C2S,
  S2C,
  EnvelopeRouterType,
  type CiphertextEnvelope,
  type ClientToServer,
  type ServerToClient,
} from '@konvo/protocol';

import type { AccessTokenService } from '../services/auth/tokens.js';
import {
  envelopeStoreTimer,
  envelopesRoutedTotal,
  envelopeOfflineQueuedTotal,
  incCounter,
  rateLimitedTotal,
  wsConnectionsGauge,
} from '../obs/metrics.js';
import {
  SEND_ENVELOPE_BUCKET,
  tryConsume,
  type TokenBucketOpts,
  type TokenBucketState,
} from './rate-limit.js';
import {
  attachInbox as attachInboxImpl,
  fanoutChannelFor as fanoutChannelForImpl,
  publishEnvelopeToRecipient,
  type FanoutDbPool,
  type InboxHandle,
} from './redis-fanout.js';
import type { WSContext, WSRedisPublisher, WSSocket } from './types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum remaining lifetime of an access token at WS connection time
 *  (Requirement 12.1). Tokens with less than 600 seconds left are
 *  rejected so a fresh connection has at least 10 minutes before it
 *  must re-authenticate. */
export const MIN_TOKEN_LIFETIME_SEC = 600;

/** HELLO must arrive within 5 seconds of socket open (Requirement 12.2). */
export const HELLO_TIMEOUT_MS = 5000;

/** `queuedCount` in HELLO_OK is capped at 10000 so a client can't infer
 *  the exact size of a backlogged inbox (Requirement 12.13). */
export const QUEUED_COUNT_CAP = 10000;

/** Standard WebSocket close codes (RFC 6455 §7.4.1). We only use 1000
 *  (Normal Closure) — every close path in this module sends an
 *  application-layer ERROR frame first that carries the structured
 *  reason. */
const CLOSE_NORMAL = 1000;

// ---------------------------------------------------------------------------
// Offline push fallback (task 10.4)
// ---------------------------------------------------------------------------

/** Maximum delay (ms) within which an offline-recipient push must be
 *  scheduled, per Requirement 12.10 ("schedule a Web_Push notification
 *  to the recipient device within 2 seconds of envelope insertion").
 *  We schedule at `OFFLINE_PUSH_DELAY_MS` (default `0`, i.e. on the
 *  next tick) and treat anything strictly less than this constant as
 *  spec-compliant — operators can adjust the delay via
 *  `WsRouteOptions.offlinePushDelayMs` (e.g. for tests asserting an
 *  exact 2 s upper bound). */
export const OFFLINE_PUSH_MAX_DELAY_MS = 2000;

/** Default scheduling delay (ms) for the offline push fallback.
 *  Defaults to `0` so the push fires on the next event-loop tick;
 *  this stays well under the 2 s ceiling and avoids pinning a
 *  long-lived timer for every offline recipient. */
export const OFFLINE_PUSH_DELAY_MS = 0;

/** Scheduler signature for the offline push fallback. The default
 *  implementation calls `setTimeout(fn, delayMs).unref()` (so a
 *  pending push doesn't keep the process alive). Tests inject a
 *  fake scheduler that returns immediately while still observing
 *  the requested `delayMs`. */
export type OfflinePushScheduler = (
  delayMs: number,
  fn: () => void,
) => void;

/** Default scheduler — `setTimeout` with `.unref()` so a queued push
 *  doesn't pin the event loop on shutdown. */
export const defaultOfflinePushScheduler: OfflinePushScheduler = (
  delayMs,
  fn,
): void => {
  const t = setTimeout(fn, delayMs);
  if (typeof t.unref === 'function') {
    t.unref();
  }
};

/** Argument shape for `OfflinePushSender`. Mirrors the strict
 *  `{ type, senderHandle, conversationId }` schema enforced by
 *  `apps/api/src/push/sender.ts:PushPayloadSchema`; the gateway
 *  builds this object from the envelope and the resolved sender
 *  handle, never from a spread of an external value. */
export interface OfflinePushArgs {
  readonly deviceId: string;
  readonly type: string;
  readonly senderHandle: string;
  readonly conversationId: string;
}

/** Function the gateway invokes when an envelope must wake up an
 *  offline recipient. The production wiring in `server.ts` binds
 *  this to `apps/api/src/push/sender.ts:sendPushNotification`; tests
 *  inject a `vi.fn()` to assert the exact call shape. The function
 *  may resolve OR reject — the gateway swallows rejections via the
 *  structured logger so a bad subscription cannot crash the
 *  envelope-routing loop. */
export type OfflinePushSender = (args: OfflinePushArgs) => Promise<unknown>;

/** Resolves the sender's display handle (`users.handle`) for a given
 *  user id. The returned string lands in the push payload's
 *  `senderHandle` field — Requirement 13.3 ("payload contains only
 *  `type`, `senderHandle`, `conversationId`"). Tests inject a
 *  function that returns a constant; production wiring queries
 *  `users.handle` (mirrors `routes/broadcast.ts`). Returning
 *  `null` (e.g. user row was deleted between session create and
 *  envelope send) skips the push gracefully — we never want to
 *  fabricate a handle. */
export type SenderHandleResolver = (userId: string) => Promise<string | null>;

/** Shared per-process registry of "currently-connected device ids".
 *  A device id is added to the set when its socket completes the
 *  HELLO handshake and is removed on the socket's close/error event.
 *  Membership in this set is the local-process answer to "is the
 *  recipient online?"; the global answer also consults the Redis
 *  pub/sub subscriber count returned by
 *  `publishEnvelopeToRecipient`. Production binds the module-level
 *  default below; tests inject their own set so each test starts
 *  empty. */
export const defaultConnectedDevices = new Set<string>();



/** The pg.Pool surface this module needs. We only run a single
 *  parameterized SELECT against `ciphertext_envelopes` for HELLO's
 *  `queuedCount`, plus the SEND_ENVELOPE upsert (`INSERT ... ON
 *  CONFLICT ... RETURNING`) and a fallback SELECT on conflict.
 *  Restating as a structural type lets tests stub it. */
type DbPool = Pick<pg.Pool, 'query'>;

export interface WsRouteOptions {
  readonly accessTokenService: AccessTokenService;
  readonly pool: DbPool;
  /** Redis publisher for the per-device fan-out channel
   *  (`dev:{recipientDeviceId}`). Wired in `server.ts` from `ioredis`;
   *  tests inject an in-memory mock. Required at boot time. */
  readonly redis: WSRedisPublisher;
  /** Override the wall-clock for tests. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Override the HELLO timeout (in ms) for tests. Defaults to 5000. */
  readonly helloTimeoutMs?: number;
  /** Override the SEND_ENVELOPE bucket for tests (e.g. to lower
   *  capacity for deterministic rate-limit assertions). Defaults to
   *  the spec-mandated 50 burst / 10 sustained per second. */
  readonly sendEnvelopeBucket?: TokenBucketOpts;
  /** Override the per-device bucket map for tests so each test starts
   *  from an empty state. Production passes the module-level
   *  `defaultSendEnvelopeBuckets` (or omits it to use that default). */
  readonly sendEnvelopeBuckets?: Map<string, TokenBucketState>;
  /** Override the per-process "currently-connected devices" set.
   *  Production passes the module-level `defaultConnectedDevices`
   *  (or omits it). Tests inject their own set so each test starts
   *  empty. The set is mutated by `handleConnection` on HELLO
   *  success and on socket close. */
  readonly connectedDevices?: Set<string>;
  /** Send a Web Push notification for an offline recipient. When
   *  omitted, the offline-push fallback is disabled (the envelope
   *  still inserts and the row stays `delivered_at IS NULL` for the
   *  recipient's next reconnect; only the push is skipped). */
  readonly offlinePushSender?: OfflinePushSender;
  /** Resolve `users.handle` for the sending user. Required when
   *  `offlinePushSender` is provided; ignored otherwise. */
  readonly senderHandleResolver?: SenderHandleResolver;
  /** Override the scheduler used to fire the offline push within
   *  `OFFLINE_PUSH_MAX_DELAY_MS`. Defaults to
   *  `defaultOfflinePushScheduler` (`setTimeout(...).unref()`).
   *  Tests inject a synchronous scheduler so they don't need fake
   *  timers across the entire suite. */
  readonly offlinePushScheduler?: OfflinePushScheduler;
  /** Override the offline-push scheduling delay (ms). Defaults to
   *  `OFFLINE_PUSH_DELAY_MS` (0). */
  readonly offlinePushDelayMs?: number;
}

/** Module-level per-device bucket state. Survives socket
 *  reconnects (Requirement 12.4 / P16: rate limit is per device, not
 *  per connection). The production server uses this default; tests
 *  pass their own map via `WsRouteOptions.sendEnvelopeBuckets`. */
export const defaultSendEnvelopeBuckets = new Map<string, TokenBucketState>();

/** The Redis fan-out channel name for a given recipient device.
 *  Re-exported from `./redis-fanout.ts` so existing call sites and
 *  tests in `ws-gateway.test.ts` keep working unchanged; the
 *  authoritative implementation lives next to `attachInbox` and
 *  `publishEnvelopeToRecipient`. */
export function fanoutChannelFor(recipientDeviceId: string): string {
  return fanoutChannelForImpl(recipientDeviceId);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/** Outcome of the boot-time access-token check. */
export type AuthResult =
  | { ok: true; userId: string; deviceId: string }
  | { ok: false; reason: 'missing_token' | 'invalid_token' | 'token_too_short' };

/** Read a bearer token from a Fastify request, preferring the
 *  `Authorization` header (non-browser clients) over the `?token=...`
 *  query string (browsers can't set custom WS headers).
 *
 *  Returns `null` when neither source carries a non-empty token. */
export function extractToken(req: FastifyRequest): string | null {
  // Header path (preferred for non-browser clients per task brief).
  const auth = req.headers.authorization;
  if (typeof auth === 'string' && auth.length > 0) {
    const space = auth.indexOf(' ');
    if (space > 0) {
      const scheme = auth.slice(0, space);
      const tokenRaw = auth.slice(space + 1).trim();
      if (scheme.toLowerCase() === 'bearer' && tokenRaw.length > 0) {
        return tokenRaw;
      }
    }
  }

  // Query-string path (browser fallback). Fastify parses `req.query`
  // as an object of `string | string[]`; we accept only a single
  // string value to avoid ambiguity from `?token=a&token=b`.
  const query = req.query as Record<string, unknown> | undefined;
  if (query !== undefined) {
    const raw = query['token'];
    if (typeof raw === 'string' && raw.length > 0) {
      return raw;
    }
  }

  return null;
}

/** Verify the presented access token and assert at least
 *  `MIN_TOKEN_LIFETIME_SEC` seconds of remaining lifetime. The `did`
 *  claim must be a non-empty UUID — tokens issued before device
 *  enrollment carry `did === ''` (see `routes/auth.ts` Phase-1 caveat)
 *  and are explicitly rejected here so the WS gateway never accepts
 *  envelope traffic from a not-yet-enrolled browser. */
export async function authenticate(
  req: FastifyRequest,
  tokenService: AccessTokenService,
  nowSec: number,
): Promise<AuthResult> {
  const token = extractToken(req);
  if (token === null) {
    return { ok: false, reason: 'missing_token' };
  }

  let claims;
  try {
    claims = await tokenService.verify(token);
  } catch {
    return { ok: false, reason: 'invalid_token' };
  }

  if (claims.exp - nowSec < MIN_TOKEN_LIFETIME_SEC) {
    return { ok: false, reason: 'token_too_short' };
  }

  // Phase-1 caveat: a token signed during a first-login (no enrolled
  // device yet) carries `did = ''`. Such tokens cannot route envelope
  // traffic; reject as `invalid_token` so the failure mode is uniform
  // with a tampered/expired token at the wire level.
  if (claims.sub === '' || claims.did === '') {
    return { ok: false, reason: 'invalid_token' };
  }

  return { ok: true, userId: claims.sub, deviceId: claims.did };
}

// ---------------------------------------------------------------------------
// Queued count
// ---------------------------------------------------------------------------

/** Count undelivered envelopes addressed to `deviceId`, capped at
 *  `QUEUED_COUNT_CAP`. Implemented as `SELECT count(*) ... LIMIT cap+1`
 *  via a subquery so a backlog of millions doesn't force Postgres into
 *  a full table scan — the partial index `env_recipient_undelivered_idx`
 *  bounds the work to the unread tail. */
export async function queuedCountForDevice(
  pool: DbPool,
  deviceId: string,
): Promise<number> {
  const result = await pool.query<{ count: string }>(
    // The subquery + LIMIT bound the scan: we don't need an exact count
    // beyond the cap, only "is it >= cap+1". `count(*)::text` is
    // returned as a string (pg's default for BIGINT) and parsed once.
    `SELECT count(*)::text AS count
       FROM (
         SELECT 1
           FROM ciphertext_envelopes
          WHERE recipient_device = $1
            AND delivered_at IS NULL
          LIMIT $2
       ) AS bounded`,
    [deviceId, QUEUED_COUNT_CAP + 1],
  );
  const row = result.rows[0];
  if (row === undefined) {
    return 0;
  }
  const parsed = Number.parseInt(row.count, 10);
  if (!Number.isFinite(parsed)) {
    return 0;
  }
  return parsed > QUEUED_COUNT_CAP ? QUEUED_COUNT_CAP : parsed;
}

// ---------------------------------------------------------------------------
// Context construction
// ---------------------------------------------------------------------------

/** Build a `WSContext` bound to the given socket and authenticated
 *  identity. `authenticated: true` is set up front because this factory
 *  is only called after `authenticate` returned `ok: true`. The HELLO
 *  state starts as `false` and flips after the first frame validates.
 *  The subscribed-rooms set starts empty and is mutated by
 *  `onSubscribeRoom` / `onUnsubscribeRoom`. */
export function buildContext(
  socket: WSSocket,
  userId: string,
  deviceId: string,
  log: FastifyBaseLogger,
): WSContext {
  return {
    socket,
    userId,
    deviceId,
    authenticated: true,
    helloReceived: false,
    log,
    subscribedRooms: new Set<string>(),
    send(msg: ServerToClient): void {
      // A socket that's already CLOSING (2) or CLOSED (3) will throw
      // on send; swallow the error so concurrent close paths don't
      // crash the gateway loop. The log statement omits the message
      // body — `msg.t` is enough for debugging without leaking any
      // server-side payload that might end up in this stream later.
      if (socket.readyState !== 1 /* OPEN */) {
        return;
      }
      try {
        socket.send(encodeS2C(msg));
      } catch (err) {
        log.warn({ err, t: msg.t }, 'ws send failed');
      }
    },
    close(code: number, reason: string): void {
      try {
        socket.close(code, reason);
      } catch (err) {
        log.warn({ err, code, reason }, 'ws close failed');
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Frame handlers
// ---------------------------------------------------------------------------

/** Send an ERROR frame and immediately close the socket with the
 *  Normal Closure code. Used for every auth/HELLO failure path so the
 *  client receives a structured reason at the application layer (the
 *  WS close code is always 1000). */
function rejectAndClose(
  ctx: WSContext,
  code: ErrorCode,
  message: string,
): void {
  ctx.send({ t: S2C.ERROR, code, message });
  ctx.close(CLOSE_NORMAL, message);
}

/** Decode a wire frame into a typed `ClientToServer`. Returns `null`
 *  on any codec failure; the caller then maps that to an
 *  `INVALID_PAYLOAD` error frame. We separate decode failures from
 *  semantic failures so the latter (e.g. wrong protoVersion in HELLO)
 *  can carry a more specific message. */
function tryDecode(raw: Uint8Array): ClientToServer | null {
  try {
    return decodeC2S(raw);
  } catch (err) {
    if (err instanceof CodecError) return null;
    // Re-throw non-codec errors so the caller's try/catch in
    // `handleClientMessage` surfaces them on the error path; we never
    // want to silently swallow an unexpected exception class.
    throw err;
  }
}

/** Process the HELLO frame. Validates `protoVersion === 1` and asserts
 *  that the client's claimed `deviceId` matches the token's `did`
 *  claim — preventing a malicious client from using a valid token to
 *  impersonate a different device id. On success, computes the queued
 *  count, replies with HELLO_OK, and flips `ctx.helloReceived`. */
async function handleHello(
  ctx: WSContext,
  msg: Extract<ClientToServer, { t: C2S.HELLO }>,
  pool: DbPool,
  now: () => number,
  attachInbox?: InboxAttacher,
): Promise<void> {
  // protoVersion must be exactly 1 (Requirement 12.14). The codec's
  // type narrowing also enforces this at decode time, but a defensive
  // runtime check here keeps the gateway robust against future codec
  // bugs that might widen the accepted set.
  if (msg.protoVersion !== 1) {
    rejectAndClose(ctx, ErrorCode.INVALID_PAYLOAD, 'unsupported protoVersion');
    return;
  }

  // Token-device binding: the client-asserted deviceId in HELLO must
  // match the `did` claim we already verified. A mismatch is treated
  // as an authentication failure rather than a payload error so the
  // distinction is clear in logs and metrics.
  if (msg.deviceId !== ctx.deviceId) {
    rejectAndClose(ctx, ErrorCode.AUTH_REQUIRED, 'deviceId does not match token');
    return;
  }

  // Compute queued count BEFORE flipping `helloReceived`. If the SQL
  // throws (pool exhausted, schema missing) we abort the handshake
  // and surface INTERNAL — leaving `helloReceived = false` ensures
  // the HELLO timer below catches the dropped handshake.
  let queuedCount: number;
  try {
    queuedCount = await queuedCountForDevice(pool, ctx.deviceId);
  } catch (err) {
    ctx.log.error({ err, deviceId: ctx.deviceId }, 'queued count query failed');
    rejectAndClose(ctx, ErrorCode.INTERNAL, 'internal error');
    return;
  }

  ctx.helloReceived = true;
  ctx.send({
    t: S2C.HELLO_OK,
    serverTimeMs: now(),
    queuedCount,
  });

  // Attach the per-connection inbox AFTER replying HELLO_OK so the
  // client never sees an `S2C.ENVELOPE` frame before the handshake
  // completes (Requirement 12.11: replay happens "after a successful
  // HELLO/HELLO_OK exchange"). Failures here do NOT tear down the
  // socket — the rows stay `delivered_at IS NULL` and the next
  // reconnect retries cleanly.
  if (attachInbox !== undefined) {
    try {
      const handle = await attachInbox(ctx);
      (ctx as unknown as InboxHandleSlot).__inboxHandle = handle;
    } catch (err) {
      ctx.log.error(
        { err, deviceId: ctx.deviceId },
        'inbox attach failed; offline replay will retry on next reconnect',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Slug validation (mirrors `routes/broadcast.ts`)
// ---------------------------------------------------------------------------

/** Optional inbox attachment callback. Invoked by `handleHello`
 *  after a successful `HELLO_OK` reply. The implementation
 *  subscribes to `dev:{ctx.deviceId}` for live fan-out and replays
 *  every undelivered envelope queued in Postgres
 *  (`./redis-fanout.ts:attachInbox`). Returning `undefined` is
 *  permitted: HELLO-only unit tests pass no attacher and skip the
 *  replay path entirely.
 *
 *  Errors thrown from the attacher are caught and logged inside
 *  `handleHello`; they do NOT close the socket because a failed
 *  replay is recoverable on the next reconnect (Requirement 12.11
 *  semantics: rows stay `delivered_at IS NULL`). */
export type InboxAttacher = (ctx: WSContext) => Promise<InboxHandle>;

/** Per-connection slot for the active `InboxHandle`. Tracked via a
 *  private property on `WSContext` so the close listener in
 *  `handleConnection` can find the handle and call `detach()`
 *  without adding another field to the public `WSContext` shape.
 *  The any-cast is local to this module (mirrors the
 *  `__roomListeners` slot used by `onSubscribeRoom`). */
interface InboxHandleSlot {
  __inboxHandle?: InboxHandle | undefined;
}

// ---------------------------------------------------------------------------
// Slug validation (mirrors `routes/broadcast.ts`)
// ---------------------------------------------------------------------------

/** Slug regex per `routes/broadcast.ts` and design.md §4 (`broadcast_rooms.slug`
 *  is `CITEXT UNIQUE NOT NULL` with no app-side regex check; the WS handler
 *  enforces the same shape used by the REST routes so a malicious client
 *  cannot subscribe to channels with arbitrary content like
 *  `room:*` glob patterns or control characters). */
const SLUG_REGEX = /^[a-z0-9-]{3,64}$/;

// ---------------------------------------------------------------------------
// ENVELOPE_RECEIVED counter (task 3.6)
// ---------------------------------------------------------------------------

/** Minimal Counter interface for ENVELOPE_RECEIVED metrics. Mirrors
 *  the `RedactionFailureCounter` shape in `obs/logger.ts` so task 10.1
 *  can wire `prom-client` here without touching the gateway. */
export interface EnvelopeReceivedCounter {
  inc(value?: number): void;
}

let envelopeReceivedCount = 0;
let envelopeReceivedCounter: EnvelopeReceivedCounter = {
  inc(value = 1): void {
    envelopeReceivedCount += value;
  },
};

/** Replace the ENVELOPE_RECEIVED counter. Wiring point for task 10.1
 *  (prom-client). Calling this resets the in-memory test counter to 0
 *  so test setup can install a fresh counter and not inherit prior
 *  state. */
export function setEnvelopeReceivedCounter(
  counter: EnvelopeReceivedCounter,
): void {
  envelopeReceivedCounter = counter;
  envelopeReceivedCount = 0;
}

/** Read the current in-memory ENVELOPE_RECEIVED count. Test-only helper. */
export function getEnvelopeReceivedCount(): number {
  return envelopeReceivedCount;
}

// ---------------------------------------------------------------------------
// SEND_ENVELOPE handler (task 3.4)
// ---------------------------------------------------------------------------

/** Dependencies the SEND_ENVELOPE path needs from the surrounding
 *  plugin. Distinct from `WsRouteOptions` because the test harness
 *  invokes `handleClientMessage` directly with a per-test object that
 *  carries the bucket map and a clock. */
export interface SendEnvelopeDeps {
  readonly pool: DbPool;
  readonly redis: WSRedisPublisher;
  readonly now: () => number;
  readonly sendEnvelopeBuckets: Map<string, TokenBucketState>;
  readonly sendEnvelopeBucket: TokenBucketOpts;
  /** Per-process registry of currently-connected device ids. When
   *  the recipient is NOT in this set AND no Redis subscriber
   *  exists for the per-device channel, the recipient is treated
   *  as offline at envelope-insertion time (Requirement 12.10). */
  readonly connectedDevices?: Set<string>;
  /** Optional offline-push hook. When provided, an offline recipient
   *  whose envelope `routerType !== ACK` triggers a Web Push
   *  scheduled within `OFFLINE_PUSH_MAX_DELAY_MS`. */
  readonly offlinePushSender?: OfflinePushSender;
  /** Required when `offlinePushSender` is provided. */
  readonly senderHandleResolver?: SenderHandleResolver;
  /** Optional scheduler override. Defaults to `defaultOfflinePushScheduler`. */
  readonly offlinePushScheduler?: OfflinePushScheduler;
  /** Optional scheduling-delay override (ms). Defaults to
   *  `OFFLINE_PUSH_DELAY_MS` (0). */
  readonly offlinePushDelayMs?: number;
}

/**
 * Handle a `SEND_ENVELOPE` frame from a post-HELLO client.
 *
 * Realizes Requirements 4.7, 12.3, 12.4, 12.9, 12.12, 12.15, 19.4 and
 * design.md §13.6 (`routeOutboundEnvelope`).
 *
 * Order of operations is load-bearing:
 *   1. Sender authority check FIRST. If `envelope.senderDeviceId !==
 *      ctx.deviceId`, reply ERROR(INVALID_PAYLOAD) and return. No row
 *      inserted, no token consumed, no Redis publish — the spec
 *      (P17) requires the impostor send to be a strict no-op. We
 *      deliberately do NOT consume a rate-limit token here either: a
 *      rate-limit metric for an impostor message would be misleading
 *      because the impostor isn't the real device.
 *   2. Rate-limit check NEXT, before any database I/O. Per Requirement
 *      19.4 we accept up to 50 envelopes burst / 10 sustained per
 *      second per device; rejected sends reply ERROR(RATE_LIMITED)
 *      and return without inserting a row.
 *   3. Idempotent insert: a UNIQUE INDEX on `(sender_device,
 *      client_nonce)` makes the database authoritative for
 *      deduplication (P13). We use `INSERT ... ON CONFLICT DO NOTHING
 *      RETURNING id` so the success path is one round trip; on
 *      conflict (no row returned) we issue a follow-up SELECT for the
 *      existing id and reply ENVELOPE_QUEUED with that id — exactly
 *      what the spec requires for retries (Requirement 12.9).
 *   4. Redis publish AFTER the insert succeeded, on the
 *      recipient-specific channel `dev:{recipientDeviceId}` only
 *      (Requirement 12.15 / P14: recipient isolation). The payload
 *      is the assigned envelope id as a decimal string — task 3.5
 *      `attachInbox` will SELECT the row by that id when it receives
 *      the publish.
 *   5. Reply ENVELOPE_QUEUED with the id, the original `clientNonce`,
 *      and the server timestamp. The client uses the `clientNonce` to
 *      mark its outbox row delivered (`sending` → `delivered` per the
 *      3-state ticker in Requirement 4.6).
 *
 * Failure handling:
 *   - DB insert error → ERROR(INTERNAL); NO Redis publish (Requirement
 *     12.12 / P18: server never publishes ciphertext that wasn't
 *     persisted).
 *   - Redis publish error → log and reply ENVELOPE_QUEUED anyway. The
 *     row IS persisted; task 3.5's `attachInbox` will replay on the
 *     recipient's next reconnect (Requirement 12.11). A failed publish
 *     means at-most-once degrades to "delivered on next reconnect"
 *     rather than "lost".
 */
export async function onSendEnvelope(
  ctx: WSContext,
  msg: { clientNonce: string; envelope: CiphertextEnvelope },
  deps: SendEnvelopeDeps,
): Promise<void> {
  const env = msg.envelope;

  // Step 1 — sender authority check (Requirement 12.3 / P17).
  if (env.senderDeviceId !== ctx.deviceId) {
    ctx.send({
      t: S2C.ERROR,
      code: ErrorCode.INVALID_PAYLOAD,
      message: 'sender mismatch',
    });
    return;
  }

  // Step 2 — rate limit (Requirement 12.4 / 19.4 / P16).
  const allowed = tryConsume(
    deps.sendEnvelopeBuckets,
    ctx.deviceId,
    deps.now(),
    deps.sendEnvelopeBucket,
  );
  if (!allowed) {
    rateLimitedTotal.inc(1);
    ctx.send({
      t: S2C.ERROR,
      code: ErrorCode.RATE_LIMITED,
      message: 'rate limit exceeded',
    });
    return;
  }

  // Step 3 — idempotent insert (Requirement 12.9 / P13). The UNIQUE
  // INDEX on `(sender_device, client_nonce)` makes the database the
  // authority for deduplication. `ON CONFLICT DO NOTHING RETURNING id`
  // returns the new id on first send and zero rows on retry; on retry
  // we re-fetch the existing id with a SELECT.
  let envelopeId: bigint;
  // Time the persist+publish pair (Requirement 18.2,
  // `konvo_envelope_store_seconds` histogram). The timer is started
  // here so a DB error path still observes the elapsed time, which
  // is what an operator wants to see in a Postgres outage.
  const stopStoreTimer = envelopeStoreTimer();
  try {
    const insertResult = await deps.pool.query<{ id: string }>(
      `INSERT INTO ciphertext_envelopes
         (session_id, sender_device, recipient_device, ciphertext, type, client_nonce)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (sender_device, client_nonce) DO NOTHING
       RETURNING id`,
      [
        env.sessionId,
        env.senderDeviceId,
        env.recipientDeviceId,
        Buffer.from(env.ciphertext),
        env.type,
        msg.clientNonce,
      ],
    );

    if (insertResult.rows.length === 1) {
      // Fresh insert. Pg returns BIGINT as a string; convert to
      // bigint for the wire frame (the protocol type is bigint).
      envelopeId = BigInt(insertResult.rows[0]!.id);
    } else {
      // Conflict on (sender_device, client_nonce). Re-read the
      // existing row so the retry reply carries the original id.
      const lookup = await deps.pool.query<{ id: string }>(
        `SELECT id
           FROM ciphertext_envelopes
          WHERE sender_device = $1
            AND client_nonce  = $2`,
        [env.senderDeviceId, msg.clientNonce],
      );
      const row = lookup.rows[0];
      if (row === undefined) {
        // Defensive: should be unreachable because the conflict
        // implies the row exists. If it's gone (e.g. a concurrent
        // DELETE truncated the table) we surface INTERNAL rather
        // than fabricate an id.
        stopStoreTimer();
        ctx.log.error(
          { deviceId: ctx.deviceId, clientNonce: msg.clientNonce },
          'envelope idempotency conflict but no existing row found',
        );
        ctx.send({
          t: S2C.ERROR,
          code: ErrorCode.INTERNAL,
          message: 'internal error',
        });
        return;
      }
      envelopeId = BigInt(row.id);

      // Idempotent retry: row already existed AND was already
      // published when first inserted. Re-acknowledge the client
      // with the original id; do NOT re-publish on Redis (P13:
      // exactly one fan-out publish across all retries).
      stopStoreTimer();
      ctx.send({
        t: S2C.ENVELOPE_QUEUED,
        clientNonce: msg.clientNonce,
        envelopeId,
        serverTimeMs: deps.now(),
      });
      return;
    }
  } catch (err) {
    // Requirement 12.12 / P18: a DB failure must not lead to a Redis
    // publish. We log without echoing any envelope bytes (logger
    // redaction also covers `ciphertext` / `body` / `key` per
    // Requirement 16.4, but keeping ciphertext out of the structured
    // record entirely is defense-in-depth).
    stopStoreTimer();
    ctx.log.error(
      { err, deviceId: ctx.deviceId, clientNonce: msg.clientNonce },
      'ciphertext envelope insert failed',
    );
    ctx.send({
      t: S2C.ERROR,
      code: ErrorCode.INTERNAL,
      message: 'internal error',
    });
    return;
  }

  // Step 4 — fan-out publish on the recipient's channel ONLY
  // (Requirement 12.15 / P14: recipient isolation). Delegated to
  // `publishEnvelopeToRecipient` in `./redis-fanout.ts` so the
  // channel-naming convention lives in one place; the payload is
  // the envelope id as a decimal string. `attachInbox` (task 3.5)
  // re-fetches the row by that id and forwards via S2C.ENVELOPE.
  //
  // We also capture the subscriber count returned by Redis: zero
  // subscribers across the cluster means no live WS connection is
  // listening for this device, which (combined with the local
  // `connectedDevices` map check) is the trigger for the offline
  // push fallback (Requirement 12.10 / task 10.4).
  let liveSubscriberCount = 0;
  let publishSucceeded = true;
  try {
    liveSubscriberCount = await publishEnvelopeToRecipient(
      deps.redis,
      env.recipientDeviceId,
      envelopeId,
    );
  } catch (err) {
    publishSucceeded = false;
    // Publish failure is non-fatal: the row is persisted, so the
    // recipient will receive the envelope on next reconnect via
    // offline replay (task 3.5). We still ack the sender so the
    // outbox doesn't replay forever.
    ctx.log.warn(
      { err, deviceId: ctx.deviceId, recipientDeviceId: env.recipientDeviceId },
      'redis fan-out publish failed; relying on offline replay',
    );
  }

  // Step 4b — offline push fallback (Requirement 12.10 / task 10.4).
  //
  //   "WHEN a recipient device is offline at the time of envelope
  //    insertion AND the envelope's router type is not `ACK`, THE
  //    WS_Gateway SHALL schedule a Web_Push notification to the
  //    recipient device within 2 seconds of envelope insertion."
  //
  // "Offline" is the conjunction of two signals:
  //   1. The recipient deviceId is NOT in the local-process
  //      `connectedDevices` map (no live WS in this api replica).
  //   2. The Redis publish reported zero subscribers, i.e. no other
  //      api replica has a live WS for this recipient either. We
  //      use `> 0` rather than `>= 1` to be explicit about the
  //      sentinel.
  //
  // We deliberately skip the fallback for `routerType === ACK`
  // envelopes — task brief: "avoid push-storming on acks". An ACK
  // is the recipient's *transport* acknowledgement of an inbound
  // message; pushing a notification on it would wake the device up
  // for its own outbound traffic, which is both noisy and unhelpful.
  //
  // The fallback is best-effort: a missing push subscription, a
  // failed `users.handle` lookup, or a thrown sender each log at
  // warn-level and degrade to "delivered on next reconnect" via
  // the offline replay path (Requirement 12.11). The envelope row
  // is persisted, so no message is lost — only the optional wake-up
  // signal.
  const offlinePushSender = deps.offlinePushSender;
  const senderHandleResolver = deps.senderHandleResolver;
  const recipientLocallyConnected =
    deps.connectedDevices !== undefined &&
    deps.connectedDevices.has(env.recipientDeviceId);
  const recipientHasRemoteSubscriber = publishSucceeded && liveSubscriberCount > 0;
  const recipientOffline =
    !recipientLocallyConnected && !recipientHasRemoteSubscriber;

  if (
    recipientOffline &&
    env.type !== EnvelopeRouterType.ACK &&
    offlinePushSender !== undefined &&
    senderHandleResolver !== undefined
  ) {
    // Bump the offline-queued counter exactly once per offline
    // recipient envelope. The metric is no-label (Requirement 18.1)
    // so it doesn't count against the cardinality cap.
    envelopeOfflineQueuedTotal.inc(1);

    const scheduler = deps.offlinePushScheduler ?? defaultOfflinePushScheduler;
    const delayMs = deps.offlinePushDelayMs ?? OFFLINE_PUSH_DELAY_MS;
    // Snapshot the values needed inside the scheduled callback so
    // the closure doesn't retain the entire `env` / `ctx` objects.
    const recipientDeviceId = env.recipientDeviceId;
    const conversationId = env.sessionId;
    const senderUserId = ctx.userId;
    const log = ctx.log;
    const pushType: 'dm.message' | 'dm.call' =
      env.type === EnvelopeRouterType.CALL ? 'dm.call' : 'dm.message';

    scheduler(delayMs, () => {
      // Resolve the sender handle and dispatch the push. Wrapped
      // in an IIFE so the scheduler signature can stay
      // `(delayMs, fn) => void` (no async return).
      void (async (): Promise<void> => {
        let senderHandle: string | null;
        try {
          senderHandle = await senderHandleResolver(senderUserId);
        } catch (err) {
          log.warn(
            { err, recipientDeviceId },
            'offline push: sender handle lookup failed; skipping push',
          );
          return;
        }
        if (senderHandle === null) {
          log.debug(
            { recipientDeviceId, senderUserId },
            'offline push: sender handle not found; skipping push',
          );
          return;
        }
        try {
          // The payload is exactly the three-field shape required
          // by Requirement 13.3. The strict zod schema in
          // `push/sender.ts:PushPayloadSchema` is the canonical
          // guard; we never construct the payload via spread so
          // there is no place for `body`/`ciphertext`/keys to
          // sneak in.
          await offlinePushSender({
            deviceId: recipientDeviceId,
            type: pushType,
            senderHandle,
            conversationId,
          });
        } catch (err) {
          // A throwing sender is a degraded path, not a failure.
          // The envelope row is persisted; the recipient will
          // receive it on next reconnect via offline replay.
          log.warn(
            { err, recipientDeviceId },
            'offline push: send failed; relying on offline replay',
          );
        }
      })();
    });
  }

  // Step 5 — confirm to sender.
  stopStoreTimer();
  // Map EnvelopeRouterType discriminator to the bounded label domain
  // used by `konvo_envelopes_routed_total`. The closed enum (3 values)
  // satisfies the Requirement 18.1 cardinality cap by construction.
  const routerLabel: 'msg' | 'ack' | 'call' =
    env.type === 2 /* ACK */
      ? 'ack'
      : env.type === 3 /* CALL */
        ? 'call'
        : 'msg';
  incCounter(envelopesRoutedTotal, { routerType: routerLabel }, 1);
  ctx.send({
    t: S2C.ENVELOPE_QUEUED,
    clientNonce: msg.clientNonce,
    envelopeId,
    serverTimeMs: deps.now(),
  });
}

// ---------------------------------------------------------------------------
// ENVELOPE_RECEIVED handler (task 3.6)
// ---------------------------------------------------------------------------

/**
 * Handle a `C2S.ENVELOPE_RECEIVED` frame.
 *
 * Realizes Requirement 12.2 and the design.md §10 contract:
 *   "transport-level ack only — does NOT mark delivered_at (that requires
 *    E2EE ACK envelope)".
 *
 * Behavior:
 *   - Increments the `EnvelopeReceivedCounter` so the boot-time counter
 *     proxies a Prometheus metric (Phase-9 task 10.1 will swap the
 *     in-memory implementation for a real `prom-client` Counter
 *     without changing this call site, mirroring the
 *     `RedactionFailureCounter` pattern in `obs/logger.ts`).
 *   - Logs at debug level so an operator can correlate the transport
 *     ack with the original `SEND_ENVELOPE` insert via the envelope
 *     id. The log line carries `envelopeId` only — never any envelope
 *     bytes, which would be redacted by the `obs/logger.ts` layer
 *     anyway but are not even constructed here as defense-in-depth.
 *   - Does NOT update `ciphertext_envelopes.delivered_at`. Per design
 *     §10 and Requirement 4.6, `delivered_at` only flips when the
 *     recipient's *application layer* acknowledges via an E2EE
 *     `InnerType.ACK_DELIVERED` envelope (a future task wires that
 *     into `onSendEnvelope`). The transport-level ack here means "I
 *     received the bytes"; the design deliberately keeps the two
 *     signals distinct so a man-in-the-middle that tampers a
 *     ciphertext can't forge an application-level read receipt.
 *   - Does NOT publish to Redis (no fan-out; the original sender's
 *     UI updates from its own optimistic state, not from the
 *     recipient's transport ack).
 *   - Does NOT reply on the WS — the ack is one-way.
 */
export function onEnvelopeReceived(
  ctx: WSContext,
  msg: { envelopeId: bigint },
): void {
  envelopeReceivedCounter.inc(1);
  ctx.log.debug(
    {
      deviceId: ctx.deviceId,
      // bigint isn't JSON-serialisable; the logger layer turns it
      // into a string via the `formatters.log` redact pass that
      // walks every value. We pre-stringify here so a future logger
      // backend that doesn't auto-stringify bigint still works.
      envelopeId: msg.envelopeId.toString(),
    },
    'ws envelope_received transport ack',
  );
}

// ---------------------------------------------------------------------------
// PRESENCE_PING handler (task 3.6)
// ---------------------------------------------------------------------------

/** Dependencies for `onPresencePing`. */
export interface PresencePingDeps {
  readonly pool: DbPool;
  readonly redis: WSRedisPublisher;
  readonly now: () => number;
}

/** TTL (in seconds) for the Redis presence key. The 30s window is
 *  load-bearing: design.md §13.6 (`routeOutboundEnvelope`) reads
 *  `presence:{deviceId}` to decide whether to schedule a Web Push for
 *  an offline recipient, and the client emits PRESENCE_PING every
 *  ~15s (well below the TTL) so a connected client's key never expires
 *  in normal operation. A client that disconnects sees its key expire
 *  within 30s, after which the next outbound envelope to that device
 *  triggers a push. */
export const PRESENCE_TTL_SEC = 30;

/**
 * Handle a `C2S.PRESENCE_PING` frame.
 *
 * Realizes Requirement 12.2 and design.md §10:
 *   "touches devices.last_seen_at + Redis presence key TTL=30s".
 *
 * Order of operations:
 *   1. UPDATE devices SET last_seen_at = $now WHERE id = ctx.deviceId.
 *      A pure update — no INSERT, no upsert. If the device row was
 *      deleted while the socket was open (race with `DELETE /devices/:id`)
 *      the UPDATE matches zero rows and we silently no-op rather than
 *      surfacing an error; the next inbound envelope to this device
 *      will already have failed at the routing layer, so adding noise
 *      here is unnecessary.
 *   2. SET `presence:{deviceId} = "1"` with EX = 30s. Re-issued every
 *      ping so the key behaves as a sliding-window TTL.
 *
 * Failures:
 *   - DB UPDATE failure → log warn, but STILL try the Redis SET (the
 *     two writes are independent observability sinks and we'd rather
 *     have one than zero).
 *   - Redis SET failure → log warn. The `routeOutboundEnvelope` path
 *     treats a missing presence key as "offline", so the worst-case
 *     outcome is an extra Web Push for a connected device — annoying
 *     but not a correctness issue.
 *
 * Does NOT reply on the WS — presence pings are fire-and-forget.
 * Does NOT consume a rate-limit token: the per-device WS rate limit
 * is for SEND_ENVELOPE, not for control frames; flooding presence
 * pings doesn't fan out anywhere and is bounded by the WS frame rate.
 */
export async function onPresencePing(
  ctx: WSContext,
  deps: PresencePingDeps,
): Promise<void> {
  // Step 1 — UPDATE devices.last_seen_at. Convert the wall-clock
  // millisecond reading to a Postgres TIMESTAMPTZ via to_timestamp,
  // which expects seconds. Using a parameterised value rather than
  // `now()` lets tests freeze the clock via `deps.now`.
  const nowMs = deps.now();
  try {
    await deps.pool.query(
      `UPDATE devices
          SET last_seen_at = to_timestamp($1::double precision / 1000.0)
        WHERE id = $2`,
      [nowMs, ctx.deviceId],
    );
  } catch (err) {
    ctx.log.warn(
      { err, deviceId: ctx.deviceId },
      'presence ping: devices.last_seen_at update failed',
    );
  }

  // Step 2 — SET presence key with 30s TTL.
  try {
    await deps.redis.setPresence(ctx.deviceId, PRESENCE_TTL_SEC);
  } catch (err) {
    ctx.log.warn(
      { err, deviceId: ctx.deviceId },
      'presence ping: redis SET failed',
    );
  }
}

// ---------------------------------------------------------------------------
// SUBSCRIBE_ROOM / UNSUBSCRIBE_ROOM handlers (task 3.6)
// ---------------------------------------------------------------------------

/** Dependencies for `onSubscribeRoom` / `onUnsubscribeRoom`. */
export interface RoomSubscriptionDeps {
  readonly redis: WSRedisPublisher;
}

/**
 * Build the per-context listener for a `room:{slug}` channel.
 *
 * Realizes Requirement 10.4 (broadcast post fan-out — task 7.3): on
 * every message published to `room:{slug}` by
 * `apps/api/src/routes/broadcast.ts`, decode the JSON
 * `BroadcastPostFanoutPayload`, reconstruct a typed `BroadcastPost`,
 * and forward it to the connected client as an `S2C.ROOM_POST` frame.
 *
 * Wire format on Redis:
 *   The publisher (`broadcastRoutes`'s `POST /rooms/:slug/messages`)
 *   serializes the post as JSON because `WSRedisPublisher.publish`
 *   takes a string and JSON survives a rolling deploy across api
 *   replicas without msgpack version skew. The shape is documented
 *   on `BroadcastPostFanoutPayload`. We re-promote `id` to `bigint`
 *   here (the protocol's `BroadcastPost.id` is bigint to allow more
 *   than 2^53 posts in a single room), base64-decode the byte
 *   fields, and surface `createdAtMs` as `createdAt` (an
 *   epoch-millisecond number, matching the protocol shape in
 *   `packages/protocol/src/ws-messages.ts`).
 *
 * Failure modes:
 *   - Malformed JSON or missing fields: log warn and drop the
 *     payload. We do NOT close the socket because a corrupt
 *     publisher should not be able to disconnect every subscribed
 *     client; the next valid publish recovers cleanly.
 *   - `ctx.send` failure: handled by `buildContext`'s send — a
 *     closed socket swallows silently.
 *
 * The `slug` argument is captured for log diagnostics only;
 * dispatch is keyed by Redis channel inside the publisher
 * (`apps/api/src/ws/redis-publisher.ts`).
 */
function makeRoomListener(ctx: WSContext, slug: string): (payload: string) => void {
  return (payload: string): void => {
    const post = decodeBroadcastPostFanoutPayload(payload);
    if (post === null) {
      ctx.log.warn(
        { deviceId: ctx.deviceId, slug, payloadBytes: payload.length },
        'ws room message: malformed fan-out payload, dropped',
      );
      return;
    }
    ctx.send({ t: S2C.ROOM_POST, post });
  };
}

/** Wire shape produced by `apps/api/src/routes/broadcast.ts` on
 *  `room:{slug}` channels. Re-stated structurally rather than
 *  imported as a type so the gateway has no compile-time dependency
 *  on the broadcast routes module — the two files are separate
 *  concerns that happen to agree on a JSON contract. The contract
 *  is enforced by the unit tests in `broadcast-fanout.test.ts`
 *  which exercise both sides at once. */
interface BroadcastPostFanoutPayloadShape {
  id: string; // decimal-string of the BIGSERIAL id
  roomId: string;
  authorUserId: string;
  authorHandle: string;
  authorIdentityPub: string; // base64
  body: string;
  authorSignature: string; // base64
  createdAtMs: number;
}

/** Decode a JSON fan-out payload published by the broadcast route.
 *  Returns `null` on any shape failure so the caller can log and
 *  drop without throwing. We accept either base64 or base64url for
 *  the byte fields (matches the convention in
 *  `routes/broadcast.ts decodeSignature`). */
function decodeBroadcastPostFanoutPayload(
  payload: string,
): {
  readonly id: bigint;
  readonly roomId: string;
  readonly authorUserId: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;
  readonly body: string;
  readonly authorSignature: Uint8Array;
  readonly createdAt: number;
} | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }
  const o = parsed as Partial<BroadcastPostFanoutPayloadShape>;
  if (
    typeof o.id !== 'string' ||
    typeof o.roomId !== 'string' ||
    typeof o.authorUserId !== 'string' ||
    typeof o.authorHandle !== 'string' ||
    typeof o.authorIdentityPub !== 'string' ||
    typeof o.body !== 'string' ||
    typeof o.authorSignature !== 'string' ||
    typeof o.createdAtMs !== 'number' ||
    !Number.isFinite(o.createdAtMs)
  ) {
    return null;
  }
  let idBig: bigint;
  try {
    idBig = BigInt(o.id);
  } catch {
    return null;
  }
  // `Buffer.from(input, 'base64')` is lenient and accepts base64url
  // because the URL-safe substitutions don't conflict with standard
  // base64. We don't validate length here (the receiver will fail
  // signature verification on a wrong-length pubkey/signature, which
  // is the same outcome as a strict reject); the gateway is a
  // pass-through — verification semantics live in the client.
  const idPub = new Uint8Array(Buffer.from(o.authorIdentityPub, 'base64'));
  const sigBytes = new Uint8Array(Buffer.from(o.authorSignature, 'base64'));
  return {
    id: idBig,
    roomId: o.roomId,
    authorUserId: o.authorUserId,
    authorHandle: o.authorHandle,
    authorIdentityPub: idPub,
    body: o.body,
    authorSignature: sigBytes,
    createdAt: o.createdAtMs,
  };
}

/**
 * Handle a `C2S.SUBSCRIBE_ROOM` frame.
 *
 * Realizes design.md §10 (`onSubscribeRoom`):
 *   - Validates the slug shape (`^[a-z0-9-]{3,64}$`); on invalid slug
 *     replies `ERROR(INVALID_PAYLOAD)`. We do NOT verify the room
 *     exists in `broadcast_rooms` here — durable existence is checked
 *     at the REST `POST /rooms/:slug/subscribe` and `GET /rooms/:slug`
 *     boundaries (Requirement 10.13). The WS layer is purely a
 *     pub/sub multiplexer; subscribing to a non-existent slug is a
 *     no-op (no traffic ever arrives) and not worth a database
 *     round-trip per ping.
 *   - Idempotent: re-subscribing to a slug already in `subscribedRooms`
 *     does NOT issue a second Redis subscribe and does NOT add a
 *     duplicate listener — the gateway treats a duplicate as a
 *     successful no-op so a confused client doesn't accumulate
 *     state.
 *   - On Redis subscribe failure: log warn and reply `ERROR(INTERNAL)`.
 *     The slug is NOT added to `subscribedRooms` so a retry can re-
 *     attempt cleanly.
 */
export async function onSubscribeRoom(
  ctx: WSContext,
  msg: { slug: string },
  deps: RoomSubscriptionDeps,
): Promise<void> {
  if (!SLUG_REGEX.test(msg.slug)) {
    ctx.send({
      t: S2C.ERROR,
      code: ErrorCode.INVALID_PAYLOAD,
      message: 'invalid slug',
    });
    return;
  }

  // Idempotent re-subscribe: silently succeed without re-issuing the
  // Redis SUBSCRIBE. The `subscribedRooms` set is the source of truth
  // for "this connection is watching slug X".
  if (ctx.subscribedRooms.has(msg.slug)) {
    return;
  }

  const listener = makeRoomListener(ctx, msg.slug);
  try {
    await deps.redis.subscribeRoom(msg.slug, listener);
  } catch (err) {
    ctx.log.warn(
      { err, deviceId: ctx.deviceId, slug: msg.slug },
      'ws subscribe_room: redis SUBSCRIBE failed',
    );
    ctx.send({
      t: S2C.ERROR,
      code: ErrorCode.INTERNAL,
      message: 'internal error',
    });
    return;
  }

  ctx.subscribedRooms.add(msg.slug);
  // Stash the listener on the context so `onUnsubscribeRoom` and the
  // connection-close drain path can pass the SAME function reference
  // back to `unsubscribeRoom`. ioredis listener removal is identity-
  // based; a fresh closure would not unbind. We piggyback on a
  // private property keyed off `__roomListeners` rather than adding
  // another field to `WSContext` (the field would be visible to every
  // handler and risk being misused). The any-cast is local to this
  // module.
  const listeners = (ctx as unknown as RoomListenerSlot).__roomListeners ?? new Map<
    string,
    (payload: string) => void
  >();
  listeners.set(msg.slug, listener);
  (ctx as unknown as RoomListenerSlot).__roomListeners = listeners;
}

/**
 * Handle a `C2S.UNSUBSCRIBE_ROOM` frame.
 *
 * Realizes design.md §10 (`onUnsubscribeRoom`):
 *   - Validates the slug shape; invalid slugs receive
 *     `ERROR(INVALID_PAYLOAD)`.
 *   - Idempotent: unsubscribing from a slug not in `subscribedRooms`
 *     is a silent no-op (no Redis call, no error).
 *   - On Redis unsubscribe failure: log warn but STILL drop the slug
 *     from the local set so the client can re-subscribe without
 *     hitting the duplicate-suppress path. Worst-case the gateway
 *     keeps an upstream subscription open until the connection
 *     closes; this is corrected by the connection-drain path.
 */
export async function onUnsubscribeRoom(
  ctx: WSContext,
  msg: { slug: string },
  deps: RoomSubscriptionDeps,
): Promise<void> {
  if (!SLUG_REGEX.test(msg.slug)) {
    ctx.send({
      t: S2C.ERROR,
      code: ErrorCode.INVALID_PAYLOAD,
      message: 'invalid slug',
    });
    return;
  }

  if (!ctx.subscribedRooms.has(msg.slug)) {
    return;
  }

  const listeners = (ctx as unknown as RoomListenerSlot).__roomListeners;
  const listener = listeners?.get(msg.slug);
  if (listener !== undefined) {
    try {
      await deps.redis.unsubscribeRoom(msg.slug, listener);
    } catch (err) {
      ctx.log.warn(
        { err, deviceId: ctx.deviceId, slug: msg.slug },
        'ws unsubscribe_room: redis UNSUBSCRIBE failed',
      );
    }
    listeners?.delete(msg.slug);
  }
  ctx.subscribedRooms.delete(msg.slug);
}

/** Internal context-augmentation slot used by SUBSCRIBE_ROOM /
 *  UNSUBSCRIBE_ROOM to round-trip the same listener function
 *  reference (ioredis listener removal is identity-based). Kept
 *  module-private; not exposed on the public `WSContext` shape. */
interface RoomListenerSlot {
  __roomListeners?: Map<string, (payload: string) => void>;
}

/** Drain every active room subscription on this context. Called from
 *  the connection-close path so a disconnected client never leaves
 *  upstream Redis subscriptions hanging. Errors are swallowed —
 *  there's nothing to surface to (the socket is gone) and a partial
 *  drain is still better than no drain. */
export async function drainRoomSubscriptions(
  ctx: WSContext,
  deps: RoomSubscriptionDeps,
): Promise<void> {
  const listeners = (ctx as unknown as RoomListenerSlot).__roomListeners;
  if (listeners === undefined || listeners.size === 0) {
    ctx.subscribedRooms.clear();
    return;
  }
  await Promise.allSettled(
    Array.from(listeners.entries()).map(([slug, fn]) =>
      deps.redis.unsubscribeRoom(slug, fn),
    ),
  );
  listeners.clear();
  ctx.subscribedRooms.clear();
}

/** Top-level dispatch invoked for every inbound binary frame. Decodes
 *  via msgpack, applies the HELLO state machine, and routes by `t`.
 *
 *  Tasks covered:
 *    - 3.3 — HELLO handshake state machine.
 *    - 3.4 — `SEND_ENVELOPE` (idempotent insert + Redis fan-out).
 *    - 3.6 — `ENVELOPE_RECEIVED`, `PRESENCE_PING`, `SUBSCRIBE_ROOM`,
 *            `UNSUBSCRIBE_ROOM`.
 *
 *  The `default` branch is the exhaustiveness check via `_exhaustive`. */
export async function handleClientMessage(
  ctx: WSContext,
  raw: Uint8Array,
  opts: SendEnvelopeDeps & {
    pool: DbPool;
    now: () => number;
    attachInbox?: InboxAttacher;
  },
): Promise<void> {
  const msg = tryDecode(raw);
  if (msg === null) {
    rejectAndClose(ctx, ErrorCode.INVALID_PAYLOAD, 'malformed frame');
    return;
  }

  // Pre-HELLO state: only HELLO is accepted. Anything else closes the
  // connection with INVALID_PAYLOAD per Requirement 12.14.
  if (!ctx.helloReceived) {
    if (msg.t !== C2S.HELLO) {
      rejectAndClose(ctx, ErrorCode.INVALID_PAYLOAD, 'expected HELLO');
      return;
    }
    await handleHello(ctx, msg, opts.pool, opts.now, opts.attachInbox);
    return;
  }

  // Post-HELLO state: route by discriminator. The narrow set of
  // handlers below is exhaustive over the C2S enum; the `default`
  // branch is the no-op compile-time check via `_exhaustive`.
  switch (msg.t) {
    case C2S.HELLO: {
      // A second HELLO is a protocol violation.
      rejectAndClose(ctx, ErrorCode.INVALID_PAYLOAD, 'duplicate HELLO');
      return;
    }
    case C2S.SEND_ENVELOPE: {
      await onSendEnvelope(ctx, msg, opts);
      return;
    }
    case C2S.ENVELOPE_RECEIVED: {
      onEnvelopeReceived(ctx, msg);
      return;
    }
    case C2S.PRESENCE_PING: {
      await onPresencePing(ctx, opts);
      return;
    }
    case C2S.SUBSCRIBE_ROOM: {
      await onSubscribeRoom(ctx, msg, opts);
      return;
    }
    case C2S.UNSUBSCRIBE_ROOM: {
      await onUnsubscribeRoom(ctx, msg, opts);
      return;
    }
    default: {
      // Exhaustiveness check. If a new C2S variant is added without a
      // case here the compiler will report `Type '...' is not
      // assignable to type 'never'`.
      const _exhaustive: never = msg;
      void _exhaustive;
      rejectAndClose(ctx, ErrorCode.INVALID_PAYLOAD, 'unknown frame');
    }
  }
}

// ---------------------------------------------------------------------------
// Connection bootstrap
// ---------------------------------------------------------------------------

/** Wire up the per-connection lifecycle: register message/close/error
 *  listeners, start the HELLO timer, and ensure cleanup on close. */
export function handleConnection(
  ctx: WSContext,
  opts: SendEnvelopeDeps & {
    pool: DbPool;
    now: () => number;
    helloTimeoutMs: number;
    attachInbox?: InboxAttacher;
  },
): void {
  // Bump the active-connections gauge (Requirement 18.2,
  // `konvo_ws_connections`). Decremented on the socket's close /
  // error event so the gauge reflects only currently-open sockets.
  wsConnectionsGauge.inc(1);
  let connectionAccounted = true;
  // Track whether we already added this device id to the offline
  // detection registry so the close/error paths can remove it
  // exactly once (and so a pre-HELLO close doesn't try to remove
  // an entry that was never added).
  let connectedRegistered = false;
  const decrementOnce = (): void => {
    if (connectionAccounted) {
      connectionAccounted = false;
      wsConnectionsGauge.dec(1);
    }
    if (connectedRegistered && opts.connectedDevices !== undefined) {
      connectedRegistered = false;
      opts.connectedDevices.delete(ctx.deviceId);
    }
  };

  // HELLO timer: if the first valid HELLO doesn't arrive within
  // `helloTimeoutMs`, send INVALID_PAYLOAD and close. The timer is
  // cancelled inside the message handler when `helloReceived` flips.
  const helloTimer: NodeJS.Timeout = setTimeout(() => {
    if (!ctx.helloReceived) {
      rejectAndClose(ctx, ErrorCode.INVALID_PAYLOAD, 'HELLO timeout');
    }
  }, opts.helloTimeoutMs);
  // Don't keep the Node event loop alive solely for this timer —
  // shutting down the api process should be able to exit even if a
  // pre-HELLO socket is still hanging.
  if (typeof helloTimer.unref === 'function') {
    helloTimer.unref();
  }

  ctx.socket.on('message', (data: Buffer | Uint8Array): void => {
    // Normalize `Buffer` (Node) and `Uint8Array` (test mocks) to a
    // plain `Uint8Array` so the codec sees a uniform input. We pass
    // through the underlying ArrayBuffer slice rather than copying.
    const buf =
      data instanceof Buffer
        ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
        : data;
    void handleClientMessage(ctx, buf, {
      pool: opts.pool,
      now: opts.now,
      redis: opts.redis,
      sendEnvelopeBuckets: opts.sendEnvelopeBuckets,
      sendEnvelopeBucket: opts.sendEnvelopeBucket,
      ...(opts.connectedDevices !== undefined
        ? { connectedDevices: opts.connectedDevices }
        : {}),
      ...(opts.offlinePushSender !== undefined
        ? { offlinePushSender: opts.offlinePushSender }
        : {}),
      ...(opts.senderHandleResolver !== undefined
        ? { senderHandleResolver: opts.senderHandleResolver }
        : {}),
      ...(opts.offlinePushScheduler !== undefined
        ? { offlinePushScheduler: opts.offlinePushScheduler }
        : {}),
      ...(opts.offlinePushDelayMs !== undefined
        ? { offlinePushDelayMs: opts.offlinePushDelayMs }
        : {}),
      ...(opts.attachInbox !== undefined ? { attachInbox: opts.attachInbox } : {}),
    })
      .then(() => {
        // After every message dispatch, check whether HELLO has just
        // landed: if so, register this device as connected so a
        // concurrent SEND_ENVELOPE from a peer correctly classifies
        // the recipient as online. We do this here (rather than
        // inside `handleHello`) to keep `handleHello` decoupled from
        // the connection-registry mechanics — the hello handler
        // doesn't need to know about offline-push detection.
        if (
          ctx.helloReceived &&
          !connectedRegistered &&
          opts.connectedDevices !== undefined
        ) {
          opts.connectedDevices.add(ctx.deviceId);
          connectedRegistered = true;
        }
      })
      .catch((err: unknown) => {
        ctx.log.error({ err }, 'ws message handler threw');
        rejectAndClose(ctx, ErrorCode.INTERNAL, 'internal error');
      });
  });

  ctx.socket.on('close', (): void => {
    clearTimeout(helloTimer);
    decrementOnce();
    // Drain any active room subscriptions so a disconnected client
    // never leaves upstream Redis subscriptions hanging. Errors are
    // swallowed inside `drainRoomSubscriptions` because there's
    // nothing to surface to (the socket is gone).
    void drainRoomSubscriptions(ctx, { redis: opts.redis });
    // Detach the per-device inbox subscription installed by
    // `attachInbox`. The publisher refcounts subscribers per
    // channel; when the last one detaches, an upstream `UNSUBSCRIBE`
    // is issued. If the connection closed before HELLO_OK no handle
    // was ever stored and this is a no-op.
    const handle = (ctx as unknown as InboxHandleSlot).__inboxHandle;
    if (handle !== undefined) {
      (ctx as unknown as InboxHandleSlot).__inboxHandle = undefined;
      void handle.detach().catch((err: unknown) => {
        ctx.log.warn({ err, deviceId: ctx.deviceId }, 'inbox detach failed');
      });
    }
  });

  ctx.socket.on('error', (err: Error): void => {
    decrementOnce();
    ctx.log.warn({ err }, 'ws transport error');
  });
}

// ---------------------------------------------------------------------------
// Fastify plugin
// ---------------------------------------------------------------------------

/** Fastify plugin that mounts the WS route at `/ws`.
 *
 *  This factory is wired in `apps/api/src/server.ts` AFTER the auth
 *  routes (so a request to `/ws` is handled by the WS upgrade path
 *  rather than by the auth router's catch-all error handler). It also
 *  registers `@fastify/websocket` once when called the first time. */
export const wsRoutes: FastifyPluginAsync<WsRouteOptions> = async (
  app,
  opts,
) => {
  const now = opts.now ?? ((): number => Date.now());
  const helloTimeoutMs = opts.helloTimeoutMs ?? HELLO_TIMEOUT_MS;
  const sendEnvelopeBucket = opts.sendEnvelopeBucket ?? SEND_ENVELOPE_BUCKET;
  const sendEnvelopeBuckets =
    opts.sendEnvelopeBuckets ?? defaultSendEnvelopeBuckets;
  // Module-level "currently-connected devices" registry. Defaults to
  // the shared `defaultConnectedDevices` set so all api boots share
  // the same in-process registry for the offline-push fallback
  // (Requirement 12.10 / task 10.4).
  const connectedDevices =
    opts.connectedDevices ?? defaultConnectedDevices;

  await ensureWebsocketPlugin(app);

  // The `{ websocket: true }` option flips the route into upgrade mode.
  // The handler signature in `@fastify/websocket@11` is
  // `(socket, request) => void` where `socket` is a `ws.WebSocket` and
  // `request` is the standard FastifyRequest carrying the upgrade
  // headers + query string.
  app.get(
    '/ws',
    { websocket: true },
    async (socket: WSSocket, req: FastifyRequest): Promise<void> => {
      const auth = await authenticate(
        req,
        opts.accessTokenService,
        Math.floor(now() / 1000),
      );
      if (!auth.ok) {
        // We construct a temporary context just so the failure path can
        // use the same `send` + `close` semantics as the success path.
        // `userId` / `deviceId` are intentionally empty here — no
        // downstream handler runs in this branch.
        const failureCtx = buildContext(socket, '', '', req.log);
        rejectAndClose(failureCtx, ErrorCode.AUTH_REQUIRED, auth.reason);
        return;
      }

      const ctx = buildContext(socket, auth.userId, auth.deviceId, req.log);
      // Bind the production inbox attacher: subscribe to
      // `dev:{deviceId}` and replay queued envelopes after HELLO_OK.
      // The same `opts.pool` and `opts.redis` instances are
      // threaded through so the attacher reuses the gateway's
      // connection pool and ioredis client. Test harnesses that
      // exercise `wsRoutes` end-to-end against a stub publisher get
      // the same behaviour because the publisher surface is
      // structural.
      const attachInbox = (innerCtx: WSContext): Promise<InboxHandle> =>
        attachInboxImpl(innerCtx, opts.redis, opts.pool as FanoutDbPool);
      handleConnection(ctx, {
        pool: opts.pool,
        redis: opts.redis,
        now,
        helloTimeoutMs,
        sendEnvelopeBuckets,
        sendEnvelopeBucket,
        connectedDevices,
        ...(opts.offlinePushSender !== undefined
          ? { offlinePushSender: opts.offlinePushSender }
          : {}),
        ...(opts.senderHandleResolver !== undefined
          ? { senderHandleResolver: opts.senderHandleResolver }
          : {}),
        ...(opts.offlinePushScheduler !== undefined
          ? { offlinePushScheduler: opts.offlinePushScheduler }
          : {}),
        ...(opts.offlinePushDelayMs !== undefined
          ? { offlinePushDelayMs: opts.offlinePushDelayMs }
          : {}),
        attachInbox,
      });
    },
  );
};

/** Idempotently register `@fastify/websocket` on the host instance.
 *  We import dynamically so the module isn't pulled into the bundle
 *  for environments that don't need WS (e.g. the standalone CLI
 *  consumers of `apps/api`). */
async function ensureWebsocketPlugin(app: FastifyInstance): Promise<void> {
  // `app.hasPlugin` works for plugins registered with explicit
  // `name` metadata; `@fastify/websocket` declares one. If a previous
  // `register` already happened (e.g. in a test harness) we skip.
  if (app.hasPlugin('@fastify/websocket')) {
    return;
  }
  const mod = await import('@fastify/websocket');
  // The package's default export is the plugin (CJS interop wraps it
  // under `.default` under ESM).
  const plugin = (mod as { default?: unknown }).default ?? mod;
  await app.register(plugin as never);
}

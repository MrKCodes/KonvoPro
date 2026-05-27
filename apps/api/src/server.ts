// Konvo API gateway (Fastify on Node 20).
//
// Order of operations is dictated by Requirement 17.6 / 19.8: env validation
// MUST run before the listener opens. Any missing/empty secret terminates
// the process inside `loadConfig()` with `process.exit(1)` before Fastify
// is even constructed.
//
// Subsequent phases register devices, prekeys, attachments, broadcast,
// and the WS gateway (see design.md §2 apps/api/src/). When the migration
// runner from task 1.6 lands it will be invoked between `loadConfig()` and
// `app.listen(...)` and will receive `config.DATABASE_URL`.

import Fastify, {
  type FastifyInstance,
  type FastifyPluginAsync,
  type FastifyPluginCallback,
  type FastifyRequest,
} from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyHelmet from '@fastify/helmet';
import fastifyRateLimit from '@fastify/rate-limit';
import pkg from 'pg';

import { loadConfig, type Config } from './config.js';
import { makeRequireAuth } from './middleware/auth.js';
import { healthRoutes } from './routes/health.js';
import { authRoutes } from './routes/auth.js';
import { devicesRoutes } from './routes/devices.js';
import { prekeyRoutes } from './routes/prekeys.js';
import { pushRoutes } from './routes/push.js';
import { turnRoutes } from './routes/turn.js';
import { broadcastLiveRoutes } from './routes/broadcast-live.js';
import { broadcastRoutes } from './routes/broadcast.js';
import {
  attachmentsRoutes,
  multipartUploadParser,
} from './routes/attachments.js';
import { createMinioStorage, type Storage } from './storage/minio.js';
import { wsRoutes } from './ws/gateway.js';
import { metricsRoutes, wireRedactionFailureCounter } from './obs/metrics.js';
import {
  createWsRedisPublisher,
  type WSRedisHandle,
} from './ws/redis-publisher.js';
import { sendPushNotification, type WebPushClient } from './push/sender.js';
import { csrfPlugin } from './services/auth/csrf.js';
import {
  createArgon2Service,
  defaultArgon2BenchmarkObserver,
  runArgon2VerifyBenchmark,
  type Argon2Service,
} from './services/auth/argon2.js';
import {
  createAccessTokenService,
  createRefreshTokenStore,
  type AccessTokenService,
  type RefreshTokenStore,
} from './services/auth/tokens.js';
import {
  createLiveKitTokenSigner,
  type LiveKitTokenSigner,
} from './services/livekit.js';

const { Pool } = pkg;

const HOST = '0.0.0.0';

/** Surface the auth-plumbing primitives the server bootstrap constructs.
 *  Kept distinct from `AuthRoutesDeps` because future phases (devices,
 *  prekeys, attachments) will share `pool` and `accessTokenService` from
 *  this same set. */
export interface ServerDeps {
  readonly pool: pkg.Pool;
  readonly argon2: Argon2Service;
  readonly accessTokenService: AccessTokenService;
  readonly refreshTokenStore: RefreshTokenStore;
  /** coturn REST-auth shared secret. Mirrors `config.COTURN_REST_SECRET`;
   *  threaded through here so `turnRoutes` can sign ephemeral
   *  credentials without re-loading the config (Requirement 7.12). */
  readonly coturnRestSecret: string;
  /** coturn realm / public host. Mirrors `config.COTURN_REALM`. */
  readonly coturnRealm: string;
  /** LiveKit publisher / viewer token signer (Requirement 11.1, 11.2).
   *  Constructed once at boot from `config.LIVEKIT_API_KEY` /
   *  `config.LIVEKIT_API_SECRET`. */
  readonly livekitSigner: LiveKitTokenSigner;
  /** Public LiveKit URL the web client connects to. Mirrors
   *  `config.LIVEKIT_URL`. */
  readonly livekitUrl: string;
  /** Redis publisher + drain hook for the WS gateway fan-out
   *  (Requirement 12.12 / 12.15). Constructed once at boot from
   *  `config.REDIS_URL`. */
  readonly redis: WSRedisHandle;
  /** Storage client for E2EE attachment ciphertext blobs (Requirement
   *  6.2 / 6.5). MinIO-backed in production; tests substitute an
   *  in-memory implementation. */
  readonly storage: Storage;
  /** MinIO bucket where attachment ciphertext blobs live. Mirrors
   *  `config.MINIO_BUCKET`. */
  readonly attachmentBucket: string;
  /** Optional Web Push client used by the WS gateway's offline push
   *  fallback (Requirement 12.10 / task 10.4). Bound to a VAPID-
   *  configured `web-push` SDK in production; tests / partial
   *  installs leave this `undefined` so the fallback is a no-op
   *  (the envelope is still persisted; the recipient receives it
   *  on next reconnect via offline replay). */
  readonly offlineWebPush?: WebPushClient;
}

/** Construct the shared service instances bound to a validated `Config`.
 *  Exported so integration tests can spin up an isolated server with
 *  alternate deps (e.g. a per-test pool or a mock argon2). */
export async function buildServerDeps(config: Config): Promise<ServerDeps> {
  const pool = new Pool({
    connectionString: config.DATABASE_URL,
    // Pool sizing is intentionally modest for Phase 1; tune in task 18 work.
    max: 10,
  });
  const argon2 = createArgon2Service({
    memoryKib: config.ARGON2_M_KIB,
    timeCost: config.ARGON2_T,
    parallelism: config.ARGON2_P,
  });
  const accessTokenService = createAccessTokenService(config.JWT_ACCESS_SECRET);
  const refreshTokenStore = createRefreshTokenStore(
    pool,
    config.REFRESH_TOKEN_PEPPER,
  );
  const livekitSigner = createLiveKitTokenSigner(
    config.LIVEKIT_API_KEY,
    config.LIVEKIT_API_SECRET,
  );
  const redis = await createWsRedisPublisher(config.REDIS_URL);
  const storage = await createMinioStorage({
    endpoint: config.MINIO_ENDPOINT,
    accessKey: config.MINIO_ACCESS_KEY,
    secretKey: config.MINIO_SECRET_KEY,
    useSsl: config.MINIO_USE_SSL,
  });
  // Optional `web-push` SDK wiring for the offline push fallback
  // (Requirement 12.10 / task 10.4). The dynamic import lets a
  // partial install (where `web-push` may not yet be materialised)
  // boot without the fallback rather than crashing the API. The
  // VAPID details are validated at config-load time.
  const offlineWebPush = await tryCreateWebPushClient(
    config.VAPID_PUBLIC_KEY,
    config.VAPID_PRIVATE_KEY,
    config.VAPID_SUBJECT,
  );
  return {
    pool,
    argon2,
    accessTokenService,
    refreshTokenStore,
    coturnRestSecret: config.COTURN_REST_SECRET,
    coturnRealm: config.COTURN_REALM,
    livekitSigner,
    livekitUrl: config.LIVEKIT_URL,
    redis,
    storage,
    attachmentBucket: config.MINIO_BUCKET,
    ...(offlineWebPush !== null ? { offlineWebPush } : {}),
  };
}

/** Construct a `WebPushClient` backed by the `web-push` npm package.
 *  Returns `null` if the package isn't installed (test / partial
 *  install) — the WS gateway then omits the offline-push fallback
 *  and relies on the offline replay path on the recipient's next
 *  reconnect (Requirement 12.11). */
async function tryCreateWebPushClient(
  vapidPublicKey: string,
  vapidPrivateKey: string,
  vapidSubject: string,
): Promise<WebPushClient | null> {
  try {
    const mod = (await import('web-push')) as unknown as {
      default?: {
        setVapidDetails(s: string, pub: string, priv: string): void;
        sendNotification(
          subscription: { endpoint: string; keys: { p256dh: string; auth: string } },
          payload: string,
        ): Promise<unknown>;
      };
      setVapidDetails?(s: string, pub: string, priv: string): void;
      sendNotification?(
        subscription: { endpoint: string; keys: { p256dh: string; auth: string } },
        payload: string,
      ): Promise<unknown>;
    };
    const sdk = mod.default ?? mod;
    if (
      typeof sdk.setVapidDetails !== 'function' ||
      typeof sdk.sendNotification !== 'function'
    ) {
      return null;
    }
    sdk.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey);
    return {
      sendNotification: sdk.sendNotification.bind(sdk),
    };
  } catch {
    return null;
  }
}

/** Build a fully-configured Fastify instance. Callers pass in pre-built
 *  deps so tests can substitute mocks; the real `bootstrap()` below
 *  constructs them from `loadConfig()`. */
export async function buildServer(deps: ServerDeps): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: process.env['LOG_LEVEL'] ?? 'info',
    },
    // Trust Caddy's X-Forwarded-For so rate-limit's `req.ip` matches the
    // real client and not Caddy's loopback address. This is safe ONLY
    // because the api is never exposed without the proxy in front of it
    // (design.md §1.1 / Requirement 17.3).
    trustProxy: true,
  });

  // @fastify/cookie must come BEFORE any route that reads `req.cookies`
  // or sets cookies via `reply.setCookie`. We don't pass a `secret` here
  // because we don't sign cookies — the refresh token is opaque random
  // bytes; signing it would add no security but would force every cookie
  // read to allocate.
  await app.register(fastifyCookie);

  // -------------------------------------------------------------------------
  // Security headers (task 10.3 — Requirement 19.1).
  //
  // @fastify/helmet wraps `helmet` and applies the chosen CSP +
  // hardening headers to every response. We register it AFTER
  // @fastify/cookie (so the helmet hooks apply to cookie-bearing routes
  // too) and BEFORE every route plugin (so the headers attach to those
  // routes' replies via the global onRequest hook).
  //
  // Caddy already emits HSTS, X-Frame-Options, X-Content-Type-Options,
  // Referrer-Policy, and Permissions-Policy at the proxy layer. We
  // restate them here as defense-in-depth: any deployment topology
  // that bypasses Caddy (e.g. a future internal cluster ingress, a
  // unit-test injection harness, an operator running `curl` against
  // the api directly via a port-forward) still gets the same
  // hardening posture. Where Caddy and helmet would emit the same
  // header, they emit identical values, so a deployer can collapse
  // either side without behavioural change.
  //
  // Content-Security-Policy is OWNED by helmet (Caddy no longer emits
  // it after this task; see infra/caddy/Caddyfile). The directives
  // below mirror the Caddyfile floor with one upgrade: `style-src`
  // accepts a per-request nonce in addition to `'self'`, replacing the
  // prior `'unsafe-inline'` token. With `enableCSPNonces: true`,
  // @fastify/helmet generates a fresh `cspNonce.{script,style}` per
  // request and AUTOMATICALLY appends `'nonce-<value>'` to both
  // `script-src` and `style-src` before serializing the header. We
  // surface the same nonce to handlers via `reply.cspNonce` if a
  // future SSR layer needs to inject inline tags. The SPA itself
  // ships with all styles bundled into the static assets and does
  // not need the nonce at runtime.
  //
  // Why we DON'T use `useDefaults: true` + spread:
  //   The helmet defaults include `upgrade-insecure-requests`, which
  //   conflicts with our same-origin `wss://` connect-src and
  //   triggers a console warning in Chromium when the API is
  //   accessed over HTTP for local docker-compose smoke tests (the
  //   browser would otherwise rewrite `ws://` to `wss://` and break
  //   the local dev loop). Listing every directive explicitly keeps
  //   the policy auditable.
  //
  // Why `wasm-unsafe-eval`:
  //   libsignal-client (packages/crypto, design.md §8) ships its
  //   protocol primitives as a WebAssembly module instantiated at
  //   runtime; `wasm-unsafe-eval` is the CSP token that allows
  //   `WebAssembly.{compile,instantiate}` while still forbidding
  //   `eval` and inline scripts. No `'unsafe-inline'` for scripts.
  await app.register(fastifyHelmet, {
    enableCSPNonces: true,
    contentSecurityPolicy: {
      // We set every directive explicitly rather than spreading
      // helmet's defaults so the policy is auditable in one place.
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'wasm-unsafe-eval'"],
        // `enableCSPNonces` will append `'nonce-<value>'` to this
        // list per-request; we list `'self'` here as the
        // non-nonce floor so bundled stylesheets continue to load.
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:', 'blob:'],
        'media-src': ["'self'", 'blob:', 'wss:'],
        // `connect-src 'self' wss: turns:` matches the Caddyfile
        // (`wss://{$KONVO_HOST}` is `wss:` once helmet sees it; we
        // accept any wss host so the api can be put behind a
        // different proxy hostname without re-emitting this header).
        'connect-src': ["'self'", 'wss:', 'turns:'],
        'font-src': ["'self'", 'data:'],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"],
      },
    },
    // HSTS: Caddy already emits `max-age=63072000; includeSubDomains;
    // preload` (Requirement 17.4). Restate the same value here so a
    // deployment that bypasses Caddy still satisfies 17.4.
    strictTransportSecurity: {
      maxAge: 63_072_000,
      includeSubDomains: true,
      preload: true,
    },
    // The Caddyfile sets these too; restating keeps the api safe
    // standalone.
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // helmet's frameguard sets `X-Frame-Options: DENY` by default,
    // which matches our Caddyfile.
    frameguard: { action: 'deny' },
    // X-Content-Type-Options: nosniff (the noSniff option is on by
    // default; restated here for explicitness).
    noSniff: true,
    // Cross-origin isolation. We DO want `same-origin` on the
    // resource policy so that broadcast post `<img>` tags from
    // attacker pages can't read our static assets. CORP is on by
    // default in helmet but the policy value defaults to
    // `same-origin`, which is exactly what we want.
    crossOriginResourcePolicy: { policy: 'same-origin' },
    // Disable the legacy XSS filter — modern browsers ignore it and
    // some older ones interact badly with strict CSPs.
    xssFilter: false,
  });

  // -------------------------------------------------------------------------
  // CSRF double-submit (task 10.3 — Requirements 19.3, 19.9).
  //
  // Registered AFTER @fastify/cookie (we need `req.cookies` parsing)
  // and AFTER @fastify/helmet (so a CSRF rejection still carries the
  // security headers). The plugin breaks Fastify encapsulation via
  // `Symbol.for('skip-override')` so the hooks attach to every
  // subsequently-registered route on this same instance.
  //
  // Skipped paths (no cookie issuance, no double-submit check):
  //   - /health  : Caddy + Prometheus probe; never carries auth.
  //   - /metrics : Prometheus scrape target (added in task 10.1);
  //                same posture as /health.
  //   - /auth/login, /auth/signup : bootstrapping problem. A login
  //     attempt on a fresh browser cannot satisfy double-submit
  //     because no `konvo_csrf` cookie exists yet. The login response
  //     carries the same protections as the rest of the auth flow:
  //     `SameSite=Lax` on the refresh-token cookie blocks the
  //     simple top-level CSRF, the per-IP rate limit (5/min) blocks
  //     credential-stuffing, and the response always sets a fresh
  //     csrf cookie via the GET-flavoured branch of the plugin (the
  //     onSend hook still runs because helmet's hooks don't
  //     short-circuit it). After login the SPA has both a refresh
  //     token AND a csrf token, and every subsequent state-changing
  //     request enforces double-submit.
  //   - /ws*, /livekit/* : reverse-proxied WebSocket upgrades, not
  //     state-changing REST calls. The Upgrade handshake itself is
  //     protected by the JWT in the connection params (task 3.3).
  await app.register(csrfPlugin, {
    skipPaths: [
      /^\/health$/,
      /^\/metrics$/,
      /^\/auth\/login$/,
      /^\/auth\/signup$/,
      /^\/ws/,
      /^\/livekit\//,
    ],
  });

  // @fastify/rate-limit registered with `global: false` so only the
  // routes that explicitly opt in via `config.rateLimit` are limited.
  // Per Requirement 19.4 the auth plugin sets per-route limits of 5/min
  // on /auth/login and 30/min on /auth/refresh.
  await app.register(fastifyRateLimit, {
    global: false,
    // `keyGenerator` defaults to `req.ip`, which honours `trustProxy` set
    // above. We restate it explicitly so the per-IP scope (Requirement
    // 19.4) is documented at the registration site.
    keyGenerator: (req: FastifyRequest) => req.ip,
    // Reply with HTTP 429 + a generic body. Per Requirement 1.15 / 19.4
    // we don't disclose the precise window.
    errorResponseBuilder: () => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'rate limit exceeded',
    }),
  });

  await app.register(healthRoutes);
  await app.register(metricsRoutes);
  await app.register(authRoutes, {
    pool: deps.pool,
    argon2: deps.argon2,
    accessTokenService: deps.accessTokenService,
    refreshTokenStore: deps.refreshTokenStore,
  });

  // Phase-2 task 3.3 — WebSocket gateway authentication + HELLO handshake
  // (Requirements 12.1, 12.2, 12.13, 12.14). Mounts `/ws` as a WebSocket
  // upgrade route; rejects connections without a fresh JWT (≥ 600s
  // remaining lifetime) and tears down sockets that don't deliver a
  // valid HELLO within 5s. Registered AFTER the auth routes so a
  // failed token verify on the WS path doesn't compete with the
  // auth-route error handlers for the same `/auth/*` requests.
  //
  // Phase-9 task 10.4 — the offline-push fallback (Requirement 12.10)
  // is wired in via the `offlinePushSender` / `senderHandleResolver`
  // options. Production wiring of the `web-push` SDK lives in a
  // dedicated boot step (see ServerDeps); when those deps are
  // present, the gateway schedules a metadata-only Web Push within
  // 2 s of envelope insertion for offline recipients. Without those
  // deps the gateway omits the fallback (the row stays
  // `delivered_at IS NULL` for the recipient's next reconnect).
  await app.register(wsRoutes, {
    accessTokenService: deps.accessTokenService,
    pool: deps.pool,
    redis: deps.redis.publisher,
    ...(deps.offlineWebPush !== undefined
      ? {
          offlinePushSender: async (args): Promise<unknown> =>
            sendPushNotification(
              { pool: deps.pool, webPush: deps.offlineWebPush! },
              args,
            ),
          senderHandleResolver: async (
            userId: string,
          ): Promise<string | null> => {
            const r = await deps.pool.query<{ handle: string }>(
              `SELECT handle FROM users WHERE id = $1`,
              [userId],
            );
            const row = r.rows[0];
            return row !== undefined ? row.handle : null;
          },
        }
      : {}),
  });

  // Phase-1 task 2.6 — device enrollment routes
  // (POST /devices, GET /devices, DELETE /devices/:id,
  //  POST /devices/:id/prekeys). Auth is enforced inline by the route
  // plugin via the shared `requireAuth` preHandler so the per-route
  // configs (bodyLimit, etc.) sit alongside their handlers.
  await app.register(devicesRoutes, {
    pool: deps.pool,
    requireAuth: makeRequireAuth(deps.accessTokenService),
  });

  // Phase-3 task 4.5 — prekey-bundle distribution endpoint
  // (GET /users/:handle/prekey-bundle?deviceId=...). PUBLIC route by
  // design: any user must be able to fetch any other user's bundle to
  // bootstrap an X3DH session, which is the entire purpose of a
  // prekey distribution server. The plugin atomically consumes one
  // unused OPK per request (Requirement 3.5) via a single SQL
  // UPDATE … RETURNING with `FOR UPDATE SKIP LOCKED` so concurrent
  // readers can never receive the same OPK twice. When no unused
  // OPK is available the response carries `oneTimePreKey: null` so
  // the client falls back to degraded X3DH (Requirement 3.6); a
  // missing handle or deviceId returns 404 with no OPK consumption
  // (Requirement 3.10). Registered after the devices plugin so any
  // future shared error handlers attached on devices registration
  // apply here too.
  await app.register(prekeyRoutes, {
    pool: deps.pool,
  });

  // Phase-8 task 9.3 — Web Push subscription routes (Requirements
  // 13.1, 13.2, 13.7, 15.3). Built off the shared `requireAuth`
  // preHandler so an unauthenticated caller cannot plant a
  // subscription on someone else's device. Both routes are
  // state-changing (POST and DELETE) so they automatically enforce
  // the CSRF double-submit check via the global `csrfPlugin`
  // registered above.
  await app.register(pushRoutes, {
    pool: deps.pool,
    requireAuth: makeRequireAuth(deps.accessTokenService),
  });

  // Phase-5 task 6.1 — ephemeral coturn TURN credential endpoint
  // (Requirement 7.12). Built off the shared `requireAuth` preHandler
  // so a JWT-less drive-by visitor cannot mint an hour of TURN relay
  // bandwidth. The route is intentionally registered AFTER auth so any
  // future global error handlers attached on auth registration apply
  // here too.
  await app.register(turnRoutes, {
    requireAuth: makeRequireAuth(deps.accessTokenService),
    coturnRestSecret: deps.coturnRestSecret,
    coturnRealm: deps.coturnRealm,
  });

  // Phase-7 task 8.1 — LiveKit publisher/viewer token issuance for
  // broadcast rooms (Requirements 11.1, 11.2). Built off the shared
  // `requireAuth` preHandler so unauthenticated callers can never mint
  // a LiveKit JWT. The plugin enforces the admin-role check for
  // `POST /rooms/:slug/live` against `broadcast_members.role = 'admin'`.
  await app.register(broadcastLiveRoutes, {
    pool: deps.pool,
    requireAuth: makeRequireAuth(deps.accessTokenService),
    livekitSigner: deps.livekitSigner,
    livekitUrl: deps.livekitUrl,
  });

  // Phase-6 task 7.2 / 7.3 — broadcast room REST routes (`POST /rooms`,
  // `GET /rooms/:slug`, `GET /rooms/:slug/messages`,
  // `POST /rooms/:slug/messages`, `POST /rooms/:slug/subscribe`).
  // Wired with the WS Redis publisher so a successful
  // `POST /rooms/:slug/messages` PUBLISHes on `room:{slug}` for fan-out
  // to every WS connection currently subscribed via `SUBSCRIBE_ROOM`
  // (Requirement 10.4 — task 7.3). The publish is best-effort: a Redis
  // failure logs at warn-level and surfaces 201 anyway because the
  // post is durably persisted in `broadcast_messages` and the next
  // `GET /rooms/:slug/messages` history fetch fills the gap.
  await app.register(broadcastRoutes, {
    pool: deps.pool,
    requireAuth: makeRequireAuth(deps.accessTokenService),
    redis: deps.redis.publisher,
  });

  // Phase-4 task 5.2 — E2EE attachment ciphertext upload + download
  // (Requirements 6.2, 6.3, 6.5, 6.6, 6.7, 6.8, 6.10).
  //
  // We register `@fastify/multipart` in an ENCAPSULATED scope so its
  // body parser only attaches to the attachments routes. Other
  // routes (auth, devices, broadcast) keep using the default JSON
  // parser. Per-file size cap is 25 MiB + 1 byte so the parser can
  // distinguish "exactly at the limit" from "over the limit" — the
  // parser surfaces oversize bodies as a typed
  // `RequestFileTooLargeError`, which our `multipartUploadParser`
  // maps onto the typed `{ ok: false, reason: 'too_large' }` result
  // and the route turns into HTTP 413 (Requirement 6.3).
  //
  // The multipart plugin is loaded via dynamic import so a missing
  // install (e.g. during a partial `pnpm install`) surfaces as a
  // clear runtime error at the multipart route's startup rather than
  // breaking unrelated routes' module resolution.
  await app.register(async (scope) => {
    // Dynamic import shape: ESM default export OR namespace export.
    // We declare the union as `unknown` and discriminate at runtime
    // so we never need an `any` annotation. The plugin signature
    // matches `FastifyPluginCallback`/`FastifyPluginAsync` so this
    // is enough surface for `scope.register(...)` to type-check.
    type MultipartModule = Readonly<{
      default?: FastifyPluginAsync<Record<string, unknown>> | FastifyPluginCallback<Record<string, unknown>>;
    }> & (FastifyPluginAsync<Record<string, unknown>> | FastifyPluginCallback<Record<string, unknown>>);
    const multipartModule = (await import('@fastify/multipart')) as unknown as MultipartModule;
    const multipartPlugin = multipartModule.default ?? multipartModule;
    await scope.register(multipartPlugin, {
      limits: {
        fileSize: 25 * 1024 * 1024 + 1,
        files: 1,
        // Each text field stays well under 4 KiB (mime, sizeBytes,
        // base64 IV/tag, comma-joined recipient UUIDs).
        fieldSize: 8 * 1024,
        fields: 16,
      },
    });
    await scope.register(attachmentsRoutes, {
      pool: deps.pool,
      requireAuth: makeRequireAuth(deps.accessTokenService),
      storage: deps.storage,
      bucket: deps.attachmentBucket,
      parseUpload: multipartUploadParser(),
    });
  });

  // Graceful shutdown — close the pg pool and Redis publisher when
  // Fastify closes so a SIGTERM from docker-compose doesn't leave
  // dangling connections.
  app.addHook('onClose', async () => {
    await Promise.allSettled([deps.pool.end(), deps.redis.close()]);
  });

  return app;
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// Validate every required env var BEFORE doing anything else. On any
// missing/invalid value loadConfig() emits structured errors and exits the
// process; the listener below is unreachable in that case.
const config = loadConfig();

const deps = await buildServerDeps(config);

// Boot-time Argon2id verify benchmark (Requirement 1.12 / design.md §18.2).
// Runs AFTER config validation and BEFORE the listener opens, so the alert
// metric is observable from the very first scrape. The default observer
// emits a structured warn line tagged with the Prometheus counter name
// `konvo_argon2_verify_under_budget_total`; task 10.1 will replace it with
// a real prom-client Counter without changing this call site.
const argon2BenchmarkResult = await runArgon2VerifyBenchmark(deps.argon2, {
  memoryKib: config.ARGON2_M_KIB,
  timeCost: config.ARGON2_T,
  parallelism: config.ARGON2_P,
});
defaultArgon2BenchmarkObserver.onBenchmarkResult(argon2BenchmarkResult);

// Record the boot-time verify duration into the Argon2 verify
// histogram so `/metrics` carries at least one sample on a fresh
// server. Subsequent /auth/login verify paths add further samples.
const { argon2VerifySeconds: argon2VerifyHistogram } = await import(
  './obs/metrics.js'
);
argon2VerifyHistogram.observe(argon2BenchmarkResult.durationMs / 1000);

// Wire the prom-client redaction-failure counter into the logger so
// dropped log records (Requirement 18.7) increment a real Prometheus
// series. This must run BEFORE buildServer (the logger is constructed
// during plugin registration) but AFTER config has been validated.
await wireRedactionFailureCounter();

const app = await buildServer(deps);

// Forward SIGTERM/SIGINT to Fastify so the onClose hook drains the
// pg pool before the process exits.
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    app
      .close()
      .then(() => process.exit(0))
      .catch((err) => {
        app.log.error(err, 'fastify close failed');
        process.exit(1);
      });
  });
}

try {
  await app.listen({ port: config.PORT, host: HOST });
} catch (err) {
  app.log.error(err);
  await Promise.allSettled([deps.pool.end(), deps.redis.close()]);
  process.exit(1);
}

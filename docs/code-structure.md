# Code Structure

Konvo is a pnpm workspace. Two apps and two shared packages live alongside an
end-to-end Playwright suite and the infra config that the docker-compose
stack mounts.

## 1. Top-level layout

```
KonvoPro/
├── apps/
│   ├── web/           # @konvo/web   — React 18 + Vite PWA
│   └── api/           # @konvo/api   — Fastify gateway (Node 20)
├── packages/
│   ├── protocol/      # @konvo/protocol — wire types + msgpack codecs
│   └── crypto/        # @konvo/crypto   — libsignal wrapper, AES-GCM helpers
├── e2e/               # @konvo/e2e   — Playwright end-to-end suite
├── infra/             # docker-compose + Caddy/coturn/LiveKit/Postgres/Prometheus configs
├── scripts/           # one-shot scripts (e.g. seed.ts)
├── docs/              # this directory
├── README.md
├── THREAT_MODEL.md
├── pnpm-workspace.yaml
├── package.json
├── tsconfig.base.json
└── .github/workflows/ci.yml
```

The workspace declaration in `pnpm-workspace.yaml` keeps `e2e` as a peer
workspace alongside `apps/*` and `packages/*`.

## 2. `apps/web` (`@konvo/web`)

React 18 + Vite PWA. Owns local key material in IndexedDB and performs all
cryptographic operations. Plaintext never leaves the browser.

```
apps/web/src/
├── routes/                    # /login /signup /dm/:handle /r/:slug /settings
├── features/
│   ├── auth/                  # signup, login, refresh, recovery-loss notice
│   ├── dm/                    # DM thread, composer, safety-number screen
│   ├── calls/                 # 1:1 audio + video, signaling, in-call SN
│   ├── broadcast/             # room view, Go Live, viewer count
│   ├── attachments/           # encrypted upload/download, LRU blob cache
│   └── settings/              # devices, push toggle, theme, key export
├── stores/                    # Zustand slices
├── queries/                   # TanStack Query hooks
├── db/                        # Dexie schema + repositories (see data-model.md)
├── ws/                        # WSS client + msgpack
├── pwa/                       # Workbox SW, push handler
└── ui/                        # shadcn/ui components
```

Tests sit under `apps/web/test/`. Vitest + Testing Library cover unit and
integration cases; Playwright (`e2e/`) covers cross-browser-context
scenarios.

Key build/test scripts (from `apps/web/package.json`):

- `pnpm -F @konvo/web dev` — Vite dev server on `http://localhost:5173`.
- `pnpm -F @konvo/web build` — `tsc --noEmit && vite build` ; output lands in
  `apps/web/dist/`.
- `pnpm -F @konvo/web test` — vitest single-run.

## 3. `apps/api` (`@konvo/api`)

Fastify gateway on Node 20. Authenticates users, hands out prekey bundles,
relays opaque envelopes, persists broadcast posts, and fans out via Redis.

```
apps/api/src/
├── routes/
│   ├── auth.ts                # /auth/{signup,login,refresh,logout}
│   ├── devices.ts             # /devices, /devices/:id/prekeys
│   ├── prekeys.ts             # /users/:handle/prekey-bundle
│   ├── attachments.ts         # /attachments  (multipart)
│   ├── broadcast.ts           # /rooms ; /rooms/:slug{,/messages,/subscribe}
│   ├── broadcast-live.ts      # /rooms/:slug/live ; /live/viewer-token
│   ├── push.ts                # /push/subscribe  (POST + DELETE)
│   ├── turn.ts                # /turn/credentials
│   └── health.ts              # /health
├── ws/
│   ├── gateway.ts             # WSS auth, HELLO, SEND_ENVELOPE, ACK, presence, room sub/unsub
│   ├── rate-limit.ts          # token bucket (50 burst / 10 sustained per device)
│   ├── redis-fanout.ts        # attachInbox, publishEnvelopeToRecipient
│   ├── redis-publisher.ts     # ioredis client wrapping
│   └── types.ts               # WSContext, WSSocket, WSRedisPublisher
├── services/
│   ├── auth/argon2.ts         # m=64 MiB t=3 p=4 ; boot benchmark
│   ├── auth/tokens.ts         # JWT access, refresh-token store + rotation
│   ├── auth/csrf.ts           # double-submit plugin
│   └── livekit.ts             # LiveKit publisher/viewer JWT signer
├── push/sender.ts             # VAPID Web Push (metadata-only payloads)
├── storage/minio.ts           # S3-compatible client for attachment ciphertext
├── obs/
│   ├── logger.ts              # pino + recursive redaction
│   └── metrics.ts             # prom-client wrapper, /metrics route
├── db/migrate.ts              # transactional migrator (reads init.sql)
├── middleware/auth.ts         # makeRequireAuth preHandler
├── config.ts                  # zod-validated env at boot
└── server.ts                  # Fastify bootstrap, plugin registration
```

Tests sit under `apps/api/test/`. The mix is heavy on property-based suites
(see [`testing.md`](./testing.md)).

Key scripts:

- `pnpm -F @konvo/api dev` — `tsx watch src/server.ts` on
  `http://localhost:3000` (auto-runs migrations at boot).
- `pnpm -F @konvo/api build` — emit `apps/api/dist/`.
- `pnpm -F @konvo/api start` — run the built server.
- `pnpm -F @konvo/api test` — vitest.

## 4. `packages/protocol` (`@konvo/protocol`)

Single source of truth for everything that crosses the WSS or REST boundary.
Pure types + msgpack codecs; depends on `@msgpack/msgpack` only.

```
packages/protocol/src/
├── envelopes.ts               # InnerType, EnvelopeRouterType, CiphertextEnvelope, AttachmentRef, IceCandidateInit, InnerPayload
├── ws-messages.ts             # C2S, S2C, ClientToServer, ServerToClient, BroadcastPost, ErrorCode
├── codec.ts                   # encode/decode for C2S and S2C; CodecError
└── rest-dto.ts                # Signup/Login/Device/Prekey/Attachment/Broadcast/Push/TURN/LiveKit DTOs
```

Public exports are re-aggregated in `src/index.ts`. Wire-format details live
in [`protocol.md`](./protocol.md); REST shapes are catalogued in
[`api-reference.md`](./api-reference.md).

Build: `pnpm -F @konvo/protocol build` ; tests: `pnpm -F @konvo/protocol test`.

## 5. `packages/crypto` (`@konvo/crypto`)

libsignal wrapper plus auxiliary primitives. Keeps libsignal types out of the
app code; persistence funnels through a `SignalProtocolStore` adapter that
the web client backs with Dexie.

```
packages/crypto/src/
├── identity.ts                # getOrCreateIdentity, AES-KW wrap, dual-key Phase-1 placeholder
├── prekeys.ts                 # generateInitialBundle, replenishOneTimePreKeys, rotateSignedPreKey
├── session.ts                 # establishSession (X3DH), hasSession, deleteSession
├── ratchet.ts                 # encryptToDevice, decryptFromDevice (Double Ratchet)
├── attachment.ts              # AES-GCM 256/96 helpers (encrypt/decrypt blob)
├── safety-number.ts           # 60-digit / 12-group fingerprint, QR payload
├── broadcast-sign.ts          # signBroadcastPost / verifyBroadcastPost (Ed25519)
└── store.ts                   # SignalProtocolStore adapter + serializable state
```

Tests under `packages/crypto/test/` carry the property suites P1–P9 and
P19–P20 (see [`testing.md`](./testing.md)).

## 6. `e2e/` (`@konvo/e2e`)

Playwright suite. Live runs are gated on `KONVO_E2E_LIVE=1`; CI activates
that gate against the docker-compose stack.

```
e2e/
├── attachment.spec.ts
├── attachments-no-leak.integration.spec.ts
├── broadcast-live.spec.ts
├── broadcast-live.integration.spec.ts
├── broadcast-post.spec.ts
├── db-redaction.integration.spec.ts
├── dm-send.spec.ts
├── offline-queue.integration.spec.ts
├── push-offline-delivery.spec.ts
├── pwa-install.spec.ts
├── signup-and-login.spec.ts
├── tamper.e2e.spec.ts
├── video-call.spec.ts
├── voice-note.spec.ts
└── playwright.config.ts
```

The full per-spec description lives in [`testing.md`](./testing.md).

## 7. `infra/`

```
infra/
├── docker-compose.yml         # api · postgres · redis · minio · livekit · coturn · prometheus · grafana · loki · caddy
├── caddy/Caddyfile            # auto-TLS reverse proxy
├── postgres/init.sql          # schema bootstrap (idempotent — see data-model.md)
├── coturn/turnserver.conf
├── livekit/config.yaml
├── prometheus/prometheus.yml
└── grafana/dashboards/        # DM Health · Calls · Auth · System
```

[`deployment.md`](./deployment.md) walks through bringing this stack up.

## 8. Build, test, and lint commands

Run from the repo root.

```bash
# Type-check every workspace.
pnpm typecheck

# Lint every workspace (eslint --max-warnings=0).
pnpm lint

# Format check / write.
pnpm format

# Unit + property tests across the monorepo.
pnpm test

# Per-workspace runs.
pnpm -F @konvo/crypto test
pnpm -F @konvo/protocol test
pnpm -F @konvo/api test
pnpm -F @konvo/web test

# Property suites only (≥100 iterations by default; nightly raises to 500).
pnpm -r run test:property
FAST_CHECK_RUNS=500 pnpm -r run test:property

# Playwright e2e (needs the dev stack running; see deployment.md).
pnpm -F @konvo/e2e test:list
pnpm -F @konvo/e2e test

# Dev servers (NEVER run these in CI).
pnpm -F @konvo/api dev
pnpm -F @konvo/web dev
```

The CI pipeline runs each of these as a separate gate; see
[`development.md`](./development.md) for the gate-by-gate detail.

## 9. Module boundaries (do not break these)

- `packages/protocol` MUST NOT import from `@konvo/crypto`, `@konvo/api`, or
  `@konvo/web`. Wire types are the contract; they cannot depend on either
  side of the wire.
- `packages/crypto` MAY import `@konvo/protocol` for shared types ; MUST NOT
  import `@konvo/api` or `@konvo/web`.
- `apps/api` MUST NOT import from `@konvo/web`.
- `apps/web` MUST NOT import from `apps/api/src/**` directly. Cross-boundary
  contracts go through `@konvo/protocol`.
- No `: any` annotations in production source under `apps/*/src` or
  `packages/*/src`. Both eslint
  (`@typescript-eslint/no-explicit-any`) and a CI grep guard enforce this.

## 10. Where to add new code

| You're adding... | Put it in... |
| --- | --- |
| A new wire-format field shared by client and server | `packages/protocol/src/` (and update both consumers) |
| A new cryptographic primitive | `packages/crypto/src/` (with property tests) |
| A new REST endpoint | `apps/api/src/routes/` (register in `server.ts`) |
| A new WS frame type | `packages/protocol/src/ws-messages.ts` + a handler in `apps/api/src/ws/gateway.ts` |
| A new IndexedDB table | `apps/web/src/db/schema.ts` (bump the Dexie version; never mutate prior versions) |
| A new Prometheus metric | `apps/api/src/obs/metrics.ts` (mind the cardinality cap) |
| A new e2e scenario | `e2e/*.spec.ts` (use `*.integration.spec.ts` for live-stack scenarios) |

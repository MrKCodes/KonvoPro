# API Reference

This is a reference catalogue of the REST endpoints and WebSocket frame types
the Konvo API gateway exposes. The wire-level types live in
[`@konvo/protocol`](../packages/protocol/src/) ; the route handlers live in
[`apps/api/src/routes/`](../apps/api/src/routes/) and
[`apps/api/src/ws/gateway.ts`](../apps/api/src/ws/gateway.ts).

For the bytes that go on the wire (msgpack encoding, frame size limits,
ratchet header layout) see [`protocol.md`](./protocol.md).

## 1. Conventions

- Base URL in dev: `http://localhost:3000` ; behind Caddy: `https://<host>`.
- All state-changing routes are gated by the **CSRF double-submit** check
  (`X-CSRF-Token` header MUST equal the `konvo_csrf` cookie). Skipped paths:
  `/health`, `/metrics`, `/auth/login`, `/auth/signup`, `/ws*`, `/livekit/*`.
- Authenticated routes expect a 15-minute HS256 JWT in
  `Authorization: Bearer <accessToken>`. The JWT carries `{sub, did, iat,
  exp}`.
- Refresh tokens are httpOnly Secure SameSite=Lax cookies named
  `refresh_token`, opaque 256-bit, rotated on every use.
- Request and response bodies are JSON unless explicitly noted as
  `multipart/form-data`. WS frames use msgpack.
- Rate limits are per-IP unless the route states otherwise. 429 responses
  return `{statusCode:429, error:"Too Many Requests", message:"rate limit
  exceeded"}`.

## 2. REST endpoints

### 2.1 Auth

| Route | Auth | Body | Reply | Rate limit |
| --- | --- | --- | --- | --- |
| `POST /auth/signup` | none | `SignupRequest` | `SignupResponse` | 5/min/IP |
| `POST /auth/login` | none | `LoginRequest` (optional `totp`) | `LoginResponse` + sets `refresh_token` cookie | 5/min/IP |
| `POST /auth/refresh` | refresh-cookie | — | `RefreshResponse` (rotates the cookie) | 30/min/IP |
| `POST /auth/logout` | bearer | — | `204` (revokes refresh token) | — |

DTOs live in
[`packages/protocol/src/rest-dto.ts`](../packages/protocol/src/rest-dto.ts).

Errors: invalid handle/password length → 400 ; invalid credentials or TOTP
→ 401 (does not disclose which factor failed) ; rate-limited → 429.

Constraints enforced server-side:

- `handle`: 3–32 lowercase chars `[a-z0-9_]`.
- `password`: 12–128 chars ; hashed via Argon2id `m=64 MiB t=3 p=4`.
- TOTP (when enabled): RFC 6238, 6 digits, 30-second window.

### 2.2 Devices and prekeys

| Route | Auth | Body | Reply | Rate limit |
| --- | --- | --- | --- | --- |
| `POST /devices` | bearer | `DeviceCreate` | `DeviceCreateResponse` | — |
| `GET /devices` | bearer | — | `DeviceListResponse` | — |
| `DELETE /devices/:id` | bearer | — | `204` | — |
| `POST /devices/:id/prekeys` | bearer | `PreKeysReplenishRequest` | `PreKeysReplenishResponse` | 100/min/device |
| `GET /users/:handle/prekey-bundle?deviceId=...` | bearer | — | `RemotePreKeyBundleResponse` | — |

Validation at `POST /devices`:

- 5-device cap per user.
- `identityPub` is exactly 32 bytes (Curve25519).
- `signedPreKey.signature` is exactly 64 bytes (Ed25519) and verifies
  against `identityEdPub`.
- `oneTimePreKeys` carries 1..100 entries, each public key 32 bytes.

`GET /users/:handle/prekey-bundle` atomically consumes one unused
one-time prekey via `UPDATE ... FOR UPDATE SKIP LOCKED RETURNING ...`. If
no unused OPK is available the response carries `oneTimePreKey: null` and
the client falls back to degraded X3DH.

### 2.3 Attachments

| Route | Auth | Body | Reply | Limits |
| --- | --- | --- | --- | --- |
| `POST /attachments` | bearer | `multipart/form-data` (file + fields) | `AttachmentCreateResponse` | per-file ≤ 25 MiB |
| `GET /attachments/:id` | bearer | — | binary stream (ciphertext) ; 403/404 enforced | — |

Multipart fields the upload route expects:

- `file` — AES-GCM ciphertext bytes only (never plaintext).
- `mime` — string ≤ 255 chars.
- `sizeBytes` — string-encoded byte length of the ciphertext.
- `contentIv` — base64 96-bit IV.
- `contentTag` — base64 128-bit GCM tag.
- `recipientUserIds` — comma-joined UUIDs the uploader declares as readers
  (the server's authorization check accepts owner OR any UUID in this
  list).

The AES key never leaves the client — it rides inside an E2EE envelope.

### 2.4 Broadcast rooms

| Route | Auth | Body | Reply | Rate limit |
| --- | --- | --- | --- | --- |
| `POST /rooms` | bearer | `RoomCreateRequest` | `RoomResponse` | — |
| `GET /rooms/:slug` | none (PUBLIC) | — | `RoomResponse` ; 404 on unknown slug | — |
| `GET /rooms/:slug/messages?before=&limit=50` | none (PUBLIC) | — | `BroadcastPostListResponse` | — |
| `POST /rooms/:slug/messages` | bearer + admin role | `BroadcastPostCreateRequest` | `BroadcastPostCreateResponse` | 1/s/admin/room |
| `POST /rooms/:slug/subscribe` | bearer | — | `204` (idempotent) | — |
| `POST /rooms/:slug/live` | bearer + admin role | — | `LiveKitTokenResponse` (publisher) | — |
| `GET /rooms/:slug/live/viewer-token` | bearer | — | `LiveKitTokenResponse` (subscriber) | — |

Broadcast post bodies are signed Ed25519 over `(body || roomId ||
createdAtMs)` by the author's per-device sub-key. The server verifies the
signature against `devices.identity_ed_pub` of the supplied `deviceId` and
rejects mismatches before persisting.

`createdAtMs` MUST be within ±60 s of the API gateway clock — otherwise
the post is rejected without persistence.

### 2.5 Push subscriptions

| Route | Auth | Body | Reply |
| --- | --- | --- | --- |
| `POST /push/subscribe` | bearer | `PushSubscriptionRequest` | `204` ; `endpoint` MUST be `https://` |
| `DELETE /push/subscribe/:id` | bearer | — | `204` |

Push payloads carry only `{type, senderHandle, conversationId}`. The
`web-push` SDK 410 path deletes the corresponding `push_subscriptions`
row.

### 2.6 TURN credentials

| Route | Auth | Body | Reply | TTL |
| --- | --- | --- | --- | --- |
| `GET /turn/credentials` | bearer | — | `TurnCredentialsResponse` | 1 h |

Returns ephemeral `username:credential` per coturn's REST-auth scheme.
Generating a credential requires no live coturn round-trip — the API signs
locally with the shared secret.

### 2.7 Ops

| Route | Auth | Reply | Notes |
| --- | --- | --- | --- |
| `GET /health` | none | `{ status: 'ok', uptimeSec: number }` | Caddy + Prometheus probe |
| `GET /metrics` | none (internal) | `text/plain; version=0.0.4` | Prometheus exposition ; bind to internal address |

## 3. WebSocket frames

The WSS endpoint mounts at `/ws`. Browsers authenticate via
`?token=<accessToken>`; non-browser clients may use
`Authorization: Bearer ...`. Tokens with less than 600 s remaining are
rejected.

After upgrade, the client MUST send `HELLO` within 5 s or the socket is
closed.

Frame encoding is msgpack (`@msgpack/msgpack`). Max frame size is **1 MiB** ;
oversize frames are rejected with `CodecError('malformed')` and the socket
sends `S2C.ERROR { code: INVALID_PAYLOAD }`.

### 3.1 Client → Server (`C2S`)

Discriminator values from
[`packages/protocol/src/ws-messages.ts`](../packages/protocol/src/ws-messages.ts):

| `t` | Frame | Shape |
| --- | --- | --- |
| `1` | `HELLO` | `{ deviceId, protoVersion: 1 }` |
| `2` | `SEND_ENVELOPE` | `{ clientNonce, envelope: CiphertextEnvelope }` |
| `3` | `ENVELOPE_RECEIVED` | `{ envelopeId: bigint }` (transport-level ack only) |
| `4` | `PRESENCE_PING` | `{}` |
| `5` | `SUBSCRIBE_ROOM` | `{ slug }` |
| `6` | `UNSUBSCRIBE_ROOM` | `{ slug }` |

`SEND_ENVELOPE` rules:

- `envelope.senderDeviceId` MUST equal the connection's authenticated
  `deviceId`.
- `(senderDeviceId, clientNonce)` is the database-enforced idempotency key.
  Repeated sends return the original `envelopeId`.
- Token bucket: 50 burst / 10 sustained per second per device. Excess sends
  receive `S2C.ERROR { code: RATE_LIMITED }`.

### 3.2 Server → Client (`S2C`)

| `t` | Frame | Shape |
| --- | --- | --- |
| `101` | `HELLO_OK` | `{ serverTimeMs, queuedCount }` (`queuedCount` capped at 10000) |
| `102` | `ENVELOPE` | `{ envelope: CiphertextEnvelope }` (inbound for this device) |
| `103` | `ENVELOPE_QUEUED` | `{ clientNonce, envelopeId, serverTimeMs }` |
| `104` | `ROOM_POST` | `{ post: BroadcastPost }` (signed plaintext) |
| `199` | `ERROR` | `{ code: ErrorCode, message: string }` |

`BroadcastPost` carries the signing device's `authorIdentityPub` so viewers
verify the Ed25519 signature client-side before rendering.

### 3.3 Error codes

From `ErrorCode` in
[`packages/protocol/src/ws-messages.ts`](../packages/protocol/src/ws-messages.ts):

| Code | Name | When |
| --- | --- | --- |
| `1` | `AUTH_REQUIRED` | missing/expired/short-lifetime token, or HELLO `deviceId` mismatch |
| `2` | `RATE_LIMITED` | per-device SEND_ENVELOPE bucket exhausted |
| `3` | `INVALID_PAYLOAD` | codec error, oversize frame, sender mismatch, unknown discriminator |
| `4` | `RECIPIENT_UNKNOWN` | `recipientDeviceId` does not exist |
| `99` | `INTERNAL` | unexpected server-side failure (DB insert, etc.) |

After sending an `ERROR` frame the gateway closes the socket with WS code
1000 (Normal Closure). The structured reason lives in the application-layer
frame, not the WS close code.

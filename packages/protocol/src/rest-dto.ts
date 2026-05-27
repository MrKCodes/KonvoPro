// packages/protocol/src/rest-dto.ts
//
// REST request / response DTOs per design.md §9 (Fastify route signatures)
// and the corresponding requirements.md clauses (§§1, 2, 3, 6, 10, 13, 7).
//
// These shapes are the wire-format contract between the Web_Client and the
// API_Gateway. They mirror the libsignal-shaped types used internally by
// `packages/crypto` (e.g. SignedPreKey, OneTimePreKey, RemotePreKeyBundle,
// PreKeyBundleUpload) but re-declare them here as transport-level structs so
// `@konvo/protocol` does not depend on `@konvo/crypto`. The crypto package
// can re-export these via `export type` at task 4.2.

// ---------------------------------------------------------------------------
// Auth (design.md §9 / Requirement 1)
// ---------------------------------------------------------------------------

/** `POST /auth/signup` body. Handle: 3–32 lowercase `[a-z0-9_]`. Password:
 *  12–128 chars (Argon2id m=64 MiB, t=3, p=4 server-side). */
export interface SignupRequest {
  readonly handle: string;
  readonly password: string;
}

export interface SignupResponse {
  readonly userId: string;
}

/** `POST /auth/login` body. `totp` is required when the user has TOTP enabled
 *  (Requirement 1.4); the server rejects with a non-disclosing error if
 *  either factor is invalid (Requirement 1.5). */
export interface LoginRequest {
  readonly handle: string;
  readonly password: string;
  readonly totp?: string;
}

export interface LoginResponse {
  readonly accessToken: string; // 15-min HS256 JWT
  readonly refreshToken: string; // also set as httpOnly Secure SameSite=Lax cookie
  readonly user: {
    readonly id: string;
    readonly handle: string;
  };
}

/** `POST /auth/refresh` reply. Refresh token rotates via cookie. */
export interface RefreshResponse {
  readonly accessToken: string;
}

// ---------------------------------------------------------------------------
// Devices & prekeys (design.md §9, §8.1 / Requirements 2, 3)
// ---------------------------------------------------------------------------

/** Signed prekey transported over REST. Mirrors `crypto.SignedPreKey` per
 *  design.md §8.1; `signature` is Ed25519 over `publicKey` by the identity
 *  key (exactly 64 bytes — see Requirement 2.4 / 3.2). */
export interface SignedPreKeyDTO {
  readonly keyId: number;
  readonly publicKey: Uint8Array; // 32 bytes Curve25519
  readonly signature: Uint8Array; // 64 bytes Ed25519
  readonly createdAt: number;
}

/** One-time prekey transported over REST. Mirrors `crypto.OneTimePreKey`. */
export interface OneTimePreKeyDTO {
  readonly keyId: number;
  readonly publicKey: Uint8Array; // 32 bytes Curve25519
}

/** `POST /devices` body. Mirrors `crypto.PreKeyBundleUpload` plus the
 *  human-readable `name` from the route signature in design.md §9.
 *
 *  Phase-1 placeholder: `identityEdPub` carries the device's Ed25519
 *  identity public key so the API_Gateway can verify
 *  `signedPreKey.signature` (Requirement 3.2). Once libsignal lands the
 *  Ed25519 key is recovered from `identityPub` on the fly via XEdDSA and
 *  this field goes away. See `packages/crypto/src/prekeys.ts` header. */
export interface DeviceCreate {
  readonly name: string; // 1..64 chars
  readonly identityPub: Uint8Array; // exactly 32 bytes (X25519)
  readonly identityEdPub: Uint8Array; // exactly 32 bytes (Ed25519, Phase-1)
  readonly registrationId: number; // 1..16383
  readonly signedPreKey: SignedPreKeyDTO;
  readonly oneTimePreKeys: readonly OneTimePreKeyDTO[]; // 1..100 entries
}

/** `POST /devices` reply. */
export interface DeviceCreateResponse {
  readonly deviceId: string;
}

/** Single entry from `GET /devices`. */
export interface DeviceListItem {
  readonly id: string;
  readonly name: string;
  readonly lastSeenAt: string | null; // ISO-8601 UTC; null if never seen
  readonly createdAt: string; // ISO-8601 UTC
}

/** `GET /devices` reply. */
export interface DeviceListResponse {
  readonly devices: readonly DeviceListItem[];
}

/** Wire-level mirror of `crypto.PreKeyBundleUpload` (design.md §8.1).
 *  Used internally where a route signature wants the full bundle as a
 *  nested object rather than the flattened `DeviceCreate`.
 *
 *  Phase-1 placeholder: `identityEdPub` carries the Ed25519 identity
 *  public key for signed-prekey signature verification. Removed when
 *  libsignal/XEdDSA is wired (task 4.x). */
export interface PreKeyBundleUpload {
  readonly identityPub: Uint8Array;
  readonly identityEdPub: Uint8Array;
  readonly registrationId: number;
  readonly signedPreKey: SignedPreKeyDTO;
  readonly oneTimePreKeys: readonly OneTimePreKeyDTO[];
}

/** `POST /devices/:id/prekeys` body. */
export interface PreKeysReplenishRequest {
  readonly oneTimePreKeys: readonly OneTimePreKeyDTO[];
}

/** `POST /devices/:id/prekeys` reply. */
export interface PreKeysReplenishResponse {
  readonly count: number;
}

/** `GET /users/:handle/prekey-bundle?deviceId=...` reply. Mirrors
 *  `crypto.RemotePreKeyBundle` (design.md §8.2). When the server has
 *  exhausted unused OPKs for the device, `oneTimePreKey` is `null` so the
 *  client falls back to degraded X3DH (Requirement 3.6). */
export interface RemotePreKeyBundleResponse {
  readonly recipientDeviceId: string;
  readonly identityPub: Uint8Array;
  readonly registrationId: number;
  readonly signedPreKey: SignedPreKeyDTO;
  readonly oneTimePreKey: OneTimePreKeyDTO | null;
}

// ---------------------------------------------------------------------------
// Attachments (design.md §9 / Requirement 6)
// ---------------------------------------------------------------------------

/** `POST /attachments` reply. Server returns the attachment id and the
 *  MinIO blob key; the AES-GCM key/iv/tag never leave the client and live
 *  inside an E2EE envelope (`AttachmentRef`). */
export interface AttachmentCreateResponse {
  readonly attachmentId: string;
  readonly blobKey: string;
}

// ---------------------------------------------------------------------------
// Broadcast rooms (design.md §9 / Requirement 10)
// ---------------------------------------------------------------------------

/** `POST /rooms` body. Slug: 3–64 lowercase `[a-z0-9-]`. Name: 1–100. */
export interface RoomCreateRequest {
  readonly slug: string;
  readonly name: string;
  readonly description?: string;
}

/** `POST /rooms` reply (also used by `GET /rooms/:slug`). */
export interface RoomResponse {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly description: string | null;
  readonly ownerHandle: string;
  readonly createdAt: string; // ISO-8601 UTC
}

/** `GET /rooms` (server-side listings) reply. */
export interface RoomListResponse {
  readonly rooms: readonly RoomResponse[];
}

/** `POST /rooms/:slug/messages` body. Signature is Ed25519 over
 *  `(body || roomId || createdAtMs)` per Requirement 10.4.
 *
 *  Phase-6 placeholder (`deviceId`):
 *    Per `packages/crypto/src/identity.ts` a user has one identity keypair
 *    per enrolled device; the Ed25519 sub-key used for broadcast signing
 *    is therefore per-device, not per-user. To verify the signature
 *    server-side the API_Gateway needs to know WHICH device produced it
 *    so it can look up that device's `identity_ed_pub`. The client
 *    populates this with the device id whose Ed25519 private key signed
 *    `(body || roomId || createdAtMs)`. The wire-level `BroadcastPost`
 *    fan-out (`packages/protocol/src/ws-messages.ts`) carries that
 *    device's `identityEdPub` so viewers can verify against the same
 *    key. When libsignal/XEdDSA collapses the per-device dual keypair
 *    back into a single libsignal identity key (task 4.x) this field
 *    can be removed. */
export interface BroadcastPostCreateRequest {
  readonly body: string; // ≤ 4 KiB
  readonly signature: Uint8Array; // 64 bytes Ed25519
  readonly createdAtMs: number; // ±60s of server clock
  readonly deviceId: string; // UUID of the signing device
}

/** `POST /rooms/:slug/messages` reply. */
export interface BroadcastPostCreateResponse {
  readonly id: bigint;
  readonly createdAt: string; // ISO-8601 UTC
}

/** Single broadcast post on the REST surface (e.g. paginated history via
 *  `GET /rooms/:slug/messages`). Structurally equivalent to the WS
 *  `BroadcastPost` but with `createdAt` as ISO-8601 string. */
export interface BroadcastPostResponse {
  readonly id: bigint;
  readonly roomId: string;
  readonly authorUserId: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;
  readonly body: string;
  readonly authorSignature: Uint8Array;
  readonly createdAt: string; // ISO-8601 UTC
}

/** `GET /rooms/:slug/messages?before=...&limit=50` reply. */
export interface BroadcastPostListResponse {
  readonly messages: readonly BroadcastPostResponse[];
  readonly nextBefore: string | null;
}

// ---------------------------------------------------------------------------
// Push subscriptions (design.md §9 / Requirement 13)
// ---------------------------------------------------------------------------

/** `POST /push/subscribe` body. Endpoint scheme MUST be HTTPS. */
export interface PushSubscriptionRequest {
  readonly deviceId: string;
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}

// ---------------------------------------------------------------------------
// Real-time media credentials (design.md §9 / Requirements 7, 11)
// ---------------------------------------------------------------------------

/** Ephemeral coturn TURN credentials (Requirement 7.12).
 *  TTL is 1 hour; `urls` carries the `turn:`/`turns:`/`stun:` URLs the
 *  client should configure on `RTCPeerConnection`. */
export interface TurnCredentialsResponse {
  readonly urls: readonly string[];
  readonly username: string;
  readonly credential: string;
  readonly ttlSec: number;
}

/** LiveKit publisher / viewer token (broadcast rooms only; never used for
 *  1:1 calls). `role` discriminates the two routes in design.md §9:
 *  - `publisher` → `POST /rooms/:slug/live`
 *  - `subscriber` → `GET /rooms/:slug/live/viewer-token` */
export interface LiveKitTokenResponse {
  readonly token: string;
  readonly url: string;
  readonly role: 'publisher' | 'subscriber';
}

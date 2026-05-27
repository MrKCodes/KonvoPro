// apps/api/src/services/livekit.ts
//
// LiveKit token signing helpers (task 8.1 — Phase 7). Mints publisher
// JWTs for broadcast-room admins (`POST /rooms/:slug/live`) and viewer
// JWTs for any authenticated user (`GET /rooms/:slug/live/viewer-token`).
//
// Realizes the signing surface required by Requirements 11.1 and 11.2:
//
//   - 11.1 : `POST /rooms/:slug/live` returns a publisher JWT with TTL
//            3600 s (the canonical default — overridable per call).
//            Publishers may publish AND subscribe (so the admin can see
//            their own preview); no `recorder`/admin-only-LiveKit grant.
//   - 11.2 : `GET /rooms/:slug/live/viewer-token` returns a viewer JWT
//            with TTL 3600 s. Viewers may subscribe but never publish.
//
// LiveKit-only-for-broadcast invariant (Requirements 7.10, 11.7, 11.8,
// 22.7) — task 6.6:
//   This module signs tokens for whatever `roomId` it is handed, BUT
//   it now refuses to mint a token when the `roomId` matches the 1:1
//   DM call id pattern. DM call ids are client-generated UUID v4
//   strings (`uuidv4()` in `apps/web/src/features/calls/`); broadcast
//   room ids surface to LiveKit as the room SLUG (`^[a-z0-9-]{3,64}$`,
//   never UUID-shaped). The runtime guard `assertBroadcastRoomId`
//   enforces this at every mint call so a hypothetical regression
//   that wired a DM call id into `signPublisher` / `signViewer` would
//   throw before the LiveKit JWT is constructed — preserving the
//   blind-router invariant that the API process never participates
//   in 1:1 call media (Requirements 7.10, 22.7).
//
//   The structural / static-analysis side of the same invariant lives
//   in `apps/api/test/livekit-only-broadcast.test.ts` (which files may
//   import the LiveKit SDK) and `apps/api/test/no-dm-call-recording.
//   test.ts` (CI assertion that no LiveKit-mint path references a DM
//   call id pattern). The two layers are complementary: the
//   static-analysis test catches a future code path that adds a new
//   mint site; the runtime guard catches a future caller that passes
//   the wrong id to the existing mint sites.
//
// Logger redaction (Requirement 18.4): the JWT payload contains the
// LiveKit room id (Konvo broadcast room UUID). That is not PII and is
// safe to log if a future caller wants observability; this module
// itself emits no logs and never returns or throws values containing
// the secret. The signing key is held by the closure returned from
// `createLiveKitTokenSigner` and is never re-exposed.
//
// Algorithm choice: livekit-server-sdk's `AccessToken.toJwt()` signs
// with HS256 against the supplied API secret. Tests verify shape via
// `jose.jwtVerify` against the same secret — see
// `apps/api/test/broadcast-live-routes.test.ts`.

import { AccessToken, type VideoGrant } from '@livekit/server-sdk';

/** Default TTL for both publisher and viewer JWTs, in seconds.
 *  Requirement 11.1 / 11.2 specify 3600 s. */
const DEFAULT_TOKEN_TTL_SEC = 3_600;

/** Broadcast-room slug shape per `broadcast_rooms.slug` and the slug
 *  validator in `routes/broadcast.ts` / `routes/broadcast-live.ts`.
 *  Requirement 8.1 / design.md §4 fix the shape at `^[a-z0-9-]{3,64}$`.
 *  The LiveKit token mint requires the supplied `roomId` to satisfy
 *  this pattern AND to NOT be a UUID; see `assertBroadcastRoomId`. */
const BROADCAST_SLUG_REGEX = /^[a-z0-9-]{3,64}$/;

/** UUID pattern (any version, hyphenated, lowercase or mixed case).
 *  Used by `assertBroadcastRoomId` to REJECT 1:1 DM call ids before
 *  any LiveKit JWT is minted (Requirements 7.10, 11.7, 11.8, 22.7).
 *  DM call ids are client-side `uuidv4()` strings; broadcast room
 *  slugs never match this shape because slugs are user-chosen labels
 *  drawn from `[a-z0-9-]` without the fixed segment lengths or
 *  version digit a UUID requires. The test
 *  `apps/api/test/no-dm-call-recording.test.ts` exercises both
 *  directions (UUID rejected; valid slug accepted). */
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Throw if the supplied `roomId` is not a valid broadcast-room slug.
 *  Realises the runtime side of the LiveKit-only-for-broadcast
 *  invariant (task 6.6 / Requirements 7.10, 11.7, 11.8, 22.7):
 *
 *    - any UUID-shaped string is treated as a 1:1 DM call id and
 *      rejected — DM call ids are the only UUID-shaped values that
 *      could plausibly reach this function from a regression in the
 *      route layer or a future call-related code path;
 *    - any string that fails the broadcast-slug regex is rejected
 *      with the same error to keep the failure mode uniform.
 *
 *  This is intentionally strict: no consumer of `LiveKitTokenSigner`
 *  should ever pass a value that fails this check, so the throw is
 *  always a programmer error, not an end-user error. */
export function assertBroadcastRoomId(roomId: string): void {
  if (UUID_REGEX.test(roomId)) {
    throw new Error(
      'LiveKitTokenSigner: roomId looks like a 1:1 DM call id (UUID); ' +
        'LiveKit is for broadcast rooms only (Requirements 7.10, 11.7, 11.8, 22.7)',
    );
  }
  if (!BROADCAST_SLUG_REGEX.test(roomId)) {
    throw new Error(
      `LiveKitTokenSigner: roomId must be a broadcast-room slug ` +
        `matching ${BROADCAST_SLUG_REGEX.source}, got ${JSON.stringify(roomId)}`,
    );
  }
}

/** Per-token mint inputs. `userId` becomes the LiveKit `identity` claim
 *  (the participant id LiveKit surfaces to other participants in the
 *  room); `roomId` is the Konvo `broadcast_rooms.id` UUID and becomes
 *  both the LiveKit room name and the JWT's `video.room` grant. */
export interface SignTokenOptions {
  readonly userId: string;
  readonly roomId: string;
  /** Override the default 3600 s TTL. Must be a positive integer. */
  readonly ttlSec?: number;
}

export interface LiveKitTokenSigner {
  /** Mint a publisher JWT for `(userId, roomId)`. The token grants
   *  `roomJoin: true`, `room: <roomId>`, `canPublish: true`, and
   *  `canSubscribe: true`. (Publishers self-subscribe so the admin can
   *  see their own preview track in the LiveKit room.) */
  signPublisher(opts: SignTokenOptions): Promise<string>;

  /** Mint a subscriber JWT for `(userId, roomId)`. The token grants
   *  `roomJoin: true`, `room: <roomId>`, `canPublish: false`, and
   *  `canSubscribe: true`. */
  signViewer(opts: SignTokenOptions): Promise<string>;
}

/** Construct a `LiveKitTokenSigner` bound to the given API key + secret.
 *  Both come from the validated config (`config.LIVEKIT_API_KEY` /
 *  `config.LIVEKIT_API_SECRET`); the schema in `config.ts` enforces a
 *  ≥32-char minimum on the secret so a successful return here implies
 *  a usable signer.
 *
 *  `defaultTtlSec` overrides the module-level 3600 s default for every
 *  mint produced by the returned signer. Per-call `opts.ttlSec` further
 *  overrides on a per-token basis.
 *
 *  This factory is pure — no DB, no Redis, no clock except whatever
 *  `livekit-server-sdk` consumes to compute `nbf` / `exp`. */
export function createLiveKitTokenSigner(
  apiKey: string,
  apiSecret: string,
  defaultTtlSec: number = DEFAULT_TOKEN_TTL_SEC,
): LiveKitTokenSigner {
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    throw new Error(
      'createLiveKitTokenSigner: apiKey must be a non-empty string',
    );
  }
  if (typeof apiSecret !== 'string' || apiSecret.length === 0) {
    throw new Error(
      'createLiveKitTokenSigner: apiSecret must be a non-empty string',
    );
  }
  if (!Number.isInteger(defaultTtlSec) || defaultTtlSec < 1) {
    throw new Error(
      `createLiveKitTokenSigner: defaultTtlSec must be a positive integer, got ${String(defaultTtlSec)}`,
    );
  }

  function resolveTtl(override?: number): number {
    if (override === undefined) return defaultTtlSec;
    if (!Number.isInteger(override) || override < 1) {
      throw new Error(
        `LiveKitTokenSigner: ttlSec must be a positive integer, got ${String(override)}`,
      );
    }
    return override;
  }

  async function sign(
    opts: SignTokenOptions,
    grant: VideoGrant,
  ): Promise<string> {
    if (typeof opts.userId !== 'string' || opts.userId.length === 0) {
      throw new Error('LiveKitTokenSigner: userId must be a non-empty string');
    }
    if (typeof opts.roomId !== 'string' || opts.roomId.length === 0) {
      throw new Error('LiveKitTokenSigner: roomId must be a non-empty string');
    }
    // Runtime guard: broadcast-only invariant (task 6.6 / Reqs 7.10,
    // 11.7, 11.8, 22.7). Reject any roomId shaped like a 1:1 DM call
    // id (UUID) before constructing the JWT. The check is centralised
    // here so EVERY mint path — `signPublisher`, `signViewer`, and
    // any future grant variant — inherits the guard automatically.
    assertBroadcastRoomId(opts.roomId);
    const ttl = resolveTtl(opts.ttlSec);

    // `AccessToken` is constructed per-call rather than reused: the
    // class carries internal mutable state for grants and identity.
    // Reuse would risk cross-token leakage of `addGrant` calls.
    const at = new AccessToken(apiKey, apiSecret, {
      identity: opts.userId,
      ttl,
    });
    at.addGrant(grant);
    return at.toJwt();
  }

  return {
    async signPublisher(opts: SignTokenOptions): Promise<string> {
      return sign(opts, {
        roomJoin: true,
        room: opts.roomId,
        canPublish: true,
        canSubscribe: true,
      });
    },

    async signViewer(opts: SignTokenOptions): Promise<string> {
      return sign(opts, {
        roomJoin: true,
        room: opts.roomId,
        canPublish: false,
        canSubscribe: true,
      });
    },
  };
}

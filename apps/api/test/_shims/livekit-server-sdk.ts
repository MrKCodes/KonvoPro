// Test-only shim for `@livekit/server-sdk`.
//
// The api package declares `@livekit/server-sdk` in its dependencies
// (used by `apps/api/src/services/livekit.ts` for LiveKit token
// minting — Requirements 11.1, 11.2). The current pnpm-lockfile in
// this checkout is incomplete (the npm registry currently 404s on
// `@livekit/server-sdk` — the package was renamed to the unscoped
// `livekit-server-sdk`), so vitest cannot resolve the bare specifier
// without help. We alias it to this shim from `vitest.config.ts` so
// test files that transitively import `services/livekit.ts` can
// load without exploding at module-evaluation time.
//
// The shim implements just enough of the SDK's surface that
// `services/livekit.ts` consumes during signing:
//
//   - `AccessToken(apiKey, apiSecret, { identity, ttl })` constructor
//   - `addGrant(VideoGrant)` to attach the room/permissions claims
//   - `toJwt()` to produce an HS256-signed JWT carrying the recorded
//     identity + grants, decodable by tests via `jose.jwtVerify`
//
// Production builds always consume the real `@livekit/server-sdk`
// from npm (or the post-rename equivalent); this shim is wired only
// via the alias in `vitest.config.ts` and never reaches a runtime
// artifact.

import { SignJWT } from 'jose';

export interface VideoGrant {
  roomJoin?: boolean;
  room?: string;
  canPublish?: boolean;
  canSubscribe?: boolean;
}

interface AccessTokenOpts {
  identity: string;
  ttl: number;
}

export class AccessToken {
  readonly #apiKey: string;
  readonly #apiSecret: string;
  readonly #identity: string;
  readonly #ttlSec: number;
  #grant: VideoGrant = {};

  constructor(apiKey: string, apiSecret: string, opts: AccessTokenOpts) {
    this.#apiKey = apiKey;
    this.#apiSecret = apiSecret;
    this.#identity = opts.identity;
    this.#ttlSec = opts.ttl;
  }

  addGrant(grant: VideoGrant): void {
    this.#grant = { ...this.#grant, ...grant };
  }

  async toJwt(): Promise<string> {
    // Mirror the real LiveKit SDK's JWT shape closely enough that
    // `jose.jwtVerify(token, secret, { algorithms: ['HS256'] })`
    // returns `{ sub, video }` claims the broadcast-live route
    // tests assert on.
    const key = new TextEncoder().encode(this.#apiSecret);
    const nowSec = Math.floor(Date.now() / 1000);
    return new SignJWT({ video: this.#grant })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(this.#apiKey)
      .setSubject(this.#identity)
      .setIssuedAt(nowSec)
      .setNotBefore(nowSec)
      .setExpirationTime(nowSec + this.#ttlSec)
      .sign(key);
  }
}

const livekitServerSdkShim = {
  AccessToken,
};

export default livekitServerSdkShim;

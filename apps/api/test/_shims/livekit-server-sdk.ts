// Test-only shim for `livekit-server-sdk`.
//
// The api package declares `livekit-server-sdk` in its dependencies
// (used by `apps/api/src/services/livekit.ts` for LiveKit token
// minting — Requirements 11.1, 11.2). The shim lets the test suite
// run without resolving the real SDK at module-evaluation time
// (useful in fully offline / partial-install environments and for
// keeping the test process small). vitest aliases the bare
// specifier to this file via `apps/api/vitest.config.ts`.
//
// The shim implements just enough of the SDK's surface that
// `services/livekit.ts` consumes during signing:
//
//   - `AccessToken(apiKey, apiSecret, { identity, ttl })` constructor
//   - `addGrant(VideoGrant)` to attach the room/permissions claims
//   - `toJwt()` to produce an HS256-signed JWT carrying the recorded
//     identity + grants, decodable by tests via `jose.jwtVerify`
//
// Production builds always consume the real `livekit-server-sdk`
// from npm; this shim is wired only via the alias in
// `vitest.config.ts` and never reaches a runtime artifact.

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

// apps/web/src/features/broadcast/api.ts
//
// Thin REST wrappers around `/rooms/*` endpoints surfaced by
// `apps/api/src/routes/broadcast.ts`. Sibling to
// `apps/web/src/features/auth/api.ts` — the wire conventions
// (`credentials: 'include'`, optional `Authorization: Bearer`,
// `X-CSRF-Token` from the `konvo_csrf` cookie on state-changing
// methods) match exactly.
//
// Why this lives here rather than as an extension of
// `AuthApiClient`:
//   - Public reads (`GET /rooms/:slug`, `GET /rooms/:slug/messages`)
//     are unauthenticated by design (Requirement 10.2). They do not
//     send `Authorization` and run successfully without an access
//     token in memory. Routing them through the auth client (which
//     auto-injects `Authorization` on every request) would either
//     leak a stale bearer when the user is logged in or fail to
//     populate a token when the user is not.
//   - Keeping per-feature API clients also matches the pattern set
//     by `auth/api.ts` and keeps the broadcast feature self-
//     contained for the public `/r/:slug` route — that route can
//     depend on `BroadcastApiClient` without pulling in the auth
//     module.
//
// Wire-shape adapters:
//   - `GET /rooms/:slug/messages` returns the JSON-friendly
//     projection from `apps/api/src/routes/broadcast.ts`: `id` is a
//     decimal string, `authorIdentityPub` and `authorSignature` are
//     base64. We surface the bytes as `Uint8Array`s and `id` as the
//     decimal string (the local `RoomPostRow.postId` is also a
//     decimal string for IndexedDB-key compatibility).
//   - `POST /rooms/:slug/messages` body is `{body, signature: base64,
//     createdAtMs, deviceId}` per the route handler.

import type { LiveKitTokenResponse } from '@konvo/protocol';

import { authActions, getAuthState } from '../auth/store.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type BroadcastApiErrorKind = 'network' | 'http';

export class BroadcastApiError extends Error {
  readonly kind: BroadcastApiErrorKind;
  readonly status: number | null;
  readonly serverError: string | null;
  override readonly cause?: unknown;

  constructor(
    kind: BroadcastApiErrorKind,
    message: string,
    opts: {
      status?: number | null;
      serverError?: string | null;
      cause?: unknown;
    } = {},
  ) {
    super(message);
    this.name = 'BroadcastApiError';
    this.kind = kind;
    this.status = opts.status ?? null;
    this.serverError = opts.serverError ?? null;
    if (opts.cause !== undefined) {
      this.cause = opts.cause;
    }
  }
}

/** Public-facing room shape returned by `getRoom` / `createRoom`.
 *  Mirrors the `RoomResponse` DTO (`createdAt` as ISO-8601 string). */
export interface RoomDto {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly description: string | null;
  readonly ownerHandle: string;
  readonly createdAt: string;
}

/** Single post shape returned by `listMessages`. The byte fields are
 *  decoded from base64; `postId` is the decimal-string form of the
 *  server's BIGSERIAL (the same wire shape persists locally as
 *  `RoomPostRow.postId`). */
export interface BroadcastPostDto {
  readonly postId: string;
  readonly roomId: string;
  readonly authorUserId: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;
  readonly body: string;
  readonly signature: Uint8Array;
  readonly createdAt: string; // ISO-8601 UTC
  readonly createdAtMs: number; // epoch-ms convenience for verification
}

export interface ListMessagesResponse {
  readonly messages: readonly BroadcastPostDto[];
  readonly nextBefore: string | null;
}

export interface BroadcastApiClientOptions {
  readonly baseUrl?: string;
  readonly fetchImpl?: typeof fetch;
  readonly readCookieHeader?: () => string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readCookieValue(header: string, name: string): string | null {
  if (header.length === 0) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (k !== name) continue;
    const v = part.slice(eq + 1).trim();
    return v.length === 0 ? null : v;
  }
  return null;
}

/** Standard-base64 decode (also tolerates base64url) → Uint8Array.
 *  Mirrors the route's `decodeSignature` lenience for the byte
 *  fields surfaced on `GET /rooms/:slug/messages`. */
function base64ToBytes(s: string): Uint8Array {
  // Browsers don't expose Buffer; use atob on a normalised string.
  // Replace base64url chars with their base64 equivalents and pad
  // to a multiple of 4.
  const normalised = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded =
    normalised.length % 4 === 0
      ? normalised
      : normalised + '='.repeat(4 - (normalised.length % 4));
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/** Standard-base64 encode (no url-safe substitution). The route
 *  accepts both flavours, but the auth/api client emits standard
 *  base64 so we follow the same convention. */
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

interface RequestOptions {
  readonly method: 'GET' | 'POST' | 'DELETE';
  readonly path: string;
  readonly body?: unknown;
  readonly includeAccessToken?: boolean;
}

export class BroadcastApiClient {
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #readCookieHeader: () => string;

  constructor(opts: BroadcastApiClientOptions = {}) {
    this.#baseUrl = opts.baseUrl ?? '';
    this.#fetch = opts.fetchImpl ?? fetch.bind(globalThis);
    this.#readCookieHeader =
      opts.readCookieHeader ??
      (() => (typeof document !== 'undefined' ? document.cookie : ''));
  }

  /** GET /rooms/:slug — public read; no auth header required. */
  async getRoom(slug: string): Promise<RoomDto> {
    return this.#request<RoomDto>({
      method: 'GET',
      path: `/rooms/${encodeURIComponent(slug)}`,
      includeAccessToken: false,
    });
  }

  /** POST /rooms — auth required. */
  async createRoom(args: {
    slug: string;
    name: string;
    description?: string;
  }): Promise<RoomDto> {
    return this.#request<RoomDto>({
      method: 'POST',
      path: '/rooms',
      body: args,
    });
  }

  /** GET /rooms/:slug/messages — public read; no auth required.
   *  `before` is an ISO-8601 string from a previous response's
   *  `nextBefore`; `limit` defaults to 50 server-side. */
  async listMessages(
    slug: string,
    opts: { before?: string; limit?: number } = {},
  ): Promise<ListMessagesResponse> {
    const qs = new URLSearchParams();
    if (opts.before !== undefined) qs.set('before', opts.before);
    if (opts.limit !== undefined) qs.set('limit', String(opts.limit));
    const suffix = qs.toString().length > 0 ? `?${qs.toString()}` : '';
    type WireMessage = {
      readonly id: string;
      readonly roomId: string;
      readonly authorUserId: string;
      readonly authorHandle: string;
      readonly authorIdentityPub: string;
      readonly body: string;
      readonly authorSignature: string;
      readonly createdAt: string;
    };
    interface WireResponse {
      readonly messages: readonly WireMessage[];
      readonly nextBefore: string | null;
    }
    const wire = await this.#request<WireResponse>({
      method: 'GET',
      path: `/rooms/${encodeURIComponent(slug)}/messages${suffix}`,
      includeAccessToken: false,
    });
    return {
      messages: wire.messages.map((m) => ({
        postId: m.id,
        roomId: m.roomId,
        authorUserId: m.authorUserId,
        authorHandle: m.authorHandle,
        authorIdentityPub: base64ToBytes(m.authorIdentityPub),
        body: m.body,
        signature: base64ToBytes(m.authorSignature),
        createdAt: m.createdAt,
        createdAtMs: Date.parse(m.createdAt),
      })),
      nextBefore: wire.nextBefore,
    };
  }

  /** POST /rooms/:slug/messages — auth + admin role. The signature
   *  is encoded as standard base64 on the wire. */
  async postMessage(
    slug: string,
    args: {
      body: string;
      signature: Uint8Array;
      createdAtMs: number;
      deviceId: string;
    },
  ): Promise<{ id: string; createdAt: string }> {
    return this.#request<{ id: string; createdAt: string }>({
      method: 'POST',
      path: `/rooms/${encodeURIComponent(slug)}/messages`,
      body: {
        body: args.body,
        signature: bytesToBase64(args.signature),
        createdAtMs: args.createdAtMs,
        deviceId: args.deviceId,
      },
    });
  }

  /** POST /rooms/:slug/subscribe — auth required, idempotent. */
  async subscribe(slug: string): Promise<void> {
    await this.#request<void>({
      method: 'POST',
      path: `/rooms/${encodeURIComponent(slug)}/subscribe`,
      body: {},
    });
  }

  /** POST /rooms/:slug/live — auth + admin role. Provisions the
   *  LiveKit room (server-side) and returns the publisher JWT plus
   *  the LiveKit URL. Server returns HTTP 403 for non-admins
   *  (Requirement 11.1). */
  async startLive(slug: string): Promise<LiveKitTokenResponse> {
    return this.#request<LiveKitTokenResponse>({
      method: 'POST',
      path: `/rooms/${encodeURIComponent(slug)}/live`,
      body: {},
    });
  }

  /** GET /rooms/:slug/live/viewer-token — any authed user. Returns
   *  the viewer JWT plus the LiveKit URL (Requirement 11.2). */
  async getViewerToken(slug: string): Promise<LiveKitTokenResponse> {
    return this.#request<LiveKitTokenResponse>({
      method: 'GET',
      path: `/rooms/${encodeURIComponent(slug)}/live/viewer-token`,
    });
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  async #request<T>(opts: RequestOptions): Promise<T> {
    const url = `${this.#baseUrl}${opts.path}`;
    const headers: Record<string, string> = {};
    let body: BodyInit | undefined;
    if (opts.body !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }

    const includeAccessToken = opts.includeAccessToken ?? true;
    if (includeAccessToken) {
      const token = getAuthState().accessToken;
      if (token !== null) {
        headers['authorization'] = `Bearer ${token}`;
      }
    }

    if (opts.method !== 'GET') {
      const csrfToken = readCookieValue(this.#readCookieHeader(), 'konvo_csrf');
      if (csrfToken !== null) {
        headers['x-csrf-token'] = csrfToken;
      }
    }

    let response: Response;
    try {
      response = await this.#fetch(url, {
        method: opts.method,
        headers,
        ...(body !== undefined ? { body } : {}),
        credentials: 'include',
      });
    } catch (err) {
      throw new BroadcastApiError('network', 'network request failed', {
        cause: err,
      });
    }

    if (response.status === 204) {
      return undefined as T;
    }

    if (!response.ok) {
      let serverError: string | null = null;
      try {
        const parsed = (await response.json()) as { error?: unknown };
        if (typeof parsed.error === 'string') {
          serverError = parsed.error;
        }
      } catch {
        // ignore
      }
      // 401 on a state-changing room route → log out so the SPA
      // forces a re-auth on the next render. Public reads (which
      // don't include the access token) never reach this branch.
      if (response.status === 401) {
        authActions.clearAuth();
      }
      throw new BroadcastApiError('http', `HTTP ${response.status}`, {
        status: response.status,
        serverError,
      });
    }

    if (response.status === 200 || response.status === 201) {
      const parsed = (await response.json()) as unknown;
      return parsed as T;
    }

    return undefined as T;
  }
}

/** Default singleton — tests construct their own client with a stub
 *  fetch via `new BroadcastApiClient({ fetchImpl: ... })`. */
export const broadcastApi: BroadcastApiClient = new BroadcastApiClient();

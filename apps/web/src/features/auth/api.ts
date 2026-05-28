// apps/web/src/features/auth/api.ts
//
// Thin REST wrappers around `/auth/*` and `/devices` endpoints
// surfaced by `apps/api/src/routes/auth.ts` and
// `apps/api/src/routes/devices.ts`.
//
// Design choices:
//   - All requests use `credentials: 'include'` so the `httpOnly`
//     refresh-token cookie set by `/auth/login` is sent back on
//     `/auth/refresh` and `/auth/logout`. Per Requirement 19.2 that
//     cookie is `Secure; HttpOnly; SameSite=Lax`.
//   - We pass the `X-CSRF-Token` header on every state-changing
//     request, copying it from the `konvo_csrf` cookie that the
//     server's CSRF plugin issues (see
//     `apps/api/src/services/auth/csrf.ts`). Login and signup are
//     exempt server-side, but we still send the header if present so
//     a future tightening doesn't silently break the SPA.
//   - The access token, when present, is taken from the in-memory
//     auth store (Requirement 1.11) and sent as
//     `Authorization: Bearer <token>`. This module never reads the
//     token from `localStorage` / `sessionStorage` — there's nothing
//     to read.
//   - The base URL defaults to `''` (same-origin), which matches the
//     production deployment where Caddy reverse-proxies `/api/*` to
//     the Fastify gateway. Tests inject a deterministic base URL
//     plus a stub `fetch` implementation.
//
// Error handling:
//   - Network failures throw `AuthApiError` with `kind: 'network'`.
//   - Non-2xx responses throw `AuthApiError` with `kind: 'http'` and
//     the status + parsed `error` field if the body is JSON. Callers
//     pattern-match on `kind` + `status` rather than parsing strings.

import type {
  DeviceCreate,
  DeviceCreateResponse,
  DeviceListResponse,
  LoginRequest,
  LoginResponse,
  PreKeysReplenishRequest,
  PreKeysReplenishResponse,
  RefreshResponse,
  SignedPreKeyDTO,
  SignupRequest,
  SignupResponse,
} from '@konvo/protocol';

import { authActions, getAuthState } from './store.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type AuthApiErrorKind = 'network' | 'http';

export class AuthApiError extends Error {
  readonly kind: AuthApiErrorKind;
  readonly status: number | null;
  /** Server-side error code from `{ error: ... }` body, when available. */
  readonly serverError: string | null;
  /** Original underlying error for `network` failures. Declared with
   *  `override` because `Error.cause` exists on the base type since
   *  ES2022 and tsc's `--strict` honours that. */
  override readonly cause?: unknown;

  constructor(
    kind: AuthApiErrorKind,
    message: string,
    opts: {
      status?: number | null;
      serverError?: string | null;
      cause?: unknown;
    } = {},
  ) {
    super(message);
    this.name = 'AuthApiError';
    this.kind = kind;
    this.status = opts.status ?? null;
    this.serverError = opts.serverError ?? null;
    if (opts.cause !== undefined) {
      this.cause = opts.cause;
    }
  }
}

/** Optional client config. Tests inject `fetchImpl` and `baseUrl`. */
export interface AuthApiClientOptions {
  readonly baseUrl?: string;
  readonly fetchImpl?: typeof fetch;
  /** Override the cookie source for CSRF token reads. Defaults to
   *  `document.cookie`. Tests can pass a stub that returns a static
   *  cookie header. */
  readonly readCookieHeader?: () => string;
}

/** Shape returned by `GET /users/:handle`. Mirrors the api's
 *  `UserDirectoryResponse` (apps/api/src/routes/users.ts). The
 *  `devices` array is empty when the peer has no enrolled devices —
 *  reachable handle, but the user is not currently online or hasn't
 *  enrolled any browser yet. */
export interface UserDirectoryDevice {
  readonly deviceId: string;
  readonly name: string;
  readonly lastSeenTime: string | null;
}
export interface UserDirectoryResponse {
  readonly userId: string;
  readonly handle: string;
  readonly devices: readonly UserDirectoryDevice[];
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

/** Lookup a single cookie value from a `Cookie:`-shaped string. Returns
 *  `null` when absent. */
function readCookieValue(header: string, name: string): string | null {
  // Mirrors the API_Gateway's CSRF plugin parser. Intentionally minimal
  // — we set the cookie ourselves on the server, no quoted strings.
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface RequestOptions {
  readonly method: 'GET' | 'POST' | 'DELETE';
  readonly path: string;
  readonly body?: unknown;
  /** Whether to include `Authorization: Bearer ...` from the in-memory
   *  store. Defaults to `true`; signup / login set it to `false`. */
  readonly includeAccessToken?: boolean;
}

/** Encode a `Uint8Array`-laden DTO for JSON transport. The server's
 *  `base64Bytes` helper accepts standard base64 (and base64url), so we
 *  emit standard base64 for clarity.
 *
 *  Recursively walks the object: `Uint8Array` values become base64
 *  strings; arrays and plain objects are walked; primitives pass
 *  through. */
function jsonEncode(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (value instanceof Uint8Array) {
    return uint8ArrayToBase64(value);
  }
  if (Array.isArray(value)) {
    return value.map(jsonEncode);
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = jsonEncode(v);
    }
    return out;
  }
  return value;
}

/** Base64 encode without leaning on Node's `Buffer` (we run in the
 *  browser). Uses `btoa` over a Latin-1 string. */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  // jsdom and modern browsers both expose `btoa`. SSR builds would need
  // a polyfill; we don't ship SSR.
  return btoa(binary);
}

export class AuthApiClient {
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #readCookieHeader: () => string;

  constructor(opts: AuthApiClientOptions = {}) {
    this.#baseUrl = opts.baseUrl ?? '';
    // Bind to globalThis to preserve `this` semantics for the default
    // `fetch`. Tests injecting a stub don't need this binding.
    this.#fetch = opts.fetchImpl ?? fetch.bind(globalThis);
    this.#readCookieHeader =
      opts.readCookieHeader ??
      (() => (typeof document !== 'undefined' ? document.cookie : ''));
  }

  /** POST /auth/signup. Does NOT auto-login on success — the form
   *  redirects to `/login` per the design's onboarding flow. */
  async signup(req: SignupRequest): Promise<SignupResponse> {
    return this.#request<SignupResponse>({
      method: 'POST',
      path: '/auth/signup',
      body: req,
      includeAccessToken: false,
    });
  }

  /** POST /auth/login. On success, populates the in-memory auth store. */
  async login(req: LoginRequest & { deviceId?: string }): Promise<LoginResponse> {
    const res = await this.#request<LoginResponse>({
      method: 'POST',
      path: '/auth/login',
      body: req,
      includeAccessToken: false,
    });
    authActions.setAuth({ accessToken: res.accessToken, user: res.user });
    return res;
  }

  /** POST /auth/refresh. Updates the in-memory access token on success. */
  async refresh(deviceId?: string): Promise<RefreshResponse> {
    const path =
      deviceId === undefined
        ? '/auth/refresh'
        : `/auth/refresh?deviceId=${encodeURIComponent(deviceId)}`;
    const res = await this.#request<RefreshResponse>({
      method: 'POST',
      path,
      body: {},
      includeAccessToken: false,
    });
    authActions.setAccessToken(res.accessToken);
    return res;
  }

  /** POST /auth/logout. Always clears the in-memory auth state, even
   *  if the server returns a non-2xx — the SPA must visibly forget the
   *  user on logout. */
  async logout(): Promise<void> {
    try {
      await this.#request<void>({
        method: 'POST',
        path: '/auth/logout',
        body: {},
        includeAccessToken: false,
      });
    } finally {
      authActions.clearAuth();
    }
  }

  // -------------------------------------------------------------------------
  // Devices
  // -------------------------------------------------------------------------

  /** POST /devices. Caller supplies the prekey bundle DTO. */
  async createDevice(body: DeviceCreate): Promise<DeviceCreateResponse> {
    return this.#request<DeviceCreateResponse>({
      method: 'POST',
      path: '/devices',
      body,
    });
  }

  /** GET /devices. */
  async listDevices(): Promise<DeviceListResponse> {
    return this.#request<DeviceListResponse>({
      method: 'GET',
      path: '/devices',
    });
  }

  /** DELETE /devices/:id. Returns void; 204 → success. */
  async revokeDevice(deviceId: string): Promise<void> {
    await this.#request<void>({
      method: 'DELETE',
      path: `/devices/${encodeURIComponent(deviceId)}`,
    });
  }

  /** GET /users/:handle — directory lookup used by the DM composer to
   *  resolve a typed handle into a `userId` (and the peer's enrolled
   *  device list, used as the X3DH bootstrap fan-out target). The
   *  server collapses every parse-failure / not-found case to HTTP
   *  404, so callers see a uniform `status === 404` for "no such
   *  handle" regardless of which check rejected it. */
  async lookupUser(handle: string): Promise<UserDirectoryResponse> {
    return this.#request<UserDirectoryResponse>({
      method: 'GET',
      path: `/users/${encodeURIComponent(handle)}`,
    });
  }

  /** GET /devices/:id/owner — reverse-lookup used by the inbound
   *  DM dispatch to map a `senderDeviceId` back to its owning user.
   *  Same anti-harvest posture as `/users/:handle`: parse / not-found
   *  collapses to 404. */
  async lookupDeviceOwner(deviceId: string): Promise<{
    deviceId: string;
    userId: string;
    handle: string;
  }> {
    return this.#request<{
      deviceId: string;
      userId: string;
      handle: string;
    }>({
      method: 'GET',
      path: `/devices/${encodeURIComponent(deviceId)}/owner`,
    });
  }

  /** POST /devices/:id/prekeys. Top up one-time prekeys for the
   *  given device (Requirements 3.3, 3.4). The body carries the freshly
   *  minted public OPKs the Web_Client just generated locally. */
  async replenishPreKeys(
    deviceId: string,
    body: PreKeysReplenishRequest,
  ): Promise<PreKeysReplenishResponse> {
    return this.#request<PreKeysReplenishResponse>({
      method: 'POST',
      path: `/devices/${encodeURIComponent(deviceId)}/prekeys`,
      body,
    });
  }

  /** POST /devices/:id/signed-prekey. Upload a freshly rotated signed
   *  prekey for the given device (Requirement 3.7). The route shape is
   *  not yet declared in design.md §9 — see the module-level doc on
   *  `opkReplenishment.ts` for the Phase-1 caveat. The server-side
   *  handler is wired alongside this client in the same task. */
  async uploadSignedPreKey(
    deviceId: string,
    signedPreKey: SignedPreKeyDTO,
  ): Promise<void> {
    await this.#request<void>({
      method: 'POST',
      path: `/devices/${encodeURIComponent(deviceId)}/signed-prekey`,
      body: { signedPreKey },
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
      body = JSON.stringify(jsonEncode(opts.body));
    }

    const includeAccessToken = opts.includeAccessToken ?? true;
    if (includeAccessToken) {
      const token = getAuthState().accessToken;
      if (token !== null) {
        headers['authorization'] = `Bearer ${token}`;
      }
    }

    // Send CSRF header for any state-changing method. The server's
    // CSRF plugin exempts /auth/login and /auth/signup but enforces
    // double-submit on every other POST/PUT/PATCH/DELETE, so we
    // include the header unconditionally — a missing cookie just
    // means we send `null`, which the server rejects with 403 (the
    // SPA should always have visited a non-state-changing endpoint
    // first to receive the cookie).
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
      throw new AuthApiError('network', 'network request failed', {
        cause: err,
      });
    }

    if (response.status === 204) {
      return undefined as T;
    }

    if (!response.ok) {
      // Try to parse `{ error: '...' }` from the body so callers can
      // surface a user-facing message. Failures to parse fall back to
      // a generic message.
      let serverError: string | null = null;
      try {
        const parsed = (await response.json()) as { error?: unknown };
        if (typeof parsed.error === 'string') {
          serverError = parsed.error;
        }
      } catch {
        // ignore
      }
      throw new AuthApiError('http', `HTTP ${response.status}`, {
        status: response.status,
        serverError,
      });
    }

    // Empty bodies surface as null on JSON parse — fall through to
    // a JSON parse and let the caller's type narrow if it cares.
    if (response.status === 200 || response.status === 201) {
      const parsed = (await response.json()) as unknown;
      return parsed as T;
    }

    return undefined as T;
  }
}

/** Default client used by the form components. Tests construct their
 *  own `AuthApiClient` with a stub fetch. */
export const authApi: AuthApiClient = new AuthApiClient();

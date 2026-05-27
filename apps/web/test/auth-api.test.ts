// Tests for task 2.10 — REST client wrappers around `/auth/*` and
// `/devices`.
//
// Scope:
//   - Login populates the in-memory store on success.
//   - State-changing requests carry the CSRF header derived from the
//     `konvo_csrf` cookie.
//   - The Authorization header is sent ONLY when the in-memory store
//     holds a token — never read from any persistent backend.
//   - Non-2xx responses surface as `AuthApiError` with the parsed
//     server `error` code.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  __resetAuthStoreForTests,
  authActions,
  AuthApiClient,
  AuthApiError,
  getAuthState,
} from '../src/features/auth/index.js';

interface CapturedRequest {
  url: string;
  init: RequestInit;
}

function makeFetchStub(responses: Array<{ status: number; body?: unknown }>): {
  fetch: typeof fetch;
  calls: CapturedRequest[];
} {
  const calls: CapturedRequest[] = [];
  let i = 0;
  const fetchImpl = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    calls.push({ url: String(input), init: init ?? {} });
    const next = responses[i] ?? responses[responses.length - 1];
    i += 1;
    if (next === undefined) {
      throw new Error('no stub response queued');
    }
    const body = next.body === undefined ? null : JSON.stringify(next.body);
    return new Response(body, {
      status: next.status,
      headers: next.body === undefined ? {} : { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

beforeEach(() => {
  __resetAuthStoreForTests();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AuthApiClient — login', () => {
  it('populates the in-memory store on success', async () => {
    const { fetch: fetchImpl, calls } = makeFetchStub([
      {
        status: 200,
        body: {
          accessToken: 'jwt-tok',
          refreshToken: 'opaque-refresh',
          user: { id: 'u1', handle: 'alice' },
        },
      },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    const res = await client.login({
      handle: 'alice',
      password: 'correct horse battery staple',
    });
    expect(res.user).toEqual({ id: 'u1', handle: 'alice' });
    expect(getAuthState().accessToken).toBe('jwt-tok');
    expect(getAuthState().user).toEqual({ id: 'u1', handle: 'alice' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.init.credentials).toBe('include');
  });

  it('does NOT send Authorization on login (no token yet)', async () => {
    const { fetch: fetchImpl, calls } = makeFetchStub([
      {
        status: 200,
        body: {
          accessToken: 'jwt-tok',
          refreshToken: 'r',
          user: { id: 'u1', handle: 'alice' },
        },
      },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    await client.login({ handle: 'alice', password: 'correct horse battery staple' });
    const headers = calls[0]!.init.headers as Record<string, string> | undefined;
    expect(headers?.['authorization']).toBeUndefined();
  });

  it('surfaces 401 as AuthApiError with the server error code', async () => {
    const { fetch: fetchImpl } = makeFetchStub([
      { status: 401, body: { error: 'invalid_credentials' } },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    await expect(
      client.login({ handle: 'alice', password: 'correct horse battery staple' }),
    ).rejects.toMatchObject({
      kind: 'http',
      status: 401,
      serverError: 'invalid_credentials',
    });
    // Failed login leaves the store untouched.
    expect(getAuthState().accessToken).toBeNull();
  });
});

describe('AuthApiClient — authorized requests', () => {
  it('sends Authorization: Bearer from the in-memory store', async () => {
    authActions.setAuth({
      accessToken: 'tok-xyz',
      user: { id: 'u1', handle: 'alice' },
    });
    const { fetch: fetchImpl, calls } = makeFetchStub([
      { status: 200, body: { devices: [] } },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    await client.listDevices();
    const headers = calls[0]!.init.headers as Record<string, string> | undefined;
    expect(headers?.['authorization']).toBe('Bearer tok-xyz');
  });

  it('omits Authorization when the store is empty', async () => {
    const { fetch: fetchImpl, calls } = makeFetchStub([
      { status: 200, body: { devices: [] } },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    await client.listDevices();
    const headers = calls[0]!.init.headers as Record<string, string> | undefined;
    expect(headers?.['authorization']).toBeUndefined();
  });

  it('forwards the X-CSRF-Token header on POST/DELETE when the cookie is present', async () => {
    authActions.setAuth({
      accessToken: 'tok',
      user: { id: 'u1', handle: 'alice' },
    });
    const { fetch: fetchImpl, calls } = makeFetchStub([
      { status: 204 },
      { status: 204 },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf-token-abc; other=ignored',
    });
    await client.revokeDevice('dev-1');
    const headers = calls[0]!.init.headers as Record<string, string> | undefined;
    expect(headers?.['x-csrf-token']).toBe('csrf-token-abc');
    expect(calls[0]!.init.method).toBe('DELETE');
  });

  it('does NOT send X-CSRF-Token on GET requests', async () => {
    authActions.setAuth({
      accessToken: 'tok',
      user: { id: 'u1', handle: 'alice' },
    });
    const { fetch: fetchImpl, calls } = makeFetchStub([
      { status: 200, body: { devices: [] } },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf-token-abc',
    });
    await client.listDevices();
    const headers = calls[0]!.init.headers as Record<string, string> | undefined;
    expect(headers?.['x-csrf-token']).toBeUndefined();
  });
});

describe('AuthApiClient — logout', () => {
  it('clears the auth store even when the server returns 500', async () => {
    authActions.setAuth({
      accessToken: 'tok',
      user: { id: 'u1', handle: 'alice' },
    });
    const { fetch: fetchImpl } = makeFetchStub([
      { status: 500, body: { error: 'internal' } },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    await expect(client.logout()).rejects.toBeInstanceOf(AuthApiError);
    expect(getAuthState()).toEqual({ accessToken: null, user: null });
  });
});

describe('AuthApiClient — base64 encoding of byte fields', () => {
  it('encodes Uint8Array fields as base64 strings before sending', async () => {
    authActions.setAuth({
      accessToken: 'tok',
      user: { id: 'u1', handle: 'alice' },
    });
    const { fetch: fetchImpl, calls } = makeFetchStub([
      { status: 201, body: { deviceId: 'dev-new' } },
    ]);
    const client = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });
    const identityPub = new Uint8Array(32);
    identityPub.fill(0xab);
    const identityEdPub = new Uint8Array(32);
    identityEdPub.fill(0xcd);
    const signedPubKey = new Uint8Array(32);
    signedPubKey.fill(0x01);
    const signedSig = new Uint8Array(64);
    signedSig.fill(0x02);
    const opkPub = new Uint8Array(32);
    opkPub.fill(0x03);

    await client.createDevice({
      name: 'Chrome on MacBook',
      identityPub,
      identityEdPub,
      registrationId: 1234,
      signedPreKey: {
        keyId: 1,
        publicKey: signedPubKey,
        signature: signedSig,
        createdAt: 1700000000000,
      },
      oneTimePreKeys: [{ keyId: 1, publicKey: opkPub }],
    });

    const body = JSON.parse(calls[0]!.init.body as string) as {
      identityPub: string;
      identityEdPub: string;
      signedPreKey: { publicKey: string; signature: string };
      oneTimePreKeys: Array<{ publicKey: string }>;
    };

    // Decode and round-trip-compare. atob is available in jsdom.
    function decodeBase64(s: string): Uint8Array {
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
      return out;
    }
    expect(Array.from(decodeBase64(body.identityPub))).toEqual(
      Array.from(identityPub),
    );
    expect(Array.from(decodeBase64(body.identityEdPub))).toEqual(
      Array.from(identityEdPub),
    );
    expect(Array.from(decodeBase64(body.signedPreKey.publicKey))).toEqual(
      Array.from(signedPubKey),
    );
    expect(Array.from(decodeBase64(body.signedPreKey.signature))).toEqual(
      Array.from(signedSig),
    );
    expect(Array.from(decodeBase64(body.oneTimePreKeys[0]!.publicKey))).toEqual(
      Array.from(opkPub),
    );
  });
});

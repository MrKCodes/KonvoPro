// Tests for task 2.10 — first-run device enrollment flow.
//
// Scope:
//   - On first run, `enrollDeviceIfNeeded` generates an identity and a
//     prekey bundle in Dexie and POSTs the bundle to /devices.
//   - The returned deviceId is cached so a second call short-circuits
//     without re-uploading.
//   - The bundle contains exactly 1 signed prekey + 100 one-time
//     prekeys (Requirement 3.1) with correctly-sized byte fields
//     (Requirement 2.4).

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { db } from '../src/db/schema.js';
import { enrollDeviceIfNeeded } from '../src/features/devices/enrollment.js';
import { AuthApiClient } from '../src/features/auth/api.js';
import {
  __resetAuthStoreForTests,
  authActions,
} from '../src/features/auth/store.js';

interface RecordedRequest {
  url: string;
  method: string;
  body: unknown;
}

function makeRecorder(deviceId: string): {
  fetch: typeof fetch;
  calls: RecordedRequest[];
} {
  const calls: RecordedRequest[] = [];
  const fetchImpl = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    let parsed: unknown = null;
    if (init?.body !== undefined && init.body !== null) {
      try {
        parsed = JSON.parse(String(init.body));
      } catch {
        parsed = init.body;
      }
    }
    calls.push({
      url: String(input),
      method: init?.method ?? 'GET',
      body: parsed,
    });
    return new Response(JSON.stringify({ deviceId }), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

beforeEach(async () => {
  __resetAuthStoreForTests();
  // Fresh auth state with a token so requests carry Authorization.
  authActions.setAuth({
    accessToken: 'tok',
    user: { id: 'u1', handle: 'alice' },
  });
  // Wipe Dexie + localStorage so each test starts clean.
  if (typeof localStorage !== 'undefined') localStorage.clear();
  await db.identity.clear();
  await db.prekeys.clear();
  await db.aesKwKeys.clear();
});

afterEach(async () => {
  __resetAuthStoreForTests();
  await db.identity.clear();
  await db.prekeys.clear();
  await db.aesKwKeys.clear();
});

describe('enrollDeviceIfNeeded', () => {
  it('generates identity + bundle and POSTs /devices on first run', async () => {
    const { fetch: fetchImpl, calls } = makeRecorder('dev-new-id');
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => 'konvo_csrf=csrf',
    });

    const result = await enrollDeviceIfNeeded({
      api,
      database: db,
      name: 'Chrome on Test',
    });

    expect(result.created).toBe(true);
    expect(result.deviceId).toBe('dev-new-id');

    // Exactly one POST /devices.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain('/devices');

    const body = calls[0]?.body as {
      name: string;
      identityPub: string;
      identityEdPub: string;
      registrationId: number;
      signedPreKey: { keyId: number; publicKey: string; signature: string };
      oneTimePreKeys: Array<{ keyId: number; publicKey: string }>;
    };
    expect(body.name).toBe('Chrome on Test');
    expect(body.registrationId).toBeGreaterThanOrEqual(1);
    expect(body.registrationId).toBeLessThanOrEqual(16383);
    // base64(32 bytes) == 44 chars (with padding); base64(64 bytes) ==
    // 88 chars. We assert via byte-decoded length.
    expect(decodeBase64Length(body.identityPub)).toBe(32);
    expect(decodeBase64Length(body.identityEdPub)).toBe(32);
    expect(decodeBase64Length(body.signedPreKey.publicKey)).toBe(32);
    expect(decodeBase64Length(body.signedPreKey.signature)).toBe(64);
    expect(body.oneTimePreKeys).toHaveLength(100);
    for (const opk of body.oneTimePreKeys) {
      expect(decodeBase64Length(opk.publicKey)).toBe(32);
    }

    // Identity row + 1 signed + 100 OPK rows persisted.
    expect(await db.identity.count()).toBe(1);
    const signedRows = await db.prekeys.where('keyType').equals('signed').toArray();
    expect(signedRows).toHaveLength(1);
    const opkRows = await db.prekeys.where('keyType').equals('opk').toArray();
    expect(opkRows).toHaveLength(100);

    // localStorage cache is populated.
    expect(localStorage.getItem('konvo:deviceId')).toBe('dev-new-id');
  });

  it('short-circuits when deviceId is already cached', async () => {
    localStorage.setItem('konvo:deviceId', 'dev-cached');
    const { fetch: fetchImpl, calls } = makeRecorder('SHOULD_NOT_BE_USED');
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });

    const result = await enrollDeviceIfNeeded({ api, database: db });

    expect(result.created).toBe(false);
    expect(result.deviceId).toBe('dev-cached');
    expect(calls).toHaveLength(0);
    // No identity / prekey rows were written either.
    expect(await db.identity.count()).toBe(0);
    expect(await db.prekeys.count()).toBe(0);
  });

  it('does not store any plaintext private key bytes in Dexie', async () => {
    const { fetch: fetchImpl } = makeRecorder('dev');
    const api = new AuthApiClient({
      fetchImpl,
      readCookieHeader: () => '',
    });
    await enrollDeviceIfNeeded({ api, database: db, name: 'd' });

    // The identity row must carry only the public key + WRAPPED private
    // bytes. Wrapped bytes are AES-KW(32-byte plaintext) = 40 bytes
    // (which differs from the raw 32). We assert on the length to
    // catch a regression that accidentally stores raw keys.
    const idRow = await db.identity.get('me');
    if (idRow === undefined) {
      throw new Error('identity row not persisted');
    }
    expect(idRow.publicKey.length).toBe(32);
    expect(idRow.wrappedPrivateKey.length).toBe(40);
    expect(idRow.ed25519PublicKey.length).toBe(32);
    expect(idRow.wrappedEd25519PrivateKey.length).toBe(40);
  });
});

function decodeBase64Length(b64: string): number {
  // jsdom exposes atob; this returns the byte length of the decoded
  // payload. Faster than allocating the typed array for length-only
  // assertions.
  return atob(b64).length;
}

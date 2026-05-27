// apps/web/test/public-room-route.test.tsx
//
// Phase 6 verification (task 7.8) — SPA-layer integration coverage
// for the public broadcast read route at `/r/:slug`.
//
// The phase-6 verification statement is:
//
//   > Public read at `/r/:slug` works without auth; signature
//   > badge verifies; non-admin POST returns 403.
//   > _Requirements: 10.2, 10.5, 10.10_
//
// Server-layer 10.2 / 10.5 are pinned by `apps/api/test/broadcast-
// routes.test.ts` (no-auth GETs return 200; subscriber POST returns
// 403) and the property test in `broadcast-admin-only.property.
// test.ts` (P21). Web-layer 10.10 / 10.11 are pinned by
// `broadcast.test.tsx` against `RoomView` directly. What was missing
// — and what this file adds — is an SPA-layer assertion that the
// PUBLIC route component (`PublicRoomRoute`, the host `App.tsx`
// mounts on `/r/:slug`) talks to the public REST endpoints WITHOUT
// an `Authorization` header even when the auth store is empty
// (logged-out visitor) and that the verified-author badge contract
// holds end-to-end through that host.
//
// What this test does NOT try to do:
//   - It does not exercise the server route. The api unit tests
//     already pin no-auth + 404 + 403 behaviour against a real
//     Fastify instance. Re-running them here would be wasteful and
//     would smear the SPA / server boundary.
//   - It does not exercise non-admin POST. That requires an admin
//     POST UI (`AdminComposer`), which the public route never
//     renders. The 403 contract is a server invariant covered by
//     `broadcast-admin-only.property.test.ts` (P21) and the unit
//     case in `broadcast-routes.test.ts`. See
//     `phase6-verification-coverage.md` for the full audit.
//
// Test-environment notes mirror `broadcast.test.tsx`:
//   - jsdom + fake-indexeddb (see test/setup.ts).
//   - Fresh KonvoDb per test so cross-test data doesn't leak.
//   - Real Ed25519 signing via `@konvo/crypto` so the verification
//     path runs without mocks.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  MemoryIdentityStore,
  getOrCreateIdentity,
  signBroadcastPost,
  verifyBroadcastPost,
  type IdentityKeyPair,
} from '@konvo/crypto';

import {
  BroadcastApiClient,
  PublicRoomRoute,
} from '../src/features/broadcast/index.js';
import { KonvoDb } from '../src/db/schema.js';
import { DexieRoomPostsStore } from '../src/db/repositories/roomPosts.js';
import { DexieRoomsStore } from '../src/db/repositories/rooms.js';
import {
  __resetAuthStoreForTests,
  authActions,
} from '../src/features/auth/store.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface Mounted {
  readonly container: HTMLDivElement;
  readonly root: Root;
}

let mounted: Mounted | null = null;
let dbInstances: KonvoDb[] = [];

function mount(node: React.ReactNode): Mounted {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(node);
  });
  const m: Mounted = { container, root };
  mounted = m;
  return m;
}

function unmount(): void {
  if (mounted === null) return;
  act(() => {
    mounted!.root.unmount();
  });
  mounted.container.remove();
  mounted = null;
}

function makeDb(): KonvoDb {
  const name = `konvo-test-public-room-${Math.random()
    .toString(36)
    .slice(2)}`;
  const db = new KonvoDb(name);
  dbInstances.push(db);
  return db;
}

beforeEach(() => {
  // Each test starts with a clean auth store. Some tests then
  // populate a stale token to assert the public route still doesn't
  // emit `Authorization` on the public endpoints.
  __resetAuthStoreForTests();
});

afterEach(async () => {
  unmount();
  for (const db of dbInstances) {
    db.close();
    try {
      await db.delete();
    } catch {
      // best effort
    }
  }
  dbInstances = [];
  __resetAuthStoreForTests();
  vi.restoreAllMocks();
});

async function waitFor(
  pred: () => boolean,
  attempts = 100,
): Promise<void> {
  for (let i = 0; i < attempts; i += 1) {
    let ok = false;
    await act(async () => {
      await Promise.resolve();
      ok = pred();
    });
    if (ok) return;
  }
  throw new Error('waitFor: predicate never became true');
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ROOM_SLUG = 'announcements';
const ROOM_ID = '11111111-2222-3333-4444-555555555555';
const ROOM_NAME = 'Announcements';
const OWNER_HANDLE = 'alice';
const ROOM_CREATED_AT_ISO = '2025-01-01T00:00:00.000Z';
const POST_ID = '7001';
const POST_BODY = 'public read works without auth';
const POST_CREATED_AT_MS = Date.parse('2025-02-01T12:00:00Z');

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

async function makeIdentity(): Promise<IdentityKeyPair> {
  return await getOrCreateIdentity(new MemoryIdentityStore());
}

interface SignedFixture {
  readonly postId: string;
  readonly body: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;
  readonly signature: Uint8Array;
  readonly createdAtMs: number;
}

function asWireMessage(f: SignedFixture): Record<string, unknown> {
  return {
    id: f.postId,
    roomId: ROOM_ID,
    authorUserId: 'user-uuid',
    authorHandle: f.authorHandle,
    authorIdentityPub: bytesToBase64(f.authorIdentityPub),
    body: f.body,
    authorSignature: bytesToBase64(f.signature),
    createdAt: new Date(f.createdAtMs).toISOString(),
  };
}

interface CapturedRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
}

/** Build a stub `fetch` that captures every request for later
 *  assertion. The capture array is shared between caller and the
 *  stub so the test can inspect headers post-hoc — in particular,
 *  whether `Authorization` was ever emitted on a public-read URL. */
function makeStubFetch(
  routes: Record<string, () => Response | Promise<Response>>,
  captured: CapturedRequest[],
): typeof fetch {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const rawHeaders = init?.headers;
    const headers: Record<string, string> = {};
    if (rawHeaders !== undefined) {
      // The broadcast api client passes a plain object; defensively
      // handle Headers / array-of-tuples too in case the underlying
      // fetch normalisation changes.
      if (rawHeaders instanceof Headers) {
        rawHeaders.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });
      } else if (Array.isArray(rawHeaders)) {
        for (const [k, v] of rawHeaders) {
          headers[String(k).toLowerCase()] = String(v);
        }
      } else {
        for (const [k, v] of Object.entries(rawHeaders)) {
          headers[k.toLowerCase()] = String(v);
        }
      }
    }
    captured.push({ url, method, headers });
    const handler = routes[url];
    if (handler === undefined) {
      throw new Error(`stub fetch: no route for ${method} ${url}`);
    }
    return handler();
  });
  return fn as unknown as typeof fetch;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PublicRoomRoute (task 7.8 — Phase 6 verification)', () => {
  it('renders the public room without sending Authorization on either request', async () => {
    const db = makeDb();
    const roomsStore = new DexieRoomsStore(db);
    const roomPostsStore = new DexieRoomPostsStore(db);

    // Real signed fixture so the verified-author badge contract
    // (Requirement 10.10) actually runs end-to-end through the
    // `verifyBroadcastPost` call inside `RoomView`.
    const identity = await makeIdentity();
    const sig = signBroadcastPost(
      POST_BODY,
      ROOM_ID,
      POST_CREATED_AT_MS,
      identity.ed25519PrivateKey,
    );
    // Sanity check the fixture itself before we hand it to the
    // component — if the test setup is broken we want to fail here,
    // not in an obscure DOM assertion.
    expect(
      verifyBroadcastPost(
        POST_BODY,
        ROOM_ID,
        POST_CREATED_AT_MS,
        sig,
        identity.ed25519PublicKey,
      ),
    ).toBe(true);
    const fixture: SignedFixture = {
      postId: POST_ID,
      body: POST_BODY,
      authorHandle: OWNER_HANDLE,
      authorIdentityPub: identity.ed25519PublicKey,
      signature: sig,
      createdAtMs: POST_CREATED_AT_MS,
    };

    const captured: CapturedRequest[] = [];
    const fetchImpl = makeStubFetch(
      {
        [`/rooms/${ROOM_SLUG}`]: () =>
          jsonResponse(200, {
            id: ROOM_ID,
            slug: ROOM_SLUG,
            name: ROOM_NAME,
            description: null,
            ownerHandle: OWNER_HANDLE,
            createdAt: ROOM_CREATED_AT_ISO,
          }),
        [`/rooms/${ROOM_SLUG}/messages?limit=50`]: () =>
          jsonResponse(200, {
            messages: [asWireMessage(fixture)],
            nextBefore: null,
          }),
      },
      captured,
    );
    const api = new BroadcastApiClient({ fetchImpl, baseUrl: '' });

    const m = mount(
      <PublicRoomRoute
        slug={ROOM_SLUG}
        api={api}
        roomsStore={roomsStore}
        roomPostsStore={roomPostsStore}
      />,
    );

    // Wait for the post to render (history fetch resolved + verify
    // ran + state committed).
    await waitFor(
      () =>
        m.container.querySelector(
          `[data-testid="room-post-${POST_ID}"]`,
        ) !== null,
    );

    // -----------------------------------------------------------------
    // 10.10 — verified-author badge
    // -----------------------------------------------------------------
    expect(
      m.container.querySelector(
        '[data-testid="room-post-badge-verified"]',
      ),
    ).not.toBeNull();
    expect(
      m.container.querySelector(
        '[data-testid="room-post-badge-unverified"]',
      ),
    ).toBeNull();

    // Room metadata + post body rendered.
    expect(m.container.textContent).toContain(ROOM_NAME);
    expect(m.container.textContent).toContain(POST_BODY);

    // The PublicRoomRoute host renders the read-only banner.
    expect(
      m.container.querySelector(
        '[data-testid="room-view-readonly-banner"]',
      ),
    ).not.toBeNull();

    // -----------------------------------------------------------------
    // 10.2 — the SPA does not send Authorization on public reads
    // -----------------------------------------------------------------
    // Both public-read URLs must have been hit, and neither request
    // may carry an `Authorization` header. The auth store is empty
    // for this test (logged-out visitor) so a leak here would be a
    // code defect, not an artefact of test ordering.
    const roomGet = captured.find(
      (r) => r.url === `/rooms/${ROOM_SLUG}` && r.method === 'GET',
    );
    const messagesGet = captured.find(
      (r) =>
        r.url === `/rooms/${ROOM_SLUG}/messages?limit=50` &&
        r.method === 'GET',
    );
    expect(roomGet, 'GET /rooms/:slug must be issued').toBeDefined();
    expect(
      messagesGet,
      'GET /rooms/:slug/messages must be issued',
    ).toBeDefined();
    expect(roomGet!.headers['authorization']).toBeUndefined();
    expect(messagesGet!.headers['authorization']).toBeUndefined();
  });

  it('still omits Authorization on the public reads even when the auth store has a stale access token', async () => {
    // Belt-and-braces guard: a user might land on `/r/:slug` while
    // already logged in (e.g. clicking a permalink from another
    // tab). The broadcast api client routes the public reads
    // through `includeAccessToken: false`, which means no Bearer
    // header even when `getAuthState().accessToken !== null`. This
    // test pins that invariant against a regression where someone
    // flips the public-read default to `true`.
    authActions.setAuth({
      accessToken: 'stale-bearer-token-canary',
      user: { id: 'u1', handle: 'someone-else' },
    });

    const db = makeDb();
    const roomsStore = new DexieRoomsStore(db);
    const roomPostsStore = new DexieRoomPostsStore(db);

    const identity = await makeIdentity();
    const sig = signBroadcastPost(
      POST_BODY,
      ROOM_ID,
      POST_CREATED_AT_MS,
      identity.ed25519PrivateKey,
    );
    const fixture: SignedFixture = {
      postId: POST_ID,
      body: POST_BODY,
      authorHandle: OWNER_HANDLE,
      authorIdentityPub: identity.ed25519PublicKey,
      signature: sig,
      createdAtMs: POST_CREATED_AT_MS,
    };

    const captured: CapturedRequest[] = [];
    const fetchImpl = makeStubFetch(
      {
        [`/rooms/${ROOM_SLUG}`]: () =>
          jsonResponse(200, {
            id: ROOM_ID,
            slug: ROOM_SLUG,
            name: ROOM_NAME,
            description: null,
            ownerHandle: OWNER_HANDLE,
            createdAt: ROOM_CREATED_AT_ISO,
          }),
        [`/rooms/${ROOM_SLUG}/messages?limit=50`]: () =>
          jsonResponse(200, {
            messages: [asWireMessage(fixture)],
            nextBefore: null,
          }),
      },
      captured,
    );
    const api = new BroadcastApiClient({ fetchImpl, baseUrl: '' });

    const m = mount(
      <PublicRoomRoute
        slug={ROOM_SLUG}
        api={api}
        roomsStore={roomsStore}
        roomPostsStore={roomPostsStore}
      />,
    );

    await waitFor(
      () =>
        m.container.querySelector(
          `[data-testid="room-post-${POST_ID}"]`,
        ) !== null,
    );

    const roomGet = captured.find(
      (r) => r.url === `/rooms/${ROOM_SLUG}` && r.method === 'GET',
    );
    const messagesGet = captured.find(
      (r) =>
        r.url === `/rooms/${ROOM_SLUG}/messages?limit=50` &&
        r.method === 'GET',
    );
    expect(roomGet).toBeDefined();
    expect(messagesGet).toBeDefined();
    expect(roomGet!.headers['authorization']).toBeUndefined();
    expect(messagesGet!.headers['authorization']).toBeUndefined();
    // Defense-in-depth: the stale token must not have leaked under
    // any other header name either.
    for (const req of captured) {
      for (const v of Object.values(req.headers)) {
        expect(v).not.toContain('stale-bearer-token-canary');
      }
    }
  });
});

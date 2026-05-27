// apps/web/test/broadcast.test.tsx
//
// Unit tests for the broadcast feature module (task 7.4).
//
// Coverage:
//   - `RoomView` runs `verifyBroadcastPost` against each post in the
//     paginated history and renders the verified-author / unverified
//     badges correctly.
//   - `RoomView` renders the unverified badge when verification
//     fails (corrupted-signature fixture; no mocking of the crypto
//     primitive — we corrupt the input bytes so the real
//     `verifyBroadcastPost` returns false).
//   - `AdminComposer` signs the body with the device Ed25519 key
//     and POSTs `{body, signature, createdAtMs, deviceId}` to
//     `/rooms/:slug/messages` — the body is verifiable by
//     `verifyBroadcastPost` against the same identity public key.
//
// Test-environment notes:
//   - jsdom + fake-indexeddb (see test/setup.ts).
//   - We construct a fresh `KonvoDb` per test and inject it into the
//     repository stores so cross-test data doesn't leak.
//   - All identity material is generated with @noble/curves so the
//     real signing/verification path runs end-to-end.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  MemoryIdentityStore,
  canonicalBroadcastMessage,
  getOrCreateIdentity,
  signBroadcastPost,
  verifyBroadcastPost,
  type IdentityKeyPair,
} from '@konvo/crypto';

import {
  AdminComposer,
  BroadcastApiClient,
  RoomView,
  type IdentityLoader,
} from '../src/features/broadcast/index.js';
import { KonvoDb } from '../src/db/schema.js';
import { DexieRoomPostsStore } from '../src/db/repositories/roomPosts.js';
import { DexieRoomsStore } from '../src/db/repositories/rooms.js';

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
  // Each test gets its own database name to avoid cross-test bleed.
  const name = `konvo-test-${Math.random().toString(36).slice(2)}`;
  const db = new KonvoDb(name);
  dbInstances.push(db);
  return db;
}

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
  vi.restoreAllMocks();
});

/** Drive React's effect loop until `pred` returns true. Mirrors the
 *  helper used by `in-call-safety-number.test.tsx`. */
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

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Build the canonical message bytes the server-side route covers
 *  with its Ed25519 signature: `body || roomId || u64-le(createdAtMs)`.
 *  Locally re-implementing this asserts that the test would notice if
 *  the server's canonical encoding ever drifted from
 *  `canonicalBroadcastMessage`. */
function canonicalBytes(
  body: string,
  roomId: string,
  createdAtMs: number,
): Uint8Array {
  const b = utf8(body);
  const r = utf8(roomId);
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(createdAtMs), true);
  const out = new Uint8Array(b.length + r.length + ts.length);
  out.set(b, 0);
  out.set(r, b.length);
  out.set(ts, b.length + r.length);
  return out;
}

/** Spin up a fresh in-memory identity (Ed25519 sub-key included)
 *  via the same path the production app uses. Returns the keypair
 *  plus the underlying store so subsequent calls (e.g. the
 *  `AdminComposer` loader) can re-read from the same source of
 *  truth. */
async function makeIdentity(): Promise<IdentityKeyPair> {
  const store = new MemoryIdentityStore();
  return await getOrCreateIdentity(store);
}

interface SignedFixture {
  postId: string;
  body: string;
  authorHandle: string;
  authorIdentityPub: Uint8Array;
  signature: Uint8Array;
  createdAtMs: number;
}

function signFixture(args: {
  postId: string;
  body: string;
  authorHandle: string;
  identity: IdentityKeyPair;
  createdAtMs: number;
}): SignedFixture {
  const sig = signBroadcastPost(
    args.body,
    ROOM_ID,
    args.createdAtMs,
    args.identity.ed25519PrivateKey,
  );
  // Sanity check the fixture: it must verify against the identity
  // public key (otherwise the test setup itself is broken).
  if (
    !verifyBroadcastPost(
      args.body,
      ROOM_ID,
      args.createdAtMs,
      sig,
      args.identity.ed25519PublicKey,
    )
  ) {
    throw new Error('signFixture: produced signature does not verify');
  }
  // Also assert our local canonical encoding matches @konvo/crypto's:
  // both should produce the same byte string for the same inputs.
  const localCanon = canonicalBytes(args.body, ROOM_ID, args.createdAtMs);
  const cryptoCanon = canonicalBroadcastMessage(
    args.body,
    ROOM_ID,
    args.createdAtMs,
  );
  if (localCanon.length !== cryptoCanon.length) {
    throw new Error('canonical encoding length mismatch');
  }
  for (let i = 0; i < localCanon.length; i += 1) {
    if (localCanon[i] !== cryptoCanon[i]) {
      throw new Error(`canonical encoding byte mismatch at ${i}`);
    }
  }
  return {
    postId: args.postId,
    body: args.body,
    authorHandle: args.authorHandle,
    authorIdentityPub: args.identity.ed25519PublicKey,
    signature: sig,
    createdAtMs: args.createdAtMs,
  };
}

/** Render a fixture in the wire shape the BroadcastApiClient
 *  expects from `GET /rooms/:slug/messages`. */
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

/** Build a stub `fetch` that maps known URLs to JSON responses.
 *  Unknown URLs reject. */
function makeStubFetch(
  routes: Record<string, () => Response | Promise<Response>>,
): typeof fetch {
  const fn = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const handler = routes[url];
    if (handler === undefined) {
      throw new Error(`stub fetch: no route for ${url}`);
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

describe('RoomView', () => {
  beforeEach(() => {
    // Clear any global fetch stubs.
  });

  it('renders the verified-author badge for posts whose signature verifies', async () => {
    const db = makeDb();
    const roomsStore = new DexieRoomsStore(db);
    const roomPostsStore = new DexieRoomPostsStore(db);

    const identity = await makeIdentity();
    const fixture = signFixture({
      postId: '1001',
      body: 'hello world',
      authorHandle: OWNER_HANDLE,
      identity,
      createdAtMs: Date.parse('2025-02-01T12:00:00Z'),
    });

    const fetchImpl = makeStubFetch({
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
    });
    const api = new BroadcastApiClient({ fetchImpl, baseUrl: '' });

    const m = mount(
      <RoomView
        slug={ROOM_SLUG}
        api={api}
        roomsStore={roomsStore}
        roomPostsStore={roomPostsStore}
      />,
    );

    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="room-post-1001"]',
        ) !== null,
    );

    // Verified badge present, unverified absent.
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

    // Body rendered (post is not blocked from view per Req 10.11).
    expect(m.container.textContent).toContain('hello world');
  });

  it('renders the red unverified badge when the signature does not verify', async () => {
    const db = makeDb();
    const roomsStore = new DexieRoomsStore(db);
    const roomPostsStore = new DexieRoomPostsStore(db);

    const identity = await makeIdentity();
    const fixture = signFixture({
      postId: '2002',
      body: 'tampered post',
      authorHandle: OWNER_HANDLE,
      identity,
      createdAtMs: Date.parse('2025-02-01T13:00:00Z'),
    });
    // Flip a bit of the signature so verification fails. We mutate
    // the bytes in place to simulate a tampered fan-out.
    const tampered = new Uint8Array(fixture.signature);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff;
    const tamperedFixture: SignedFixture = {
      ...fixture,
      signature: tampered,
    };

    const fetchImpl = makeStubFetch({
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
          messages: [asWireMessage(tamperedFixture)],
          nextBefore: null,
        }),
    });
    const api = new BroadcastApiClient({ fetchImpl, baseUrl: '' });

    const m = mount(
      <RoomView
        slug={ROOM_SLUG}
        api={api}
        roomsStore={roomsStore}
        roomPostsStore={roomPostsStore}
      />,
    );

    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="room-post-2002"]',
        ) !== null,
    );

    // Unverified badge present, verified absent.
    expect(
      m.container.querySelector(
        '[data-testid="room-post-badge-unverified"]',
      ),
    ).not.toBeNull();
    expect(
      m.container.querySelector(
        '[data-testid="room-post-badge-verified"]',
      ),
    ).toBeNull();

    // Per Requirement 10.11 the post body is still visible.
    expect(m.container.textContent).toContain('tampered post');
  });
});

describe('AdminComposer', () => {
  it('signs the body locally and POSTs the right wire shape', async () => {
    const db = makeDb();
    void db; // database not needed for this test (loader is injected)

    // Spin up a real Ed25519 sub-key the same way enrollment does.
    // The composer signs against the private key; the assertion below
    // re-verifies the produced signature against the matching public
    // key, mirroring what the server-side handler does.
    const identity = await makeIdentity();
    // The default loader returns raw 32-byte Ed25519 seed bytes;
    // mirror that contract here. `bytes()` returns a defensive copy
    // we can hand directly to the composer.
    const loader: IdentityLoader = {
      loadEd25519Private: async () => identity.ed25519PrivateKey.bytes(),
    };

    let capturedRequest: { url: string; init: RequestInit } | null = null;
    const fetchImpl = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input.toString();
        capturedRequest = { url, init: init ?? {} };
        return jsonResponse(200, {
          id: '4242',
          createdAt: '2025-02-01T14:00:00.000Z',
        });
      },
    );
    const api = new BroadcastApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
      baseUrl: '',
    });

    const fixedNow = Date.parse('2025-02-01T14:00:00.000Z');
    const onPosted = vi.fn();
    const m = mount(
      <AdminComposer
        slug={ROOM_SLUG}
        roomId={ROOM_ID}
        deviceId="device-uuid-abc"
        api={api}
        identityLoader={loader}
        now={() => fixedNow}
        onPosted={onPosted}
      />,
    );

    // Type into the textarea and submit the form.
    const textarea = m.container.querySelector<HTMLTextAreaElement>(
      '[data-testid="admin-composer-body"]',
    );
    expect(textarea).not.toBeNull();
    act(() => {
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        'value',
      )!.set!;
      setter.call(textarea!, 'hello broadcast');
      textarea!.dispatchEvent(new Event('input', { bubbles: true }));
    });

    const form = m.container.querySelector('form')!;
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    await waitFor(() => onPosted.mock.calls.length > 0);

    // Captured request asserts wire shape.
    expect(capturedRequest).not.toBeNull();
    const { url, init } = capturedRequest!;
    expect(url).toBe(`/rooms/${ROOM_SLUG}/messages`);
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/json');

    const sentBody = JSON.parse(init.body as string) as {
      body: string;
      signature: string;
      createdAtMs: number;
      deviceId: string;
    };
    expect(sentBody.body).toBe('hello broadcast');
    expect(sentBody.createdAtMs).toBe(fixedNow);
    expect(sentBody.deviceId).toBe('device-uuid-abc');
    expect(typeof sentBody.signature).toBe('string');

    // Re-verify the signature: it must validate against the device
    // identity public key over the canonical
    // `(body || roomId || createdAtMs)` bytes.
    const sigBytes = base64ToBytes(sentBody.signature);
    expect(sigBytes.length).toBe(64);
    const ok = verifyBroadcastPost(
      sentBody.body,
      ROOM_ID,
      sentBody.createdAtMs,
      sigBytes,
      identity.ed25519PublicKey,
    );
    expect(ok).toBe(true);

    // onPosted carries the server-supplied id.
    expect(onPosted).toHaveBeenCalledWith('4242');
  });
});

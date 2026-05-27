// apps/api/test/broadcast-admin-only.property.test.ts
//
// Property test for task 7.7 (Phase 6) — P21: admin-only post enforcement.
//
// Property under test (orchestrator-specified P21 wording, also
// design.md §21.21 / requirements.md §21):
//
//   For any user U and any room R, `POST /rooms/:slug/messages` with
//   U's auth either succeeds (returning 201) iff U has role='admin' for
//   R, or fails with 403 otherwise — independent of the (validly
//   signed) body content. Property holds across role transitions
//   because each iteration assigns U's role afresh against a fresh
//   room.
//
// **Validates: Requirements 10.5, 21.21**
//
// Strategy:
//   - Mirror the FakeDb / fakeRequireAuth pattern from
//     `broadcast-routes.test.ts` (we only model the SQL the
//     `POST /rooms/:slug/messages` path reaches: room SELECT, role
//     SELECT, devices SELECT, broadcast_messages INSERT).
//   - Reuse a single Fastify harness across all fast-check iterations
//     (per the orchestrator's note in the task brief: spinning up a
//     fresh app per iteration would push runtime from ms to seconds).
//     Each iteration:
//       * generates a unique room id + slug, so the per-(userId, roomId)
//         rate-limit bucket from `broadcast.ts` is fresh and cannot
//         spuriously emit 429 between iterations,
//       * picks one of {admin, subscriber, none} for U's membership
//         against that room,
//       * signs a non-empty body with U's Ed25519 identity key and
//         POSTs it.
//   - Assertion: `role === 'admin' ⇔ statusCode === 201`; otherwise
//     statusCode must be 403.
//
// Iteration count comes from the global fast-check config in
// `test/setup.ts` (default 100 / nightly 500 via FAST_CHECK_RUNS),
// satisfying the ≥ 100 minimum required for property-based tests.

import * as fc from 'fast-check';
import {
  afterAll,
  beforeAll,
  describe,
  expect,
  it,
} from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

import {
  signBroadcastPost,
  MemoryIdentityStore,
  getOrCreateIdentity,
  type IdentityKeyPair,
} from '@konvo/crypto';

import {
  broadcastRoutes,
  type BroadcastRoutesDeps,
} from '../src/routes/broadcast.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub (subset of broadcast-routes.test.ts FakeDb)
// ---------------------------------------------------------------------------
//
// We only model the queries reached by `POST /rooms/:slug/messages`:
//   - SELECT r.id, r.slug, ... FROM broadcast_rooms r JOIN users u
//   - SELECT role FROM broadcast_members
//   - SELECT identity_ed_pub FROM devices
//   - INSERT INTO broadcast_messages
//
// The richer harness in `broadcast-routes.test.ts` covers room-create
// and history-read SQL too; replicating all of it here would be noise
// for this single-route property.

interface UserRow {
  id: string;
  handle: string;
}
interface DeviceRow {
  id: string;
  user_id: string;
  identity_ed_pub: Uint8Array | null;
}
interface RoomDbRow {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  owner_user: string;
  created_at: Date;
}
interface MemberRow {
  room_id: string;
  user_id: string;
  role: 'admin' | 'subscriber';
}
interface MessageRow {
  id: string;
  room_id: string;
  author_user: string;
  author_device: string | null;
  body: string;
  author_signature: Uint8Array;
  created_at: Date;
}

class FakeDb {
  users = new Map<string, UserRow>();
  devices = new Map<string, DeviceRow>();
  rooms = new Map<string, RoomDbRow>();
  roomsBySlug = new Map<string, RoomDbRow>();
  members: MemberRow[] = [];
  messages: MessageRow[] = [];
  #nextMessageId = 1;

  addUser(id: string, handle: string): void {
    this.users.set(id, { id, handle });
  }

  addDevice(id: string, userId: string, identityEdPub: Uint8Array): void {
    this.devices.set(id, {
      id,
      user_id: userId,
      identity_ed_pub: identityEdPub,
    });
  }

  addRoom(row: Omit<RoomDbRow, 'created_at'> & { created_at?: Date }): void {
    const r: RoomDbRow = { ...row, created_at: row.created_at ?? new Date() };
    this.rooms.set(r.id, r);
    this.roomsBySlug.set(r.slug.toLowerCase(), r);
  }

  setMember(
    room_id: string,
    user_id: string,
    role: 'admin' | 'subscriber',
  ): void {
    const i = this.members.findIndex(
      (m) => m.room_id === room_id && m.user_id === user_id,
    );
    if (i >= 0) this.members.splice(i, 1);
    this.members.push({ room_id, user_id, role });
  }

  nextMessageId(): string {
    const n = this.#nextMessageId;
    this.#nextMessageId += 1;
    return n.toString();
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase();

      // SELECT room by slug (join users)
      if (
        lower.includes('from broadcast_rooms') &&
        lower.includes('join users')
      ) {
        const slug = String(params[0]);
        const room = db.roomsBySlug.get(slug.toLowerCase());
        if (room === undefined) return { rows: [], rowCount: 0 };
        const owner = db.users.get(room.owner_user);
        const out = {
          id: room.id,
          slug: room.slug,
          name: room.name,
          description: room.description,
          owner_user: room.owner_user,
          owner_handle: owner?.handle ?? '',
          created_at: room.created_at,
        };
        return { rows: [out as unknown as T], rowCount: 1 };
      }

      // SELECT role from broadcast_members
      if (lower.includes('select role from broadcast_members')) {
        const room_id = String(params[0]);
        const user_id = String(params[1]);
        const m = db.members.find(
          (x) => x.room_id === room_id && x.user_id === user_id,
        );
        if (m === undefined) return { rows: [], rowCount: 0 };
        return { rows: [{ role: m.role } as unknown as T], rowCount: 1 };
      }

      // SELECT identity_ed_pub from devices
      if (lower.includes('from devices') && lower.includes('identity_ed_pub')) {
        const device_id = String(params[0]);
        const user_id = String(params[1]);
        const d = db.devices.get(device_id);
        if (d === undefined || d.user_id !== user_id) {
          return { rows: [], rowCount: 0 };
        }
        return {
          rows: [{ identity_ed_pub: d.identity_ed_pub } as unknown as T],
          rowCount: 1,
        };
      }

      // INSERT broadcast_messages
      if (lower.startsWith('insert into broadcast_messages')) {
        const [room_id, author_user, body, author_signature, author_device] =
          params as [
            string,
            string,
            string,
            Buffer | Uint8Array,
            string,
            number,
          ];
        const createdAtMs = params[5] as number;
        const created_at = new Date(createdAtMs);
        const id = db.nextMessageId();
        const sigBytes =
          author_signature instanceof Uint8Array
            ? new Uint8Array(author_signature)
            : new Uint8Array(author_signature);
        db.messages.push({
          id,
          room_id,
          author_user,
          author_device,
          body,
          author_signature: sigBytes,
          created_at,
        });
        return {
          rows: [{ id, created_at } as unknown as T],
          rowCount: 1,
        };
      }

      throw new Error(`unexpected SQL in property test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Fake auth preHandler (mirrors broadcast-routes.test.ts)
// ---------------------------------------------------------------------------

const fakeRequireAuth = async (
  req: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
): Promise<void> => {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer test:')) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const payload = header.slice('Bearer test:'.length);
  const parts = payload.split(':');
  const userId = parts[0];
  const deviceId = parts[1];
  if (
    typeof userId !== 'string' ||
    typeof deviceId !== 'string' ||
    userId.length === 0
  ) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const principal: AuthenticatedUser = { userId, deviceId };
  req.authUser = principal;
};

// ---------------------------------------------------------------------------
// Fixed identifiers
// ---------------------------------------------------------------------------
//
// `deviceId` on the wire must match `z.string().uuid()` from
// `PostMessageSchema`, hence the formal UUID for BOB_DEVICE. The
// userIds are arbitrary opaque strings — the route doesn't UUID-check
// them, only `req.authUser.userId` flows through into role and INSERT
// SQL parameters.

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const BOB_ID = '22222222-2222-2222-2222-222222222222';
const BOB_DEVICE = '44444444-4444-4444-4444-444444444444';

let bobIdentity: IdentityKeyPair;
let app: FastifyInstance;
let db: FakeDb;
let nowMs = Date.now();
let roomCounter = 0;

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
}

beforeAll(async () => {
  // One identity for Bob, reused across iterations. Generating a fresh
  // identity per iteration would dominate runtime (AES-KW + Ed25519
  // keygen). Bob's identity-ed pubkey is what the route looks up when
  // verifying the signature, so we wire it into the fake `devices`
  // table once below.
  bobIdentity = await getOrCreateIdentity(new MemoryIdentityStore());

  db = new FakeDb();
  db.addUser(ALICE_ID, 'alice');
  db.addUser(BOB_ID, 'bob');
  db.addDevice(BOB_DEVICE, BOB_ID, bobIdentity.ed25519PublicKey);

  app = Fastify({ logger: false });
  const deps: BroadcastRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
    now: () => nowMs,
  };
  await app.register(broadcastRoutes, deps);
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

// ---------------------------------------------------------------------------
// Property: P21 — admin-only post enforcement
// ---------------------------------------------------------------------------

describe('P21: admin-only post enforcement (Requirements 10.5, 21.21)', () => {
  it('POST /rooms/:slug/messages returns 201 iff caller is admin, else 403', async () => {
    const arbRole = fc.constantFrom<'admin' | 'subscriber' | 'none'>(
      'admin',
      'subscriber',
      'none',
    );
    // Body must be non-empty (zod min(1)) and within the 4 KiB UTF-8
    // byte cap. fc.string here yields ASCII-ish chars by default; even
    // multi-byte chars expand at most 4× so 256 chars × 4 = 1024 bytes,
    // well under 4096.
    const arbBody = fc.string({ minLength: 1, maxLength: 256 });

    await fc.assert(
      fc.asyncProperty(arbRole, arbBody, async (role, body) => {
        // Fresh room id + slug per iteration. Two reasons:
        //   1. Each iteration tests Bob's role against a *new* room,
        //      so role transitions across iterations cannot leak state
        //      and the property holds independently each time.
        //   2. The route's per-(userId, roomId) rate-limit bucket
        //      (Requirement 19.4) is keyed on roomId; using a fresh
        //      roomId guarantees we never get a spurious 429.
        roomCounter += 1;
        const roomId = `room-${roomCounter}`;
        const slug = `r-${roomCounter}`; // satisfies ^[a-z0-9-]{3,64}$

        db.addRoom({
          id: roomId,
          slug,
          name: 'X',
          description: null,
          owner_user: ALICE_ID,
        });
        if (role !== 'none') {
          db.setMember(roomId, BOB_ID, role);
        }

        // Sign the post so signature verification succeeds when the
        // role check would otherwise let the request through. The
        // property is about role enforcement, so we don't want a
        // bad signature to mask a missing 403.
        const createdAtMs = Date.now();
        nowMs = createdAtMs;
        const sig = signBroadcastPost(
          body,
          roomId,
          createdAtMs,
          bobIdentity.ed25519PrivateKey,
        );

        const res = await app.inject({
          method: 'POST',
          url: `/rooms/${slug}/messages`,
          headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
          payload: {
            body,
            signature: Buffer.from(sig).toString('base64'),
            createdAtMs,
            deviceId: BOB_DEVICE,
          },
        });

        if (role === 'admin') {
          // Admin path: signature is valid, body is in-range, clock is
          // current → must succeed.
          return res.statusCode === 201;
        }
        // Non-admin (subscriber or non-member): MUST be 403, not 201
        // and not anything else (e.g., 401 would mean auth broke).
        return res.statusCode === 403;
      }),
    );

    // Sanity: the property iterated. Fast-check would have thrown on
    // failure, so reaching here means all iterations held.
    expect(roomCounter).toBeGreaterThan(0);
  });
});

// apps/api/test/attachments-routes.test.ts
//
// Unit tests for the E2EE attachment ciphertext routes.
//
// Created in task 5.2 (route implementation) and formally adopted as
// the deliverable for task 5.6 ("Unit tests for attachment routes").
//
// Task-5.6 audit (each clause from the task brief and the test that
// covers it):
//
//   Clause                                   Requirement   Test
//   ---------------------------------------  ------------  -----------------
//   Size cap rejection at 25 MiB + 1         6.3           "rejects ciphertext > 25 MiB with 413 ..."
//                                                          + "rejects ciphertext at exactly MAX+1 ..."
//   No presigned URLs ever issued            6.7           "owner round-trip: GET streams the ciphertext bytes ..."
//   Owner/recipient authorization (403)      6.8           "non-owner non-recipient: 403"
//   404 on missing blob                      6.10          "missing blob (row exists, MinIO has nothing): 404"
//
// (Cross-reference: requirements.md §Requirement 6 Acceptance
// Criteria 3, 7, 8, 10. Earlier comments in this file used the
// route's internal numbering, which counts the criteria differently;
// the task brief uses requirements.md's numbering, and so does this
// audit block.)
//
// Beyond the four task-5.6 clauses, the file also exercises the
// adjacent acceptance criteria from task 5.2:
//
//   6.2  : multipart upload accepting ciphertext + mime + size + iv + tag
//   6.5  : owner round-trip preserves the ciphertext bytes
//   6.6  : never serve plaintext bytes (the body is opaque ciphertext;
//          Content-Type is application/octet-stream)
//   6.10 : mime length ≤ 255 chars (rejected with 400)
//
// Strategy mirrors `devices-routes.test.ts`:
//   - We exercise `attachmentsRoutes` against a fresh Fastify instance
//     per test, with a hand-rolled `pg.Pool` stub holding an in-memory
//     attachments table.
//   - The Storage interface is satisfied by an in-memory map of
//     `blobKey -> Buffer`. No real MinIO container, no real `minio`
//     SDK — the route is decoupled from the storage backend by
//     design (see `apps/api/src/storage/minio.ts`).
//   - We bypass `@fastify/multipart` entirely: the route's
//     `parseUpload` dependency is a stub that reads the test's
//     pre-arranged upload payload from a per-request property.
//   - The `requireAuth` preHandler is replaced by a trivial stub that
//     reads `Authorization: Bearer test:<userId>:<deviceId>`.

import { Readable } from 'node:stream';

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
} from 'vitest';
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from 'fastify';

import {
  attachmentsRoutes,
  MAX_CIPHERTEXT_BYTES,
  type AttachmentsRoutesDeps,
  type AttachmentUploadParser,
  type ParsedAttachmentUpload,
} from '../src/routes/attachments.js';
import type { Storage } from '../src/storage/minio.js';
import type { AuthenticatedUser } from '../src/middleware/auth.js';

// ---------------------------------------------------------------------------
// In-memory storage stub (Storage interface)
// ---------------------------------------------------------------------------

class FakeStorage implements Storage {
  readonly blobs = new Map<string, Buffer>();

  async putObject(
    _bucket: string,
    key: string,
    body: Buffer,
  ): Promise<void> {
    this.blobs.set(key, Buffer.from(body));
  }

  async getObject(
    _bucket: string,
    key: string,
  ): Promise<{ body: Readable; sizeBytes: number }> {
    const buf = this.blobs.get(key);
    if (buf === undefined) {
      throw Object.assign(new Error('NoSuchKey'), { code: 'NoSuchKey' });
    }
    return {
      body: Readable.from([buf]),
      sizeBytes: buf.length,
    };
  }

  async headObject(
    _bucket: string,
    key: string,
  ): Promise<{ sizeBytes: number } | null> {
    const buf = this.blobs.get(key);
    if (buf === undefined) return null;
    return { sizeBytes: buf.length };
  }
}

// ---------------------------------------------------------------------------
// In-memory pg.Pool stub
// ---------------------------------------------------------------------------

interface AttachmentRow {
  id: string;
  owner_user: string;
  owner_device_id: string | null;
  blob_key: string;
  content_iv: Buffer;
  content_tag: Buffer;
  size_bytes: number;
  mime: string;
  allowed_recipient_user_ids: string[];
  created_at: Date;
}

class FakeDb {
  attachments: AttachmentRow[] = [];
  #nextSeq = 1;

  newAttachmentId(): string {
    const seq = String(this.#nextSeq++).padStart(12, '0');
    return `aaaaaaaa-bbbb-4ccc-8ddd-${seq}`;
  }
}

function makePool(db: FakeDb) {
  return {
    async query<T = unknown>(
      sql: string,
      params: readonly unknown[] = [],
    ): Promise<{ rows: T[]; rowCount: number }> {
      const lower = sql.toLowerCase().trim();

      // ---- INSERT INTO attachments ... RETURNING id ----
      if (lower.startsWith('insert into attachments')) {
        const [
          ownerUser,
          ownerDeviceId,
          blobKey,
          contentIv,
          contentTag,
          sizeBytes,
          mime,
          allowedRecipients,
        ] = params as [
          string,
          string | null,
          string,
          Buffer,
          Buffer,
          number,
          string,
          string[],
        ];
        const id = db.newAttachmentId();
        db.attachments.push({
          id,
          owner_user: ownerUser,
          owner_device_id: ownerDeviceId,
          blob_key: blobKey,
          content_iv: contentIv,
          content_tag: contentTag,
          size_bytes: sizeBytes,
          mime,
          allowed_recipient_user_ids: [...allowedRecipients],
          created_at: new Date(),
        });
        return { rows: [{ id } as unknown as T], rowCount: 1 };
      }

      // ---- SELECT owner_user, blob_key, allowed_recipient_user_ids ... ----
      if (
        lower.startsWith('select owner_user') &&
        lower.includes('from attachments')
      ) {
        const id = String(params[0]);
        const row = db.attachments.find((a) => a.id === id);
        if (row === undefined) return { rows: [], rowCount: 0 };
        return {
          rows: [
            {
              owner_user: row.owner_user,
              blob_key: row.blob_key,
              allowed_recipient_user_ids: [
                ...row.allowed_recipient_user_ids,
              ],
            } as unknown as T,
          ],
          rowCount: 1,
        };
      }

      throw new Error(`unexpected SQL in test: ${sql}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const ALICE_DEVICE = '33333333-3333-3333-3333-333333333333';
const BOB_ID = '22222222-2222-2222-2222-222222222222';
const BOB_DEVICE = '44444444-4444-4444-4444-444444444444';
const CAROL_ID = '55555555-5555-5555-5555-555555555555';
const CAROL_DEVICE = '66666666-6666-6666-6666-666666666666';
const NONEXISTENT_ID = '99999999-9999-9999-9999-999999999999';

const fakeRequireAuth = async (
  req: FastifyRequest,
  reply: FastifyReply,
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
    userId.length === 0 ||
    typeof deviceId !== 'string'
  ) {
    await reply.code(401).send({ error: 'auth_required' });
    return;
  }
  const principal: AuthenticatedUser = { userId, deviceId };
  req.authUser = principal;
};

/** Test-only injectable upload payload. Each request that hits POST
 *  /attachments arranges a `req.testUpload` value via a custom header
 *  decoded by the parser stub below. */
interface TestUploadEnvelope {
  readonly upload?: ParsedAttachmentUpload;
  readonly tooLarge?: boolean;
  readonly invalid?: boolean;
}

/** Module-scoped registry of pre-arranged uploads, keyed by a token
 *  passed via the `x-test-upload` header. Each test inserts a token,
 *  the parser stub looks it up, and the test removes it afterwards.
 *  Using a registry rather than `req.body` avoids fighting Fastify's
 *  body-parsing pipeline. */
const uploadRegistry = new Map<string, TestUploadEnvelope>();

const stubParser: AttachmentUploadParser = async (req) => {
  const token = req.headers['x-test-upload'];
  if (typeof token !== 'string') {
    return { ok: false, reason: 'invalid' };
  }
  const env = uploadRegistry.get(token);
  if (env === undefined) {
    return { ok: false, reason: 'invalid' };
  }
  if (env.tooLarge === true) {
    return { ok: false, reason: 'too_large' };
  }
  if (env.invalid === true) {
    return { ok: false, reason: 'invalid' };
  }
  if (env.upload === undefined) {
    return { ok: false, reason: 'invalid' };
  }
  return { ok: true, value: env.upload };
};

interface Harness {
  app: FastifyInstance;
  db: FakeDb;
  storage: FakeStorage;
}

async function buildHarness(): Promise<Harness> {
  const db = new FakeDb();
  const storage = new FakeStorage();

  const app = Fastify({ logger: false });
  // Bump the body limit so an empty POST body doesn't trip
  // Fastify's default size guards (we drive the upload via a stub
  // parser that reads from the registry, not the body).
  const deps: AttachmentsRoutesDeps = {
    pool: makePool(db),
    requireAuth: fakeRequireAuth,
    storage,
    bucket: 'test-bucket',
    parseUpload: stubParser,
  };
  await app.register(attachmentsRoutes, deps);
  await app.ready();
  return { app, db, storage };
}

function authHeader(userId: string, deviceId: string): string {
  return `Bearer test:${userId}:${deviceId}`;
}

function arrangeUpload(env: TestUploadEnvelope): string {
  const token = `t-${Math.random().toString(36).slice(2)}`;
  uploadRegistry.set(token, env);
  return token;
}

function happyUpload(opts?: {
  ciphertextBytes?: number;
  allowedRecipients?: readonly string[];
  mime?: string;
}): ParsedAttachmentUpload {
  const ciphertextBytes = opts?.ciphertextBytes ?? 64;
  const ciphertext = Buffer.alloc(ciphertextBytes);
  // Fill with a deterministic non-zero pattern so the round-trip
  // assertion catches any byte mangling.
  for (let i = 0; i < ciphertextBytes; i++) {
    ciphertext[i] = (i * 31 + 7) & 0xff;
  }
  return {
    ciphertext,
    mime: opts?.mime ?? 'application/octet-stream',
    sizeBytes: ciphertextBytes,
    contentIv: Buffer.alloc(12, 0xab),
    contentTag: Buffer.alloc(16, 0xcd),
    allowedRecipients: [...(opts?.allowedRecipients ?? [])],
  };
}

let activeApp: FastifyInstance | null = null;
beforeEach(() => {
  uploadRegistry.clear();
});
afterEach(async () => {
  if (activeApp !== null) {
    await activeApp.close();
    activeApp = null;
  }
  uploadRegistry.clear();
});

// ---------------------------------------------------------------------------
// POST /attachments — happy path + size cap
// ---------------------------------------------------------------------------

describe('POST /attachments', () => {
  it('happy path: persists row, stores blob, returns 201 { attachmentId, blobKey }', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const upload = happyUpload({ ciphertextBytes: 1024 });
    const token = arrangeUpload({ upload });

    const res = await h.app.inject({
      method: 'POST',
      url: '/attachments',
      headers: {
        authorization: authHeader(ALICE_ID, ALICE_DEVICE),
        'x-test-upload': token,
      },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json() as { attachmentId: string; blobKey: string };
    expect(typeof body.attachmentId).toBe('string');
    expect(body.attachmentId.length).toBeGreaterThan(0);
    expect(body.blobKey.startsWith('attachments/')).toBe(true);

    expect(h.db.attachments).toHaveLength(1);
    const row = h.db.attachments[0]!;
    expect(row.owner_user).toBe(ALICE_ID);
    expect(row.owner_device_id).toBe(ALICE_DEVICE);
    expect(row.size_bytes).toBe(1024);
    expect(row.mime).toBe('application/octet-stream');
    expect(row.content_iv.length).toBe(12);
    expect(row.content_tag.length).toBe(16);

    // Storage now has the ciphertext at the returned blob key.
    const stored = h.storage.blobs.get(body.blobKey);
    expect(stored).toBeDefined();
    expect(stored!.length).toBe(1024);
    expect(stored!.equals(upload.ciphertext)).toBe(true);
  });

  it('rejects ciphertext > 25 MiB with 413 and persists nothing', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const token = arrangeUpload({ tooLarge: true });

    const res = await h.app.inject({
      method: 'POST',
      url: '/attachments',
      headers: {
        authorization: authHeader(ALICE_ID, ALICE_DEVICE),
        'x-test-upload': token,
      },
    });

    expect(res.statusCode).toBe(413);
    expect(h.db.attachments).toHaveLength(0);
    expect(h.storage.blobs.size).toBe(0);
  });

  it('rejects ciphertext at exactly MAX+1 bytes with 413 (defense-in-depth)', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Bypass the parser's "too_large" path by handing the route an
    // upload that already exceeds the cap. The route itself MUST
    // re-check the size cap (Requirement 6.3) and reject 413, even
    // when the parser claims the payload was fine.
    const upload: ParsedAttachmentUpload = {
      ...happyUpload({ ciphertextBytes: 16 }),
      ciphertext: Buffer.alloc(MAX_CIPHERTEXT_BYTES + 1),
      sizeBytes: MAX_CIPHERTEXT_BYTES + 1,
    };
    const token = arrangeUpload({ upload });

    const res = await h.app.inject({
      method: 'POST',
      url: '/attachments',
      headers: {
        authorization: authHeader(ALICE_ID, ALICE_DEVICE),
        'x-test-upload': token,
      },
    });

    expect(res.statusCode).toBe(413);
    expect(h.db.attachments).toHaveLength(0);
    expect(h.storage.blobs.size).toBe(0);
  });

  it('rejects mime > 255 chars with 400 and persists nothing (Requirement 6.10)', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const upload = happyUpload({ mime: 'a'.repeat(256) });
    const token = arrangeUpload({ upload });

    const res = await h.app.inject({
      method: 'POST',
      url: '/attachments',
      headers: {
        authorization: authHeader(ALICE_ID, ALICE_DEVICE),
        'x-test-upload': token,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(h.db.attachments).toHaveLength(0);
    expect(h.storage.blobs.size).toBe(0);
  });

  it('returns 401 when the request has no Authorization header', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const upload = happyUpload();
    const token = arrangeUpload({ upload });

    const res = await h.app.inject({
      method: 'POST',
      url: '/attachments',
      headers: { 'x-test-upload': token },
    });

    expect(res.statusCode).toBe(401);
    expect(h.db.attachments).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GET /attachments/:id — auth, ACL, 404
// ---------------------------------------------------------------------------

describe('GET /attachments/:id', () => {
  /** Helper: upload an attachment as Alice with the given recipient
   *  list, returning the attachment id + blob key. */
  async function uploadAsAlice(
    h: Harness,
    recipients: readonly string[] = [],
  ): Promise<{ attachmentId: string; blobKey: string; ciphertext: Buffer }> {
    const upload = happyUpload({
      ciphertextBytes: 256,
      allowedRecipients: recipients,
    });
    const token = arrangeUpload({ upload });
    const res = await h.app.inject({
      method: 'POST',
      url: '/attachments',
      headers: {
        authorization: authHeader(ALICE_ID, ALICE_DEVICE),
        'x-test-upload': token,
      },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json() as { attachmentId: string; blobKey: string };
    return { ...body, ciphertext: upload.ciphertext };
  }

  it('owner round-trip: GET streams the ciphertext bytes (not a presigned URL) — Requirement 6.7', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const { attachmentId, ciphertext } = await uploadAsAlice(h);

    const res = await h.app.inject({
      method: 'GET',
      url: `/attachments/${attachmentId}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(200);
    // Response must be the raw bytes, not a JSON envelope or a URL
    // string (Requirement 6.7: never issue presigned URLs for E2EE
    // blobs).
    expect(res.headers['content-type']).toBe('application/octet-stream');
    expect(res.headers['content-length']).toBe(String(ciphertext.length));
    expect(res.headers['cache-control']).toBe('private, no-store');
    // No redirect to a presigned URL: the route must not 30x out to
    // MinIO, and there must be no `Location` header pointing the
    // client at storage. A presigned-URL implementation would
    // typically use 302/303 + Location, or 200 with a JSON body
    // containing the URL. We rule out both.
    expect(res.statusCode).not.toBe(301);
    expect(res.statusCode).not.toBe(302);
    expect(res.statusCode).not.toBe(303);
    expect(res.statusCode).not.toBe(307);
    expect(res.statusCode).not.toBe(308);
    expect(res.headers['location']).toBeUndefined();
    // `inject` returns the body as a Buffer-coerced string; compare
    // bytes directly via `rawPayload`.
    expect(res.rawPayload).toBeInstanceOf(Buffer);
    expect((res.rawPayload as Buffer).equals(ciphertext)).toBe(true);
    // Sanity: the body is NOT a JSON-shaped presigned URL.
    const asString = res.rawPayload.toString('utf8');
    expect(asString.startsWith('http')).toBe(false);
    expect(asString.startsWith('{')).toBe(false);
  });

  it('allowed recipient: GET succeeds and streams ciphertext', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const { attachmentId, ciphertext } = await uploadAsAlice(h, [BOB_ID]);

    const res = await h.app.inject({
      method: 'GET',
      url: `/attachments/${attachmentId}`,
      headers: { authorization: authHeader(BOB_ID, BOB_DEVICE) },
    });

    expect(res.statusCode).toBe(200);
    expect((res.rawPayload as Buffer).equals(ciphertext)).toBe(true);
  });

  it('non-owner non-recipient: 403 (Requirement 6.8)', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    // Alice uploads with Bob as the only allowed recipient; Carol is
    // neither owner nor in the ACL.
    const { attachmentId } = await uploadAsAlice(h, [BOB_ID]);

    const res = await h.app.inject({
      method: 'GET',
      url: `/attachments/${attachmentId}`,
      headers: { authorization: authHeader(CAROL_ID, CAROL_DEVICE) },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json() as { error: string };
    expect(body.error).toBe('forbidden');
  });

  it('missing blob (row exists, MinIO has nothing): 404 (Requirement 6.10)', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const { attachmentId, blobKey } = await uploadAsAlice(h);
    // Simulate a deleted-out-of-band blob: drop the bytes from
    // storage but leave the row in place.
    h.storage.blobs.delete(blobKey);

    const res = await h.app.inject({
      method: 'GET',
      url: `/attachments/${attachmentId}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });

  it('missing row: 404 (does not leak existence to unauthorized callers)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: `/attachments/${NONEXISTENT_ID}`,
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });

  it('malformed UUID: 404 (same shape as missing row)', async () => {
    const h = await buildHarness();
    activeApp = h.app;

    const res = await h.app.inject({
      method: 'GET',
      url: '/attachments/not-a-uuid',
      headers: { authorization: authHeader(ALICE_ID, ALICE_DEVICE) },
    });

    expect(res.statusCode).toBe(404);
  });

  it('returns 401 without auth', async () => {
    const h = await buildHarness();
    activeApp = h.app;
    const { attachmentId } = await uploadAsAlice(h);

    const res = await h.app.inject({
      method: 'GET',
      url: `/attachments/${attachmentId}`,
    });
    expect(res.statusCode).toBe(401);
  });
});

// apps/web/test/attachments.test.ts
//
// Unit tests for the web attachment feature (task 5.3).
//
// Coverage map (per the task brief):
//   - Round-trip: encrypt → upload (mock fetch) → download → decrypt
//     → bytes match.
//   - AES-GCM tag failure on the recipient side surfaces a typed
//     `decrypt_failed` result that maps to the
//     "attachment couldn't be decrypted" placeholder.
//   - HTTP 404 from the server surfaces a typed `not_found` result
//     that maps to the "attachment unavailable" placeholder.
//   - LRU eviction keeps the cache footprint at-or-below the
//     configured cap, evicting the oldest rows by `lastAccessedAt`.
//
// We run against jsdom + fake-indexeddb (see test/setup.ts). The
// `Blob`/`File`/`FormData`/`URL.createObjectURL` paths the upload +
// AttachmentView depend on are jsdom-supplied.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  encryptAttachment,
  type EncryptedAttachment,
} from '@konvo/crypto';
import type { AttachmentRef } from '@konvo/protocol';

import { KonvoDb } from '../src/db/schema.js';
import {
  AttachmentDownloadError,
  AttachmentUploadError,
  downloadAttachment,
  LocalAttachmentsStore,
  uploadAttachment,
} from '../src/features/attachments/index.js';

// ---------------------------------------------------------------------------
// Per-test Dexie isolation
// ---------------------------------------------------------------------------

let activeDb: KonvoDb | null = null;
let dbCounter = 0;

function freshDb(): KonvoDb {
  dbCounter += 1;
  const name = `konvo-attachments-test-${dbCounter}-${Math.random()
    .toString(36)
    .slice(2)}`;
  const db = new KonvoDb(name);
  activeDb = db;
  return db;
}

afterEach(async () => {
  if (activeDb !== null) {
    activeDb.close();
    await activeDb.delete();
    activeDb = null;
  }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a `File` of `size` bytes with a deterministic content
 *  pattern. The pattern matters for the round-trip assertion: we
 *  want every byte to participate in the AES-GCM tag check, so
 *  truncation or off-by-one errors surface clearly. */
function makeFile(
  size: number,
  mime = 'application/octet-stream',
  name = 'test.bin',
): File {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i += 1) bytes[i] = (i * 7 + 13) & 0xff;
  return new File([bytes], name, { type: mime });
}

/** Read a `Blob` (or `File`) into a `Uint8Array`. jsdom 25 ships
 *  `Blob` without the `arrayBuffer()` method, so we feature-detect
 *  and fall back to `FileReader`. */
async function blobToBytes(blob: Blob): Promise<Uint8Array> {
  const maybe = (blob as Blob & { arrayBuffer?: () => Promise<ArrayBuffer> })
    .arrayBuffer;
  if (typeof maybe === 'function') {
    return new Uint8Array(await maybe.call(blob));
  }
  return new Promise<Uint8Array>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (): void => {
      const r = reader.result;
      if (r instanceof ArrayBuffer) resolve(new Uint8Array(r));
      else reject(new Error('blobToBytes: non-ArrayBuffer result'));
    };
    reader.onerror = (): void => reject(reader.error ?? new Error('blobToBytes failed'));
    reader.readAsArrayBuffer(blob);
  });
}

/** Build a fake `fetch` that captures the upload request and yields
 *  whatever response we hand it. */
interface CapturedRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: BodyInit | null;
}

function captureFetch(
  responses: ReadonlyArray<Response | (() => Promise<Response>)>,
): { fetchImpl: typeof fetch; calls: CapturedRequest[] } {
  const calls: CapturedRequest[] = [];
  let i = 0;
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as URL).toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers ?? {});
    const body = init?.body ?? null;
    calls.push({ url, method, headers, body });
    if (i >= responses.length) {
      throw new Error(`captureFetch: no response queued for call ${i + 1}`);
    }
    const slot = responses[i]!;
    i += 1;
    return typeof slot === 'function' ? await slot() : slot;
  };
  return { fetchImpl, calls };
}

// ---------------------------------------------------------------------------
// 1. Encrypt → upload → download → decrypt → bytes match
// ---------------------------------------------------------------------------

describe('attachments round-trip', () => {
  it('encrypts, uploads, downloads, decrypts, and yields the original bytes', async () => {
    const file = makeFile(2048, 'image/png', 'pic.png');
    const original = await blobToBytes(file);

    // The server-side ciphertext bytes captured during upload — we
    // hand them right back on the GET so the round-trip round-trips
    // through the same body the client sent.
    let serverCiphertext: Uint8Array | null = null;

    const upload = captureFetch([
      // POST /attachments — read the multipart `ciphertext` part
      // out of the FormData body so we can echo it on GET later.
      async () => {
        return new Response(
          JSON.stringify({
            attachmentId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            blobKey: 'attachments/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        );
      },
    ]);

    // Upload. We sniff the multipart body via a fetch interceptor
    // so we can echo the ciphertext back during the download step.
    const uploadFetch: typeof fetch = async (input, init) => {
      const url =
        typeof input === 'string' ? input : (input as URL).toString();
      const body = init?.body;
      if (body instanceof FormData) {
        const part = body.get('ciphertext');
        if (part instanceof Blob) {
          serverCiphertext = await blobToBytes(part);
        }
      }
      return upload.fetchImpl(input, init);
    };

    const ref = await uploadAttachment(file, ['recipient-uuid-1'], {
      fetchImpl: uploadFetch,
      tokenProvider: () => 'test-access-token',
      csrfTokenProvider: () => null,
    });

    expect(ref.attachmentId).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    expect(ref.key.length).toBe(32);
    expect(ref.iv.length).toBe(12);
    expect(ref.tag.length).toBe(16);
    expect(ref.sizeBytes).toBe(original.length);
    expect(serverCiphertext).not.toBeNull();
    // AES-GCM ciphertext byte length equals the plaintext byte
    // length (the tag rides separately in `ref.tag`).
    expect(serverCiphertext!.length).toBe(original.length);

    // Download — the server hands back the captured ciphertext
    // bytes verbatim.
    const download = captureFetch([
      new Response(serverCiphertext! as unknown as BodyInit, {
        status: 200,
        headers: {
          'content-type': 'application/octet-stream',
          'content-length': String(serverCiphertext!.length),
        },
      }),
    ]);

    const result = await downloadAttachment(ref, {
      fetchImpl: download.fetchImpl,
      tokenProvider: () => 'test-access-token',
    });

    expect(result.kind).toBe('ok');
    if (result.kind === 'ok') {
      expect(result.plaintext).toEqual(original);
    }
  });

  it('rejects oversize files at the client guard before encrypting', async () => {
    // 25 MiB + 1 byte. We pass a stub File whose `size` claims the
    // oversize value without actually allocating that many bytes —
    // the guard runs against `file.size`, so we never reach the
    // `arrayBuffer()` read.
    const file = new File([new Uint8Array(8)], 'big.bin');
    Object.defineProperty(file, 'size', { value: 25 * 1024 * 1024 + 1 });

    await expect(
      uploadAttachment(file, [], {
        fetchImpl: vi.fn() as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ kind: 'oversize' });
  });
});

// ---------------------------------------------------------------------------
// 2. AES-GCM tag failure → typed decrypt_failed result
// ---------------------------------------------------------------------------

describe('attachments tag-failure path', () => {
  it('returns a decrypt_failed result when the ciphertext is tampered', async () => {
    const original = new Uint8Array(64);
    for (let i = 0; i < 64; i += 1) original[i] = i;
    const enc: EncryptedAttachment = await encryptAttachment(original);

    // Flip one byte in the ciphertext body. AES-GCM is
    // all-or-nothing under any single-bit mutation, so the tag
    // verification fails.
    const tampered = new Uint8Array(enc.ciphertext);
    tampered[0] = tampered[0] === 0 ? 1 : tampered[0] ^ 0xff;

    const ref: AttachmentRef = {
      attachmentId: 'tampered-id',
      key: enc.key,
      iv: enc.iv,
      tag: enc.tag,
      sizeBytes: original.length,
    };

    const { fetchImpl } = captureFetch([
      new Response(tampered as unknown as BodyInit, {
        status: 200,
        headers: { 'content-type': 'application/octet-stream' },
      }),
    ]);

    const result = await downloadAttachment(ref, { fetchImpl });
    expect(result.kind).toBe('decrypt_failed');
  });
});

// ---------------------------------------------------------------------------
// 3. HTTP 404 → typed not_found result
// ---------------------------------------------------------------------------

describe('attachments 404 path', () => {
  it('returns a not_found result on HTTP 404 without throwing', async () => {
    const ref: AttachmentRef = {
      attachmentId: 'missing-id',
      key: new Uint8Array(32),
      iv: new Uint8Array(12),
      tag: new Uint8Array(16),
      sizeBytes: 0,
    };

    const { fetchImpl } = captureFetch([
      new Response(JSON.stringify({ error: 'not_found' }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      }),
    ]);

    const result = await downloadAttachment(ref, { fetchImpl });
    expect(result.kind).toBe('not_found');
  });

  it('throws AttachmentDownloadError on 403 (transient, retryable)', async () => {
    const ref: AttachmentRef = {
      attachmentId: 'forbidden-id',
      key: new Uint8Array(32),
      iv: new Uint8Array(12),
      tag: new Uint8Array(16),
      sizeBytes: 0,
    };

    const { fetchImpl } = captureFetch([
      new Response('forbidden', { status: 403 }),
    ]);

    await expect(downloadAttachment(ref, { fetchImpl })).rejects.toBeInstanceOf(
      AttachmentDownloadError,
    );
  });
});

// ---------------------------------------------------------------------------
// 4. LRU eviction at the configured cap
// ---------------------------------------------------------------------------

describe('LocalAttachmentsStore — LRU eviction', () => {
  it('evicts oldest rows by lastAccessedAt until the cap is satisfied', async () => {
    const db = freshDb();
    // Configure a tiny cap so we can drive the loop without
    // allocating real megabytes. The cap is intentionally smaller
    // than the sum of inserted ciphertext byte counts so eviction
    // MUST trigger.
    let clock = 0;
    const now = (): number => {
      clock += 1;
      return clock;
    };
    const cache = new LocalAttachmentsStore(db, {
      maxBytes: 100,
      now,
    });

    const mk = (bytes: number): Uint8Array => {
      const u = new Uint8Array(bytes);
      for (let i = 0; i < bytes; i += 1) u[i] = i & 0xff;
      return u;
    };

    // Insert four 40-byte rows. After the fourth, total ciphertext
    // is 160 bytes — the cap is 100 — so eviction must drop the
    // oldest until the residual ≤ 100. With four equally-sized
    // rows that means dropping the two oldest, leaving 80 bytes.
    await cache.putCiphertext({
      attachmentId: 'a',
      ciphertext: mk(40),
      mime: 'application/octet-stream',
      filename: 'a.bin',
    });
    await cache.putCiphertext({
      attachmentId: 'b',
      ciphertext: mk(40),
      mime: 'application/octet-stream',
      filename: 'b.bin',
    });
    await cache.putCiphertext({
      attachmentId: 'c',
      ciphertext: mk(40),
      mime: 'application/octet-stream',
      filename: 'c.bin',
    });
    await cache.putCiphertext({
      attachmentId: 'd',
      ciphertext: mk(40),
      mime: 'application/octet-stream',
      filename: 'd.bin',
    });

    const total = await cache.totalBytes();
    expect(total).toBeLessThanOrEqual(100);

    // The two newest survivors should be present; the two oldest
    // should be gone.
    expect(await cache.getByAttachmentId('a')).toBeNull();
    expect(await cache.getByAttachmentId('b')).toBeNull();
    expect(await cache.getByAttachmentId('c')).not.toBeNull();
    expect(await cache.getByAttachmentId('d')).not.toBeNull();
  });

  it('promotes a recently accessed row so eviction skips it', async () => {
    const db = freshDb();
    let clock = 0;
    const now = (): number => {
      clock += 1;
      return clock;
    };
    const cache = new LocalAttachmentsStore(db, {
      maxBytes: 100,
      now,
    });

    const fill = new Uint8Array(40).fill(7);
    await cache.putCiphertext({
      attachmentId: 'a',
      ciphertext: fill,
      mime: 'application/octet-stream',
      filename: 'a.bin',
    });
    await cache.putCiphertext({
      attachmentId: 'b',
      ciphertext: fill,
      mime: 'application/octet-stream',
      filename: 'b.bin',
    });
    // Touch 'a' so its `lastAccessedAt` is fresher than 'b'.
    expect(await cache.getByAttachmentId('a')).not.toBeNull();
    // Now insert 'c'. With a 100-byte cap and 120 bytes in flight,
    // exactly one row must be evicted — the LRU policy picks the
    // oldest by `lastAccessedAt`, which is 'b' (we just promoted
    // 'a').
    await cache.putCiphertext({
      attachmentId: 'c',
      ciphertext: fill,
      mime: 'application/octet-stream',
      filename: 'c.bin',
    });

    expect(await cache.getByAttachmentId('b')).toBeNull();
    expect(await cache.getByAttachmentId('a')).not.toBeNull();
    expect(await cache.getByAttachmentId('c')).not.toBeNull();
  });

  it('defaults the cap to 200 MiB when no override is provided', () => {
    const db = freshDb();
    const cache = new LocalAttachmentsStore(db);
    expect(cache.maxBytes).toBe(200 * 1024 * 1024);
  });
});

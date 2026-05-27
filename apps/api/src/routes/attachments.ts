// apps/api/src/routes/attachments.ts
//
// E2EE attachment ciphertext upload + download routes (task 5.2 — Phase 4).
// Per design.md §9 (REST route signatures) and §3.3 (encrypt + upload
// flow):
//
//   POST /attachments                                 (auth)
//     multipart: { ciphertext, mime, sizeBytes,
//                  contentIv, contentTag,
//                  allowedRecipients }
//     reply 201: { attachmentId, blobKey }
//     reply 413: ciphertext > 25 MiB (26214400 bytes)
//
//   GET /attachments/:id                              (auth)
//     reply 200: binary stream of ciphertext bytes
//                Content-Type: application/octet-stream
//     reply 403: caller is neither owner nor an allowed recipient
//     reply 404: row missing OR blob missing in MinIO
//
// Realizes Requirements 6.2, 6.3, 6.5, 6.6, 6.7, 6.8, 6.10:
//
//   6.2  : multipart upload accepting ciphertext + mime + size + iv + tag
//   6.3  : reject any single attachment ciphertext > 25 MiB
//   6.5  : recipient streams ciphertext bytes (decrypts client-side via
//          the AES key carried inside an E2EE envelope; the server has
//          no access to the key, IV, or tag at fetch time)
//   6.6  : never serve plaintext bytes (the server only ever stores +
//          serves ciphertext); never issue presigned URLs (the route
//          forwards the MinIO stream through the API process so the
//          authorization check on the same code path is authoritative)
//   6.7  : reject 403 if caller is neither owner nor an allowed
//          recipient of any envelope referencing the attachment
//   6.8  : 404 if blob is missing
//   6.10 : mime length ≤ 255 chars
//
// Why the recipient ACL is stored on the attachments row
// (`allowed_recipient_user_ids[]`) rather than derived from envelopes:
//
//   The envelope payload (see packages/protocol/src/envelopes.ts —
//   `AttachmentRef`) is E2EE-encrypted, so the API_Gateway literally
//   cannot read the `attachmentId` field of any sent envelope. This
//   means we cannot do the authorization check by joining
//   `ciphertext_envelopes` against attachments. Instead, the uploader
//   must declare the set of permitted readers as a multipart field at
//   upload time, and the GET path verifies the caller's `userId` is
//   the owner or appears in that list. This matches the task brief's
//   NOTE block. The list is opaque to the server (it learns "Bob and
//   Carol can read attachment X" but nothing about the conversation
//   structure), preserving the metadata-minimization spirit of
//   design.md §5 even when the server is fully compromised — Bob and
//   Carol's ability to download the ciphertext is still gated on
//   their auth tokens, and they still need the AES key from the
//   E2EE envelope to decrypt it. The ACL only prevents random
//   authenticated users from probing arbitrary blob keys.
//
// Why no presigned URLs (Requirement 6.6):
//
//   A presigned URL bypasses the API process and lets MinIO serve the
//   bytes directly. That breaks the authorization check: the server
//   would have to encode the recipient identity into the URL, and
//   anyone who got the URL could fetch the ciphertext. By streaming
//   through the API process we keep the auth + retrieval on the same
//   code path. The ciphertext is opaque to the proxy hop anyway, so
//   there's no confidentiality reason to prefer a presigned URL.
//
// Streaming + memory budget:
//
//   The ciphertext upload buffer is bounded by the 25 MiB cap from
//   Requirement 6.3. Past that we reply 413 BEFORE buffering any
//   bytes (the multipart parser is configured with `limits.fileSize
//   = 25 MiB + 1`, which surfaces oversize uploads as a typed error).
//
//   The download is a true stream: `getObject` returns a Readable
//   that we hand to `reply.send(stream)`, never buffering the
//   ciphertext in the API process. `Content-Length` comes from a
//   prior `headObject` call so clients can show progress.

import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler,
} from 'fastify';
import type pg from 'pg';
import { z } from 'zod';

import type { AttachmentCreateResponse } from '@konvo/protocol';

import type { Storage } from '../storage/minio.js';

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/** Minimal `pg.Pool` shape this plugin needs. Restated structurally so
 *  tests can stub the pool without spinning up Postgres. */
type DbPool = Pick<pg.Pool, 'query'>;

/** Multipart upload payload after parsing. The server reads the binary
 *  ciphertext as a `Buffer` (capped at 25 MiB by the parser) and the
 *  text fields as strings. The route then validates each field and
 *  decodes the byte fields from base64. */
export interface ParsedAttachmentUpload {
  /** Binary ciphertext bytes. Already size-capped by the parser. */
  readonly ciphertext: Buffer;
  /** Declared content type. Length must be ≤ 255 (Requirement 6.10). */
  readonly mime: string;
  /** Declared plaintext size in bytes. Echoed back to the client via
   *  the database row but not used for routing decisions. */
  readonly sizeBytes: number;
  /** AES-GCM IV. Exactly 12 bytes (NIST SP 800-38D 96-bit recommendation). */
  readonly contentIv: Buffer;
  /** AES-GCM tag. Exactly 16 bytes. */
  readonly contentTag: Buffer;
  /** User UUIDs the uploader permits to GET this attachment. */
  readonly allowedRecipients: readonly string[];
}

/** Pluggable multipart parser. Tests inject a synchronous parser that
 *  reads from a pre-arranged request body; production wires this to
 *  `@fastify/multipart` via `multipartUploadParser`. */
export type AttachmentUploadParser = (
  req: FastifyRequest,
) => Promise<ParseResult>;

/** Parser result. Discriminated so the parser can signal "too large"
 *  without throwing — the route maps this to HTTP 413 instead of 5xx. */
export type ParseResult =
  | { readonly ok: true; readonly value: ParsedAttachmentUpload }
  | { readonly ok: false; readonly reason: 'too_large' | 'invalid' };

export interface AttachmentsRoutesDeps {
  readonly pool: DbPool;
  readonly requireAuth: preHandlerAsyncHookHandler;
  readonly storage: Storage;
  readonly bucket: string;
  /** Multipart parser. Defaults to a `@fastify/multipart`-backed
   *  implementation; tests provide a synchronous in-memory parser. */
  readonly parseUpload: AttachmentUploadParser;
  /** Override the wall-clock for deterministic tests. */
  readonly now?: () => number;
}

/** Maximum ciphertext size: 25 MiB (Requirement 6.3). Anything larger
 *  is rejected with HTTP 413 before any DB row is written or any
 *  MinIO PUT is issued. */
export const MAX_CIPHERTEXT_BYTES = 25 * 1024 * 1024; // 26_214_400

const MAX_MIME_LENGTH = 255;

// ---------------------------------------------------------------------------
// Validation schemas
// ---------------------------------------------------------------------------

/** Validate a parsed upload at the route layer. The parser does the
 *  multipart byte-shoving; the schema enforces semantic constraints
 *  (size cap, IV/tag lengths, mime length, recipient UUIDs).
 *
 *  We DO NOT validate the ciphertext bytes themselves — they're
 *  opaque AES-GCM output to the server and any pattern is plausible.
 *  The size cap is checked imperatively below so we can return a
 *  413 (instead of 400) for the specific "too large" case
 *  (Requirement 6.3). */
const UploadSchema = z
  .object({
    ciphertext: z.instanceof(Buffer),
    mime: z.string().min(1).max(MAX_MIME_LENGTH),
    sizeBytes: z.number().int().nonnegative(),
    contentIv: z.instanceof(Buffer).refine((b) => b.length === 12, {
      message: 'contentIv must be exactly 12 bytes',
    }),
    contentTag: z.instanceof(Buffer).refine((b) => b.length === 16, {
      message: 'contentTag must be exactly 16 bytes',
    }),
    allowedRecipients: z.array(z.string().uuid()).max(1024),
  })
  .strict();

const UuidSchema = z.string().uuid();

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const attachmentsRoutes: FastifyPluginAsync<AttachmentsRoutesDeps> =
  async (app, deps) => {
    // -----------------------------------------------------------------------
    // POST /attachments — upload ciphertext blob (Requirements 6.2, 6.3, 6.10)
    // -----------------------------------------------------------------------
    app.post(
      '/attachments',
      { preHandler: deps.requireAuth },
      async (req: FastifyRequest, reply: FastifyReply) => {
        const auth = req.authUser;
        if (auth === undefined) {
          return reply.code(401).send({ error: 'auth_required' });
        }

        const parsed = await deps.parseUpload(req);
        if (!parsed.ok) {
          if (parsed.reason === 'too_large') {
            // Requirement 6.3: any single attachment ciphertext > 25
            // MiB is rejected. We surface this as HTTP 413 (Payload
            // Too Large) so clients can distinguish it from a
            // generic schema rejection.
            return reply.code(413).send({ error: 'payload_too_large' });
          }
          return reply.code(400).send({ error: 'invalid_request' });
        }

        const validated = UploadSchema.safeParse(parsed.value);
        if (!validated.success) {
          return reply.code(400).send({ error: 'invalid_request' });
        }
        const upload = validated.data;

        // Defense-in-depth: re-check the size cap at the route layer
        // even though the parser should have rejected oversize bytes
        // already. A misbehaving parser cannot smuggle past
        // Requirement 6.3 this way.
        if (upload.ciphertext.length > MAX_CIPHERTEXT_BYTES) {
          return reply.code(413).send({ error: 'payload_too_large' });
        }

        // Generate the MinIO object key. We use a UUID + an
        // `attachments/` prefix so the key is unguessable AND so
        // operators inspecting the bucket immediately see the data
        // class. The key never appears in plaintext logs (Requirement
        // 18.4 / 4.14). The owning device, when present, is bound to
        // the auth token's `did` claim (`auth.deviceId`); we treat
        // an empty deviceId as "no device" so this column is null —
        // which preserves the audit trail for tokens issued before
        // device enrollment lands.
        const blobKey = `attachments/${randomUUID()}`;
        const ownerDeviceId =
          auth.deviceId.length > 0 ? auth.deviceId : null;

        // Insert the metadata row FIRST. If the MinIO PUT then fails
        // we have an orphan row that points at no blob; the GET path
        // surfaces this as 404 (Requirement 6.8) so clients see a
        // consistent failure mode. Doing the PUT first would leave
        // an orphan ciphertext blob in MinIO with no row to find it
        // via, which is harder to clean up later.
        const ins = await deps.pool.query<{ id: string }>(
          `INSERT INTO attachments
             (owner_user, owner_device_id, blob_key,
              content_iv, content_tag, size_bytes, mime,
              allowed_recipient_user_ids)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id`,
          [
            auth.userId,
            ownerDeviceId,
            blobKey,
            upload.contentIv,
            upload.contentTag,
            upload.sizeBytes,
            upload.mime,
            upload.allowedRecipients,
          ],
        );
        if (ins.rowCount === 0) {
          return reply.code(500).send({ error: 'internal' });
        }
        const attachmentId = (ins.rows[0] as { id: string }).id;

        // Upload the ciphertext bytes. On failure we leave the row
        // in place; it will simply 404 on GET (Requirement 6.8) until
        // a janitorial sweep removes orphan rows. This is the same
        // shape as a row whose blob was deliberately deleted later.
        await deps.storage.putObject(
          deps.bucket,
          blobKey,
          upload.ciphertext,
        );

        const response: AttachmentCreateResponse = {
          attachmentId,
          blobKey,
        };
        return reply.code(201).send(response);
      },
    );

    // -----------------------------------------------------------------------
    // GET /attachments/:id — stream ciphertext (Requirements 6.5–6.8)
    // -----------------------------------------------------------------------
    app.get(
      '/attachments/:id',
      { preHandler: deps.requireAuth },
      async (req, reply) => {
        const auth = req.authUser;
        if (auth === undefined) {
          return reply.code(401).send({ error: 'auth_required' });
        }
        const params = req.params as { id?: unknown };
        const idParsed = UuidSchema.safeParse(params.id);
        if (!idParsed.success) {
          // A malformed UUID can't match any real attachment, so 404
          // is the right shape (matches the convention from
          // routes/devices.ts DELETE).
          return reply.code(404).send({ error: 'not_found' });
        }

        // Fetch the row + ACL. We retrieve `allowed_recipient_user_ids`
        // here so the same query that proves the row exists also
        // gives us everything authorization needs.
        interface Row {
          owner_user: string;
          blob_key: string;
          allowed_recipient_user_ids: readonly string[];
        }
        const r = await deps.pool.query<Row>(
          `SELECT owner_user, blob_key,
                  COALESCE(allowed_recipient_user_ids, ARRAY[]::UUID[])
                    AS allowed_recipient_user_ids
             FROM attachments
            WHERE id = $1
            LIMIT 1`,
          [idParsed.data],
        );
        if (r.rowCount === 0) {
          return reply.code(404).send({ error: 'not_found' });
        }
        const row = r.rows[0] as Row;

        // Authorization (Requirement 6.7): the caller must be the
        // owner OR appear in the recipient ACL. We check both
        // before any storage call so an unauthorized caller cannot
        // even probe whether the blob exists. We use === for the
        // owner check (UUIDs from `pg` are already strings) and
        // `Array.includes` against the ACL array.
        const isOwner = row.owner_user === auth.userId;
        const isRecipient = row.allowed_recipient_user_ids.includes(
          auth.userId,
        );
        if (!isOwner && !isRecipient) {
          return reply.code(403).send({ error: 'forbidden' });
        }

        // Probe blob existence. A 404 here means the row points at a
        // blob that vanished (deleted out-of-band, or PUT failed
        // during upload). Either way we surface as HTTP 404 per
        // Requirement 6.8 so the client renders the
        // "attachment unavailable" placeholder.
        const head = await deps.storage.headObject(
          deps.bucket,
          row.blob_key,
        );
        if (head === null) {
          return reply.code(404).send({ error: 'not_found' });
        }

        // Stream the ciphertext bytes. `Content-Type:
        // application/octet-stream` is the conservative choice — the
        // bytes are AES-GCM ciphertext (random-looking) and we never
        // want a browser to sniff them as anything else. We reply
        // with the raw stream (no presigned URL anywhere — Requirement
        // 6.6) so the auth check on the same code path is the
        // authoritative gate.
        const obj = await deps.storage.getObject(
          deps.bucket,
          row.blob_key,
        );
        reply.header('Content-Type', 'application/octet-stream');
        reply.header('Content-Length', String(head.sizeBytes));
        // Cache-Control: even though the ciphertext is content-
        // addressed via blob_key, we mark the response private so
        // shared proxies don't cache the ciphertext under one
        // recipient's URL. The client may cache the decrypted
        // plaintext locally per Requirement 6.5.
        reply.header('Cache-Control', 'private, no-store');
        return reply.send(obj.body);
      },
    );
  };

// ---------------------------------------------------------------------------
// @fastify/multipart-backed parser (production wiring)
// ---------------------------------------------------------------------------

/** Default multipart parser bound to `@fastify/multipart`. The route
 *  imports this lazily via the `parseUpload` dep so unit tests that
 *  only exercise the route logic don't pull `@fastify/multipart` into
 *  their bundle.
 *
 *  The function expects `@fastify/multipart` to be registered on the
 *  Fastify instance with `attachFieldsToBody: false` (default) so we
 *  drive the parts iterator ourselves. Each call collects the binary
 *  `ciphertext` field into a Buffer and the text fields into strings,
 *  enforcing the 25 MiB cap on the binary field as it streams in.
 *
 *  The parser is exported as a factory so the bucket / cap can be
 *  passed at registration time. */
export function multipartUploadParser(): AttachmentUploadParser {
  return async function parse(req: FastifyRequest): Promise<ParseResult> {
    // @fastify/multipart decorates the request with `parts()` once
    // registered. We call it via a structural cast so this file
    // type-checks without depending on the plugin's types.
    const reqWithParts = req as unknown as {
      parts(): AsyncIterable<MultipartPart>;
      isMultipart(): boolean;
    };
    if (typeof reqWithParts.isMultipart !== 'function' ||
        !reqWithParts.isMultipart()) {
      return { ok: false, reason: 'invalid' };
    }

    let ciphertext: Buffer | null = null;
    let mime: string | null = null;
    let sizeBytes: number | null = null;
    let contentIv: Buffer | null = null;
    let contentTag: Buffer | null = null;
    let allowedRecipients: string[] = [];

    try {
      for await (const part of reqWithParts.parts()) {
        if (part.type === 'file') {
          if (part.fieldname !== 'ciphertext') {
            // Drain unknown file fields rather than leaving the
            // socket open. A malformed multipart body that includes
            // an extra file would otherwise block the request.
            await drainStream(part.file);
            continue;
          }
          const collected = await collectStream(
            part.file,
            MAX_CIPHERTEXT_BYTES,
          );
          if (collected === null) {
            return { ok: false, reason: 'too_large' };
          }
          ciphertext = collected;
        } else {
          // Text field. `value` is already a string (or string[]) per
          // @fastify/multipart's contract.
          const v = typeof part.value === 'string' ? part.value : '';
          switch (part.fieldname) {
            case 'mime':
              mime = v;
              break;
            case 'sizeBytes':
              sizeBytes = Number.parseInt(v, 10);
              break;
            case 'contentIv':
              contentIv = Buffer.from(v, 'base64');
              break;
            case 'contentTag':
              contentTag = Buffer.from(v, 'base64');
              break;
            case 'allowedRecipients':
              allowedRecipients = v.length > 0 ? v.split(',') : [];
              break;
            default:
              // Ignore unknown fields. The schema validator will
              // reject the upload if a required field is missing.
              break;
          }
        }
      }
    } catch (err) {
      // @fastify/multipart throws a `RequestFileTooLargeError` when
      // the per-file limit is hit. We map it (and any other thrown
      // error during iteration) onto the typed result rather than
      // letting it propagate as a 500.
      if (isTooLargeError(err)) {
        return { ok: false, reason: 'too_large' };
      }
      return { ok: false, reason: 'invalid' };
    }

    if (
      ciphertext === null ||
      mime === null ||
      sizeBytes === null ||
      contentIv === null ||
      contentTag === null
    ) {
      return { ok: false, reason: 'invalid' };
    }

    return {
      ok: true,
      value: {
        ciphertext,
        mime,
        sizeBytes,
        contentIv,
        contentTag,
        allowedRecipients,
      },
    };
  };
}

/** Structural shape of a `@fastify/multipart` part. Restated here so
 *  the file compiles without depending on the plugin's types. */
interface MultipartPart {
  readonly type: 'file' | 'field';
  readonly fieldname: string;
  readonly file: Readable;
  readonly value: unknown;
}

/** Collect a Readable into a Buffer, returning `null` if the byte
 *  count exceeds `cap`. Streams are drained on overflow so the
 *  underlying TCP connection doesn't stay open. */
async function collectStream(
  stream: Readable,
  cap: number,
): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > cap) {
      // Drain remaining bytes silently so we don't leak the socket.
      // The caller maps the returned `null` to a 413 response.
      stream.resume();
      return null;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

/** Drain a Readable to /dev/null. Used for unknown file parts. */
async function drainStream(stream: Readable): Promise<void> {
  for await (const _chunk of stream as AsyncIterable<unknown>) {
    void _chunk;
  }
}

/** Detect a `@fastify/multipart` "file too large" error. We test by
 *  the documented `code` field rather than instanceof so the route
 *  can compile without importing the plugin's types. */
function isTooLargeError(err: unknown): boolean {
  if (err === null || err === undefined || typeof err !== 'object') {
    return false;
  }
  const e = err as { code?: unknown };
  return (
    typeof e.code === 'string' &&
    (e.code === 'FST_REQ_FILE_TOO_LARGE' ||
      e.code === 'FST_FILES_LIMIT' ||
      e.code === 'FST_REQ_FILE_TOO_LARGE_ERR')
  );
}

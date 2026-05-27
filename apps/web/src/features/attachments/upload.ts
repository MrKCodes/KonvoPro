// apps/web/src/features/attachments/upload.ts
//
// Encrypt + upload flow for an E2EE attachment (task 5.3 — Phase 4).
//
// Realises the design.md §3.3 sequence + Requirements 6.1, 6.4:
//
//   plaintext blob  ── encryptAttachment ──▶  (ciphertext, key, iv, tag)
//                                              │              │  │  │
//                                              │              └──┴──┴── inside
//                                              │                       AttachmentRef
//                                              │                       (E2EE inner
//                                              │                        payload)
//                                              ▼
//                                       POST /attachments
//                                       (multipart, ciphertext +
//                                        mime + sizeBytes +
//                                        contentIv + contentTag +
//                                        allowedRecipients)
//                                              │
//                                              ▼
//                                       { attachmentId, blobKey }
//
// The function signature matches the task brief exactly:
//   `uploadAttachment(file, allowedRecipientIds): Promise<AttachmentRef>`
//
// What this module owns:
//   - Reading the `File` into a `Uint8Array` for the AES-GCM encrypt.
//     We do this in one go because the 25 MiB attachment cap (req
//     6.3) bounds the in-memory footprint. A future streaming
//     variant could chunk this without changing the public surface.
//   - Building the multipart form. The API_Gateway parser
//     (`apps/api/src/routes/attachments.ts` — `multipartUploadParser`)
//     decodes `contentIv` and `contentTag` from base64, so we encode
//     them on the way out. `ciphertext` rides as a binary file part
//     (the only file part the parser keeps); `mime` / `sizeBytes` /
//     `allowedRecipients` are text parts.
//   - Parsing the JSON reply into `AttachmentRef`. The server returns
//     `{ attachmentId, blobKey }` (per `AttachmentCreateResponse`);
//     the AES-GCM key/iv/tag NEVER round-trip through the API so the
//     caller already holds them locally — we splice them into the
//     returned `AttachmentRef` so the same object can be embedded in
//     the E2EE inner payload.
//
// What this module does NOT own:
//   - Wrapping the `AttachmentRef` inside an `InnerType.ATTACHMENT`
//     payload + libsignal envelope. The DM controller / composer
//     does that; this module is plumbing one step below.
//   - Local cache writes. After a successful upload the uploader
//     already has the plaintext bytes in memory; the cache layer
//     (`cache.ts`) is the receiver-side concern. We do, however,
//     accept an optional `localCache` parameter so an integrating
//     component can pre-warm the recipient row without re-decrypting
//     after a local round-trip.
//   - Auth / CSRF mechanics. We accept a pluggable
//     `tokenProvider` + `csrfTokenProvider` so the function can run
//     in tests with a stub fetch and in production wired against
//     the auth store. The `authApi` client used elsewhere is not
//     reused here because its `request` helper enforces JSON
//     content-type, which conflicts with our multipart body.

import {
  encryptAttachment,
  type EncryptedAttachment,
} from '@konvo/crypto';
import type { AttachmentRef } from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Server-error shape thrown by `uploadAttachment` on a non-2xx
 *  response. Mirrors `AuthApiError` in spirit but lives separately
 *  so the attachments feature does not depend on the auth feature. */
export class AttachmentUploadError extends Error {
  readonly kind: 'network' | 'http' | 'oversize';
  readonly status: number | null;

  constructor(
    kind: 'network' | 'http' | 'oversize',
    message: string,
    status: number | null = null,
  ) {
    super(message);
    this.name = 'AttachmentUploadError';
    this.kind = kind;
    this.status = status;
  }
}

export interface UploadAttachmentOptions {
  /** Override the upload URL. Defaults to `/attachments`. */
  readonly endpoint?: string;
  /** Override `fetch`. Defaults to `globalThis.fetch`. */
  readonly fetchImpl?: typeof fetch;
  /** Bearer-token provider. Returning `null` skips the
   *  `Authorization` header — the server returns 401 in that case. */
  readonly tokenProvider?: () => string | null;
  /** Optional CSRF-token provider. The server's CSRF middleware
   *  rejects state-changing requests without a matching cookie/header
   *  pair (see `apps/api/src/services/auth/csrf.ts`); the form
   *  components elsewhere read `document.cookie` and we mirror that
   *  default. */
  readonly csrfTokenProvider?: () => string | null;
}

// ---------------------------------------------------------------------------
// Implementation helpers
// ---------------------------------------------------------------------------

/** Encode a `Uint8Array` as standard base64. Mirrors the helper in
 *  `apps/web/src/features/auth/api.ts` so the JSON-shaped fields and
 *  the multipart-shaped fields use the same encoding. */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

/** Read a `File` into a `Uint8Array`. We rely on `arrayBuffer()`
 *  because `File.bytes()` is still proposal-stage in some browsers.
 *  When `arrayBuffer` is missing (older jsdom builds and some
 *  embedded WebViews), we fall back to the legacy
 *  `FileReader.readAsArrayBuffer` API which jsdom and every browser
 *  ship. */
async function readFileBytes(file: File): Promise<Uint8Array> {
  // Modern path: `Blob.prototype.arrayBuffer` (Fetch spec).
  const maybeArrayBuffer = (file as Blob & { arrayBuffer?: () => Promise<ArrayBuffer> })
    .arrayBuffer;
  if (typeof maybeArrayBuffer === 'function') {
    const buf = await maybeArrayBuffer.call(file);
    return new Uint8Array(buf);
  }
  // Fallback: FileReader. Wrap it in a Promise so the public
  // surface stays async.
  const FileReaderCtor = (globalThis as unknown as {
    FileReader?: typeof FileReader;
  }).FileReader;
  if (FileReaderCtor === undefined) {
    throw new Error(
      'readFileBytes: neither Blob.arrayBuffer nor FileReader is available',
    );
  }
  return new Promise<Uint8Array>((resolve, reject) => {
    const reader = new FileReaderCtor();
    reader.onload = (): void => {
      const r = reader.result;
      if (r instanceof ArrayBuffer) {
        resolve(new Uint8Array(r));
      } else {
        reject(new Error('readFileBytes: FileReader returned non-ArrayBuffer'));
      }
    };
    reader.onerror = (): void => {
      reject(reader.error ?? new Error('readFileBytes: FileReader failed'));
    };
    reader.readAsArrayBuffer(file);
  });
}

/** Default cookie reader used in production. Tests inject a stub
 *  via `csrfTokenProvider`. */
function readCsrfFromCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const header = document.cookie;
  if (header.length === 0) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (k !== 'konvo_csrf') continue;
    const v = part.slice(eq + 1).trim();
    return v.length === 0 ? null : v;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Encrypt a `File` with a fresh AES-GCM 256-bit key + 96-bit IV and
 * upload the ciphertext to `POST /attachments`. Returns an
 * `AttachmentRef` carrying the server-assigned `attachmentId` plus
 * the (key, iv, tag) the recipient needs to decrypt.
 *
 * The returned `AttachmentRef` is *not* the wire envelope — the
 * caller embeds it inside an `InnerType.ATTACHMENT` /
 * `InnerType.VOICE_NOTE` inner payload before encrypting the whole
 * thing through libsignal (req 6.4). The key bytes never leave the
 * client in cleartext.
 *
 * Errors:
 *   - `AttachmentUploadError('oversize', ...)` if the file size
 *     exceeds the 25 MiB cap *before* we even encrypt. AES-GCM tags
 *     add 16 bytes; the ciphertext byte length equals the plaintext
 *     length (GCM is a stream cipher), so the route's 25 MiB cap
 *     applies to the plaintext bytes too.
 *   - `AttachmentUploadError('network', ...)` on fetch failure.
 *   - `AttachmentUploadError('http', ..., status)` on non-2xx. The
 *     server's 413 path translates to `kind: 'oversize'` so callers
 *     get one consistent shape regardless of which side (client
 *     guard or server guard) caught the size violation.
 */
export async function uploadAttachment(
  file: File,
  allowedRecipientIds: readonly string[],
  options: UploadAttachmentOptions = {},
): Promise<AttachmentRef> {
  const fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  const endpoint = options.endpoint ?? '/attachments';

  // Pre-flight size check. The route cap is 25 MiB on the
  // ciphertext, but AES-GCM ciphertext == plaintext length, so we
  // can guard at the input boundary. Catching this before encrypt
  // saves the AES round-trip on a doomed upload.
  const MAX_BYTES = 25 * 1024 * 1024;
  if (file.size > MAX_BYTES) {
    throw new AttachmentUploadError(
      'oversize',
      `attachment exceeds 25 MiB cap (got ${file.size} bytes)`,
    );
  }

  // Encrypt. `encryptAttachment` mints a fresh (key, iv) per call
  // (req 6.1: "AES-GCM 256-bit key and 96-bit IV that are unique per
  // attachment, never reused"), so even concurrent calls cannot
  // collide.
  const plaintext = await readFileBytes(file);
  const enc: EncryptedAttachment = await encryptAttachment(plaintext);

  // Build the multipart form. Field names match the parser in
  // `apps/api/src/routes/attachments.ts` (`multipartUploadParser`).
  // `contentIv`/`contentTag` are base64-encoded text fields per the
  // parser's contract; `ciphertext` is the only file part the
  // parser collects.
  const form = new FormData();
  // Wrap ciphertext bytes as a Blob with octet-stream MIME so the
  // parser sees a `file` part regardless of how `FormData` decides
  // to serialise typed arrays. The filename is irrelevant to the
  // server (it doesn't read multipart filenames) but jsdom's
  // FormData implementation requires one, so we pass a synthetic.
  //
  // We materialise a fresh `ArrayBuffer`-backed copy and feed THAT
  // to `Blob`. TypeScript 5.7 narrowed `BlobPart` to require an
  // `ArrayBuffer`-backed view (not `Uint8Array<ArrayBufferLike>`,
  // and not `ArrayBuffer | SharedArrayBuffer` from `.buffer.slice()`).
  // The fresh copy has a known concrete type and adds the same one
  // copy that `Blob` already performs internally for typed arrays.
  const ciphertextBuffer = new ArrayBuffer(enc.ciphertext.byteLength);
  new Uint8Array(ciphertextBuffer).set(enc.ciphertext);
  const ciphertextBlob = new Blob([ciphertextBuffer], {
    type: 'application/octet-stream',
  });
  form.append('ciphertext', ciphertextBlob, 'ciphertext.bin');
  form.append('mime', file.type.length > 0 ? file.type : 'application/octet-stream');
  form.append('sizeBytes', String(plaintext.length));
  form.append('contentIv', uint8ArrayToBase64(enc.iv));
  form.append('contentTag', uint8ArrayToBase64(enc.tag));
  if (allowedRecipientIds.length > 0) {
    // Server splits on `,` (see `multipartUploadParser`).
    form.append('allowedRecipients', allowedRecipientIds.join(','));
  }

  // Request headers. We do NOT set `Content-Type` — the browser
  // (or jsdom) will set the correct `multipart/form-data` boundary
  // automatically when the body is a `FormData` instance.
  const headers: Record<string, string> = {};
  const token = options.tokenProvider?.() ?? null;
  if (token !== null) {
    headers['authorization'] = `Bearer ${token}`;
  }
  const csrf =
    options.csrfTokenProvider !== undefined
      ? options.csrfTokenProvider()
      : readCsrfFromCookie();
  if (csrf !== null) {
    headers['x-csrf-token'] = csrf;
  }

  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      headers,
      body: form,
      credentials: 'include',
    });
  } catch (err) {
    throw new AttachmentUploadError(
      'network',
      `attachment upload network failure: ${(err as Error).message}`,
    );
  }

  if (response.status === 413) {
    throw new AttachmentUploadError(
      'oversize',
      'server rejected attachment as oversize',
      413,
    );
  }
  if (!response.ok) {
    throw new AttachmentUploadError(
      'http',
      `attachment upload failed with HTTP ${response.status}`,
      response.status,
    );
  }

  const parsed = (await response.json()) as { attachmentId?: unknown };
  if (typeof parsed.attachmentId !== 'string') {
    throw new AttachmentUploadError(
      'http',
      'attachment upload reply missing attachmentId',
      response.status,
    );
  }

  // Splice (key, iv, tag) onto the server-assigned id to produce
  // the wire `AttachmentRef`. The caller embeds this inside an
  // E2EE inner payload before sending; the server NEVER sees these
  // three fields (req 5.3 / 6.1).
  const ref: AttachmentRef = {
    attachmentId: parsed.attachmentId,
    key: enc.key,
    iv: enc.iv,
    tag: enc.tag,
    sizeBytes: plaintext.length,
  };
  return ref;
}

// apps/web/src/features/attachments/download.ts
//
// Recipient-side fetch + decrypt for an E2EE attachment (task 5.3).
//
// Realises Requirements 6.5, 6.9, 6.10:
//
//   AttachmentRef ── GET /attachments/:id ──▶ ciphertext bytes
//                                                       │
//                                                       ▼
//                       decryptAttachment(ciphertext,
//                                          ref.key, ref.iv, ref.tag)
//                                                       │
//                                                       ▼
//                            ok ? plaintext  :  invalid_attachment
//
// Behaviour matrix:
//   - 2xx + AES-GCM tag verifies   → `Uint8Array` plaintext
//   - 2xx + AES-GCM tag fails      → `DecryptError` (req 6.9 — caller
//                                     renders the "attachment couldn't
//                                     be decrypted" placeholder; the
//                                     envelope itself is preserved)
//   - 404                          → `NotFoundError`  (req 6.10 — caller
//                                     renders the "attachment
//                                     unavailable" placeholder; the
//                                     envelope itself is preserved)
//   - 403 / 5xx / network          → thrown `AttachmentDownloadError`
//                                     (the higher-level UI surfaces a
//                                      generic retry path; not the same
//                                      shape as `tag failure` because
//                                      the placeholder rationale
//                                      differs)
//
// Why a typed-result return for tag failure + 404 instead of throws:
//   The task brief calls them out as distinct render outcomes; the
//   caller renders different placeholders for each. Throws would
//   force the renderer to inspect `Error` subclasses, which is
//   strictly less ergonomic than a discriminated union. Other
//   failures (403, 5xx, network) DO throw because they're rare,
//   transient, and don't carry a stable UX placeholder.
//
// The `NotFoundError` and `DecryptError` shapes are deliberately
// declared as plain interfaces (not class instances) so callers can
// pattern-match on `result.kind` without `instanceof` checks across
// module boundaries.

import {
  decryptAttachment,
  type AttachmentDecryptResult,
} from '@konvo/crypto';
import type { AttachmentRef } from '@konvo/protocol';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface NotFoundError {
  readonly kind: 'not_found';
}

export interface DecryptError {
  readonly kind: 'decrypt_failed';
  /** Short diagnostic; never leaks ciphertext / plaintext bytes. */
  readonly details?: string;
}

export type DownloadResult =
  | { readonly kind: 'ok'; readonly plaintext: Uint8Array }
  | NotFoundError
  | DecryptError;

/** Thrown for transient / unexpected errors (403, 5xx, network).
 *  Tag-failure and 404 do not throw — they return a typed result. */
export class AttachmentDownloadError extends Error {
  readonly kind: 'network' | 'http' | 'forbidden';
  readonly status: number | null;

  constructor(
    kind: 'network' | 'http' | 'forbidden',
    message: string,
    status: number | null = null,
  ) {
    super(message);
    this.name = 'AttachmentDownloadError';
    this.kind = kind;
    this.status = status;
  }
}

export interface DownloadAttachmentOptions {
  /** Override the base URL. Defaults to `/attachments`. */
  readonly endpoint?: string;
  readonly fetchImpl?: typeof fetch;
  readonly tokenProvider?: () => string | null;
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Fetch the ciphertext for `ref.attachmentId` and decrypt it with
 * `ref.key`/`ref.iv`/`ref.tag`. Returns a discriminated union per
 * the behaviour matrix above.
 *
 * Note that we always read the response body, even on the failure
 * paths, before deciding what to return. This is intentional:
 * leaving an HTTP body undrained can keep the underlying connection
 * pooled in a "pending" state across browsers + jsdom alike.
 */
export async function downloadAttachment(
  ref: AttachmentRef,
  options: DownloadAttachmentOptions = {},
): Promise<DownloadResult> {
  const fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  const endpoint = options.endpoint ?? '/attachments';
  const url = `${endpoint}/${encodeURIComponent(ref.attachmentId)}`;

  const headers: Record<string, string> = {};
  const token = options.tokenProvider?.() ?? null;
  if (token !== null) {
    headers['authorization'] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers,
      credentials: 'include',
    });
  } catch (err) {
    throw new AttachmentDownloadError(
      'network',
      `attachment download network failure: ${(err as Error).message}`,
    );
  }

  if (response.status === 404) {
    // Drain the body so the connection can be released. The body is
    // a small JSON `{ error: "not_found" }`.
    try {
      await response.text();
    } catch {
      // Ignore; we've already decided the result.
    }
    return { kind: 'not_found' };
  }
  if (response.status === 403) {
    throw new AttachmentDownloadError(
      'forbidden',
      'attachment download forbidden',
      403,
    );
  }
  if (!response.ok) {
    throw new AttachmentDownloadError(
      'http',
      `attachment download failed with HTTP ${response.status}`,
      response.status,
    );
  }

  // Read the ciphertext bytes. The route's `Content-Type` is
  // `application/octet-stream`; `arrayBuffer()` is the standard
  // way to materialise a binary body.
  let ciphertext: Uint8Array;
  try {
    ciphertext = new Uint8Array(await response.arrayBuffer());
  } catch (err) {
    throw new AttachmentDownloadError(
      'network',
      `attachment download body read failure: ${(err as Error).message}`,
    );
  }

  const decrypted: AttachmentDecryptResult = await decryptAttachment(
    ciphertext,
    ref.key,
    ref.iv,
    ref.tag,
  );

  if (decrypted.ok) {
    return { kind: 'ok', plaintext: decrypted.plaintext };
  }
  // AES-GCM authentication failed (req 6.9). The caller renders the
  // "attachment couldn't be decrypted" placeholder; the envelope
  // remains unchanged.
  return {
    kind: 'decrypt_failed',
    ...(decrypted.error.details !== undefined
      ? { details: decrypted.error.details }
      : {}),
  };
}

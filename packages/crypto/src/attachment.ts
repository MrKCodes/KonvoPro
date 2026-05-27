// packages/crypto/src/attachment.ts
//
// Implements task 5.1: Crypto_Module attachment AES-GCM helpers, per
// design.md §8.3 and requirements 5.3, 6.1, 6.9.
//
// What this module owns
// ---------------------
//   - `encryptAttachment(plaintext)`: generates a fresh 32-byte AES-256
//     key and a fresh 12-byte (96-bit) IV per attachment via
//     `crypto.getRandomValues`, runs `crypto.subtle.encrypt` with
//     AES-GCM (128-bit tag), and returns the four-tuple
//     `(ciphertext, key, iv, tag)`. The key bytes never leave this
//     module's caller's control — they go inside an E2EE inner
//     payload (`AttachmentRef` per design.md §6.1) and are never
//     transmitted to the API_Gateway in cleartext (req 5.3 / 6.1).
//
//   - `decryptAttachment(ciphertext, key, iv, tag)`: reassembles the
//     standard WebCrypto AES-GCM input shape (`ciphertext || tag`)
//     and runs `crypto.subtle.decrypt`. On AES-GCM authentication
//     failure (tampered ciphertext, tampered tag, wrong key, wrong
//     IV) this returns the typed failure
//     `{ ok: false, error: { kind: 'invalid_attachment' } }` and
//     emits no plaintext bytes anywhere — req 6.9: "WHEN the AES-GCM
//     authentication tag fails to verify on the recipient side, the
//     Web_Client SHALL render an 'attachment couldn't be decrypted'
//     placeholder and SHALL NOT display any partial bytes".
//
//   - Length validation: per design.md §8.3 the public surface is
//     `(key: 32 bytes, iv: 12 bytes, tag: 16 bytes)`. Any inbound
//     buffer with the wrong length is rejected as
//     `invalid_attachment` *before* we touch WebCrypto, so a caller
//     who passes a malformed buffer can't cause an internal throw or
//     a partial decrypt. The error `details` field carries a short
//     diagnostic string ("invalid key length", etc.) but never any
//     ciphertext or plaintext bytes.
//
// What this module does NOT own
// -----------------------------
//   - The attachment route layer (`apps/api/src/routes/attachments.ts`,
//     task 5.2): bucket plumbing, size cap (25 MiB), authorization,
//     and the 403/404 surface.
//
//   - The web upload/download flow (`apps/web/src/features/attachments`,
//     task 5.3): MinIO upload, the `attachment unavailable` placeholder
//     for HTTP 404, and the ratchet / envelope binding.
//
//   - Voice notes (`task 5.4`): voice notes use this same module for
//     their AES-GCM step, but the recorder, MIME handling, and
//     waveform rendering live in the web app.
//
// Why a separate ciphertext / tag split (vs. WebCrypto's concatenated
// ciphertext || tag)
// -------------------------------------------------------------------
// design.md §8.3 specifies the public type as
//   `{ ciphertext, key, iv, tag }`
// with `tag` exposed as a distinct 16-byte field. This matches the
// `AttachmentRef` wire shape (design.md §6.1) where `iv` and `tag`
// travel inside the E2EE inner payload while `ciphertext` is the blob
// uploaded to MinIO. WebCrypto's AES-GCM operates on a concatenated
// `ciphertext || tag` buffer; we split on the way out of `encrypt`
// and rejoin on the way into `decrypt`, so the public surface
// matches the design while the implementation uses the standard
// WebCrypto idiom.
//
// AES-GCM correctness
// -------------------
// AES-GCM authentication is all-or-nothing: WebCrypto's
// `crypto.subtle.decrypt` buffers the entire plaintext and only
// surfaces it after the tag check passes; on tag mismatch it throws
// `OperationError` and returns no bytes. We catch that throw and
// translate it to `invalid_attachment` without ever touching a
// partial plaintext (req 6.9).
//
// Per-attachment freshness / nonce reuse safety
// ---------------------------------------------
// Each call to `encryptAttachment` generates a fresh 32-byte key and
// a fresh 12-byte IV from `crypto.getRandomValues`. Because the
// (key, iv) pair is unique per attachment, AES-GCM nonce reuse
// across attachments is structurally impossible regardless of how
// many attachments a single sender produces. We do NOT reuse a
// long-lived attachment key under a counter-style IV scheme — every
// attachment carries its own one-shot key.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** AES-256-GCM key length in bytes. */
const KEY_LENGTH = 32;
/** AES-GCM IV length in bytes (96 bits — the GCM standard / NIST SP 800-38D
 *  recommendation, also what WebCrypto expects). */
const IV_LENGTH = 12;
/** AES-GCM authentication tag length in bytes (128 bits — full-strength
 *  GCM tag, matches the `tagLength: 128` parameter we pass to WebCrypto). */
const TAG_LENGTH = 16;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * The four-tuple produced by `encryptAttachment`. Per design.md §8.3:
 *
 *   - `ciphertext`: the AES-GCM ciphertext (sans tag) — uploaded to
 *     MinIO via `POST /attachments`. Server-visible.
 *   - `key`: 32-byte AES-256 key — placed inside the E2EE inner
 *     payload (`AttachmentRef`) and never transmitted to the
 *     API_Gateway in cleartext (req 5.3, 6.1).
 *   - `iv`: 12-byte AES-GCM IV — also inside the inner payload.
 *   - `tag`: 16-byte AES-GCM authentication tag — also inside the
 *     inner payload. Required by `decryptAttachment` to authenticate
 *     the ciphertext.
 *
 * Each field is a defensive copy returned to the caller; mutating
 * any of these buffers does not affect any internal state.
 */
export interface EncryptedAttachment {
  readonly ciphertext: Uint8Array;
  readonly key: Uint8Array; // 32 bytes
  readonly iv: Uint8Array; // 12 bytes
  readonly tag: Uint8Array; // 16 bytes
}

/**
 * Failure shape returned by `decryptAttachment` when AES-GCM
 * authentication fails or any input has the wrong length.
 *
 * The error object never carries plaintext or ciphertext bytes —
 * `details` is a short diagnostic string only. Per req 6.9 the
 * caller must render an "attachment couldn't be decrypted"
 * placeholder and emit no partial bytes; this shape carries no
 * partial bytes by construction.
 */
export interface AttachmentDecryptError {
  readonly ok: false;
  readonly error: {
    readonly kind: 'invalid_attachment';
    readonly details?: string;
  };
}

/**
 * Result of `decryptAttachment`. Either a successful decryption
 * yielding the exact original plaintext bytes, or
 * `AttachmentDecryptError` on tag-verification or input-length
 * failure.
 */
export type AttachmentDecryptResult =
  | { readonly ok: true; readonly plaintext: Uint8Array }
  | AttachmentDecryptError;

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Import a raw 32-byte AES key into a non-extractable WebCrypto
 * CryptoKey for one-shot use. The CryptoKey is discarded after the
 * encrypt / decrypt call returns — the raw bytes are still held by
 * the caller (in the returned `EncryptedAttachment.key`), but the
 * imported handle itself is non-extractable so it can't be exported
 * back out via `crypto.subtle.exportKey`.
 */
async function importAesKey(
  raw: Uint8Array,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toBufferSource(raw),
    { name: 'AES-GCM' },
    /* extractable */ false,
    [usage],
  );
}

/**
 * Coerce a `Uint8Array<ArrayBufferLike>` to a `Uint8Array<ArrayBuffer>`
 * for WebCrypto's `BufferSource` input slot.
 *
 * TypeScript 5.7 tightened `lib.dom.d.ts` so `BufferSource` is now
 * `ArrayBufferView<ArrayBuffer> | ArrayBuffer` (not
 * `ArrayBufferView<ArrayBufferLike>`). At runtime we only ever
 * construct over `ArrayBuffer` (never `SharedArrayBuffer`), so the
 * structural cast is sound — but we still copy when `.buffer` reports
 * `SharedArrayBuffer` to keep the contract honest at runtime.
 */
function toBufferSource(u: Uint8Array): Uint8Array<ArrayBuffer> {
  if (u.buffer instanceof ArrayBuffer) {
    return u as Uint8Array<ArrayBuffer>;
  }
  const copy = new Uint8Array(u.byteLength);
  copy.set(u);
  return copy;
}

/**
 * Build a typed `invalid_attachment` failure. Centralised so every
 * call site uses the same shape; `details` is a short ASCII
 * diagnostic that names the failing precondition without leaking
 * any ciphertext / key / iv / tag bytes.
 */
function invalid(details: string): AttachmentDecryptError {
  return { ok: false, error: { kind: 'invalid_attachment', details } };
}

// ---------------------------------------------------------------------------
// Public surface — encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt an attachment plaintext blob with a freshly generated
 * AES-256-GCM key + 96-bit IV.
 *
 * Per design.md §8.3 / req 6.1 / req 5.3:
 *   - Generates a fresh 32-byte key from `crypto.getRandomValues`.
 *   - Generates a fresh 12-byte IV from `crypto.getRandomValues`.
 *   - The (key, iv) pair is unique per attachment; nonce reuse
 *     across attachments is structurally impossible.
 *   - Returns ciphertext (sans tag), key, iv, and tag as separate
 *     `Uint8Array` fields per the design surface. The caller embeds
 *     `key`, `iv`, and `tag` into the E2EE inner payload; only
 *     `ciphertext` is uploaded to the server.
 *
 * WebCrypto AES-GCM produces `ciphertext || tag` concatenated; we
 * split at the boundary on the way out so the public surface matches
 * the design.
 *
 * Accepts plaintexts of any length, including zero — the GCM
 * construction is well-defined for empty input (the output is just
 * the 16-byte tag with an empty ciphertext). The 25 MiB upload cap
 * is enforced by the route layer (task 5.2), not here, so this
 * primitive is reusable by both attachment uploads and voice notes.
 */
export async function encryptAttachment(
  plaintext: Uint8Array,
): Promise<EncryptedAttachment> {
  const key = new Uint8Array(KEY_LENGTH);
  crypto.getRandomValues(key);
  const iv = new Uint8Array(IV_LENGTH);
  crypto.getRandomValues(iv);

  const cryptoKey = await importAesKey(key, 'encrypt');
  // WebCrypto returns an ArrayBuffer of `ciphertext || tag`. Wrap it
  // as a Uint8Array view so we can `.slice()` cleanly.
  const combined = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: 128 },
      cryptoKey,
      toBufferSource(plaintext),
    ),
  );

  // Split: last 16 bytes are the tag, everything before is the
  // ciphertext body. `.slice()` allocates fresh buffers so the
  // returned fields don't share backing memory with the WebCrypto
  // output.
  const ciphertext = combined.slice(0, combined.length - TAG_LENGTH);
  const tag = combined.slice(combined.length - TAG_LENGTH);

  return { ciphertext, key, iv, tag };
}

// ---------------------------------------------------------------------------
// Public surface — decrypt
// ---------------------------------------------------------------------------

/**
 * Decrypt an attachment ciphertext with the AES-GCM key, IV, and
 * tag from the E2EE inner payload.
 *
 * Behaviour:
 *   - Returns `{ ok: true, plaintext }` on success — the exact
 *     bytes the sender encrypted (req 6.5).
 *   - Returns
 *     `{ ok: false, error: { kind: 'invalid_attachment', details } }`
 *     on AES-GCM authentication failure (tampered ciphertext,
 *     tampered tag, wrong key, wrong IV) — req 6.9. No partial
 *     plaintext is ever produced (WebCrypto AES-GCM is
 *     all-or-nothing).
 *   - Returns the same `invalid_attachment` failure on any
 *     wrong-length input (`key !== 32`, `iv !== 12`, `tag !== 16`)
 *     before invoking WebCrypto, so a malformed buffer cannot
 *     crash the caller or trigger a partial decrypt path.
 *
 * Implementation note: WebCrypto expects `ciphertext || tag`
 * concatenated. We allocate a fresh combined buffer and feed it
 * to `crypto.subtle.decrypt`; the backing inputs (`ciphertext`,
 * `tag`) are not mutated.
 */
export async function decryptAttachment(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
): Promise<AttachmentDecryptResult> {
  if (key.length !== KEY_LENGTH) {
    return invalid('invalid key length');
  }
  if (iv.length !== IV_LENGTH) {
    return invalid('invalid iv length');
  }
  if (tag.length !== TAG_LENGTH) {
    return invalid('invalid tag length');
  }

  // Reassemble `ciphertext || tag` for WebCrypto. Allocate fresh so
  // we don't mutate caller buffers.
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  const cryptoKey = await importAesKey(key, 'decrypt');
  try {
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv), tagLength: 128 },
      cryptoKey,
      toBufferSource(combined),
    );
    // Wrap the ArrayBuffer in a Uint8Array view. WebCrypto only
    // surfaces this on a successful tag check, so there is no
    // partial-bytes path here.
    return { ok: true, plaintext: new Uint8Array(plaintextBuf) };
  } catch {
    // WebCrypto throws `OperationError` on AES-GCM authentication
    // failure (and on any other crypto-layer error). We translate
    // every such failure to `invalid_attachment` so the caller
    // surfaces the "attachment couldn't be decrypted" placeholder
    // (req 6.9). The thrown error object is dropped — never logged
    // or propagated — so no plaintext / ciphertext bytes leak via
    // a stack trace.
    return invalid('aes-gcm authentication failed');
  }
}

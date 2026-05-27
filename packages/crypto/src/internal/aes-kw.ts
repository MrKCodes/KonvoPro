// packages/crypto/src/internal/aes-kw.ts
//
// Shared AES-KW wrap/unwrap helpers used by both `identity.ts` (task 2.7)
// and `prekeys.ts` (task 2.8) so the wrapping algorithm choice and the
// HMAC-import trick live in exactly one place.
//
// Why HMAC as the inner key type:
//   `crypto.subtle.wrapKey('raw', ...)` operates on a `CryptoKey`, not on
//   raw bytes. X25519 / Ed25519 aren't WebCrypto-native algorithms across
//   all target browsers, so we import the 32 random bytes as an HMAC key.
//   HMAC accepts arbitrary byte lengths, which is the standard trick for
//   wrapping opaque secret material under AES-KW. The imported HMAC key is
//   `extractable: true` because `wrapKey` requires the inner key to be
//   extractable in the chosen wrap format — extractability here only
//   matters until the wrap completes and the imported key handle is
//   discarded; the persisted form is the AES-KW ciphertext.
//
// Wire size: AES-KW ciphertext is `inputLength + 8` bytes (RFC 3394), so a
// 32-byte private key wraps to exactly 40 bytes.
//
// The KEK itself is the responsibility of the caller — the identity store
// generates it `extractable: false` with usages `['wrapKey', 'unwrapKey']`
// and persists the (non-extractable) `CryptoKey` in IndexedDB via
// structured cloning.

/**
 * Coerce a `Uint8Array<ArrayBufferLike>` to a `Uint8Array<ArrayBuffer>`
 * for WebCrypto's `BufferSource` input slot. See `attachment.ts` /
 * `ratchet.ts` for the rationale (TypeScript 5.7 narrowed `BufferSource`
 * to require `ArrayBuffer`-backed views).
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
 * Wrap a 32-byte private-key seed under an AES-KW key-encryption-key.
 *
 * The returned `Uint8Array` is RFC 3394 ciphertext: input length + 8.
 *
 * The input bytes are copied before import so that the imported key
 * doesn't share a backing buffer with caller state we're about to zero.
 */
export async function wrapPrivateKeyBytes(
  privateKeyBytes: Uint8Array,
  kek: CryptoKey,
): Promise<Uint8Array> {
  const inner = await crypto.subtle.importKey(
    'raw',
    toBufferSource(privateKeyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    /* extractable */ true,
    ['sign'],
  );
  const wrapped = await crypto.subtle.wrapKey('raw', inner, kek, 'AES-KW');
  return new Uint8Array(wrapped);
}

/**
 * Inverse of `wrapPrivateKeyBytes`: unwrap, then export the inner HMAC
 * key back to raw bytes.
 *
 * The exported `Uint8Array` is intended to be fed directly into a
 * privacy-aware container (e.g. `IdentityPrivateKey`) and the
 * intermediate buffer dropped or zeroed by the caller.
 */
export async function unwrapPrivateKeyBytes(
  wrappedPrivateKey: Uint8Array,
  kek: CryptoKey,
): Promise<Uint8Array> {
  const inner = await crypto.subtle.unwrapKey(
    'raw',
    toBufferSource(wrappedPrivateKey),
    kek,
    'AES-KW',
    { name: 'HMAC', hash: 'SHA-256' },
    /* extractable */ true,
    ['sign'],
  );
  const raw = await crypto.subtle.exportKey('raw', inner);
  return new Uint8Array(raw);
}

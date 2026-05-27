// apps/web/src/features/dm/wire.ts
//
// Wire-format helpers for the DM ciphertext envelope (task 4.7).
//
// The Phase-3 `@konvo/crypto` ratchet exposes
// `encryptToDevice(...)` / `decryptFromDevice(...)` against a
// `(state, ciphertext, header)` triple. The libsignal swap in a
// future task will collapse the header back into an opaque
// `Uint8Array` blob, but at the Phase-3 placeholder the header is
// kept separate to make the trial-decrypt / AAD discipline
// observable in unit tests.
//
// Production wire envelopes carry exactly one byte buffer in
// `CiphertextEnvelope.ciphertext`. To keep the wire shape stable
// across the Phase-3-to-libsignal transition we splice the
// 40-byte serialized header onto the front of the AES-GCM body
// here, and reverse it on the receive side. When libsignal lands
// the encoded envelope is already a single `Uint8Array`; this
// helper becomes a no-op identity pass-through and can be deleted
// without changing any caller's wire format.
//
// Layout (matches `serializeHeader` inside `@konvo/crypto`'s
// `ratchet.ts`):
//   - bytes 0..31:  header.dhPub
//   - bytes 32..35: header.prevChainLength (uint32 big-endian)
//   - bytes 36..39: header.messageNumber   (uint32 big-endian)
//   - bytes 40..:   AES-256-GCM ciphertext || tag
//
// Both sides read this same layout. Tampering anywhere in the 40
// header bytes breaks the AAD that AES-GCM verifies, so a
// header-tamper surfaces as `invalid_message` on the receiver
// just like a body-tamper would.

import type { RatchetMessageHeader } from '@konvo/crypto';

/** Length in bytes of the serialized ratchet header. */
const HEADER_BYTES = 40;
/** X25519 public-key length in bytes. */
const KEY_LENGTH = 32;

/**
 * Splice the serialized header onto the front of the AES-GCM body
 * to produce the single byte buffer that occupies
 * `CiphertextEnvelope.ciphertext`.
 *
 * The returned buffer is owned by the caller — internally we
 * allocate a fresh `Uint8Array` and copy both inputs in, so the
 * caller can safely scrub the source `body` after this returns
 * without affecting the encoded buffer.
 *
 * Throws on a malformed `header.dhPub`. The other two header
 * fields are bounds-checked by `DataView.setUint32`'s implicit
 * `>>> 0` coercion in the same way `serializeHeader` inside
 * `@konvo/crypto` does.
 */
export function encodeWireCiphertext(
  header: RatchetMessageHeader,
  body: Uint8Array,
): Uint8Array {
  if (header.dhPub.length !== KEY_LENGTH) {
    throw new Error(
      `encodeWireCiphertext: header.dhPub must be ${KEY_LENGTH} bytes, got ${header.dhPub.length}`,
    );
  }
  const out = new Uint8Array(HEADER_BYTES + body.length);
  out.set(header.dhPub, 0);
  const view = new DataView(out.buffer, out.byteOffset, HEADER_BYTES);
  view.setUint32(32, header.prevChainLength >>> 0, /* littleEndian */ false);
  view.setUint32(36, header.messageNumber >>> 0, /* littleEndian */ false);
  out.set(body, HEADER_BYTES);
  return out;
}

/**
 * Pull the header off the front of the wire ciphertext buffer
 * and return the (header, body) pair the ratchet's
 * `decryptFromDevice` consumes.
 *
 * The returned `body` is a fresh `Uint8Array` view (allocated as
 * a copy, not a sub-array of the input) so callers can mutate /
 * scrub it without affecting any other consumer of the input.
 *
 * Throws on a frame that's too short to even fit a header. The
 * AES-GCM verify will reject any frame that's been truncated
 * mid-body — the controller surfaces both as `invalid_message`.
 */
export function decodeWireCiphertext(
  bytes: Uint8Array,
): { readonly header: RatchetMessageHeader; readonly body: Uint8Array } {
  if (bytes.length < HEADER_BYTES) {
    throw new Error(
      `decodeWireCiphertext: frame is ${bytes.length} bytes, need at least ${HEADER_BYTES}`,
    );
  }
  const dhPub = bytes.slice(0, 32);
  const view = new DataView(bytes.buffer, bytes.byteOffset, HEADER_BYTES);
  const prevChainLength = view.getUint32(32, /* littleEndian */ false);
  const messageNumber = view.getUint32(36, /* littleEndian */ false);
  const body = bytes.slice(HEADER_BYTES);
  return {
    header: { dhPub, prevChainLength, messageNumber },
    body,
  };
}

/**
 * Inert UI text rendered into a message row's `body` when the
 * inbound envelope's libsignal decrypt returned
 * `invalid_message` (requirement 4.11). Stored as plain UTF-8
 * bytes the same way successful inbound bodies are, so the
 * `ThreadView`'s body decoder does not need a separate code
 * path. The accompanying row state is `'tampered'`, which the
 * `StateTicker` renders with a warning glyph + the matching
 * a11y label.
 */
export const TAMPERED_PLACEHOLDER_TEXT =
  "message couldn't be decrypted (tampered or corrupted)";

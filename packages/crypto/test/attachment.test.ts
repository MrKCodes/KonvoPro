// Tests for task 5.1: Crypto_Module attachment AES-GCM helpers.
//
// These are example-based unit tests covering the producer
// (`attachment.ts`) end-to-end against the platform's WebCrypto
// AES-GCM — no mocks, no fakes. Each test exercises one concrete
// scenario from design.md §8.3 / requirements 5.3, 6.1, 6.9. The
// companion property-based round-trip test (P2) lands in task 5.5.
//
// Coverage matrix vs requirements:
//   - 5.3 / 6.1 (fresh key + IV per attachment, AES-GCM 256, key
//                stays inside E2EE inner payload):
//             → "round-trip preserves bytes (1B / 1KiB / 1MiB)",
//               "fresh key per call", "fresh IV per call",
//               "key length is 32 bytes", "iv length is 12 bytes",
//               "tag length is 16 bytes".
//   - 6.9    (tag failure → invalid_attachment, no partial bytes):
//             → "tampered ciphertext byte → invalid_attachment",
//               "tampered tag bit → invalid_attachment",
//               "wrong key → invalid_attachment",
//               "wrong iv → invalid_attachment".
//   - Defensive validation (length check before WebCrypto):
//             → "wrong-length key/iv/tag → invalid_attachment".

import { describe, expect, it } from 'vitest';

import {
  decryptAttachment,
  encryptAttachment,
} from '../src/attachment.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/** Build a deterministic-looking but non-trivial plaintext of the
 *  requested length. Pattern is `i mod 251` so consecutive bytes
 *  differ across most positions and we'd notice a per-byte off-by-one
 *  in the round-trip. */
function pattern(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = i % 251;
  }
  return out;
}

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

// ---------------------------------------------------------------------------

describe('encryptAttachment + decryptAttachment round-trip (req 5.3 / 6.1)', () => {
  it('preserves a 1-byte plaintext', async () => {
    const plaintext = new Uint8Array([0x42]);
    const enc = await encryptAttachment(plaintext);
    const result = await decryptAttachment(enc.ciphertext, enc.key, enc.iv, enc.tag);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(bytesEqual(result.plaintext, plaintext)).toBe(true);
    }
  });

  it('preserves a 1 KiB plaintext exactly', async () => {
    const plaintext = pattern(1024);
    const enc = await encryptAttachment(plaintext);
    const result = await decryptAttachment(enc.ciphertext, enc.key, enc.iv, enc.tag);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(bytesEqual(result.plaintext, plaintext)).toBe(true);
    }
  });

  it('preserves a 1 MiB plaintext exactly', async () => {
    const plaintext = pattern(1024 * 1024);
    const enc = await encryptAttachment(plaintext);
    const result = await decryptAttachment(enc.ciphertext, enc.key, enc.iv, enc.tag);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(bytesEqual(result.plaintext, plaintext)).toBe(true);
    }
  });

  it('preserves an empty plaintext', async () => {
    // GCM is well-defined for empty input; the route layer enforces
    // size policy. The primitive itself must round-trip empty bytes.
    const plaintext = new Uint8Array(0);
    const enc = await encryptAttachment(plaintext);
    const result = await decryptAttachment(enc.ciphertext, enc.key, enc.iv, enc.tag);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext.length).toBe(0);
    }
  });
});

describe('per-attachment key + IV freshness (req 5.3 / 6.1)', () => {
  it('returns a 32-byte AES key, 12-byte IV, and 16-byte tag', async () => {
    const enc = await encryptAttachment(pattern(64));
    expect(enc.key.length).toBe(32);
    expect(enc.iv.length).toBe(12);
    expect(enc.tag.length).toBe(16);
  });

  it('generates a different key on every call', async () => {
    const a = await encryptAttachment(pattern(32));
    const b = await encryptAttachment(pattern(32));
    expect(bytesEqual(a.key, b.key)).toBe(false);
  });

  it('generates a different IV on every call', async () => {
    const a = await encryptAttachment(pattern(32));
    const b = await encryptAttachment(pattern(32));
    expect(bytesEqual(a.iv, b.iv)).toBe(false);
  });

  it('produces different ciphertexts for the same plaintext across calls (fresh key+IV)', async () => {
    const plaintext = pattern(64);
    const a = await encryptAttachment(plaintext);
    const b = await encryptAttachment(plaintext);
    expect(bytesEqual(a.ciphertext, b.ciphertext)).toBe(false);
  });

  it('ciphertext length equals plaintext length (tag is exposed separately)', async () => {
    // Per design.md §8.3, ciphertext and tag are exposed as separate
    // fields, so ciphertext.length should equal plaintext.length.
    for (const len of [0, 1, 17, 1024, 65537]) {
      const plaintext = pattern(len);
      const enc = await encryptAttachment(plaintext);
      expect(enc.ciphertext.length).toBe(len);
    }
  });
});

describe('tamper rejection (req 6.9)', () => {
  it('flipping one byte of the ciphertext returns invalid_attachment', async () => {
    const plaintext = pattern(256);
    const enc = await encryptAttachment(plaintext);

    const tampered = new Uint8Array(enc.ciphertext);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff;

    const result = await decryptAttachment(tampered, enc.key, enc.iv, enc.tag);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('invalid_attachment');
      // No partial bytes are exposed via the failure shape.
      expect(result).not.toHaveProperty('plaintext');
    }
  });

  it('flipping one bit of the tag returns invalid_attachment', async () => {
    const plaintext = pattern(256);
    const enc = await encryptAttachment(plaintext);

    const tamperedTag = new Uint8Array(enc.tag);
    tamperedTag[0] = (tamperedTag[0]! ^ 0x01) & 0xff;

    const result = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      enc.iv,
      tamperedTag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('invalid_attachment');
    }
  });

  it('wrong key returns invalid_attachment', async () => {
    const plaintext = pattern(256);
    const enc = await encryptAttachment(plaintext);

    const wrongKey = new Uint8Array(32);
    crypto.getRandomValues(wrongKey);

    const result = await decryptAttachment(
      enc.ciphertext,
      wrongKey,
      enc.iv,
      enc.tag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('invalid_attachment');
    }
  });

  it('wrong iv returns invalid_attachment', async () => {
    const plaintext = pattern(256);
    const enc = await encryptAttachment(plaintext);

    const wrongIv = new Uint8Array(12);
    crypto.getRandomValues(wrongIv);

    const result = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      wrongIv,
      enc.tag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('invalid_attachment');
    }
  });

  it('the original (key, iv, tag, ciphertext) still decrypts after a tamper attempt', async () => {
    // Tamper attempts must not corrupt caller buffers — the same
    // tuple should still round-trip after the failed decrypt.
    const plaintext = pattern(256);
    const enc = await encryptAttachment(plaintext);

    const tampered = new Uint8Array(enc.ciphertext);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff;

    const failed = await decryptAttachment(tampered, enc.key, enc.iv, enc.tag);
    expect(failed.ok).toBe(false);

    const recovered = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      enc.iv,
      enc.tag,
    );
    expect(recovered.ok).toBe(true);
    if (recovered.ok) {
      expect(bytesEqual(recovered.plaintext, plaintext)).toBe(true);
    }
  });
});

describe('input length validation (defensive checks before WebCrypto)', () => {
  it('rejects a 31-byte key as invalid_attachment', async () => {
    const enc = await encryptAttachment(pattern(64));
    const result = await decryptAttachment(
      enc.ciphertext,
      new Uint8Array(31),
      enc.iv,
      enc.tag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('invalid_attachment');
  });

  it('rejects a 33-byte key as invalid_attachment', async () => {
    const enc = await encryptAttachment(pattern(64));
    const result = await decryptAttachment(
      enc.ciphertext,
      new Uint8Array(33),
      enc.iv,
      enc.tag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('invalid_attachment');
  });

  it('rejects an 11-byte iv as invalid_attachment', async () => {
    const enc = await encryptAttachment(pattern(64));
    const result = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      new Uint8Array(11),
      enc.tag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('invalid_attachment');
  });

  it('rejects a 13-byte iv as invalid_attachment', async () => {
    const enc = await encryptAttachment(pattern(64));
    const result = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      new Uint8Array(13),
      enc.tag,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('invalid_attachment');
  });

  it('rejects a 15-byte tag as invalid_attachment', async () => {
    const enc = await encryptAttachment(pattern(64));
    const result = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      enc.iv,
      new Uint8Array(15),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('invalid_attachment');
  });

  it('rejects a 17-byte tag as invalid_attachment', async () => {
    const enc = await encryptAttachment(pattern(64));
    const result = await decryptAttachment(
      enc.ciphertext,
      enc.key,
      enc.iv,
      new Uint8Array(17),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe('invalid_attachment');
  });
});

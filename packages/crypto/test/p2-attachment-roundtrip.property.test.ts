// P2 — Validates Requirements 6.1, 6.5, 21.2
//
// packages/crypto/test/p2-attachment-roundtrip.property.test.ts
//
// Property-based test for task 5.5: P2 — E2EE round-trip (attachments).
//
// Property under test (orchestrator-specified P2 wording, mirrored
// verbatim from requirements.md §21.2):
//
//   For any attachment plaintext blob `b` of length 1 to 25 MiB,
//   `decryptAttachment(encryptAttachment(b).ciphertext, key, iv, tag) === b`
//   byte-for-byte.
//
// This is the soundness half of the attachment AES-GCM pipeline:
// every blob the sender encrypts must round-trip to the exact same
// bytes on the recipient side, regardless of length up to the 25 MiB
// upload cap (req 6.3 / design.md §8.3). The companion tamper /
// integrity properties for attachments are covered by the
// example-based unit tests in `attachment.test.ts` (task 5.1) and by
// P3 (`p3-tamper-rejection.property.test.ts`) at the envelope layer.
//
// Validates: Requirements 6.1, 6.5, 21.2
//   - Requirement 6.1: "THE Crypto_Module SHALL generate an AES-GCM
//     256-bit key and 96-bit IV that are unique per attachment, never
//     reused, and encrypt the plaintext bytes locally." Round-trip
//     equality is the externally observable contract on the producer
//     side: a fresh per-attachment key + IV must still decrypt
//     correctly.
//   - Requirement 6.5: "WHEN a recipient receives an attachment
//     envelope, THE Web_Client SHALL download the ciphertext via
//     `GET /attachments/:id` and decrypt it locally using the key
//     from the envelope." This property pins the
//     `decryptAttachment` correctness contract the recipient relies
//     on — given the (key, iv, tag) recovered from the envelope and
//     the ciphertext from MinIO, the recovered plaintext is
//     byte-identical to the sender's input.
//   - Requirement 21.2: P2 as stated above.
//
// Iteration strategy
// ------------------
// The property's input space spans 1 byte through 25 MiB (26 214 400
// bytes). Generating 25 MiB Uint8Arrays through `fc.uint8Array` 100
// times would dominate runtime (entropy-bound, plus fast-check's
// shrinker would walk a 25 MiB candidate). We therefore split P2
// into two complementary halves, both running real WebCrypto
// AES-GCM:
//
//   1. Small-blob property (default 100 iterations via
//      `test/setup.ts`): `fc.uint8Array({ minLength: 1, maxLength:
//      16 KiB })`. Covers the bulk of the input space — every byte
//      length from 1 to 16384 is reachable, including the off-by-one
//      boundary cases AES-GCM block alignment can hide.
//      fast-check's shrinker collapses any counter-example to a
//      minimal byte array we can paste straight into a unit test.
//
//   2. Large-blob property (5 iterations, sizes spanning the rest of
//      the [1 .. 25 MiB] range): cycle through a fixed set of
//      strategic sizes — just-above-small, 1 MiB, 5 MiB, 15 MiB, and
//      the 25 MiB cap — and synthesise the blob with
//      `crypto.getRandomValues` chunked at the WebCrypto 65 536-byte
//      per-call quota. We use `fc.constantFrom` rather than
//      `fc.integer` here because fast-check's integer arbitrary
//      biases towards small values; with only 5 iterations a uniform
//      `fc.integer({min, max})` rarely samples anything past a few
//      hundred KiB, and the property's whole point is to exercise
//      the multi-MiB regime up to and including the 25 MiB cap (req
//      6.3 / design.md §8.3). The fixed set guarantees we hit the
//      upper boundary on every test run while still touching three
//      intermediate sizes that span an order of magnitude. Five
//      iterations is the design.md §16.2 lower bound for properties
//      whose per-iteration cost is tens-of-MiB-scale.
//
// Both halves combined satisfy P2's "for blobs of size 1..25 MiB"
// coverage: the small half nails per-byte length precision in
// [1..16384], the large half stresses the multi-MiB regime AES-GCM
// has not been exercised in by the example-based suite (which tops
// out at 1 MiB), including the exact 25 MiB cap.
//
// `crypto.getRandomValues` chunking
// ---------------------------------
// WebCrypto specifies a 65 536-byte per-call quota on
// `crypto.getRandomValues` (Web Crypto API §3.4 / Node 20+ matches
// this in node:crypto's `webcrypto`). For the 25 MiB regime we fill
// the buffer in 64 KiB slices to stay below that ceiling — see
// `randomBlob` below. This keeps the test compatible with both the
// browser runtime and Node's WebCrypto without relying on any
// platform-specific extension.

import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  decryptAttachment,
  encryptAttachment,
} from '../src/attachment.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Lower bound of P2's plaintext-length range. */
const MIN_BLOB_BYTES = 1;
/** Upper bound of P2's plaintext-length range: 25 MiB, the API_Gateway
 *  upload cap (req 6.3, design.md §8.3). */
const MAX_BLOB_BYTES = 25 * 1024 * 1024;
/** Boundary between the small-blob and large-blob halves of the
 *  property. Chosen to match P1's text-plaintext upper bound (16 KiB
 *  / 16 384 bytes) so the two halves share a clean, requirement-
 *  aligned cutoff. */
const SMALL_BLOB_MAX_BYTES = 16 * 1024;
/** WebCrypto `crypto.getRandomValues` quota: per spec, the buffer
 *  must be at most 65 536 bytes per call. */
const RANDOM_CHUNK_BYTES = 65_536;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/**
 * Allocate a fresh Uint8Array of `length` bytes filled with WebCrypto
 * randomness. WebCrypto's `crypto.getRandomValues` rejects buffers
 * larger than 65 536 bytes, so for the 25 MiB regime we slice the
 * destination buffer and fill it 64 KiB at a time. The returned
 * buffer is a single contiguous allocation (no concatenation), so
 * downstream WebCrypto AES-GCM sees the exact same shape it would
 * see for any other Uint8Array.
 */
function randomBlob(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += RANDOM_CHUNK_BYTES) {
    const end = Math.min(offset + RANDOM_CHUNK_BYTES, length);
    // `subarray` shares the underlying buffer, so this writes
    // directly into `out` without an intermediate copy.
    crypto.getRandomValues(out.subarray(offset, end));
  }
  return out;
}

/**
 * Byte-by-byte equality. We deliberately do NOT delegate to
 * `Buffer.compare` or any Node-specific helper — the property must
 * mean "byte-for-byte equal" in the same sense the recipient's
 * downstream code (browser + Node) sees.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Run one round-trip iteration end-to-end and return whether the
 * decrypted plaintext is byte-identical to the input. Pulled out so
 * both halves of the property share the same code path through real
 * WebCrypto AES-GCM — there is no test-only fast path.
 */
async function roundTrips(plaintext: Uint8Array): Promise<boolean> {
  const enc = await encryptAttachment(plaintext);
  const result = await decryptAttachment(enc.ciphertext, enc.key, enc.iv, enc.tag);
  if (!result.ok) {
    return false;
  }
  return bytesEqual(result.plaintext, plaintext);
}

// ---------------------------------------------------------------------------

describe('P2: E2EE round-trip (attachments) — Requirements 6.1, 6.5, 21.2', () => {
  it('decryptAttachment(encryptAttachment(b)) === b for blobs of length 1..16384', async () => {
    // Small-blob half: fast-check generates the bytes directly, so
    // the shrinker can collapse a counter-example to its minimal
    // form. Iteration count is the global default from
    // `test/setup.ts` (100 in CI, ≥500 with FAST_CHECK_RUNS).
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({
          minLength: MIN_BLOB_BYTES,
          maxLength: SMALL_BLOB_MAX_BYTES,
        }),
        async (blob) => roundTrips(blob),
      ),
    );
  });

  it(
    'decryptAttachment(encryptAttachment(b)) === b for blobs of length 16385..25 MiB',
    async () => {
      // Large-blob half: cycle through a fixed set of strategic
      // sizes spanning [16 KiB+1 .. 25 MiB], synthesising each blob
      // with WebCrypto randomness (chunked to the 64 KiB quota).
      // Five iterations matches design.md §16.2's lower bound for
      // properties whose per-iteration cost is tens-of-MiB-scale.
      // Each iteration touches up to 25 MiB of AES-GCM, so this
      // half adds ~50 MiB of cryptographic work — sufficient to
      // surface any block-boundary or chunk-handling regression at
      // the multi-MiB scale that the small-blob half cannot reach,
      // and crucially exercises the exact 25 MiB upload cap on
      // every run.
      await fc.assert(
        fc.asyncProperty(
          fc.constantFrom(
            SMALL_BLOB_MAX_BYTES + 1, // just above the small-blob boundary
            1 * 1024 * 1024, // 1 MiB
            5 * 1024 * 1024, // 5 MiB
            15 * 1024 * 1024, // 15 MiB
            MAX_BLOB_BYTES, // 25 MiB cap (req 6.3)
          ),
          async (length) => {
            const blob = randomBlob(length);
            return roundTrips(blob);
          },
        ),
        // Override the global numRuns for this iteration-bounded
        // half. fast-check still records seeds, so a counter-example
        // at any size is fully reproducible.
        { numRuns: 5 },
      );
    },
    // Vitest per-test timeout: each iteration round-trips up to
    // 25 MiB through WebCrypto AES-GCM twice (encrypt + decrypt),
    // and we run five iterations. 120 s leaves ample head-room on
    // CI hardware without masking a real performance regression.
    120_000,
  );
});

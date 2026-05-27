// packages/crypto/src/passphrase-kdf.ts
//
// Argon2id passphrase-derived key utility (task 9.5 — the
// `Crypto_Module` half of requirement 15.5).
//
// What this module owns:
//   - a thin wrapper around `@noble/hashes/argon2`'s `argon2idAsync`
//     that takes the production-mandated parameters (`m = 64 MiB,
//     t = 3, p = 4`, RFC 9106 argon2id) and a fresh salt, and
//     returns a 32-byte derived key suitable for AES-256-GCM.
//
// What this module does NOT own:
//   - random salt generation (the caller supplies one — every
//     export should use a fresh 16-byte CSPRNG salt),
//   - encryption itself — the derived key is fed into WebCrypto
//     AES-GCM at the call site.
//
// Why this lives in `@konvo/crypto` rather than `apps/web`
// --------------------------------------------------------
// `@noble/hashes` is already a dependency of `@konvo/crypto` (used
// by `safety-number.ts` and `session.ts`). Re-exporting an
// argon2id-derive helper from this package keeps `apps/web` free
// of a direct `@noble/hashes` dependency and centralises every
// secret-shaping primitive behind a single audit boundary —
// design.md Appendix A's "no libsignal symbols outside
// `@konvo/crypto`" guideline naturally extends to "no raw KDF
// usage outside `@konvo/crypto`".
//
// Test ergonomics
// ---------------
// Production parameters (`m = 65536 KiB = 64 MiB, t = 3, p = 4`)
// take ~500 ms per call on a modern desktop. To keep test suites
// fast, callers can override the parameters via the optional
// fields in `Argon2idParams`. Production code paths must NOT pass
// overrides — they exist solely so unit tests don't pay for a
// 64 MiB working set on every round trip.

import { argon2idAsync } from '@noble/hashes/argon2';

/** Argon2id parameters mandated by requirement 15.5 (and matching
 *  design.md §18.2 for the API's password-hashing parameters). */
export const ARGON2ID_PRODUCTION_PARAMS: Argon2idParams = {
  memoryKib: 65536,
  timeCost: 3,
  parallelism: 4,
};

/** Argon2id parameters. `memoryKib` is `m` in the Argon2 paper
 *  expressed in KiB (1 MiB = 1024 KiB). */
export interface Argon2idParams {
  readonly memoryKib: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

/**
 * Derive a 32-byte key from a passphrase + salt using Argon2id.
 *
 * Inputs:
 *   - `passphrase`: the user-supplied secret. The caller is
 *     responsible for length validation (e.g. requirement 15.7's
 *     8–128 char policy for backups). Encoded as UTF-8 before
 *     mixing into Argon2id.
 *   - `salt`: 16 bytes of CSPRNG output, freshly generated per
 *     export. Salts smaller than 8 bytes are rejected per RFC
 *     9106.
 *   - `params`: defaults to the requirement-mandated production
 *     values. Tests may override to keep the suite fast.
 *
 * Returns 32 bytes of derived key material. The caller owns
 * scrubbing the returned buffer once it has been imported into a
 * WebCrypto key.
 */
export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  params: Argon2idParams = ARGON2ID_PRODUCTION_PARAMS,
): Promise<Uint8Array> {
  if (salt.length < 8) {
    throw new Error(
      `deriveKeyFromPassphrase: salt must be at least 8 bytes, got ${salt.length}`,
    );
  }
  if (!Number.isInteger(params.memoryKib) || params.memoryKib < 1) {
    throw new Error(
      `deriveKeyFromPassphrase: memoryKib must be a positive integer, got ${String(params.memoryKib)}`,
    );
  }
  if (!Number.isInteger(params.timeCost) || params.timeCost < 1) {
    throw new Error(
      `deriveKeyFromPassphrase: timeCost must be a positive integer, got ${String(params.timeCost)}`,
    );
  }
  if (!Number.isInteger(params.parallelism) || params.parallelism < 1) {
    throw new Error(
      `deriveKeyFromPassphrase: parallelism must be a positive integer, got ${String(params.parallelism)}`,
    );
  }

  const passwordBytes = new TextEncoder().encode(passphrase);
  try {
    const derived = await argon2idAsync(passwordBytes, salt, {
      m: params.memoryKib,
      t: params.timeCost,
      p: params.parallelism,
      dkLen: 32,
    });
    // Copy into a fresh buffer so the returned value is owned by
    // us; the input passphrase bytes can then be scrubbed without
    // touching the derived key.
    return new Uint8Array(derived);
  } finally {
    passwordBytes.fill(0);
  }
}

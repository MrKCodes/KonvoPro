// packages/crypto/src/prekeys.ts
//
// Implements task 2.8: Crypto_Module prekey generation, replenishment, and
// rotation, per design.md §8.1 and requirements 3.1, 3.2, 3.3, 3.7.
//
// What this module owns:
//   - generating the initial prekey bundle on first device enrollment
//     (1 signed prekey + 100 one-time prekeys),
//   - replenishing one-time prekeys (OPKs) when fewer than `threshold`
//     unused remain locally,
//   - rotating the signed prekey when its age exceeds 7 days,
//   - signing the signed-prekey public key with the device's identity key
//     so a peer can verify the bundle before X3DH.
//
// What this module does NOT own:
//   - persistence — that lives behind the `PreKeyStore` adapter; the
//     production wiring is `apps/web/src/db/repositories/prekeys.ts`
//     (task 2.9) and tests use `MemoryPreKeyStore` from `../test/`
//   - upload to the API_Gateway — the caller wraps the returned
//     `PreKeyBundleUpload` / `OneTimePreKey[]` into a `POST /devices` or
//     `POST /devices/:id/prekeys` request.
//   - X3DH session establishment — task 4.x.
//
// Phase-1 placeholder: dual-key identity
// --------------------------------------
// design.md §8.1 specifies an Ed25519 signature over the signed-prekey
// public key by the device's identity key. Real libsignal achieves this
// with XEdDSA, which derives an Ed25519 signing key from a Curve25519
// (X25519) keypair on the fly. `@noble/curves` does not expose XEdDSA
// directly, so Phase 1 carries a parallel Ed25519 keypair next to the
// X25519 keypair (see `identity.ts`). When task 4.x wires libsignal in,
// the Ed25519 sub-key disappears and `ed25519.sign` here gets replaced
// with an XEdDSA call against the single identity key. Until then, the
// upload DTOs (`PreKeyBundleUpload`) carry an additional `identityEdPub`
// field so verifiers can run `ed25519.verify(sig, spk.publicKey, …)`.

import { ed25519, x25519 } from '@noble/curves/ed25519';

import {
  type IdentityKeyPair,
  type IdentityPrivateKey,
} from './identity.js';
import {
  unwrapPrivateKeyBytes,
  wrapPrivateKeyBytes,
} from './internal/aes-kw.js';

// ---------------------------------------------------------------------------
// Public-only DTO shapes — what the producer hands back to the caller for
// upload to the API_Gateway.
// ---------------------------------------------------------------------------

/**
 * Public part of a signed prekey, exactly the wire shape from
 * design.md §8.1.
 *
 * `signature` is 64 bytes of Ed25519 over `publicKey` by the device's
 * identity key. The verifier runs
 * `ed25519.verify(signature, publicKey, identityEdPub)` (see Phase-1
 * note in the file header).
 */
export interface SignedPreKey {
  readonly keyId: number;
  readonly publicKey: Uint8Array; // 32 bytes Curve25519 (X25519)
  readonly signature: Uint8Array; // 64 bytes Ed25519
  readonly createdAt: number;
}

/** Public part of a one-time prekey. */
export interface OneTimePreKey {
  readonly keyId: number;
  readonly publicKey: Uint8Array; // 32 bytes Curve25519 (X25519)
}

/**
 * Bundle uploaded to the API_Gateway on device enrollment.
 *
 * Mirrors `crypto.PreKeyBundleUpload` from design.md §8.1, with the
 * Phase-1 `identityEdPub` field appended (see file header). Once
 * libsignal lands the Ed25519 public key is recovered from the X25519
 * identity public key on the fly and `identityEdPub` goes away.
 */
export interface PreKeyBundleUpload {
  readonly identityPub: Uint8Array; // 32 bytes X25519
  readonly identityEdPub: Uint8Array; // 32 bytes Ed25519 (Phase-1 only)
  readonly registrationId: number;
  readonly signedPreKey: SignedPreKey;
  readonly oneTimePreKeys: readonly OneTimePreKey[];
}

// ---------------------------------------------------------------------------
// Persistence-shaped records — what the `PreKeyStore` adapter sees.
// ---------------------------------------------------------------------------

/**
 * Persistence-shaped record for a signed prekey. The wire `SignedPreKey`
 * differs only in that this carries `wrappedPrivateKey` (the AES-KW
 * ciphertext of the X25519 private bytes) for local-only consumption.
 */
export interface SignedPreKeyRecord {
  readonly keyId: number;
  readonly publicKey: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
  readonly signature: Uint8Array; // 64 bytes Ed25519
  readonly createdAt: number;
}

/**
 * Persistence-shaped record for a one-time prekey.
 *
 * `used` is set to `true` exactly once — when the matching X3DH session
 * is established and libsignal consumes the OPK. New rows insert with
 * `used: false`.
 */
export interface OneTimePreKeyRecord {
  readonly keyId: number;
  readonly publicKey: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
  readonly createdAt: number;
  readonly used: boolean;
}

/**
 * Storage adapter the prekey logic delegates to. The Dexie wiring lives
 * in `apps/web/src/db/repositories/prekeys.ts` (task 2.9); tests use a
 * `MemoryPreKeyStore`.
 *
 * Method semantics:
 *   - `listUnusedOneTimePreKeyCount()` — fast count for the
 *     replenishment trigger (requirement 3.3).
 *   - `getNextSignedPreKeyId()` / `getNextOneTimePreKeyId()` —
 *     monotonically-increasing keyId allocator. Two calls in the same
 *     session MUST return strictly increasing values; once persisted,
 *     a keyId is never reused.
 *   - `saveSignedPreKey(...)` — append-only; the most recent signed
 *     prekey is the "current" one.
 *   - `saveOneTimePreKey(...)` — append-only; new OPKs land with
 *     `used: false`.
 *   - `getCurrentSignedPreKey()` — newest signed prekey by `keyId`, or
 *     `null` on first run.
 */
export interface PreKeyStore {
  listUnusedOneTimePreKeyCount(): Promise<number>;
  getNextSignedPreKeyId(): Promise<number>;
  getNextOneTimePreKeyId(): Promise<number>;
  saveSignedPreKey(record: SignedPreKeyRecord): Promise<void>;
  saveOneTimePreKey(record: OneTimePreKeyRecord): Promise<void>;
  getCurrentSignedPreKey(): Promise<SignedPreKeyRecord | null>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Local target for unused OPKs: the producer keeps this many on hand. */
export const ONE_TIME_PREKEY_TARGET = 100 as const;

/** Replenishment trigger threshold (requirement 3.3). */
export const ONE_TIME_PREKEY_THRESHOLD = 20 as const;

/** Signed-prekey rotation age (requirement 3.7). */
export const SIGNED_PREKEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// X25519 / Ed25519 private-key seed length. Both formats use 32 bytes.
const PRIVATE_KEY_LENGTH = 32;

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/**
 * Generate a fresh X25519 keypair using `crypto.getRandomValues` for
 * entropy and `@noble/curves`' X25519 derivation for the public point.
 *
 * The caller owns the returned `privateKey` buffer and is responsible
 * for either persisting (after wrapping) or scrubbing it. The buffer is
 * returned, not held internally, so the caller can `.fill(0)` after the
 * defensive copy made by `wrapPrivateKeyBytes`.
 */
function generateX25519KeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const privateKey = new Uint8Array(PRIVATE_KEY_LENGTH);
  crypto.getRandomValues(privateKey);
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Sign the X25519 public bytes of a prekey with the device's Ed25519
 * identity sub-key (Phase-1 placeholder; see file header).
 *
 * Returns 64 bytes per RFC 8032.
 */
function signSignedPreKey(
  publicKey: Uint8Array,
  identityEdPrivate: IdentityPrivateKey,
): Uint8Array {
  const sk = identityEdPrivate.bytes();
  try {
    return ed25519.sign(publicKey, sk);
  } finally {
    // Best-effort scrub of the transient seed copy. The
    // `IdentityPrivateKey` always returns a fresh copy so this only
    // zeros our local view, not the cached private state.
    sk.fill(0);
  }
}

/**
 * Build a `SignedPreKeyRecord` for persistence and a `SignedPreKey` DTO
 * for upload from a single X25519 keypair + identity Ed25519 signing
 * key. The keyId is supplied by the caller (allocated from the store).
 *
 * The function wraps the private bytes under the supplied KEK before
 * returning; the raw bytes are scrubbed before this function returns so
 * they live in JS memory only for the duration of the wrap.
 */
async function buildSignedPreKey(
  identity: IdentityKeyPair,
  store: PreKeyStore,
  kek: CryptoKey,
): Promise<{ record: SignedPreKeyRecord; dto: SignedPreKey }> {
  const keyId = await store.getNextSignedPreKeyId();
  const { publicKey, privateKey } = generateX25519KeyPair();
  try {
    const wrappedPrivateKey = await wrapPrivateKeyBytes(privateKey, kek);
    const signature = signSignedPreKey(publicKey, identity.ed25519PrivateKey);
    const createdAt = Date.now();
    const record: SignedPreKeyRecord = {
      keyId,
      publicKey,
      wrappedPrivateKey,
      signature,
      createdAt,
    };
    const dto: SignedPreKey = {
      keyId,
      publicKey: new Uint8Array(publicKey),
      signature: new Uint8Array(signature),
      createdAt,
    };
    return { record, dto };
  } finally {
    // wrapPrivateKeyBytes already made a defensive copy on import.
    privateKey.fill(0);
  }
}

/**
 * Build a single `OneTimePreKeyRecord` (for persistence) and matching
 * `OneTimePreKey` DTO. Same scrubbing discipline as
 * `buildSignedPreKey`.
 */
async function buildOneTimePreKey(
  store: PreKeyStore,
  kek: CryptoKey,
): Promise<{ record: OneTimePreKeyRecord; dto: OneTimePreKey }> {
  const keyId = await store.getNextOneTimePreKeyId();
  const { publicKey, privateKey } = generateX25519KeyPair();
  try {
    const wrappedPrivateKey = await wrapPrivateKeyBytes(privateKey, kek);
    const createdAt = Date.now();
    const record: OneTimePreKeyRecord = {
      keyId,
      publicKey,
      wrappedPrivateKey,
      createdAt,
      used: false,
    };
    const dto: OneTimePreKey = {
      keyId,
      publicKey: new Uint8Array(publicKey),
    };
    return { record, dto };
  } finally {
    privateKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Generate the device's initial prekey bundle: 1 signed prekey + 100
 * one-time prekeys (requirement 3.1).
 *
 * Preconditions:
 *   - The store MUST be empty for this device (no signed prekey, zero
 *     unused OPKs). Calling on a populated store is a programming error
 *     — the device has already enrolled — and throws so a re-run after
 *     a partial-success enrollment doesn't silently double-mint keys.
 *
 * Postconditions:
 *   - Exactly 1 signed prekey row and 100 unused OPK rows persisted.
 *   - The returned `PreKeyBundleUpload` is suitable for `POST /devices`.
 *   - Private bytes never appear in the return value or in any error
 *     thrown.
 */
export async function generateInitialBundle(
  identity: IdentityKeyPair,
  store: PreKeyStore,
  kek: CryptoKey,
): Promise<PreKeyBundleUpload> {
  // Guard: refuse to operate on a non-empty store so partial-success
  // recovery paths (server NACK after the client has persisted) don't
  // silently double-mint.
  const existingSigned = await store.getCurrentSignedPreKey();
  const existingOpkCount = await store.listUnusedOneTimePreKeyCount();
  if (existingSigned !== null || existingOpkCount > 0) {
    throw new Error(
      'generateInitialBundle: store is not empty (signed prekey or OPKs already present)',
    );
  }

  const { record: signedRecord, dto: signedDto } = await buildSignedPreKey(
    identity,
    store,
    kek,
  );
  await store.saveSignedPreKey(signedRecord);

  const opkDtos: OneTimePreKey[] = [];
  for (let i = 0; i < ONE_TIME_PREKEY_TARGET; i++) {
    const { record, dto } = await buildOneTimePreKey(store, kek);
    await store.saveOneTimePreKey(record);
    opkDtos.push(dto);
  }

  return {
    identityPub: new Uint8Array(identity.publicKey),
    identityEdPub: new Uint8Array(identity.ed25519PublicKey),
    registrationId: identity.registrationId,
    signedPreKey: signedDto,
    oneTimePreKeys: opkDtos,
  };
}

/**
 * Replenish one-time prekeys when fewer than `threshold` unused remain
 * locally (requirement 3.3).
 *
 * No-op (returns `[]`) when current unused count is already at or above
 * `threshold`. Otherwise generates `target - currentCount` fresh OPKs,
 * persists them, and returns the public DTOs for upload via
 * `POST /devices/:id/prekeys`.
 *
 * @param threshold trigger threshold; default 20 per requirement 3.3
 * @param target    desired post-replenishment unused count; default 100
 *                  per requirement 3.3
 */
export async function replenishOneTimePreKeys(
  _identity: IdentityKeyPair,
  store: PreKeyStore,
  kek: CryptoKey,
  threshold: number = ONE_TIME_PREKEY_THRESHOLD,
  target: number = ONE_TIME_PREKEY_TARGET,
): Promise<OneTimePreKey[]> {
  if (!Number.isInteger(threshold) || threshold < 0) {
    throw new Error(
      `replenishOneTimePreKeys: threshold must be a non-negative integer, got ${threshold}`,
    );
  }
  if (!Number.isInteger(target) || target < threshold) {
    throw new Error(
      `replenishOneTimePreKeys: target must be an integer >= threshold (${threshold}), got ${target}`,
    );
  }

  const currentCount = await store.listUnusedOneTimePreKeyCount();
  if (currentCount >= threshold) {
    return [];
  }

  const needed = target - currentCount;
  const minted: OneTimePreKey[] = [];
  for (let i = 0; i < needed; i++) {
    const { record, dto } = await buildOneTimePreKey(store, kek);
    await store.saveOneTimePreKey(record);
    minted.push(dto);
  }
  return minted;
}

/**
 * Rotate the signed prekey: generate a fresh X25519 keypair, sign its
 * public key with the identity Ed25519 sub-key, persist as a new signed
 * prekey row (with a strictly larger keyId than the current one), and
 * return the public DTO for upload (requirement 3.7).
 *
 * The caller is responsible for:
 *   - deciding whether to rotate (use `shouldRotateSignedPreKey` against
 *     the current record's `createdAt`),
 *   - uploading the result via `POST /devices/:id/signed-prekey` (or the
 *     equivalent route surfaced by the API_Gateway in task 2.6).
 */
export async function rotateSignedPreKey(
  identity: IdentityKeyPair,
  store: PreKeyStore,
  kek: CryptoKey,
): Promise<SignedPreKey> {
  const { record, dto } = await buildSignedPreKey(identity, store, kek);
  await store.saveSignedPreKey(record);
  return dto;
}

/**
 * Returns `true` when the signed prekey is at least
 * `SIGNED_PREKEY_MAX_AGE_MS` (7 days) old per requirement 3.7.
 *
 * Pure function — does not consult the store or the clock beyond the
 * supplied `now`. Callers can plumb a deterministic clock for tests.
 */
export function shouldRotateSignedPreKey(
  spk: { readonly createdAt: number },
  now: number = Date.now(),
): boolean {
  return now - spk.createdAt >= SIGNED_PREKEY_MAX_AGE_MS;
}

// ---------------------------------------------------------------------------
// Verification helper — exposed so tests and downstream verifiers
// (including the API_Gateway integration test harness) share one
// implementation.
// ---------------------------------------------------------------------------

/**
 * Verify a signed-prekey signature against the device's Ed25519 identity
 * public key. Returns `true` iff the signature is well-formed and valid.
 *
 * Phase-1 only — once libsignal lands the verifier reconstructs the
 * Ed25519 key from the X25519 identity key on the fly via XEdDSA, and
 * this helper is removed.
 */
export function verifySignedPreKeySignature(
  spk: SignedPreKey,
  identityEdPub: Uint8Array,
): boolean {
  return ed25519.verify(spk.signature, spk.publicKey, identityEdPub);
}

// ---------------------------------------------------------------------------
// Local helpers — used to materialize the unwrapped private bytes of a
// stored prekey. Kept near the producer so the wrap discipline stays in
// one file. Consumers (X3DH session establishment, task 4.x) call this
// to retrieve the ephemeral X25519 private bytes for a stored OPK or
// signed prekey.
// ---------------------------------------------------------------------------

/**
 * Unwrap a stored prekey's private bytes. The caller MUST scrub the
 * returned buffer when done.
 */
export async function unwrapStoredPrekeyPrivate(
  wrappedPrivateKey: Uint8Array,
  kek: CryptoKey,
): Promise<Uint8Array> {
  return unwrapPrivateKeyBytes(wrappedPrivateKey, kek);
}

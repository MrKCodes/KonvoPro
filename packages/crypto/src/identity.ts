// packages/crypto/src/identity.ts
//
// Implements task 2.7: Crypto_Module identity primitives.
//
// Per design.md §8.1 this module owns the device's long-term identity keypair
// and the registration ID. The private key material is the most sensitive
// secret in the system; it never leaves this module in an extractable form,
// is wrapped at rest, and is branded so accidental `JSON.stringify` (or
// `console.log`) cannot serialize it.
//
// References:
//   - requirements.md §2.1: generate fresh Curve25519 identity keypair and
//     a registrationId in [1, 16383] on first run for a device.
//   - requirements.md §2.2: wrap the identity private key with AES-KW under
//     a non-extractable WebCrypto key and persist only the wrapped bytes.
//   - requirements.md §2.3: only the public key, registrationId, and prekey
//     bundle ever leave the device — that's enforced by callers, but this
//     module hands the public key out as a raw Uint8Array and the private
//     key wrapped in an opaque `IdentityPrivateKey` instance.
//   - requirements.md §2.11: the identity private key MUST NOT be
//     serializable through `JSON.stringify` and MUST NOT be loggable.
//
// Phase-1 placeholder: dual-key identity
// --------------------------------------
// design.md §8.1 specifies a single 32-byte identity keypair, and §13.1 then
// invokes `ed25519.verify(sig, publicKey, identityPub)` against that key.
// Real libsignal achieves this with XEdDSA, which derives an Ed25519 signing
// key from a Curve25519 (X25519) keypair on the fly. `@noble/curves` does
// not expose XEdDSA directly, and libsignal isn't on disk yet (it lands in
// task 4.x). So Phase 1 carries a parallel Ed25519 keypair next to the
// X25519 keypair: same identity record, two wrapped private keys, two
// public keys. The wire-level shape (`PreKeyBundleUpload.identityPub`) still
// carries 32 bytes — but for *signature verification* the verifier needs
// the Ed25519 public key. Task 4.x will collapse this back to a single
// libsignal-managed key.
//
// libsignal note:
//   We use `@noble/curves` (audited, dependency-free) for X25519 derivation
//   and Ed25519 signing. When libsignal is wired in, the persistence shape
//   stays the same so the migration is purely a producer swap.
//
// AES-KW wrap rationale:
//   The wrap/unwrap helpers live in `./internal/aes-kw.ts` so both this
//   module and `prekeys.ts` (task 2.8) wrap private-key material the same
//   way. The wrapping key (the AES-KW KEK) itself is generated as
//   `extractable: false` and stored as an IndexedDB CryptoKey via the
//   IdentityStore so non-extractability is preserved across reloads.

import { ed25519, x25519 } from '@noble/curves/ed25519';

import {
  unwrapPrivateKeyBytes,
  wrapPrivateKeyBytes,
} from './internal/aes-kw.js';

// ---------------------------------------------------------------------------
// Branding: prevent accidental JSON.stringify / logger inclusion.
// ---------------------------------------------------------------------------

/**
 * Opaque wrapper around 32 raw bytes of private-key material (X25519 or
 * Ed25519 seed; both are 32 bytes in the formats we use).
 *
 * Why a class (not just `Uint8Array & { brand }`):
 *   - `JSON.stringify` walks plain objects and arrays. A `Uint8Array` brand
 *     is only a TypeScript fiction; at runtime it's still a typed array and
 *     `JSON.stringify` happily emits `{"0": 17, "1": 42, ...}`.
 *   - This class hides the bytes behind a `#bytes` private field that
 *     `JSON.stringify` cannot reach, and overrides `toJSON` to throw,
 *     `toString` and `Symbol.for('nodejs.util.inspect.custom')` to redact.
 *
 * Per requirements.md §2.11 the Crypto_Module SHALL NOT serialize the
 * identity private key through `JSON.stringify` or write it to any logger.
 */
export class IdentityPrivateKey {
  static readonly LENGTH = 32;

  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    if (bytes.length !== IdentityPrivateKey.LENGTH) {
      throw new Error(
        `identity private key must be exactly ${IdentityPrivateKey.LENGTH} bytes, got ${bytes.length}`,
      );
    }
    // Defensive copy so the caller can't zero/mutate the underlying buffer.
    this.#bytes = new Uint8Array(bytes);
  }

  /**
   * Expose the raw bytes. Callers MUST treat the returned view as read-only;
   * mutating it corrupts the in-memory key. We return a fresh copy so
   * accidental mutations don't propagate.
   */
  bytes(): Uint8Array {
    return new Uint8Array(this.#bytes);
  }

  /**
   * Defeats `JSON.stringify(privateKey)` and `JSON.stringify({ privateKey })`.
   * `JSON.stringify` invokes `toJSON` if present, so this throws on any
   * structured-clone-style serialization attempt.
   */
  toJSON(): never {
    throw new Error('IdentityPrivateKey is not serializable');
  }

  toString(): string {
    return '[IdentityPrivateKey REDACTED]';
  }

  // Node's `util.inspect` and pino both consult this symbol for custom
  // representations. Returning a redaction string keeps the bytes out of
  // logs / REPL output.
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return '[IdentityPrivateKey REDACTED]';
  }
}

// ---------------------------------------------------------------------------
// Public surface — extends design.md §8.1 IdentityKeyPair shape with the
// Phase-1 Ed25519 sub-key; see header comment for rationale.
// ---------------------------------------------------------------------------

/**
 * Per design.md §8.1, with the Phase-1 Ed25519 placeholder fields.
 *
 * `publicKey` is the 32-byte X25519 (Curve25519) public key — the value
 * uploaded as `identityPub` in the prekey bundle and used for X3DH.
 * `privateKey` is the opaque, non-stringifiable wrapper around the
 * corresponding 32-byte X25519 private key.
 * `ed25519PublicKey` is the 32-byte Ed25519 public key used by recipients
 * to verify signatures (e.g. on signed prekeys). Phase 1 only — see header.
 * `ed25519PrivateKey` is the opaque wrapper around the Ed25519 32-byte
 * seed used by `prekeys.ts` to sign signed-prekey public keys. Phase 1 only.
 * `registrationId` is a 14-bit integer in [1, 16383] used as the libsignal
 * registration ID for this device.
 */
export interface IdentityKeyPair {
  readonly publicKey: Uint8Array;
  readonly privateKey: IdentityPrivateKey;
  readonly ed25519PublicKey: Uint8Array;
  readonly ed25519PrivateKey: IdentityPrivateKey;
  readonly registrationId: number;
}

/**
 * Persistence-shaped record of an identity. Only this shape — never the raw
 * private-key bytes — should ever cross a storage boundary.
 *
 * Mirrors `IdentityRow` from design.md §11 (with `id: 'me'` implied), with
 * the Phase-1 Ed25519 fields appended.
 */
export interface WrappedIdentityRecord {
  readonly publicKey: Uint8Array;
  readonly wrappedPrivateKey: Uint8Array;
  readonly ed25519PublicKey: Uint8Array;
  readonly wrappedEd25519PrivateKey: Uint8Array;
  readonly registrationId: number;
}

/**
 * Storage adapter abstraction. The real wiring lives in the Dexie
 * repository (task 2.9); this module accepts any conforming store so it
 * can be unit-tested with `MemoryIdentityStore` below.
 */
export interface IdentityStore {
  /**
   * Returns the persisted identity record, or `null` if this is the first
   * run for this Web_Client.
   */
  loadWrappedIdentity(): Promise<WrappedIdentityRecord | null>;

  /**
   * Persists a freshly generated identity. MUST be atomic with respect to
   * concurrent calls within the same browser tab; the Dexie implementation
   * uses an `&id` primary key on a single-row table to enforce this.
   */
  saveWrappedIdentity(record: WrappedIdentityRecord): Promise<void>;

  /**
   * Returns the AES-KW key-encryption-key (KEK) used to wrap the identity
   * private key. The KEK MUST be generated `extractable: false` and stored
   * as an IndexedDB CryptoKey so the key bytes never enter JS memory.
   *
   * The implementation is responsible for either creating the KEK on first
   * call and persisting the (non-extractable) CryptoKey, or returning the
   * already-persisted CryptoKey on subsequent calls. The CryptoKey returned
   * MUST have `usages: ['wrapKey', 'unwrapKey']`.
   */
  getOrCreateAesKwKey(): Promise<CryptoKey>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const REGISTRATION_ID_MIN = 1;
const REGISTRATION_ID_MAX = 16383; // 2^14 − 1, per requirements.md §2.1.

/**
 * Generates a uniformly-distributed integer in [1, 16383] using rejection
 * sampling. We sample a 16-bit value, mask to 14 bits, and reject 0 (so the
 * range is [1, 16383] without any modulo bias).
 */
function generateRegistrationId(): number {
  const buf = new Uint16Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    const candidate = buf[0]! & 0x3fff; // 14 bits → [0, 16383]
    if (candidate >= REGISTRATION_ID_MIN && candidate <= REGISTRATION_ID_MAX) {
      return candidate;
    }
  }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Per design.md §8.1: idempotent. Returns the existing identity if one is
 * already persisted; otherwise generates fresh keypairs (one X25519, one
 * Ed25519) and a registration ID, wraps each private key under the same
 * AES-KW KEK, and persists everything via the supplied `IdentityStore`.
 *
 * Validates:
 *   - requirements.md §2.1 (fresh keypair + registration ID on first run)
 *   - requirements.md §2.2 (private keys wrapped with AES-KW under a
 *     non-extractable WebCrypto key, only wrapped bytes persisted)
 *   - requirements.md §2.3 (only public keys + registration ID leave the
 *     device — caller's responsibility, but this function never returns
 *     anything else)
 *   - requirements.md §2.11 (private keys cannot be JSON.stringify'd —
 *     see `IdentityPrivateKey` above)
 */
export async function getOrCreateIdentity(
  store: IdentityStore,
): Promise<IdentityKeyPair> {
  const existing = await store.loadWrappedIdentity();
  if (existing !== null) {
    const kek = await store.getOrCreateAesKwKey();
    const rawX25519Priv = await unwrapPrivateKeyBytes(
      existing.wrappedPrivateKey,
      kek,
    );
    const rawEd25519Priv = await unwrapPrivateKeyBytes(
      existing.wrappedEd25519PrivateKey,
      kek,
    );
    try {
      return Object.freeze({
        publicKey: new Uint8Array(existing.publicKey),
        privateKey: new IdentityPrivateKey(rawX25519Priv),
        ed25519PublicKey: new Uint8Array(existing.ed25519PublicKey),
        ed25519PrivateKey: new IdentityPrivateKey(rawEd25519Priv),
        registrationId: existing.registrationId,
      });
    } finally {
      // Best-effort scrub of the transient raw-bytes buffers. The
      // IdentityPrivateKey constructor already made defensive copies.
      rawX25519Priv.fill(0);
      rawEd25519Priv.fill(0);
    }
  }

  // First run: generate fresh material for both keypairs.
  const x25519PrivBytes = new Uint8Array(IdentityPrivateKey.LENGTH);
  crypto.getRandomValues(x25519PrivBytes);
  const x25519PubBytes = x25519.getPublicKey(x25519PrivBytes);

  const ed25519PrivBytes = new Uint8Array(IdentityPrivateKey.LENGTH);
  crypto.getRandomValues(ed25519PrivBytes);
  const ed25519PubBytes = ed25519.getPublicKey(ed25519PrivBytes);

  const registrationId = generateRegistrationId();

  const kek = await store.getOrCreateAesKwKey();
  const wrappedX25519Priv = await wrapPrivateKeyBytes(x25519PrivBytes, kek);
  const wrappedEd25519Priv = await wrapPrivateKeyBytes(ed25519PrivBytes, kek);

  await store.saveWrappedIdentity({
    publicKey: x25519PubBytes,
    wrappedPrivateKey: wrappedX25519Priv,
    ed25519PublicKey: ed25519PubBytes,
    wrappedEd25519PrivateKey: wrappedEd25519Priv,
    registrationId,
  });

  const identity: IdentityKeyPair = Object.freeze({
    publicKey: new Uint8Array(x25519PubBytes),
    privateKey: new IdentityPrivateKey(x25519PrivBytes),
    ed25519PublicKey: new Uint8Array(ed25519PubBytes),
    ed25519PrivateKey: new IdentityPrivateKey(ed25519PrivBytes),
    registrationId,
  });

  // Scrub the transient raw-bytes buffers; IdentityPrivateKey copied them.
  x25519PrivBytes.fill(0);
  ed25519PrivBytes.fill(0);

  return identity;
}

// ---------------------------------------------------------------------------
// In-memory store — for tests and for the API package's typecheck. The real
// Dexie-backed store ships in task 2.9.
// ---------------------------------------------------------------------------

/**
 * Test-only IdentityStore that holds the wrapped record and KEK in memory.
 * The KEK is still generated `extractable: false`, so even in tests the
 * private-key bytes are only ever observable via the public `wrapKey` /
 * `unwrapKey` path.
 */
export class MemoryIdentityStore implements IdentityStore {
  #record: WrappedIdentityRecord | null = null;
  #kek: CryptoKey | null = null;

  async loadWrappedIdentity(): Promise<WrappedIdentityRecord | null> {
    return this.#record;
  }

  async saveWrappedIdentity(record: WrappedIdentityRecord): Promise<void> {
    // Defensive copy so callers can mutate their buffers without affecting
    // persisted state.
    this.#record = {
      publicKey: new Uint8Array(record.publicKey),
      wrappedPrivateKey: new Uint8Array(record.wrappedPrivateKey),
      ed25519PublicKey: new Uint8Array(record.ed25519PublicKey),
      wrappedEd25519PrivateKey: new Uint8Array(record.wrappedEd25519PrivateKey),
      registrationId: record.registrationId,
    };
  }

  async getOrCreateAesKwKey(): Promise<CryptoKey> {
    if (this.#kek === null) {
      this.#kek = await crypto.subtle.generateKey(
        { name: 'AES-KW', length: 256 },
        /* extractable */ false,
        ['wrapKey', 'unwrapKey'],
      );
    }
    return this.#kek;
  }
}

// packages/crypto/src/session.ts
//
// Implements task 4.2: Crypto_Module session establishment via X3DH, per
// design.md §8.2 and §13.1, requirements 4.1–4.3.
//
// What this module owns:
//   - the `RemotePreKeyBundle` shape (the wire form of a peer's prekey
//     bundle as returned by `GET /users/:handle/prekey-bundle`),
//   - the X3DH agreement that derives a 32-byte root key (`SK`) shared
//     between Alice (initiator, `establishSession`) and Bob (responder,
//     `acceptSession`),
//   - hard refusal — with no side effects — when the signed-prekey
//     signature does not verify.
//
// What this module does NOT own:
//   - fetching the bundle (the caller, `apps/web`, calls
//     `GET /users/:handle/prekey-bundle?deviceId=...` and feeds the
//     response in here; on network/HTTP failure the caller surfaces the
//     error and never invokes `establishSession`, so no local state
//     advances — requirement 4.3),
//   - persisting ratchet state in Dexie (Phase-3 follow-up; tasks 4.3 /
//     4.4 add libsignal sessions on top of the SK derived here),
//   - identity TOFU bookkeeping (`remoteIdentities` upsert + safety-
//     number checks live in task 4.7),
//   - actual encryption — that's the Double Ratchet, task 4.3.
//
// Phase-3 placeholder: X3DH-shaped, not real libsignal
// ----------------------------------------------------
// design.md §13.1 hands the bundle off to libsignal's `SessionBuilder`
// which performs X3DH and seeds the Double Ratchet. libsignal isn't
// wired in yet (task 4.x). For Phase 3 we build the X3DH agreement
// ourselves on top of `@noble/curves`' X25519 ECDH and `@noble/hashes`'
// HKDF-SHA256, mirroring the four-DH X3DH flow exactly. The output is a
// 32-byte root key both sides agree on. When libsignal lands, this
// module's public surface stays the same (`establishSession` /
// `acceptSession` returning a 32-byte root key) but the body becomes a
// thin wrapper around libsignal's `SessionBuilder` /
// `processPreKeyBundle`. The wire shape (`RemotePreKeyBundle`,
// `SessionInit`) is already aligned with what libsignal needs.
//
// Phase-1 placeholder: dual-key identity
// --------------------------------------
// design.md §8.1 specifies a single 32-byte identity keypair, and §13.1
// invokes `ed25519.verify(sig, publicKey, identityPub)` against that
// key. Real libsignal achieves this with XEdDSA. Until libsignal lands,
// `IdentityKeyPair` carries both an X25519 keypair (for ECDH /
// `identityPub`) and an Ed25519 keypair (for signature verify). The
// recipient's `RemotePreKeyBundle` therefore includes a separate
// `identityEdPub` field — see `packages/crypto/src/prekeys.ts`. Task
// 4.x removes the parallel Ed25519 sub-key in favor of XEdDSA.
//
// Refusal semantics (requirement 4.2)
// -----------------------------------
// `establishSession` performs the signed-prekey verify FIRST, before
// generating the ephemeral keypair, before computing any DH share, and
// before deriving anything. On verify failure it throws
// `InvalidSignedPreKeyError` and returns no value, no ciphertext, and
// has not touched any local state — there is no local state to touch
// (the module is purely functional; persistence is the caller's job).
// requirement 4.3 is enforced upstream by the caller: if the bundle
// fetch fails (network / 404), `establishSession` is simply not
// invoked, so no ratchet state advances.

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import { type IdentityKeyPair } from './identity.js';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown by `establishSession` when the signed-prekey Ed25519 signature
 * does not verify against the bundle's `identityEdPub`. Per requirement
 * 4.2 the caller must surface this to the user, produce no ciphertext,
 * and discard the bundle.
 *
 * The message is fixed and contains no bundle bytes, so logging the
 * error never leaks key material.
 */
export class InvalidSignedPreKeyError extends Error {
  constructor() {
    super('signed prekey signature did not verify');
    this.name = 'InvalidSignedPreKeyError';
  }
}

// ---------------------------------------------------------------------------
// Wire shapes — the bundle the API_Gateway returns and the per-session
// init the recipient needs to derive the same SK.
// ---------------------------------------------------------------------------

/**
 * Bundle fetched from `GET /users/:handle/prekey-bundle?deviceId=...`,
 * mirroring design.md §8.2 with the Phase-1 `identityEdPub` field
 * appended (see file header).
 *
 * `oneTimePreKey` is `null` when the server has run out of unused OPKs
 * for the recipient device. X3DH degrades gracefully to a 3-DH variant
 * (DH1..DH3) in that case — requirement 3.6.
 */
export interface RemotePreKeyBundle {
  readonly recipientDeviceId: string;
  readonly identityPub: Uint8Array; // 32 bytes X25519
  readonly identityEdPub: Uint8Array; // 32 bytes Ed25519 (Phase-1 only)
  readonly registrationId: number;
  readonly signedPreKey: {
    readonly keyId: number;
    readonly publicKey: Uint8Array; // 32 bytes X25519
    readonly signature: Uint8Array; // 64 bytes Ed25519 over publicKey
    readonly createdAt: number;
  };
  readonly oneTimePreKey: {
    readonly keyId: number;
    readonly publicKey: Uint8Array; // 32 bytes X25519
  } | null;
}

/**
 * The minimum information the recipient needs to derive the same root
 * key as the initiator. The initiator emits this in the first
 * (PreKeySignal-shaped) ciphertext envelope; the recipient feeds it
 * into `acceptSession` along with its own private key material.
 *
 * `aliceIdentityPub` is the initiator's X25519 identity public key
 * (the recipient can also obtain this via TOFU on the inbound envelope;
 * carrying it here keeps `acceptSession` self-contained and makes
 * cross-device replay easier to reason about).
 *
 * `signedPreKeyId` and `oneTimePreKeyId` tell the recipient which of
 * its own prekeys to look up. `oneTimePreKeyId` is `null` when the
 * initiator's bundle had no OPK (degraded 3-DH mode).
 */
export interface SessionInit {
  readonly aliceIdentityPub: Uint8Array;
  readonly ephemeralPub: Uint8Array;
  readonly signedPreKeyId: number;
  readonly oneTimePreKeyId: number | null;
}

/**
 * Output of a successful `establishSession`. The caller hands `rootKey`
 * to the Double Ratchet (task 4.3) as the initial root chain key, and
 * embeds `sessionInit` in the first envelope to the recipient.
 */
export interface EstablishedSession {
  readonly rootKey: Uint8Array; // 32 bytes derived via HKDF-SHA256
  readonly sessionInit: SessionInit;
}

// ---------------------------------------------------------------------------
// X3DH constants
// ---------------------------------------------------------------------------

/**
 * X3DH HKDF info string. Per the X3DH spec (Signal §3.3) the info field
 * binds the derivation to a specific protocol so a key derived for one
 * protocol cannot be misinterpreted as a key for another. We use a
 * Konvo-specific tag.
 */
const X3DH_INFO = new TextEncoder().encode('konvo-x3dh');

/**
 * X3DH HKDF salt: 32 zero bytes. Per the X3DH spec (Signal §3.3) the
 * salt is a 32- (or 64-) byte zero buffer when deriving the session key
 * from the concatenated DH shares.
 */
const X3DH_SALT = new Uint8Array(32);

/**
 * Length of the derived session key. 32 bytes — a single AES-256 / SHA-
 * 256 chain key, suitable for seeding the Double Ratchet root chain.
 */
const SK_LENGTH = 32;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Concatenate a sequence of `Uint8Array` chunks into a single buffer.
 * Used to assemble the X3DH IKM (`DH1 || DH2 || DH3 || DH4?`).
 *
 * Returning a fresh allocation rather than a `Buffer.concat`-style
 * borrowed view ensures the IKM lives in one contiguous region we can
 * scrub with `.fill(0)` after derivation.
 */
function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) {
    total += c.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/**
 * Derive the X3DH session key from the concatenated DH shares.
 *
 * `SK = HKDF-SHA256(IKM = DH1 || DH2 || DH3 [|| DH4],
 *                   salt = 32 zero bytes,
 *                   info = 'konvo-x3dh',
 *                   L    = 32)`
 *
 * The IKM buffer is scrubbed before the function returns so the
 * concatenated DH shares (which are themselves shared-secret material)
 * don't linger on the heap.
 */
function deriveSessionKey(dhShares: readonly Uint8Array[]): Uint8Array {
  const ikm = concatBytes(...dhShares);
  try {
    return hkdf(sha256, ikm, X3DH_SALT, X3DH_INFO, SK_LENGTH);
  } finally {
    ikm.fill(0);
  }
}

/**
 * Compute an X25519 ECDH shared secret. `@noble/curves`' x25519
 * exposes `getSharedSecret(secretKey, publicKey)` which is an alias of
 * `scalarMult` and returns 32 bytes — the standard X25519 output.
 *
 * Wrapped in this helper so all four DH calls in X3DH go through one
 * named site, making the four-DH structure obvious at the call site.
 */
function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Initiator (Alice) side of X3DH.
 *
 * Per design.md §13.1 / requirement 4.1:
 *   1. Verify the signed-prekey Ed25519 signature against the bundle's
 *      `identityEdPub`. On failure, throw `InvalidSignedPreKeyError`
 *      and produce no further state (requirement 4.2).
 *   2. Generate a fresh ephemeral X25519 keypair (EK).
 *   3. Compute the four DH shares (or three if the bundle has no OPK):
 *        DH1 = DH(IK_A_priv, SPK_B_pub)
 *        DH2 = DH(EK_A_priv, IK_B_pub)
 *        DH3 = DH(EK_A_priv, SPK_B_pub)
 *        DH4 = DH(EK_A_priv, OPK_B_pub)   // only if OPK present
 *   4. SK = HKDF-SHA256(DH1 || DH2 || DH3 [|| DH4], salt=zero32,
 *      info='konvo-x3dh', L=32).
 *
 * Returns the derived 32-byte root key plus the `SessionInit` record
 * the recipient needs to feed into `acceptSession` to derive the same
 * SK. The ephemeral private key is scrubbed before this function
 * returns; only its public half travels on the wire.
 *
 * This module performs no I/O. The caller is responsible for:
 *   - fetching the bundle and surfacing fetch errors (requirement 4.3
 *     — on failure this function is simply not called, so no local
 *     ratchet state advances),
 *   - persisting `rootKey` into the Double Ratchet's root chain (task
 *     4.3),
 *   - shipping `sessionInit` in the first envelope to the recipient,
 *   - TOFU / safety-number bookkeeping for `bundle.identityPub` (task
 *     4.7).
 */
export function establishSession(
  aliceIdentity: IdentityKeyPair,
  bundle: RemotePreKeyBundle,
): EstablishedSession {
  // Step 1: verify the signed-prekey signature FIRST. No ephemeral key
  // is generated, no DH is computed, no derivation runs unless the
  // signature checks out. This makes refusal observably side-effect-
  // free — requirement 4.2.
  //
  // `ed25519.verify` is non-throwing for malformed inputs in
  // `@noble/curves` (it returns `false`), so a hostile or corrupted
  // bundle yields a clean refusal rather than a parse exception.
  const sigValid = ed25519.verify(
    bundle.signedPreKey.signature,
    bundle.signedPreKey.publicKey,
    bundle.identityEdPub,
  );
  if (!sigValid) {
    throw new InvalidSignedPreKeyError();
  }

  // Step 2: generate Alice's ephemeral X25519 keypair (EK). Fresh per
  // session establishment — never reused. Provides the perfect-
  // forward-secrecy property of X3DH: leaking IK_A_priv after the fact
  // does not let an attacker recover SK without also having recorded
  // EK_A_priv at session-init time.
  const ekPrivBytes = new Uint8Array(32);
  crypto.getRandomValues(ekPrivBytes);
  const ekPubBytes = x25519.getPublicKey(ekPrivBytes);

  // Step 3: pull Alice's identity X25519 private bytes out of the
  // opaque container exactly once, immediately copy them, do the two
  // DH calls that need IK_A_priv, then scrub. The
  // `IdentityPrivateKey.bytes()` accessor already returns a defensive
  // copy, so we own this buffer.
  const ikAPriv = aliceIdentity.privateKey.bytes();
  let dh1: Uint8Array;
  let dh2: Uint8Array;
  let dh3: Uint8Array;
  let dh4: Uint8Array | null = null;
  try {
    // DH1 = DH(IK_A_priv, SPK_B_pub)
    dh1 = dh(ikAPriv, bundle.signedPreKey.publicKey);
    // DH2 = DH(EK_A_priv, IK_B_pub)
    dh2 = dh(ekPrivBytes, bundle.identityPub);
    // DH3 = DH(EK_A_priv, SPK_B_pub)
    dh3 = dh(ekPrivBytes, bundle.signedPreKey.publicKey);
    // DH4 = DH(EK_A_priv, OPK_B_pub) — only if the recipient had an
    // unused one-time prekey available. Degrading to 3-DH preserves
    // confidentiality but loses the OPK's contribution to the
    // post-compromise security guarantee — requirement 3.6.
    if (bundle.oneTimePreKey !== null) {
      dh4 = dh(ekPrivBytes, bundle.oneTimePreKey.publicKey);
    }
  } finally {
    // Scrub the transient IK_A_priv copy. The opaque container still
    // holds the canonical bytes for future use.
    ikAPriv.fill(0);
  }

  // Step 4: derive SK = HKDF-SHA256(DH1 || DH2 || DH3 [|| DH4]).
  const dhShares: Uint8Array[] =
    dh4 !== null ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];
  let rootKey: Uint8Array;
  try {
    rootKey = deriveSessionKey(dhShares);
  } finally {
    // Scrub the DH outputs themselves; the SK is the only material
    // that should outlive this call.
    dh1.fill(0);
    dh2.fill(0);
    dh3.fill(0);
    if (dh4 !== null) {
      dh4.fill(0);
    }
    // Scrub the ephemeral private bytes; only the public half is
    // safe to keep around.
    ekPrivBytes.fill(0);
  }

  const sessionInit: SessionInit = {
    aliceIdentityPub: new Uint8Array(aliceIdentity.publicKey),
    ephemeralPub: ekPubBytes,
    signedPreKeyId: bundle.signedPreKey.keyId,
    oneTimePreKeyId: bundle.oneTimePreKey?.keyId ?? null,
  };

  return { rootKey, sessionInit };
}

/**
 * Responder (Bob) side of X3DH.
 *
 * Per design.md §13.1, with the four DHs computed from Bob's
 * perspective (so that DH1..DH4 each evaluate to the same 32-byte
 * shared secret as on Alice's side):
 *
 *   DH1 = DH(SPK_B_priv, IK_A_pub)   // matches Alice's DH1
 *   DH2 = DH(IK_B_priv,  EK_A_pub)   // matches Alice's DH2
 *   DH3 = DH(SPK_B_priv, EK_A_pub)   // matches Alice's DH3
 *   DH4 = DH(OPK_B_priv, EK_A_pub)   // matches Alice's DH4 (if OPK)
 *   SK  = HKDF-SHA256(DH1 || DH2 || DH3 [|| DH4], salt=zero32,
 *                     info='konvo-x3dh', L=32)
 *
 * Inputs:
 *   - `bobIdentity`: Bob's local `IdentityKeyPair` (provides IK_B_priv).
 *   - `signedPreKeyPriv`: 32 raw X25519 bytes for SPK_B_priv. The
 *     prekey store yields the wrapped form; the caller unwraps via
 *     `unwrapStoredPrekeyPrivate` from `prekeys.ts` and is responsible
 *     for scrubbing the buffer after this function returns.
 *   - `oneTimePreKeyPriv`: 32 raw X25519 bytes for OPK_B_priv if the
 *     initiator used an OPK; `null` otherwise. The caller MUST mark
 *     the OPK as `used` in the prekey store regardless of whether
 *     this function succeeds (so a tamper-induced failure doesn't
 *     leak the OPK to a retry). Same scrubbing discipline as
 *     `signedPreKeyPriv`.
 *   - `sessionInit`: the record Alice attached to the first envelope.
 *
 * Returns the same 32-byte root key Alice derived. By P3 (forward
 * secrecy, design.md §14.1), an adversary who later compromises Bob's
 * IK_B_priv but did not record SPK_B_priv at session-init time cannot
 * recover this SK.
 *
 * `acceptSession` does NOT consult or mutate any store. The caller
 * upstream of this is responsible for:
 *   - marking the consumed OPK as used (atomically with the
 *     `signedPreKeyId` lookup, to prevent a duplicate-init replay),
 *   - feeding `rootKey` into the Double Ratchet's root chain on Bob's
 *     side (task 4.3).
 */
export function acceptSession(
  bobIdentity: IdentityKeyPair,
  signedPreKeyPriv: Uint8Array,
  oneTimePreKeyPriv: Uint8Array | null,
  sessionInit: SessionInit,
): { rootKey: Uint8Array } {
  // Sanity: an OPK keyId without matching private bytes (or vice
  // versa) is a programming error in the caller. Fail closed rather
  // than derive a key with three DHs while Alice computed four (or
  // four while Alice computed three) — that would silently produce
  // mismatched root keys on the two sides.
  const aliceUsedOpk = sessionInit.oneTimePreKeyId !== null;
  const bobHasOpk = oneTimePreKeyPriv !== null;
  if (aliceUsedOpk !== bobHasOpk) {
    throw new Error(
      'acceptSession: OPK presence in sessionInit does not match supplied private key',
    );
  }

  const ikBPriv = bobIdentity.privateKey.bytes();
  let dh1: Uint8Array;
  let dh2: Uint8Array;
  let dh3: Uint8Array;
  let dh4: Uint8Array | null = null;
  try {
    // DH1 = DH(SPK_B_priv, IK_A_pub)
    dh1 = dh(signedPreKeyPriv, sessionInit.aliceIdentityPub);
    // DH2 = DH(IK_B_priv, EK_A_pub)
    dh2 = dh(ikBPriv, sessionInit.ephemeralPub);
    // DH3 = DH(SPK_B_priv, EK_A_pub)
    dh3 = dh(signedPreKeyPriv, sessionInit.ephemeralPub);
    // DH4 = DH(OPK_B_priv, EK_A_pub) — only if Alice used an OPK.
    if (oneTimePreKeyPriv !== null) {
      dh4 = dh(oneTimePreKeyPriv, sessionInit.ephemeralPub);
    }
  } finally {
    ikBPriv.fill(0);
  }

  const dhShares: Uint8Array[] =
    dh4 !== null ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];
  try {
    const rootKey = deriveSessionKey(dhShares);
    return { rootKey };
  } finally {
    dh1.fill(0);
    dh2.fill(0);
    dh3.fill(0);
    if (dh4 !== null) {
      dh4.fill(0);
    }
  }
}

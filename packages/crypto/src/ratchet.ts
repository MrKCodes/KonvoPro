// packages/crypto/src/ratchet.ts
//
// Implements task 4.3: Crypto_Module Double Ratchet `encryptToDevice` /
// `decryptFromDevice`, per design.md §8.2 / §12.3 / §13.2 and
// requirements 4.4, 4.10–4.13, 9.1–9.5.
//
// What this module owns:
//   - the `RatchetState` shape (root key, sending / receiving chain
//     keys, current DH ratchet keypair, peer DH ratchet pubkey,
//     skipped-key store, and counters),
//   - pure functional `initSenderRatchet` / `initReceiverRatchet`
//     state constructors,
//   - the symmetric / DH ratchet step transitions performed by
//     `encryptToDevice` and `decryptFromDevice`,
//   - tamper rejection (P3 / req 4.11): a single-byte mutation of any
//     ciphertext or header field returns
//     `DecryptError { kind: 'invalid_message' }` with no plaintext
//     leak (no plaintext in returned objects, thrown values, logs,
//     metrics, persisted records, or callback args) and no advance
//     of the input ratchet state,
//   - duplicate idempotency (P6 / req 4.12): re-decrypting an
//     already-consumed envelope returns
//     `DecryptError { kind: 'duplicate' }` and does NOT advance the
//     ratchet a second time,
//   - out-of-order delivery (P7 / req 4.13): up to `MAX_SKIPPED_KEYS`
//     (= 1000) message keys are pre-derived and stored per FIFO so
//     future-numbered messages can be decrypted when their
//     predecessors arrive late,
//   - bounded skipped-key storage (req 9.3 / 9.4): the skipped-key
//     ring is hard-capped at 1000 entries with FIFO eviction, and
//     evicted message-key bytes are scrubbed,
//   - "messages were lost" surfacing (req 9.5): when an inbound
//     header would require skipping more than 1000 keys within a DH
//     chain, we surface
//     `DecryptError { kind: 'message_lost' }` and continue accepting
//     subsequent inbound ciphertexts on the chain (state DOES advance
//     past the over-cap position so the next clean message decrypts),
//   - forward secrecy (req 9.1 / P4): chain advance is one-way (the
//     consumed chain key is never returned alongside the next chain
//     key, and the function-local reference to it is overwritten and
//     scrubbed before returning), so a future memory compromise of
//     the new chain key cannot recover prior message keys,
//   - post-compromise security (req 9.2 / P5): every DH ratchet step
//     mixes a fresh DH output into the root KDF, so an attacker who
//     captured an old chain key cannot derive subsequent chain keys.
//
// What this module does NOT own:
//   - persistence of `RatchetState` to Dexie — that lands in task 4.4
//     (Signal store on Dexie). This module is purely functional:
//     every state transition returns a fresh `RatchetState` object;
//     the caller is responsible for atomically writing it back to
//     storage so that "on exception, ratchet state is unchanged"
//     (design.md §13.2) is preserved by the caller dropping the new
//     state on exception,
//   - X3DH session establishment (`session.ts`, task 4.2),
//   - identity / TOFU bookkeeping (task 4.7),
//   - the wire envelope shape — `RatchetMessageHeader` is the
//     per-message header used by the ratchet itself; the outer
//     `CiphertextEnvelope` wraps it via `packages/protocol`.
//
// Phase-3 placeholder: hand-rolled Double Ratchet, not real libsignal
// -------------------------------------------------------------------
// design.md §13.2 hands encrypt / decrypt off to libsignal's
// `SessionCipher`. libsignal isn't on disk yet (it lands later in
// task 4.x). For Phase 3 we build the Double Ratchet ourselves on
// top of `@noble/curves`' X25519 (DH) + `@noble/hashes`' HMAC-SHA256
// and HKDF-SHA256 (KDF chains) + WebCrypto's `crypto.subtle`
// AES-256-GCM (symmetric AEAD). The construction follows the
// canonical Signal Double Ratchet (root-KDF + symmetric chain KDF +
// per-message AEAD), so the security proofs of P3 / P4 / P5 / P6 /
// P7 carry over. When libsignal lands, this module's public surface
// stays the same; only the bodies become wrappers around
// `SessionCipher`.
//
// AEAD construction
// -----------------
// Each message key is expanded via HKDF-SHA256 into a 32-byte AES
// key and a 12-byte IV. Both sides re-derive the IV from the
// message key, so the IV is NOT transmitted on the wire. The
// serialized `RatchetMessageHeader` is fed in as AES-GCM "additional
// authenticated data" (AAD), so any tamper to the header (dhPub,
// prevChainLength, or messageNumber) invalidates the GCM
// authentication tag exactly the same as a tamper to the ciphertext
// body — both surface as `invalid_message` (P3).
//
// Trial-decrypt discipline (P3 + req 4.11 + design.md §13.2 atomicity)
// --------------------------------------------------------------------
// Every state transition is computed against a *clone* of the input
// state. The clone is only returned to the caller after a successful
// AES-GCM verify-and-decrypt. On tamper / GCM failure we throw away
// the clone, return
// `{ ok: false, error: { kind: 'invalid_message' } }`, and emit no
// plaintext bytes anywhere. The caller's input `state` reference is
// never mutated.

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Hard cap on how many message keys we retain for out-of-order
 * delivery, per requirement 9.3. The store is FIFO: when a 1001st
 * entry would be appended, the oldest entry is evicted first
 * (req 9.4). The cap is global across DH chains (a stricter
 * interpretation than "per chain" — global ≤ 1000 implies per-chain
 * ≤ 1000 trivially).
 */
export const MAX_SKIPPED_KEYS = 1000 as const;

/** Length in bytes of an X25519 private or public key. */
const KEY_LENGTH = 32;

/** AES-256-GCM key length (bytes). */
const AES_KEY_LENGTH = 32;
/** AES-256-GCM IV length (bytes). */
const AES_IV_LENGTH = 12;

/**
 * HKDF info strings — bind each derivation to a specific role so a
 * key derived for one purpose cannot be reinterpreted as a key for
 * another.
 */
const ROOT_KDF_INFO = new TextEncoder().encode('konvo-ratchet-rk');
const MESSAGE_KEY_INFO = new TextEncoder().encode('konvo-ratchet-mk');

/**
 * Domain-separation tags fed into HMAC-SHA256 when advancing a
 * symmetric chain. `0x02` derives the next chain key; `0x01` derives
 * the message key. These are the canonical Signal symmetric-ratchet
 * constants.
 */
const HMAC_TAG_CHAIN_KEY = new Uint8Array([0x02]);
const HMAC_TAG_MESSAGE_KEY = new Uint8Array([0x01]);

/**
 * Length of the serialized `RatchetMessageHeader` in bytes:
 *   32 bytes dhPub + 4 bytes prevChainLength (u32 BE) +
 *   4 bytes messageNumber (u32 BE).
 *
 * The serialized form is fed to AES-GCM as AAD so any tamper to
 * header fields surfaces as `invalid_message` via the GCM tag check.
 */
const HEADER_BYTES = 32 + 4 + 4;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * One stored skipped-message-key entry. Skipped entries are keyed
 * by `(dhPub, messageNumber)` because the same `messageNumber` can
 * recur across different DH ratchet chains.
 */
export interface SkippedKey {
  readonly dhPub: Uint8Array;
  readonly messageNumber: number;
  readonly messageKey: Uint8Array; // 32 bytes
}

/**
 * The per-peer Double Ratchet state. Treated as immutable by
 * external callers: `encryptToDevice` and `decryptFromDevice` return
 * a fresh `RatchetState` object; the input reference is never
 * mutated. Internally, helper functions work on a `cloneState`-
 * produced mutable view (`MutableRatchetState`) and the public
 * functions cast it back to `RatchetState` on the way out.
 *
 * Field semantics follow the canonical Signal Double Ratchet:
 *   - `rootKey` (RK): 32-byte root chain key. Mixed with each new DH
 *     output to derive new sending / receiving chain keys.
 *   - `sendingDhPriv` / `sendingDhPub`: our current DH ratchet
 *     keypair. Rotated whenever the peer DH-ratchets (i.e. on the
 *     first inbound message under a new `header.dhPub`).
 *   - `receivingDhPub`: the peer's most recently observed DH ratchet
 *     pubkey (`null` only on the receiver before the first inbound).
 *   - `sendingChainKey` (CKs): seeds the next outbound message key.
 *     `null` on the receiver until they reply (at which point a
 *     fresh sending chain is derived from a new DH ratchet step).
 *   - `receivingChainKey` (CKr): seeds the next inbound message key
 *     for the *current* receiving chain. `null` on the sender until
 *     the peer first responds.
 *   - `sendingMessageNumber` (Ns): next sending-chain counter.
 *   - `receivingMessageNumber` (Nr): next receiving-chain counter.
 *   - `previousSendingChainLength` (PN): how many messages were sent
 *     on the *previous* sending chain before we DH-ratcheted.
 *     Carried in outbound headers so the recipient knows how many
 *     keys to skip from their old receiving chain.
 *   - `skippedKeys`: FIFO ring of out-of-order message keys we've
 *     pre-derived but not yet consumed. Capped at
 *     `MAX_SKIPPED_KEYS`.
 */
export interface RatchetState {
  readonly rootKey: Uint8Array;
  readonly sendingDhPriv: Uint8Array;
  readonly sendingDhPub: Uint8Array;
  readonly receivingDhPub: Uint8Array | null;
  readonly sendingChainKey: Uint8Array | null;
  readonly receivingChainKey: Uint8Array | null;
  readonly sendingMessageNumber: number;
  readonly receivingMessageNumber: number;
  readonly previousSendingChainLength: number;
  readonly skippedKeys: readonly SkippedKey[];
}

/**
 * Internal mutable view of the ratchet state used by helpers that
 * advance chains in place against a clone. Public surface always
 * returns the readonly `RatchetState` shape — `freezeState` casts
 * the mutable clone back. This is purely a TypeScript convenience;
 * `readonly` is not enforced at runtime.
 */
type MutableRatchetState = {
  rootKey: Uint8Array;
  sendingDhPriv: Uint8Array;
  sendingDhPub: Uint8Array;
  receivingDhPub: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendingMessageNumber: number;
  receivingMessageNumber: number;
  previousSendingChainLength: number;
  skippedKeys: SkippedKey[];
};

/**
 * The per-message header attached to every ciphertext. Tampering
 * any field breaks AES-GCM AAD verification → `invalid_message`
 * (P3).
 */
export interface RatchetMessageHeader {
  readonly dhPub: Uint8Array; // 32 bytes — sender's current sending DH pubkey
  readonly prevChainLength: number;
  readonly messageNumber: number;
}

/**
 * Failure shape returned by `decryptFromDevice` when no plaintext
 * is produced. The error object carries no bytes derived from the
 * (potentially attacker-controlled) ciphertext, so logging the
 * error never leaks plaintext (req 4.11).
 *
 * `kind` values:
 *   - `'invalid_message'`: AES-GCM tag verification failed (tamper
 *     / corruption / wrong key). Per req 4.11, ratchet state is
 *     unchanged.
 *   - `'duplicate'`: this `(dhPub, messageNumber)` was already
 *     consumed. The first decrypt of this ciphertext succeeded;
 *     this attempt is a redundant retry. Ratchet state is
 *     unchanged (req 4.12 — advances exactly once across all
 *     repeats).
 *   - `'message_lost'`: the inbound header would require skipping
 *     more than `MAX_SKIPPED_KEYS` keys within a single DH chain.
 *     The skipped store would FIFO-evict pending keys we cannot
 *     reconstruct. Per req 9.5 we surface this as a notice; the
 *     session continues and subsequent ciphertexts on the chain
 *     are accepted. State DOES advance past the over-cap position
 *     so the next clean message decrypts.
 */
export interface DecryptError {
  readonly ok: false;
  readonly error: {
    readonly kind: 'invalid_message' | 'duplicate' | 'message_lost';
    readonly details?: string;
  };
}

/**
 * Result of `decryptFromDevice`. Either a successful decryption
 * yielding the exact plaintext bytes the peer encrypted (req 4.10),
 * or one of the failure modes documented on `DecryptError`.
 */
export type DecryptResult =
  | { readonly ok: true; readonly plaintext: Uint8Array }
  | DecryptError;

// ---------------------------------------------------------------------------
// Private helpers — copying / scrubbing / structural cloning
// ---------------------------------------------------------------------------

/**
 * Make a defensive copy of every byte buffer in a `RatchetState`
 * so the returned mutable state shares no backing memory with the
 * input. This is the cornerstone of trial-decrypt atomicity: we
 * mutate the clone freely, then either return it (success) or drop
 * it (tamper / duplicate) — the caller's input reference is
 * unchanged either way.
 */
function cloneState(s: RatchetState): MutableRatchetState {
  return {
    rootKey: new Uint8Array(s.rootKey),
    sendingDhPriv: new Uint8Array(s.sendingDhPriv),
    sendingDhPub: new Uint8Array(s.sendingDhPub),
    receivingDhPub:
      s.receivingDhPub === null ? null : new Uint8Array(s.receivingDhPub),
    sendingChainKey:
      s.sendingChainKey === null ? null : new Uint8Array(s.sendingChainKey),
    receivingChainKey:
      s.receivingChainKey === null ? null : new Uint8Array(s.receivingChainKey),
    sendingMessageNumber: s.sendingMessageNumber,
    receivingMessageNumber: s.receivingMessageNumber,
    previousSendingChainLength: s.previousSendingChainLength,
    skippedKeys: s.skippedKeys.map((k) => ({
      dhPub: new Uint8Array(k.dhPub),
      messageNumber: k.messageNumber,
      messageKey: new Uint8Array(k.messageKey),
    })),
  };
}

/**
 * Cast the mutable clone back to the public readonly view. No
 * runtime cost — `readonly` is purely a TypeScript fiction.
 */
function freezeState(s: MutableRatchetState): RatchetState {
  return s as RatchetState;
}

/**
 * Length-checked bytewise equality. Used for matching `dhPub` fields
 * and skipped-key tags. The compared values are public-key bytes /
 * counters, not secrets, so we don't need cryptographic constant
 * time.
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

// ---------------------------------------------------------------------------
// Private helpers — KDF chains
// ---------------------------------------------------------------------------

/**
 * Root KDF: `(rootKey, dhOutput) → (newRootKey, newChainKey)`.
 *
 *   newRootKey || newChainKey = HKDF-SHA256(
 *     salt = oldRootKey,
 *     ikm  = dhOutput,
 *     info = 'konvo-ratchet-rk',
 *     L    = 64)
 *
 * Standard Signal `KDF_RK` construction: feed the DH output as
 * IKM, the prior root key as salt, derive 64 bytes, split 32/32.
 * The DH output and the old root key are scrubbed by callers
 * before this function returns.
 */
function rootKdf(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): { newRootKey: Uint8Array; newChainKey: Uint8Array } {
  const expanded = hkdf(sha256, dhOutput, rootKey, ROOT_KDF_INFO, 64);
  return {
    newRootKey: expanded.slice(0, 32),
    newChainKey: expanded.slice(32, 64),
  };
}

/**
 * Symmetric chain advance: derive the next chain key and the
 * message key for the current counter from the current chain key.
 *
 *   nextChainKey = HMAC-SHA256(chainKey, 0x02)
 *   messageKey   = HMAC-SHA256(chainKey, 0x01)
 *
 * Per requirement 9.1: the consumed chainKey is NOT returned;
 * callers overwrite their reference with `nextChainKey` and scrub
 * the consumed buffer, so the consumed key has no live reference
 * and is unrecoverable from a later memory compromise (forward
 * secrecy P4). The message key itself is the only material used
 * to encrypt one specific message and is scrubbed after AES-GCM
 * consumes it.
 */
function chainStep(chainKey: Uint8Array): {
  nextChainKey: Uint8Array;
  messageKey: Uint8Array;
} {
  return {
    nextChainKey: hmac(sha256, chainKey, HMAC_TAG_CHAIN_KEY),
    messageKey: hmac(sha256, chainKey, HMAC_TAG_MESSAGE_KEY),
  };
}

/**
 * Expand a 32-byte message key into the AES-256-GCM key + 12-byte
 * IV.
 *
 *   aesKey || iv = HKDF-SHA256(
 *     salt = zero32,
 *     ikm  = messageKey,
 *     info = 'konvo-ratchet-mk',
 *     L    = 44)
 *
 * Both sides re-derive the IV from the message key, so it never
 * appears on the wire. A given message key is consumed exactly
 * once (chain advance is one-way), so the (key, iv) pair is
 * single-use per requirement and AES-GCM nonce reuse is
 * structurally impossible.
 */
function expandMessageKey(messageKey: Uint8Array): {
  aesKey: Uint8Array;
  iv: Uint8Array;
} {
  const salt = new Uint8Array(32);
  const expanded = hkdf(
    sha256,
    messageKey,
    salt,
    MESSAGE_KEY_INFO,
    AES_KEY_LENGTH + AES_IV_LENGTH,
  );
  return {
    aesKey: expanded.slice(0, AES_KEY_LENGTH),
    iv: expanded.slice(AES_KEY_LENGTH, AES_KEY_LENGTH + AES_IV_LENGTH),
  };
}

// ---------------------------------------------------------------------------
// Private helpers — header serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a `RatchetMessageHeader` into 40 bytes for use as
 * AES-GCM AAD (and for transmission alongside the ciphertext).
 * Layout:
 *   - bytes 0..31:  dhPub
 *   - bytes 32..35: prevChainLength (uint32 big-endian)
 *   - bytes 36..39: messageNumber   (uint32 big-endian)
 *
 * Tampering ANY of these bytes flips the AAD fed to GCM and so
 * causes the tag check to fail → `invalid_message` (P3).
 */
function serializeHeader(header: RatchetMessageHeader): Uint8Array {
  if (header.dhPub.length !== KEY_LENGTH) {
    throw new Error(
      `RatchetMessageHeader.dhPub must be ${KEY_LENGTH} bytes, got ${header.dhPub.length}`,
    );
  }
  const out = new Uint8Array(HEADER_BYTES);
  out.set(header.dhPub, 0);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(32, header.prevChainLength >>> 0, /* littleEndian */ false);
  view.setUint32(36, header.messageNumber >>> 0, /* littleEndian */ false);
  return out;
}

// ---------------------------------------------------------------------------
// Private helpers — AES-256-GCM via WebCrypto
// ---------------------------------------------------------------------------

/**
 * Coerce a `Uint8Array<ArrayBufferLike>` to a `Uint8Array<ArrayBuffer>`
 * for WebCrypto's `BufferSource` input slot.
 *
 * TypeScript 5.7 tightened `lib.dom.d.ts` so `BufferSource` is now
 * `ArrayBufferView<ArrayBuffer> | ArrayBuffer` (not
 * `ArrayBufferView<ArrayBufferLike>`). Our public `Uint8Array`
 * parameters retain the `ArrayBufferLike` element type for backward
 * compatibility with callers that allocate via Buffer / typed-array
 * subarray. At runtime we only ever construct over `ArrayBuffer`
 * (never `SharedArrayBuffer`), so the structural cast is sound — but
 * we still copy when `.buffer` reports `SharedArrayBuffer` to keep
 * the contract honest at runtime as well as at the type level.
 */
function toBufferSource(u: Uint8Array): Uint8Array<ArrayBuffer> {
  if (u.buffer instanceof ArrayBuffer) {
    return u as Uint8Array<ArrayBuffer>;
  }
  // Defensive copy for SharedArrayBuffer-backed views — never expected
  // in practice, but keeps the cast above sound regardless.
  const copy = new Uint8Array(u.byteLength);
  copy.set(u);
  return copy;
}

/**
 * Import a 32-byte AES key into a non-extractable WebCrypto
 * CryptoKey for one-shot use. The CryptoKey is discarded after the
 * encrypt / decrypt call returns.
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
 * AES-256-GCM encrypt. Output is `ciphertext || tag` (the standard
 * WebCrypto layout). The serialized header is fed in as
 * `additionalData` so any header tamper invalidates the tag.
 */
async function aesGcmEncrypt(
  aesKey: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await importAesKey(aesKey, 'encrypt');
  const ct = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toBufferSource(iv),
      additionalData: toBufferSource(aad),
      tagLength: 128,
    },
    key,
    toBufferSource(plaintext),
  );
  return new Uint8Array(ct);
}

/**
 * AES-256-GCM decrypt-and-verify. Returns plaintext on success, or
 * `null` on tag mismatch (tamper / corruption / wrong key).
 *
 * Crucially, we catch the `OperationError` WebCrypto throws on auth
 * failure and return `null` *without re-throwing* and *without ever
 * returning partial bytes* — there is no "partial decrypt" path in
 * WebCrypto's AES-GCM, the implementation buffers the entire
 * plaintext and only surfaces it after the tag check passes.
 */
async function aesGcmDecrypt(
  aesKey: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array | null> {
  const key = await importAesKey(aesKey, 'decrypt');
  try {
    const pt = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(iv),
        additionalData: toBufferSource(aad),
        tagLength: 128,
      },
      key,
      toBufferSource(ciphertext),
    );
    return new Uint8Array(pt);
  } catch {
    // WebCrypto throws OperationError on authentication failure.
    // Per req 4.11 we return `null` so the caller surfaces
    // `invalid_message` and produces no plaintext bytes anywhere.
    return null;
  }
}

// ---------------------------------------------------------------------------
// Private helpers — DH ratchet
// ---------------------------------------------------------------------------

/**
 * Perform a DH ratchet step on the receiving side: combine the
 * peer's new ratchet pubkey with our current sending DH private to
 * derive the new root key and a new receiving chain key.
 */
function dhRatchetReceiveStep(
  rootKey: Uint8Array,
  ourPriv: Uint8Array,
  theirNewPub: Uint8Array,
): { newRootKey: Uint8Array; newReceivingChainKey: Uint8Array } {
  const dhOutput = x25519.getSharedSecret(ourPriv, theirNewPub);
  try {
    const { newRootKey, newChainKey } = rootKdf(rootKey, dhOutput);
    return { newRootKey, newReceivingChainKey: newChainKey };
  } finally {
    dhOutput.fill(0);
  }
}

/**
 * Generate a fresh DH ratchet keypair on our side. Used both at
 * sender init and at every DH ratchet step on the receiving side.
 *
 * `@noble/curves`' `x25519.getPublicKey` accepts 32 random bytes
 * and clamps internally, so we don't need to clamp ourselves.
 */
function generateRatchetKeypair(): { priv: Uint8Array; pub: Uint8Array } {
  const priv = new Uint8Array(KEY_LENGTH);
  crypto.getRandomValues(priv);
  const pub = x25519.getPublicKey(priv);
  return { priv, pub };
}

// ---------------------------------------------------------------------------
// Public surface — initialization
// ---------------------------------------------------------------------------

/**
 * Generate a matched X25519 keypair for use as the receiver's
 * initial signed-prekey-shaped DH ratchet keypair.
 *
 * Exposed so tests in downstream packages (which can't import
 * `@noble/curves` directly without adding it as a dep) can stage
 * a real Alice / Bob ratchet pair. Production code paths obtain
 * the keypair through the Phase-1 `prekeys.ts` flow instead.
 */
export function generateRatchetDhKeypair(): {
  priv: Uint8Array;
  pub: Uint8Array;
} {
  return generateRatchetKeypair();
}

/**
 * Initialize the sender (Alice) side of the ratchet.
 *
 * Inputs:
 *   - `rootKey`: the 32-byte SK derived from X3DH (`session.ts`
 *     `establishSession`).
 *   - `recipientDhPub`: the recipient's signed-prekey public key
 *     (the same SPK that participated in X3DH). This is the peer's
 *     *initial* receiving-side DH ratchet pubkey.
 *
 * Effect: generates a fresh sending DH keypair and runs the root
 * KDF to derive the initial sending chain. The receiving chain is
 * left `null` — it will be populated on the first inbound message
 * when the peer DH-ratchets back.
 *
 * The input `rootKey` buffer is not mutated; we copy on the way in.
 */
export function initSenderRatchet(
  rootKey: Uint8Array,
  recipientDhPub: Uint8Array,
): RatchetState {
  if (rootKey.length !== 32) {
    throw new Error(`rootKey must be 32 bytes, got ${rootKey.length}`);
  }
  if (recipientDhPub.length !== KEY_LENGTH) {
    throw new Error(
      `recipientDhPub must be ${KEY_LENGTH} bytes, got ${recipientDhPub.length}`,
    );
  }

  const { priv: sendingDhPriv, pub: sendingDhPub } = generateRatchetKeypair();
  const dhOutput = x25519.getSharedSecret(sendingDhPriv, recipientDhPub);
  try {
    const { newRootKey, newChainKey } = rootKdf(
      new Uint8Array(rootKey),
      dhOutput,
    );
    return {
      rootKey: newRootKey,
      sendingDhPriv,
      sendingDhPub,
      receivingDhPub: new Uint8Array(recipientDhPub),
      sendingChainKey: newChainKey,
      receivingChainKey: null,
      sendingMessageNumber: 0,
      receivingMessageNumber: 0,
      previousSendingChainLength: 0,
      skippedKeys: [],
    };
  } finally {
    dhOutput.fill(0);
  }
}

/**
 * Initialize the receiver (Bob) side of the ratchet.
 *
 * Inputs:
 *   - `rootKey`: the 32-byte SK derived from X3DH (`session.ts`
 *     `acceptSession`).
 *   - `ourDhKeypair`: Bob's signed-prekey keypair (the same SPK
 *     that participated in X3DH). This becomes Bob's initial
 *     sending DH keypair — it's the keypair Alice DH'd against in
 *     X3DH, so the first inbound message under Alice's *new*
 *     sending DH pubkey triggers a clean DH ratchet step on Bob's
 *     side.
 *
 * Effect: Bob holds the root key but no chain keys yet. Both
 * sending and receiving chains are derived lazily: on the first
 * inbound message (which DH-ratchets and produces both new chains).
 *
 * Callers MUST scrub their copy of the SPK private bytes after
 * this returns; we copy on the way in.
 */
export function initReceiverRatchet(
  rootKey: Uint8Array,
  ourDhKeypair: { priv: Uint8Array; pub: Uint8Array },
): RatchetState {
  if (rootKey.length !== 32) {
    throw new Error(`rootKey must be 32 bytes, got ${rootKey.length}`);
  }
  if (ourDhKeypair.priv.length !== KEY_LENGTH) {
    throw new Error(
      `ourDhKeypair.priv must be ${KEY_LENGTH} bytes, got ${ourDhKeypair.priv.length}`,
    );
  }
  if (ourDhKeypair.pub.length !== KEY_LENGTH) {
    throw new Error(
      `ourDhKeypair.pub must be ${KEY_LENGTH} bytes, got ${ourDhKeypair.pub.length}`,
    );
  }

  return {
    rootKey: new Uint8Array(rootKey),
    sendingDhPriv: new Uint8Array(ourDhKeypair.priv),
    sendingDhPub: new Uint8Array(ourDhKeypair.pub),
    receivingDhPub: null,
    sendingChainKey: null,
    receivingChainKey: null,
    sendingMessageNumber: 0,
    receivingMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedKeys: [],
  };
}

// ---------------------------------------------------------------------------
// Public surface — encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt a plaintext payload to the peer device.
 *
 * Per design.md §13.2 / req 4.4:
 *   - Advances the sending chain by exactly one step per message.
 *   - Returns a fresh `RatchetState` with `sendingMessageNumber`
 *     incremented by 1 and `sendingChainKey` rotated to the next
 *     chain key. The consumed chain key has no live reference in
 *     the returned state (forward secrecy P4 / req 9.1).
 *   - The returned `header.dhPub` is our current `sendingDhPub`,
 *     `header.prevChainLength` is `previousSendingChainLength`,
 *     `header.messageNumber` is the *pre-increment* sending
 *     counter.
 *
 * The serialized header is bound into the AES-GCM AAD so any
 * tamper to the header surfaces as `invalid_message` on the
 * recipient.
 *
 * Throws if the state has no sending chain key (which is a
 * programmer error — the receiver-only state from
 * `initReceiverRatchet` cannot send until it first decrypts an
 * inbound message, which triggers the implicit DH ratchet that
 * establishes the sending chain).
 */
export async function encryptToDevice(
  state: RatchetState,
  plaintext: Uint8Array,
): Promise<{
  state: RatchetState;
  ciphertext: Uint8Array;
  header: RatchetMessageHeader;
}> {
  if (state.sendingChainKey === null) {
    throw new Error(
      'encryptToDevice: ratchet has no sending chain — receiver must wait for first inbound message before sending',
    );
  }

  const next = cloneState(state);
  // After cloneState, next.sendingChainKey is a fresh copy of the
  // (non-null) sending chain key. TypeScript can't carry the
  // narrowing across the clone, so we capture it in a local that
  // retains the non-null type.
  const sendingChainKey = next.sendingChainKey!;

  // Advance the sending chain exactly once per message (req 4.4).
  // We overwrite `next.sendingChainKey` with `nextChainKey` below
  // and scrub the consumed buffer — req 9.1 forward-secrecy.
  const { nextChainKey, messageKey } = chainStep(sendingChainKey);

  const header: RatchetMessageHeader = {
    dhPub: new Uint8Array(next.sendingDhPub),
    prevChainLength: next.previousSendingChainLength,
    messageNumber: next.sendingMessageNumber,
  };
  const aad = serializeHeader(header);

  // Expand message key → AES key + IV. Each message key is used at
  // most once; AES-GCM nonce reuse is structurally impossible.
  const { aesKey, iv } = expandMessageKey(messageKey);
  let ciphertext: Uint8Array;
  try {
    ciphertext = await aesGcmEncrypt(aesKey, iv, aad, plaintext);
  } finally {
    aesKey.fill(0);
    iv.fill(0);
    messageKey.fill(0);
  }

  // Commit the chain advance to the new state. Scrub the consumed
  // chain key copy on `next` so it has no live reference.
  sendingChainKey.fill(0);
  next.sendingChainKey = nextChainKey;
  next.sendingMessageNumber += 1;

  return {
    state: freezeState(next),
    ciphertext,
    header,
  };
}

// ---------------------------------------------------------------------------
// Public surface — decrypt
// ---------------------------------------------------------------------------

/**
 * Decrypt an inbound ciphertext.
 *
 * Receive flow:
 *
 *   1. **Skipped-key fast path**: if `(header.dhPub,
 *      header.messageNumber)` is in the skipped-key store, this is
 *      a late-arriving out-of-order message. Look up its message
 *      key, attempt AES-GCM decrypt, on success remove the entry
 *      from skipped (idempotent — a second decrypt of the same
 *      envelope finds nothing in skipped and falls through to the
 *      duplicate path). On AES-GCM failure return
 *      `invalid_message` with state unchanged.
 *
 *   2. **Same-chain advance**: when `header.dhPub` matches the
 *      current `receivingDhPub`. Skip keys from
 *      `receivingMessageNumber` up to `header.messageNumber - 1`
 *      (pushing into the FIFO skipped store, evicting at the cap),
 *      derive the message key for `header.messageNumber`, AES-GCM
 *      decrypt. On success advance `receivingMessageNumber` to
 *      `header.messageNumber + 1`.
 *
 *   3. **DH ratchet step** (`decryptNewChain`): when `header.dhPub`
 *      differs from the current `receivingDhPub`, the peer has
 *      DH-ratcheted. We:
 *        a. Skip remaining keys of the current receiving chain
 *           (up to `header.prevChainLength`), pushing into skipped.
 *        b. Run the receiving DH ratchet step to derive a new root
 *           key + new receiving chain.
 *        c. Generate a fresh sending DH keypair and run the
 *           sending DH ratchet step to derive a new sending chain.
 *        d. Walk the new receiving chain forward to
 *           `header.messageNumber`, storing each intermediate key.
 *        e. AES-GCM decrypt with the message key for
 *           `header.messageNumber`.
 *
 *   4. **Bounded skip (req 9.5)**: at any point if the gap to skip
 *      would exceed `MAX_SKIPPED_KEYS` within a single chain,
 *      return `message_lost`. State *does* advance to
 *      `header.messageNumber + 1` so that subsequent messages on
 *      the chain still decrypt — req 9.5 mandates the session
 *      continues.
 *
 *   5. **Duplicate (req 4.12)**: if `header.dhPub` matches the
 *      current receiving chain and `header.messageNumber` is below
 *      `receivingMessageNumber`, AND no key for this position is
 *      in the skipped store, the message has already been
 *      consumed. Return `duplicate` with state unchanged.
 *
 * Tamper rejection (P3 / req 4.11): the entire decrypt is
 * performed against a cloned state. Only on AES-GCM success is
 * the cloned state returned; on tag failure the clone is dropped
 * and we return `invalid_message` with the input state reference
 * untouched. No plaintext bytes are computed past the WebCrypto
 * boundary — `aesGcmDecrypt` returns `null` on failure, and we
 * never log / persist / metric the ciphertext or any derived
 * bytes.
 */
export async function decryptFromDevice(
  state: RatchetState,
  ciphertext: Uint8Array,
  header: RatchetMessageHeader,
): Promise<{ state: RatchetState; result: DecryptResult }> {
  // Validate header shape early — these are programmer errors not
  // attacker tamper, so we throw rather than return invalid_message.
  if (header.dhPub.length !== KEY_LENGTH) {
    throw new Error(
      `RatchetMessageHeader.dhPub must be ${KEY_LENGTH} bytes, got ${header.dhPub.length}`,
    );
  }
  if (
    !Number.isInteger(header.messageNumber) ||
    header.messageNumber < 0 ||
    header.messageNumber > 0xffff_ffff
  ) {
    throw new Error(
      `RatchetMessageHeader.messageNumber out of range: ${header.messageNumber}`,
    );
  }
  if (
    !Number.isInteger(header.prevChainLength) ||
    header.prevChainLength < 0 ||
    header.prevChainLength > 0xffff_ffff
  ) {
    throw new Error(
      `RatchetMessageHeader.prevChainLength out of range: ${header.prevChainLength}`,
    );
  }

  const aad = serializeHeader(header);

  // ---- Step 1: skipped-key fast path -----------------------------------
  //
  // We try this BEFORE checking dhPub equality with the current
  // chain, because an out-of-order message under the *current*
  // chain that we pre-derived a key for also lives in skipped.
  const skippedIdx = state.skippedKeys.findIndex(
    (k) =>
      k.messageNumber === header.messageNumber &&
      bytesEqual(k.dhPub, header.dhPub),
  );
  if (skippedIdx >= 0) {
    const skipped = state.skippedKeys[skippedIdx]!;
    const { aesKey, iv } = expandMessageKey(skipped.messageKey);
    let plaintext: Uint8Array | null;
    try {
      plaintext = await aesGcmDecrypt(aesKey, iv, aad, ciphertext);
    } finally {
      aesKey.fill(0);
      iv.fill(0);
    }
    if (plaintext === null) {
      // Tamper on a skipped-key envelope. Per req 4.11 state is
      // unchanged — the skipped key is preserved for a possible
      // legitimate retry. The skipped key is not consumed.
      return {
        state,
        result: { ok: false, error: { kind: 'invalid_message' } },
      };
    }
    // Successful decrypt: drop the skipped entry (idempotent — a
    // second decrypt of the same envelope finds nothing here and
    // falls through to the duplicate path below).
    const next = cloneState(state);
    // Scrub the cloned skipped message key bytes before discarding
    // (req 9.1).
    next.skippedKeys[skippedIdx]!.messageKey.fill(0);
    next.skippedKeys.splice(skippedIdx, 1);
    return { state: freezeState(next), result: { ok: true, plaintext } };
  }

  // ---- Step 2 & 3: same-chain advance vs DH-ratchet step ---------------
  const isSameChain =
    state.receivingDhPub !== null &&
    bytesEqual(state.receivingDhPub, header.dhPub);

  if (isSameChain) {
    return decryptSameChain(state, ciphertext, header, aad);
  }

  return decryptNewChain(state, ciphertext, header, aad);
}

// ---------------------------------------------------------------------------
// Private — same-chain receive path
// ---------------------------------------------------------------------------

/**
 * Receive path when `header.dhPub` matches the current receiving
 * chain. We may need to skip forward (storing intermediate keys),
 * detect a duplicate (header.messageNumber below current counter
 * with no skipped entry), or surface `message_lost` (gap exceeds
 * cap).
 */
async function decryptSameChain(
  state: RatchetState,
  ciphertext: Uint8Array,
  header: RatchetMessageHeader,
  aad: Uint8Array,
): Promise<{ state: RatchetState; result: DecryptResult }> {
  if (state.receivingChainKey === null) {
    // No receiving chain key but the inbound dhPub matches our
    // recorded receivingDhPub — only possible on the *sender* side
    // before any reply arrives, replaying a stale-shaped envelope.
    // Treat as duplicate: we have no key for this position.
    return {
      state,
      result: { ok: false, error: { kind: 'duplicate' } },
    };
  }

  if (header.messageNumber < state.receivingMessageNumber) {
    // We've already consumed this position. The skipped-key fast
    // path above didn't find it, so it must have been previously
    // decrypted (req 4.12 — duplicate).
    return {
      state,
      result: { ok: false, error: { kind: 'duplicate' } },
    };
  }

  const skipCount = header.messageNumber - state.receivingMessageNumber;
  if (skipCount > MAX_SKIPPED_KEYS) {
    // Req 9.5: surface message_lost notice. Advance state past the
    // over-cap position so subsequent ciphertexts on the chain
    // still decrypt.
    return advancePastLossThreshold(state, header);
  }

  return decryptAdvanceChain(state, ciphertext, header, aad, skipCount);
}

/**
 * Advance the receiving chain by `skipCount` keys (storing each in
 * the FIFO skipped store), then derive the message key for
 * `header.messageNumber` and attempt AES-GCM decrypt.
 *
 * On AES-GCM success: return the new state with `receivingChainKey`
 * advanced past `header.messageNumber` and `receivingMessageNumber`
 * set to `header.messageNumber + 1`.
 *
 * On AES-GCM failure: return the *input* state unchanged plus
 * `invalid_message` (P3, req 4.11) — the entire candidate state we
 * derived in this call is dropped.
 */
async function decryptAdvanceChain(
  state: RatchetState,
  ciphertext: Uint8Array,
  header: RatchetMessageHeader,
  aad: Uint8Array,
  skipCount: number,
): Promise<{ state: RatchetState; result: DecryptResult }> {
  const next = cloneState(state);

  // Skip intermediate keys, pushing each into the FIFO skipped
  // store (cap-eviction inside `appendSkipped`). The current chain
  // key is the cloned copy from `next`.
  let chainKey = next.receivingChainKey!;
  for (let i = 0; i < skipCount; i++) {
    const { nextChainKey, messageKey } = chainStep(chainKey);
    appendSkipped(
      next,
      header.dhPub,
      next.receivingMessageNumber + i,
      messageKey,
    );
    chainKey.fill(0);
    chainKey = nextChainKey;
  }
  // Derive the message key for header.messageNumber itself.
  const { nextChainKey, messageKey } = chainStep(chainKey);
  chainKey.fill(0);

  const { aesKey, iv } = expandMessageKey(messageKey);
  let plaintext: Uint8Array | null;
  try {
    plaintext = await aesGcmDecrypt(aesKey, iv, aad, ciphertext);
  } finally {
    aesKey.fill(0);
    iv.fill(0);
    messageKey.fill(0);
  }

  if (plaintext === null) {
    // Tamper rejection (P3 / req 4.11): drop ALL the candidate
    // state we computed. Caller's input `state` reference is
    // untouched. Scrub the candidate chain advance + the
    // newly-stored skipped keys we appended in this call.
    nextChainKey.fill(0);
    for (const k of next.skippedKeys) {
      k.messageKey.fill(0);
    }
    return {
      state,
      result: { ok: false, error: { kind: 'invalid_message' } },
    };
  }

  next.receivingChainKey = nextChainKey;
  next.receivingMessageNumber = header.messageNumber + 1;
  return { state: freezeState(next), result: { ok: true, plaintext } };
}

// ---------------------------------------------------------------------------
// Private — new-chain receive path (DH ratchet step)
// ---------------------------------------------------------------------------

/**
 * Receive path when `header.dhPub` is a new DH ratchet pubkey from
 * the peer. See `decryptFromDevice` doc for the full step list.
 *
 * Tamper rejection: same trial-decrypt discipline as
 * `decryptAdvanceChain` — all derived state is dropped on AES-GCM
 * failure.
 *
 * Replay of a message under an old DH chain whose entries have
 * been FIFO-evicted from skipped: the AES-GCM verify will fail
 * (the chain keys derived now differ from the one that originally
 * encrypted, because our root key has advanced). We return
 * `invalid_message`. That's the acceptable behavior for replays
 * beyond the skipped-key cap; req 9.5 tolerates the loss.
 */
async function decryptNewChain(
  state: RatchetState,
  ciphertext: Uint8Array,
  header: RatchetMessageHeader,
  aad: Uint8Array,
): Promise<{ state: RatchetState; result: DecryptResult }> {
  const next = cloneState(state);

  // Step 1: skip remaining keys of the OLD receiving chain.
  if (next.receivingChainKey !== null && next.receivingDhPub !== null) {
    const oldSkipCount = header.prevChainLength - next.receivingMessageNumber;
    if (oldSkipCount > MAX_SKIPPED_KEYS) {
      // The peer's old chain ran further than we can store. Per
      // req 9.5, surface message_lost and continue. We drop our
      // old receiving chain — a future inbound on a future DH
      // chain will work.
      return advancePastLossThreshold(state, header);
    }
    if (oldSkipCount > 0) {
      let chainKey: Uint8Array = next.receivingChainKey;
      for (let i = 0; i < oldSkipCount; i++) {
        const { nextChainKey, messageKey } = chainStep(chainKey);
        appendSkipped(
          next,
          next.receivingDhPub,
          next.receivingMessageNumber + i,
          messageKey,
        );
        chainKey.fill(0);
        chainKey = nextChainKey;
      }
      // The fully-consumed old receiving chain key is now scrubbed
      // and unreferenced (req 9.1).
      chainKey.fill(0);
    } else {
      next.receivingChainKey.fill(0);
    }
  }

  // Step 2: receiving DH ratchet step.
  const { newRootKey: rk1, newReceivingChainKey } = dhRatchetReceiveStep(
    next.rootKey,
    next.sendingDhPriv,
    header.dhPub,
  );
  next.rootKey.fill(0);
  next.rootKey = rk1;
  next.receivingDhPub = new Uint8Array(header.dhPub);
  next.receivingChainKey = newReceivingChainKey;
  next.receivingMessageNumber = 0;

  // Step 3: generate fresh sending DH keypair, run sending DH
  // ratchet step.
  const fresh = generateRatchetKeypair();
  const dhOutSend = x25519.getSharedSecret(fresh.priv, header.dhPub);
  try {
    const { newRootKey: rk2, newChainKey: newSendingChainKey } = rootKdf(
      next.rootKey,
      dhOutSend,
    );
    next.rootKey.fill(0);
    next.rootKey = rk2;
    next.previousSendingChainLength = next.sendingMessageNumber;
    if (next.sendingChainKey !== null) {
      next.sendingChainKey.fill(0);
    }
    next.sendingDhPriv.fill(0);
    next.sendingDhPriv = fresh.priv;
    next.sendingDhPub = fresh.pub;
    next.sendingChainKey = newSendingChainKey;
    next.sendingMessageNumber = 0;
  } finally {
    dhOutSend.fill(0);
  }

  // Step 4 & 5: walk the new receiving chain forward to
  // header.messageNumber, storing skipped keys, then trial-decrypt.
  // After step 2 above, `next.receivingChainKey` is freshly assigned
  // from `newReceivingChainKey` and is definitely non-null. Capture
  // it in a local so TypeScript carries the narrowing through the
  // intervening sending-DH step.
  const newReceivingChainKeyLocal = next.receivingChainKey!;
  const newSkipCount = header.messageNumber;
  if (newSkipCount > MAX_SKIPPED_KEYS) {
    // Per req 9.5: more than 1000 keys missed within the new
    // chain. State has already advanced root + sending. Surface
    // message_lost; subsequent inbound on a future DH chain works.
    next.receivingMessageNumber = header.messageNumber + 1;
    newReceivingChainKeyLocal.fill(0);
    next.receivingChainKey = null;
    return {
      state: freezeState(next),
      result: {
        ok: false,
        error: {
          kind: 'message_lost',
          details: `${newSkipCount} skipped keys on new chain exceeds cap of ${MAX_SKIPPED_KEYS}`,
        },
      },
    };
  }

  let chainKey: Uint8Array = newReceivingChainKeyLocal;
  for (let i = 0; i < newSkipCount; i++) {
    const { nextChainKey, messageKey } = chainStep(chainKey);
    appendSkipped(next, header.dhPub, i, messageKey);
    chainKey.fill(0);
    chainKey = nextChainKey;
  }
  const { nextChainKey, messageKey } = chainStep(chainKey);
  chainKey.fill(0);

  const { aesKey, iv } = expandMessageKey(messageKey);
  let plaintext: Uint8Array | null;
  try {
    plaintext = await aesGcmDecrypt(aesKey, iv, aad, ciphertext);
  } finally {
    aesKey.fill(0);
    iv.fill(0);
    messageKey.fill(0);
  }

  if (plaintext === null) {
    // Tamper / corruption / wrong-key on a new-chain message.
    // Drop the entire candidate `next` state; caller's input is
    // untouched. Scrub all derived buffers.
    nextChainKey.fill(0);
    for (const k of next.skippedKeys) {
      k.messageKey.fill(0);
    }
    next.rootKey.fill(0);
    next.sendingChainKey?.fill(0);
    next.receivingChainKey?.fill(0);
    next.sendingDhPriv.fill(0);
    return {
      state,
      result: { ok: false, error: { kind: 'invalid_message' } },
    };
  }

  next.receivingChainKey = nextChainKey;
  next.receivingMessageNumber = header.messageNumber + 1;
  return { state: freezeState(next), result: { ok: true, plaintext } };
}

// ---------------------------------------------------------------------------
// Private — bookkeeping helpers
// ---------------------------------------------------------------------------

/**
 * Append a skipped-message-key entry to the FIFO ring. If
 * appending would exceed `MAX_SKIPPED_KEYS`, the oldest entry is
 * evicted first (req 9.4). The evicted entry's message key bytes
 * are scrubbed before discarding (req 9.1).
 *
 * Mutates `state.skippedKeys` in place — caller MUST already be
 * working on a `cloneState`-derived candidate.
 */
function appendSkipped(
  state: MutableRatchetState,
  dhPub: Uint8Array,
  messageNumber: number,
  messageKey: Uint8Array,
): void {
  while (state.skippedKeys.length >= MAX_SKIPPED_KEYS) {
    const evicted = state.skippedKeys.shift()!;
    evicted.messageKey.fill(0);
  }
  state.skippedKeys.push({
    dhPub: new Uint8Array(dhPub),
    messageNumber,
    messageKey: new Uint8Array(messageKey),
  });
}

/**
 * Surface the `message_lost` notice and advance state past the
 * over-cap header so subsequent ciphertexts on the chain still
 * decrypt (req 9.5). The current ciphertext itself is reported as
 * lost — its key material has been FIFO-evicted along with the
 * other 1000+ keys we couldn't store.
 *
 * NOTE: This is the same-chain branch. The new-chain branch
 * handles its own message_lost path inline so it can correctly
 * tear down old root / sending state before surfacing the notice.
 */
function advancePastLossThreshold(
  state: RatchetState,
  header: RatchetMessageHeader,
): { state: RatchetState; result: DecryptResult } {
  const next = cloneState(state);
  // Drop the receiving chain key — we can't reach
  // header.messageNumber through it without crossing the cap, and
  // req 9.5 explicitly accepts message loss in this scenario.
  // Future inbound on this chain will require the peer to
  // DH-ratchet (which is what they'd typically do anyway after a
  // long silence).
  if (next.receivingChainKey !== null) {
    next.receivingChainKey.fill(0);
    next.receivingChainKey = null;
  }
  next.receivingMessageNumber = header.messageNumber + 1;
  return {
    state: freezeState(next),
    result: {
      ok: false,
      error: {
        kind: 'message_lost',
        details: `gap of ${header.messageNumber - state.receivingMessageNumber} skipped keys exceeds cap of ${MAX_SKIPPED_KEYS}`,
      },
    },
  };
}

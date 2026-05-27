// apps/web/src/features/settings/key-backup.ts
//
// Encrypted key-backup export / import (task 9.5 — the export half of
// requirement 15.5, 15.6, 15.7).
//
// What this module owns:
//   - validating the user-supplied passphrase (8–128 chars, requirement
//     15.7),
//   - deriving a 32-byte symmetric key from the passphrase via Argon2id
//     with the requirement-mandated parameters
//     (`m = 64 MiB = 65536 KiB, t = 3, p = 4`, per requirement 15.5)
//     and a fresh 16-byte random salt,
//   - collecting the device's long-term key material from Dexie —
//     identity keypair (with wrapped private bytes unwrapped under
//     the AES-KW KEK so the backup is portable across browsers),
//     prekey state (the signed prekey + every still-relevant OPK),
//     and ratchet sessions (every per-peer ratchet state row),
//   - encrypting the JSON-serialised blob with WebCrypto AES-256-GCM
//     using a fresh 12-byte IV (requirement 15.6 — never export key
//     material in cleartext under any setting),
//   - serialising the binary backup as a single
//     `magic(8) || version(1) || salt(16) || iv(12) || ciphertext(N)`
//     buffer where `ciphertext` is the GCM output (already includes
//     the 16-byte authentication tag). The trailing tag is what
//     guards both the wrong-passphrase path (the GCM verify fails
//     and the import surfaces a typed error) and the tamper path
//     (any single-byte mutation of the file rejects on import).
//
// What this module does NOT own:
//   - the UI affordance for the export / import buttons (lives next
//     to the rest of Settings in `Settings.tsx`),
//   - re-uploading restored prekeys to the API_Gateway (a future
//     restoration flow; out of scope for this task),
//   - any "cleartext export" — there is intentionally NO code path
//     that returns plaintext key bytes (requirement 15.6). The only
//     producer of bytes that leave the module is
//     `exportEncryptedBackup`, which always encrypts.
//
// Threat model
// ------------
// The backup file is intended to be archived by the user (cloud
// drive, USB, etc) and re-imported on a fresh browser to recover
// E2EE history. Confidentiality of every byte in the file rests on
// the passphrase: an attacker who steals the file but does not
// know the passphrase faces an Argon2id-fronted brute force. The
// chosen parameters (`m = 64 MiB, t = 3, p = 4`) match the API's
// password-hashing parameters from design.md §18.2 and are the
// same values requirement 15.5 binds. Salt is per-export, so two
// backups under the same passphrase share no derived key.
//
// We do NOT additionally wrap the derived key under a separate KEK;
// the derived AES-GCM key is used directly. Adding a layer of
// indirection would not change the security boundary (the
// attacker still has the file + the same passphrase guesses) and
// would only widen the format.
//
// File layout (binary, little-endian where multi-byte ints appear)
// ----------------------------------------------------------------
//   offset  size   meaning
//   ------  ----   ----------------------------------------------
//   0       8      magic bytes `"KONVOBK1"` (ASCII)
//   8       1      format version (currently `1`)
//   9       16     Argon2id salt (random per export)
//   25      12     AES-GCM IV (random per export)
//   37      N      AES-GCM ciphertext, including the 16-byte tag
//                  appended by WebCrypto's `subtle.encrypt`
//
// The magic + version prefix lets a future format bump distinguish
// the layout cleanly. Importers reject any file whose magic bytes
// don't match.

import {
  deriveKeyFromPassphrase as cryptoDeriveKeyFromPassphrase,
  unwrapStoredPrekeyPrivate,
  type Argon2idParams,
} from '@konvo/crypto';

import { db, type KonvoDb, type PreKeyRow, type SessionRow } from '../../db/schema.js';

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

/** ASCII magic bytes prefixing every backup file. */
const MAGIC = new TextEncoder().encode('KONVOBK1');

/** Backup format version. Bump on any layout change. */
const FORMAT_VERSION = 1 as const;

/** Argon2id parameters per requirement 15.5. `m` is in KiB
 *  (65536 KiB = 64 MiB). */
const ARGON2_MEMORY_KIB = 65536;
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 4;

/** Length of the random salt fed into Argon2id, per export. */
const SALT_LENGTH = 16;

/** Length of the AES-GCM IV, per export. 96 bits is the recommended
 *  GCM nonce length. */
const IV_LENGTH = 12;

/** Passphrase length bounds per requirement 15.7. */
const MIN_PASSPHRASE_LENGTH = 8;
const MAX_PASSPHRASE_LENGTH = 128;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Validation error code surfaced when a passphrase fails the
 *  length policy (requirement 15.7). The UI maps the code to a
 *  localised message; this module never composes the user-facing
 *  string itself. */
export type PassphraseValidationCode =
  | 'passphrase_empty'
  | 'passphrase_too_short'
  | 'passphrase_too_long';

/** Thrown when the supplied passphrase fails the length policy.
 *  Carries the failure code so the caller can render the right
 *  validation message. */
export class PassphraseValidationError extends Error {
  readonly code: PassphraseValidationCode;

  constructor(code: PassphraseValidationCode) {
    super(`passphrase validation failed: ${code}`);
    this.name = 'PassphraseValidationError';
    this.code = code;
  }
}

/** Thrown by `importEncryptedBackup` when the file's structural
 *  envelope is malformed (wrong magic, truncated, unsupported
 *  version). NEVER thrown for "wrong passphrase" or "ciphertext
 *  tampered" — those surface as `BackupDecryptError`. */
export class BackupFormatError extends Error {
  readonly code: 'magic_mismatch' | 'truncated' | 'unsupported_version';

  constructor(code: BackupFormatError['code'], detail?: string) {
    super(
      detail !== undefined
        ? `backup format error: ${code}: ${detail}`
        : `backup format error: ${code}`,
    );
    this.name = 'BackupFormatError';
    this.code = code;
  }
}

/** Thrown by `importEncryptedBackup` when AES-GCM tag verification
 *  fails. The cause is either a wrong passphrase (the derived key
 *  is different) or a tampered ciphertext (any byte flipped after
 *  encryption). The two are indistinguishable by design — the
 *  caller surfaces a single non-disclosing message. */
export class BackupDecryptError extends Error {
  constructor() {
    super('backup decryption failed: wrong passphrase or tampered file');
    this.name = 'BackupDecryptError';
  }
}

/** Public shape of a successfully imported backup. Byte fields are
 *  fresh `Uint8Array`s; the caller owns scrubbing them after
 *  re-persisting. */
export interface RestoredBackup {
  readonly identity: RestoredIdentity;
  readonly prekeys: readonly RestoredPreKey[];
  readonly sessions: readonly RestoredSession[];
  /** ISO-8601 UTC timestamp the backup was produced. Useful for
   *  displaying "this backup is N days old". */
  readonly exportedAtIso: string;
}

export interface RestoredIdentity {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly ed25519PublicKey: Uint8Array;
  readonly ed25519PrivateKey: Uint8Array;
  readonly registrationId: number;
}

export interface RestoredPreKey {
  readonly keyType: 'signed' | 'opk';
  readonly keyId: number;
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly signature: Uint8Array | null;
  readonly createdAt: number;
  readonly used: boolean;
}

export interface RestoredSession {
  readonly peerUserId: string;
  readonly peerDeviceId: string;
  readonly state: SessionRow['state'];
  readonly updatedAt: number;
}

/** Optional dependencies. Tests inject a stub `database` and may
 *  override the Argon2id parameters to keep the test suite fast.
 *  The default values are the requirement-mandated production
 *  parameters. */
export interface BackupOptions {
  readonly database?: KonvoDb;
  /** Override the Argon2id memory parameter in KiB. ONLY for
   *  tests; production callers MUST NOT pass a value here. */
  readonly argon2MemoryKib?: number;
  /** Override the Argon2id time parameter. ONLY for tests. */
  readonly argon2TimeCost?: number;
  /** Override the Argon2id parallelism parameter. ONLY for tests. */
  readonly argon2Parallelism?: number;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Produce an encrypted backup blob containing the device's identity
 * keypair, prekey state, and ratchet sessions.
 *
 * Validation:
 *   - Throws `PassphraseValidationError('passphrase_empty')` if the
 *     supplied passphrase is the empty string.
 *   - Throws `PassphraseValidationError('passphrase_too_short')` if
 *     the passphrase is fewer than 8 characters.
 *   - Throws `PassphraseValidationError('passphrase_too_long')` if
 *     the passphrase exceeds 128 characters.
 *
 * The validation runs FIRST, before any DB read, so a rejected
 * passphrase produces no side effects (no temp files, no DB row
 * mutation, no log lines that include the passphrase).
 *
 * No code path in this function returns or yields plaintext key
 * bytes. The only producer of output bytes is the AES-GCM
 * ciphertext, which is the body of the returned blob.
 */
export async function exportEncryptedBackup(
  passphrase: string,
  options: BackupOptions = {},
): Promise<Uint8Array> {
  validatePassphrase(passphrase);

  const database = options.database ?? db;

  // --- 1. Collect material from Dexie -------------------------------------
  const identityRow = await database.identity.get('me');
  if (identityRow === undefined) {
    // Refuse to produce an "empty" backup. The caller should never
    // reach this state because Settings only renders the export
    // button after first-run enrollment, but defending against a
    // racey "log out then export" path keeps the contract clear.
    throw new Error(
      'export-encrypted-backup: no identity persisted yet; cannot export',
    );
  }

  const kek = await database.aesKwKeys.get('me');
  if (kek === undefined) {
    throw new Error(
      'export-encrypted-backup: AES-KW KEK missing; cannot unwrap private bytes',
    );
  }

  const identityPriv = await unwrapStoredPrekeyPrivate(
    identityRow.wrappedPrivateKey,
    kek.cryptoKey,
  );
  const identityEdPriv = await unwrapStoredPrekeyPrivate(
    identityRow.wrappedEd25519PrivateKey,
    kek.cryptoKey,
  );

  const prekeyRows: PreKeyRow[] = await database.prekeys.toArray();
  const restoredPrekeys: RestoredPreKey[] = [];
  for (const row of prekeyRows) {
    // Unwrap each prekey's private bytes under the same KEK.
    // Produced once on export; the caller is responsible for
    // scrubbing the bytes from memory once the backup is
    // re-persisted on import. We can't avoid touching plaintext
    // here — the whole point of an exportable backup is that the
    // ciphertext on disk is the only persistent secret bytes the
    // user has to protect.
    const priv = await unwrapStoredPrekeyPrivate(row.wrappedPrivateKey, kek.cryptoKey);
    restoredPrekeys.push({
      keyType: row.keyType,
      keyId: row.keyId,
      publicKey: new Uint8Array(row.publicKey),
      privateKey: priv,
      signature: row.signature !== undefined ? new Uint8Array(row.signature) : null,
      createdAt: row.createdAt,
      used: row.used === 1,
    });
  }

  const sessionRows: SessionRow[] = await database.sessions.toArray();
  const restoredSessions: RestoredSession[] = sessionRows.map((row) => ({
    peerUserId: row.peerUserId,
    peerDeviceId: row.peerDeviceId,
    state: row.state,
    updatedAt: row.updatedAt,
  }));

  const payload = {
    identity: {
      publicKey: bytesToBase64(identityRow.publicKey),
      privateKey: bytesToBase64(identityPriv),
      ed25519PublicKey: bytesToBase64(identityRow.ed25519PublicKey),
      ed25519PrivateKey: bytesToBase64(identityEdPriv),
      registrationId: identityRow.registrationId,
    },
    prekeys: restoredPrekeys.map((p) => ({
      keyType: p.keyType,
      keyId: p.keyId,
      publicKey: bytesToBase64(p.publicKey),
      privateKey: bytesToBase64(p.privateKey),
      signature: p.signature !== null ? bytesToBase64(p.signature) : null,
      createdAt: p.createdAt,
      used: p.used,
    })),
    sessions: restoredSessions.map((s) => ({
      peerUserId: s.peerUserId,
      peerDeviceId: s.peerDeviceId,
      state: serializeStateForBackup(s.state),
      updatedAt: s.updatedAt,
    })),
    exportedAtIso: new Date().toISOString(),
  };

  // --- 2. Derive AES key from passphrase + fresh salt ---------------------
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);

  const derived = await deriveKeyFromPassphrase(
    passphrase,
    salt,
    options.argon2MemoryKib ?? ARGON2_MEMORY_KIB,
    options.argon2TimeCost ?? ARGON2_TIME_COST,
    options.argon2Parallelism ?? ARGON2_PARALLELISM,
  );

  let aesKey: CryptoKey | null = null;
  try {
    aesKey = await crypto.subtle.importKey(
      'raw',
      derived as BufferSource,
      { name: 'AES-GCM' },
      /* extractable */ false,
      ['encrypt', 'decrypt'],
    );

    // --- 3. Encrypt the JSON payload --------------------------------------
    const iv = new Uint8Array(IV_LENGTH);
    crypto.getRandomValues(iv);

    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        aesKey,
        plaintext as BufferSource,
      ),
    );

    // Best-effort scrub of the in-memory plaintext bytes. The
    // serialised payload existed briefly while we constructed it;
    // we can't reach back into the V8 string heap, but we can zero
    // the byte view we just produced.
    plaintext.fill(0);

    // --- 4. Pack the binary blob -----------------------------------------
    return packBackup(salt, iv, ciphertext);
  } finally {
    // Scrub the derived key bytes — the imported AES key is held
    // by WebCrypto and goes out of scope when this function
    // returns, but the raw bytes we passed to `importKey` are
    // ours to clean up.
    derived.fill(0);
    // Scrub the unwrapped identity privates. The serialised
    // payload above already lifted them into a JSON string, but
    // zeroing the buffers we created here at least keeps any
    // stray `Uint8Array` reference from being read by a later
    // crash dump.
    identityPriv.fill(0);
    identityEdPriv.fill(0);
    for (const p of restoredPrekeys) {
      // Defensive: scrub the unwrapped prekey privates too.
      (p.privateKey as Uint8Array).fill(0);
    }
  }
}

/**
 * Inverse of `exportEncryptedBackup`: parse + decrypt + deserialise
 * a backup blob.
 *
 * Throws `PassphraseValidationError` for the same length-bound
 * cases as the export side. Throws `BackupFormatError` for
 * structural problems (bad magic, truncated buffer, unsupported
 * version). Throws `BackupDecryptError` when AES-GCM tag
 * verification fails (wrong passphrase OR tampered file —
 * indistinguishable by design).
 */
export async function importEncryptedBackup(
  blob: Uint8Array,
  passphrase: string,
  options: BackupOptions = {},
): Promise<RestoredBackup> {
  validatePassphrase(passphrase);

  const { salt, iv, ciphertext } = unpackBackup(blob);

  const derived = await deriveKeyFromPassphrase(
    passphrase,
    salt,
    options.argon2MemoryKib ?? ARGON2_MEMORY_KIB,
    options.argon2TimeCost ?? ARGON2_TIME_COST,
    options.argon2Parallelism ?? ARGON2_PARALLELISM,
  );

  try {
    const aesKey = await crypto.subtle.importKey(
      'raw',
      derived as BufferSource,
      { name: 'AES-GCM' },
      /* extractable */ false,
      ['encrypt', 'decrypt'],
    );

    let plaintext: Uint8Array;
    try {
      plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as BufferSource },
          aesKey,
          ciphertext as BufferSource,
        ),
      );
    } catch {
      // WebCrypto throws an OperationError on tag-verify failure.
      // Surface our typed error with no further detail.
      throw new BackupDecryptError();
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(plaintext));
    } finally {
      plaintext.fill(0);
    }

    return parseRestoredBackup(parsed);
  } finally {
    derived.fill(0);
  }
}

/**
 * Convert a `Uint8Array` returned by `exportEncryptedBackup` into a
 * `Blob` suitable for `URL.createObjectURL` + an anchor download.
 * Pure helper, no DOM access — the caller decides what to do with
 * the resulting `Blob`.
 */
export function backupBlob(bytes: Uint8Array): Blob {
  return new Blob([bytes as BlobPart], { type: 'application/octet-stream' });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function validatePassphrase(passphrase: string): void {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new PassphraseValidationError('passphrase_empty');
  }
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new PassphraseValidationError('passphrase_too_short');
  }
  if (passphrase.length > MAX_PASSPHRASE_LENGTH) {
    throw new PassphraseValidationError('passphrase_too_long');
  }
}

async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  memoryKib: number,
  timeCost: number,
  parallelism: number,
): Promise<Uint8Array> {
  const params: Argon2idParams = { memoryKib, timeCost, parallelism };
  return cryptoDeriveKeyFromPassphrase(passphrase, salt, params);
}

function packBackup(
  salt: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(MAGIC.length + 1 + salt.length + iv.length + ciphertext.length);
  let offset = 0;
  out.set(MAGIC, offset);
  offset += MAGIC.length;
  out[offset] = FORMAT_VERSION;
  offset += 1;
  out.set(salt, offset);
  offset += salt.length;
  out.set(iv, offset);
  offset += iv.length;
  out.set(ciphertext, offset);
  return out;
}

interface UnpackedBackup {
  readonly salt: Uint8Array;
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
}

function unpackBackup(blob: Uint8Array): UnpackedBackup {
  const headerLength = MAGIC.length + 1 + SALT_LENGTH + IV_LENGTH;
  if (blob.length < headerLength + 16 /* min ciphertext = GCM tag */) {
    throw new BackupFormatError('truncated', `blob length ${blob.length}`);
  }
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (blob[i] !== MAGIC[i]) {
      throw new BackupFormatError('magic_mismatch');
    }
  }
  const version = blob[MAGIC.length];
  if (version !== FORMAT_VERSION) {
    throw new BackupFormatError(
      'unsupported_version',
      `expected ${String(FORMAT_VERSION)}, got ${String(version)}`,
    );
  }
  let offset = MAGIC.length + 1;
  const salt = blob.slice(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = blob.slice(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const ciphertext = blob.slice(offset);
  return { salt, iv, ciphertext };
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/** Convert a `SessionRow.state` (`SerializedRatchetState` with raw
 *  `Uint8Array`s) into a JSON-serialisable form that base64-encodes
 *  every byte buffer. Used on the export side to keep the JSON
 *  payload pure-string. */
function serializeStateForBackup(state: SessionRow['state']): Record<string, unknown> {
  return {
    rootKey: bytesToBase64(state.rootKey),
    sendingDhPriv: bytesToBase64(state.sendingDhPriv),
    sendingDhPub: bytesToBase64(state.sendingDhPub),
    receivingDhPub:
      state.receivingDhPub === null ? null : bytesToBase64(state.receivingDhPub),
    sendingChainKey:
      state.sendingChainKey === null ? null : bytesToBase64(state.sendingChainKey),
    receivingChainKey:
      state.receivingChainKey === null ? null : bytesToBase64(state.receivingChainKey),
    sendingMessageNumber: state.sendingMessageNumber,
    receivingMessageNumber: state.receivingMessageNumber,
    previousSendingChainLength: state.previousSendingChainLength,
    skippedKeys: state.skippedKeys.map((k: { dhPub: Uint8Array; messageNumber: number; messageKey: Uint8Array }) => ({
      dhPub: bytesToBase64(k.dhPub),
      messageNumber: k.messageNumber,
      messageKey: bytesToBase64(k.messageKey),
    })),
  };
}

function deserializeStateFromBackup(input: unknown): SessionRow['state'] {
  if (typeof input !== 'object' || input === null) {
    throw new Error('restore: state is not an object');
  }
  const o = input as Record<string, unknown>;
  return {
    rootKey: base64ToBytes(asString(o['rootKey'])),
    sendingDhPriv: base64ToBytes(asString(o['sendingDhPriv'])),
    sendingDhPub: base64ToBytes(asString(o['sendingDhPub'])),
    receivingDhPub:
      o['receivingDhPub'] === null
        ? null
        : base64ToBytes(asString(o['receivingDhPub'])),
    sendingChainKey:
      o['sendingChainKey'] === null
        ? null
        : base64ToBytes(asString(o['sendingChainKey'])),
    receivingChainKey:
      o['receivingChainKey'] === null
        ? null
        : base64ToBytes(asString(o['receivingChainKey'])),
    sendingMessageNumber: asNumber(o['sendingMessageNumber']),
    receivingMessageNumber: asNumber(o['receivingMessageNumber']),
    previousSendingChainLength: asNumber(o['previousSendingChainLength']),
    skippedKeys: asArray(o['skippedKeys']).map((k) => {
      const e = k as Record<string, unknown>;
      return {
        dhPub: base64ToBytes(asString(e['dhPub'])),
        messageNumber: asNumber(e['messageNumber']),
        messageKey: base64ToBytes(asString(e['messageKey'])),
      };
    }),
  };
}

function parseRestoredBackup(input: unknown): RestoredBackup {
  if (typeof input !== 'object' || input === null) {
    throw new BackupFormatError('truncated', 'payload is not a JSON object');
  }
  const o = input as Record<string, unknown>;

  const idObj = o['identity'];
  if (typeof idObj !== 'object' || idObj === null) {
    throw new BackupFormatError('truncated', 'identity missing');
  }
  const id = idObj as Record<string, unknown>;

  const restoredIdentity: RestoredIdentity = {
    publicKey: base64ToBytes(asString(id['publicKey'])),
    privateKey: base64ToBytes(asString(id['privateKey'])),
    ed25519PublicKey: base64ToBytes(asString(id['ed25519PublicKey'])),
    ed25519PrivateKey: base64ToBytes(asString(id['ed25519PrivateKey'])),
    registrationId: asNumber(id['registrationId']),
  };

  const prekeys = asArray(o['prekeys']).map((row): RestoredPreKey => {
    const r = row as Record<string, unknown>;
    const keyType = asString(r['keyType']);
    if (keyType !== 'signed' && keyType !== 'opk') {
      throw new BackupFormatError('truncated', `prekey keyType=${keyType}`);
    }
    return {
      keyType,
      keyId: asNumber(r['keyId']),
      publicKey: base64ToBytes(asString(r['publicKey'])),
      privateKey: base64ToBytes(asString(r['privateKey'])),
      signature:
        r['signature'] === null
          ? null
          : base64ToBytes(asString(r['signature'])),
      createdAt: asNumber(r['createdAt']),
      used: asBoolean(r['used']),
    };
  });

  const sessions = asArray(o['sessions']).map((row): RestoredSession => {
    const r = row as Record<string, unknown>;
    return {
      peerUserId: asString(r['peerUserId']),
      peerDeviceId: asString(r['peerDeviceId']),
      state: deserializeStateFromBackup(r['state']),
      updatedAt: asNumber(r['updatedAt']),
    };
  });

  return {
    identity: restoredIdentity,
    prekeys,
    sessions,
    exportedAtIso: asString(o['exportedAtIso']),
  };
}

function asString(v: unknown): string {
  if (typeof v !== 'string') {
    throw new BackupFormatError('truncated', `expected string, got ${typeof v}`);
  }
  return v;
}

function asNumber(v: unknown): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    throw new BackupFormatError('truncated', `expected number, got ${typeof v}`);
  }
  return v;
}

function asBoolean(v: unknown): boolean {
  if (typeof v !== 'boolean') {
    throw new BackupFormatError('truncated', `expected boolean, got ${typeof v}`);
  }
  return v;
}

function asArray(v: unknown): unknown[] {
  if (!Array.isArray(v)) {
    throw new BackupFormatError('truncated', `expected array, got ${typeof v}`);
  }
  return v;
}

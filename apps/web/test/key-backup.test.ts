// apps/web/test/key-backup.test.ts
//
// Tests for task 9.5's encrypted key-backup module
// (`apps/web/src/features/settings/key-backup.ts`). Realises the
// "tests" plank of the task brief:
//
//   - Reject passphrases that are empty or shorter than 8 chars
//     (and reject > 128 chars too) — requirement 15.7.
//   - Round-trip: importEncryptedBackup(exportEncryptedBackup(p), p)
//     recovers identity bytes, prekey privates, and ratchet sessions
//     verbatim — requirement 15.5.
//   - Importing with the wrong passphrase fails with a typed
//     decrypt error (AES-GCM tag verification) — requirement 15.6.
//   - The exported binary blob does NOT contain the cleartext
//     identity-private bytes anywhere — requirement 15.6, defended
//     in depth with a substring scan.
//
// Test discipline: tests use the *real* WebCrypto + the *real*
// Argon2id, but with reduced parameters (`memoryKib = 1024 KiB,
// t = 1, p = 1`) so the suite stays fast (≈ 50 ms per round trip
// instead of seconds at production parameters). The chosen
// parameters still exercise the full Argon2id path; production
// callers always use the requirement-mandated parameters.
//
// Tests run under jsdom + fake-indexeddb (see `test/setup.ts`).

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  BackupDecryptError,
  BackupFormatError,
  exportEncryptedBackup,
  importEncryptedBackup,
  PassphraseValidationError,
  type BackupOptions,
} from '../src/features/settings/key-backup.js';
import { KonvoDb } from '../src/db/schema.js';

// Inlined AES-KW wrap helper that mirrors the production helper in
// `packages/crypto/src/internal/aes-kw.ts`. Duplicated here (rather
// than imported as a subpath) because `@konvo/crypto` only exposes
// its top-level entry point in the workspace export map. The two
// implementations must stay byte-compatible — if a future change
// alters the wrap algorithm in either spot, this test will break
// at the round-trip assertion below, surfacing the drift.
async function wrapPrivateKeyBytes(
  privateKeyBytes: Uint8Array,
  kek: CryptoKey,
): Promise<Uint8Array> {
  const inner = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(privateKeyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    /* extractable */ true,
    ['sign'],
  );
  const wrapped = await crypto.subtle.wrapKey('raw', inner, kek, 'AES-KW');
  return new Uint8Array(wrapped);
}

// ---------------------------------------------------------------------------
// Test fixtures — fresh DB per case, pre-populated with deterministic
// identity/prekey/session bytes so we can assert exact round-trip values.
// ---------------------------------------------------------------------------

let activeDb: KonvoDb | null = null;

function freshDb(): KonvoDb {
  const name = `konvo-test-${Math.random().toString(36).slice(2)}`;
  activeDb = new KonvoDb(name);
  return activeDb;
}

afterEach(async () => {
  if (activeDb !== null) {
    activeDb.close();
    await activeDb.delete();
    activeDb = null;
  }
});

/** Test-only Argon2id parameters. ~50 ms per derive on a modern
 *  CPU; production uses `memoryKib = 65536, t = 3, p = 4` per
 *  requirement 15.5. The export still exercises the real
 *  `argon2idAsync` code path. */
const FAST_ARGON2: BackupOptions = {
  argon2MemoryKib: 1024,
  argon2TimeCost: 1,
  argon2Parallelism: 1,
};

/** Identity material with recognisable canary bytes, so the
 *  no-cleartext-leak test can grep the encrypted blob for them. */
const IDENTITY_PUB = new Uint8Array(32).fill(0xab);
const IDENTITY_PRIV = new Uint8Array(32).fill(0xcd);
const IDENTITY_ED_PUB = new Uint8Array(32).fill(0xef);
const IDENTITY_ED_PRIV = new Uint8Array(32).fill(0x12);
const REGISTRATION_ID = 4242;

const SIGNED_PUB = new Uint8Array(32).fill(0x21);
const SIGNED_PRIV = new Uint8Array(32).fill(0x22);
const SIGNED_SIG = new Uint8Array(64).fill(0x23);

const OPK_PUB = new Uint8Array(32).fill(0x31);
const OPK_PRIV = new Uint8Array(32).fill(0x32);

/** Pre-populate the DB with one identity + one signed prekey + one
 *  OPK + one ratchet session row. Returns the wrapped DB so callers
 *  can pass it through `BackupOptions.database`. */
async function seedDatabase(database: KonvoDb): Promise<void> {
  // Generate the AES-KW KEK and persist it.
  const kek = await crypto.subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    /* extractable */ false,
    ['wrapKey', 'unwrapKey'],
  );
  await database.aesKwKeys.put({ id: 'me', cryptoKey: kek });

  // Wrap and persist the identity.
  const wrappedIdentity = await wrapPrivateKeyBytes(IDENTITY_PRIV, kek);
  const wrappedEdIdentity = await wrapPrivateKeyBytes(IDENTITY_ED_PRIV, kek);
  await database.identity.put({
    id: 'me',
    publicKey: IDENTITY_PUB,
    wrappedPrivateKey: wrappedIdentity,
    ed25519PublicKey: IDENTITY_ED_PUB,
    wrappedEd25519PrivateKey: wrappedEdIdentity,
    registrationId: REGISTRATION_ID,
    createdAt: 1700000000000,
  });

  // Persist a signed prekey and an OPK.
  const wrappedSigned = await wrapPrivateKeyBytes(SIGNED_PRIV, kek);
  await database.prekeys.add({
    keyType: 'signed',
    keyId: 1,
    publicKey: SIGNED_PUB,
    wrappedPrivateKey: wrappedSigned,
    signature: SIGNED_SIG,
    createdAt: 1700000001000,
    used: 0,
  });

  const wrappedOpk = await wrapPrivateKeyBytes(OPK_PRIV, kek);
  await database.prekeys.add({
    keyType: 'opk',
    keyId: 7,
    publicKey: OPK_PUB,
    wrappedPrivateKey: wrappedOpk,
    createdAt: 1700000002000,
    used: 0,
  });

  // Persist a ratchet session row.
  await database.sessions.put({
    id: 'peer-user-1:peer-device-1',
    peerUserId: 'peer-user-1',
    peerDeviceId: 'peer-device-1',
    state: {
      rootKey: new Uint8Array(32).fill(0x41),
      sendingDhPriv: new Uint8Array(32).fill(0x42),
      sendingDhPub: new Uint8Array(32).fill(0x43),
      receivingDhPub: new Uint8Array(32).fill(0x44),
      sendingChainKey: new Uint8Array(32).fill(0x45),
      receivingChainKey: null,
      sendingMessageNumber: 5,
      receivingMessageNumber: 0,
      previousSendingChainLength: 0,
      skippedKeys: [
        {
          dhPub: new Uint8Array(32).fill(0x46),
          messageNumber: 2,
          messageKey: new Uint8Array(32).fill(0x47),
        },
      ],
    },
    updatedAt: 1700000003000,
  });
}

beforeEach(() => {
  // Sanity guard: each test starts with no leftover db handle.
  activeDb = null;
});

// ---------------------------------------------------------------------------
// 1. Passphrase validation (requirement 15.7)
// ---------------------------------------------------------------------------

describe('exportEncryptedBackup — passphrase validation', () => {
  it('rejects an empty passphrase before any DB read', async () => {
    const db = freshDb(); // intentionally not seeded
    await expect(
      exportEncryptedBackup('', { database: db, ...FAST_ARGON2 }),
    ).rejects.toBeInstanceOf(PassphraseValidationError);
    await expect(
      exportEncryptedBackup('', { database: db, ...FAST_ARGON2 }),
    ).rejects.toMatchObject({ code: 'passphrase_empty' });
  });

  it('rejects passphrases shorter than 8 characters', async () => {
    const db = freshDb();
    for (const tooShort of ['a', 'ab', '1234567']) {
      await expect(
        exportEncryptedBackup(tooShort, { database: db, ...FAST_ARGON2 }),
      ).rejects.toMatchObject({
        name: 'PassphraseValidationError',
        code: 'passphrase_too_short',
      });
    }
  });

  it('rejects passphrases longer than 128 characters', async () => {
    const db = freshDb();
    const tooLong = 'x'.repeat(129);
    await expect(
      exportEncryptedBackup(tooLong, { database: db, ...FAST_ARGON2 }),
    ).rejects.toMatchObject({
      name: 'PassphraseValidationError',
      code: 'passphrase_too_long',
    });
  });

  it('accepts a passphrase exactly 8 characters long', async () => {
    const db = freshDb();
    await seedDatabase(db);
    const blob = await exportEncryptedBackup('12345678', {
      database: db,
      ...FAST_ARGON2,
    });
    expect(blob.byteLength).toBeGreaterThan(0);
  });

  it('accepts a passphrase exactly 128 characters long', async () => {
    const db = freshDb();
    await seedDatabase(db);
    const blob = await exportEncryptedBackup('y'.repeat(128), {
      database: db,
      ...FAST_ARGON2,
    });
    expect(blob.byteLength).toBeGreaterThan(0);
  });
});

describe('importEncryptedBackup — passphrase validation', () => {
  it('rejects empty / short / long passphrases regardless of blob shape', async () => {
    const empty = new Uint8Array(0);
    await expect(importEncryptedBackup(empty, '')).rejects.toMatchObject({
      name: 'PassphraseValidationError',
      code: 'passphrase_empty',
    });
    await expect(importEncryptedBackup(empty, 'short')).rejects.toMatchObject({
      code: 'passphrase_too_short',
    });
    await expect(
      importEncryptedBackup(empty, 'q'.repeat(200)),
    ).rejects.toMatchObject({
      code: 'passphrase_too_long',
    });
  });
});

// ---------------------------------------------------------------------------
// 2. Round-trip: export → import recovers identity / prekeys / sessions
// ---------------------------------------------------------------------------

describe('exportEncryptedBackup → importEncryptedBackup round-trip', () => {
  it('recovers identity, prekey privates, and session state byte-for-byte', async () => {
    const db = freshDb();
    await seedDatabase(db);

    const passphrase = 'correct horse battery staple';
    const blob = await exportEncryptedBackup(passphrase, {
      database: db,
      ...FAST_ARGON2,
    });

    const restored = await importEncryptedBackup(blob, passphrase, FAST_ARGON2);

    // Identity round-trip.
    expect(Array.from(restored.identity.publicKey)).toEqual(Array.from(IDENTITY_PUB));
    expect(Array.from(restored.identity.privateKey)).toEqual(Array.from(IDENTITY_PRIV));
    expect(Array.from(restored.identity.ed25519PublicKey)).toEqual(
      Array.from(IDENTITY_ED_PUB),
    );
    expect(Array.from(restored.identity.ed25519PrivateKey)).toEqual(
      Array.from(IDENTITY_ED_PRIV),
    );
    expect(restored.identity.registrationId).toBe(REGISTRATION_ID);

    // Prekey round-trip — order is whatever Dexie returns; sort by
    // keyType+keyId to compare deterministically.
    const sorted = [...restored.prekeys].sort((a, b) =>
      a.keyType === b.keyType ? a.keyId - b.keyId : a.keyType.localeCompare(b.keyType),
    );
    expect(sorted).toHaveLength(2);

    const opk = sorted.find((p) => p.keyType === 'opk');
    expect(opk).toBeDefined();
    expect(opk?.keyId).toBe(7);
    expect(Array.from(opk!.publicKey)).toEqual(Array.from(OPK_PUB));
    expect(Array.from(opk!.privateKey)).toEqual(Array.from(OPK_PRIV));
    expect(opk?.signature).toBeNull();
    expect(opk?.used).toBe(false);

    const signed = sorted.find((p) => p.keyType === 'signed');
    expect(signed).toBeDefined();
    expect(signed?.keyId).toBe(1);
    expect(Array.from(signed!.publicKey)).toEqual(Array.from(SIGNED_PUB));
    expect(Array.from(signed!.privateKey)).toEqual(Array.from(SIGNED_PRIV));
    expect(Array.from(signed!.signature!)).toEqual(Array.from(SIGNED_SIG));

    // Session round-trip.
    expect(restored.sessions).toHaveLength(1);
    const session = restored.sessions[0]!;
    expect(session.peerUserId).toBe('peer-user-1');
    expect(session.peerDeviceId).toBe('peer-device-1');
    expect(Array.from(session.state.rootKey)).toEqual(Array.from(new Uint8Array(32).fill(0x41)));
    expect(Array.from(session.state.sendingDhPriv)).toEqual(
      Array.from(new Uint8Array(32).fill(0x42)),
    );
    expect(session.state.sendingMessageNumber).toBe(5);
    expect(session.state.skippedKeys).toHaveLength(1);
    expect(session.state.skippedKeys[0]!.messageNumber).toBe(2);
    expect(Array.from(session.state.skippedKeys[0]!.messageKey)).toEqual(
      Array.from(new Uint8Array(32).fill(0x47)),
    );

    // Exported-at timestamp is a parseable ISO-8601 string.
    expect(Number.isFinite(Date.parse(restored.exportedAtIso))).toBe(true);
  });

  it('produces distinct ciphertext for two exports under the same passphrase (fresh salt + IV)', async () => {
    const db = freshDb();
    await seedDatabase(db);
    const passphrase = 'correct horse battery staple';

    const blobA = await exportEncryptedBackup(passphrase, {
      database: db,
      ...FAST_ARGON2,
    });
    const blobB = await exportEncryptedBackup(passphrase, {
      database: db,
      ...FAST_ARGON2,
    });

    // Same passphrase, but the per-export salt + IV differ, so the
    // ciphertexts must not be byte-equal.
    expect(blobA.byteLength).toBe(blobB.byteLength);
    let allEqual = true;
    for (let i = 0; i < blobA.length; i += 1) {
      if (blobA[i] !== blobB[i]) {
        allEqual = false;
        break;
      }
    }
    expect(allEqual).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 3. Wrong passphrase rejects with BackupDecryptError
// ---------------------------------------------------------------------------

describe('importEncryptedBackup — wrong passphrase', () => {
  it('throws BackupDecryptError when the passphrase does not match', async () => {
    const db = freshDb();
    await seedDatabase(db);

    const blob = await exportEncryptedBackup('correct passphrase', {
      database: db,
      ...FAST_ARGON2,
    });

    await expect(
      importEncryptedBackup(blob, 'wrong passphrase', FAST_ARGON2),
    ).rejects.toBeInstanceOf(BackupDecryptError);
  });

  it('throws BackupDecryptError when any single byte of ciphertext is flipped', async () => {
    const db = freshDb();
    await seedDatabase(db);
    const passphrase = 'correct horse battery staple';

    const blob = await exportEncryptedBackup(passphrase, {
      database: db,
      ...FAST_ARGON2,
    });

    // Flip a byte well inside the ciphertext region (after the
    // 8-byte magic + 1-byte version + 16-byte salt + 12-byte IV =
    // 37-byte header, so index 50 is solidly within the GCM body).
    const tampered = new Uint8Array(blob);
    tampered[50] = (tampered[50]! ^ 0xff) & 0xff;

    await expect(
      importEncryptedBackup(tampered, passphrase, FAST_ARGON2),
    ).rejects.toBeInstanceOf(BackupDecryptError);
  });
});

// ---------------------------------------------------------------------------
// 4. No cleartext key material in the exported blob (requirement 15.6)
// ---------------------------------------------------------------------------

describe('exportEncryptedBackup — never exports cleartext key material', () => {
  it('produces a blob that does NOT contain the raw identity/prekey/session bytes', async () => {
    const db = freshDb();
    await seedDatabase(db);
    const passphrase = 'correct horse battery staple';

    const blob = await exportEncryptedBackup(passphrase, {
      database: db,
      ...FAST_ARGON2,
    });

    // Build the set of "cleartext canaries" the blob must NOT
    // contain: every secret byte sequence that lived in plaintext
    // in the in-memory state.
    const canaries: Uint8Array[] = [
      IDENTITY_PRIV,
      IDENTITY_ED_PRIV,
      SIGNED_PRIV,
      OPK_PRIV,
      // Ratchet privates / chain keys also count as cleartext key
      // material — the AES-GCM ciphertext must hide them as well.
      new Uint8Array(32).fill(0x41), // rootKey
      new Uint8Array(32).fill(0x42), // sendingDhPriv
      new Uint8Array(32).fill(0x45), // sendingChainKey
      new Uint8Array(32).fill(0x47), // skippedKeys[0].messageKey
    ];

    // Each canary is 32 bytes, all-the-same-byte. We check via
    // a window scan: the blob must not contain any 32-byte run
    // of the canary's repeated byte. This catches any failure
    // mode where the export accidentally writes the cleartext
    // bytes into the file (sloppy serialisation, base64'd
    // private buffer that didn't get encrypted, etc).
    for (const canary of canaries) {
      const repeatedByte = canary[0]!;
      let foundRun = false;
      let runLength = 0;
      for (let i = 0; i < blob.length; i += 1) {
        if (blob[i] === repeatedByte) {
          runLength += 1;
          if (runLength >= canary.length) {
            foundRun = true;
            break;
          }
        } else {
          runLength = 0;
        }
      }
      // AES-GCM with a fresh IV produces uniform-looking
      // ciphertext, so a 32-byte run of the canary's value
      // would only appear with probability ≈ 256^-32 ≈ 0. If
      // we see one, the export leaked plaintext.
      expect(foundRun).toBe(false);
    }
  });

  it('rejects modified-magic / truncated blobs with BackupFormatError', async () => {
    const db = freshDb();
    await seedDatabase(db);
    const blob = await exportEncryptedBackup('passphrase!', {
      database: db,
      ...FAST_ARGON2,
    });

    // Truncate to below the header size.
    const truncated = blob.slice(0, 10);
    await expect(
      importEncryptedBackup(truncated, 'passphrase!', FAST_ARGON2),
    ).rejects.toBeInstanceOf(BackupFormatError);

    // Flip the magic byte.
    const wrongMagic = new Uint8Array(blob);
    wrongMagic[0] = (wrongMagic[0]! ^ 0x01) & 0xff;
    await expect(
      importEncryptedBackup(wrongMagic, 'passphrase!', FAST_ARGON2),
    ).rejects.toMatchObject({ name: 'BackupFormatError', code: 'magic_mismatch' });
  });
});

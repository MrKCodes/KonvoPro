// @konvo/crypto — libsignal wrapper providing identity, prekey, session,
// ratchet, attachment, and safety-number primitives.
//
// Per design.md Appendix A this package is the only place libsignal types
// are allowed to be referenced from, so the rest of the monorepo stays
// libsignal-free until those modules ship.
//
// Currently exported:
//   - identity primitives (task 2.7): Curve25519 keypair + registration
//     ID, AES-KW wrapping, branded private-key type.
//   - prekey primitives (task 2.8): generateInitialBundle,
//     replenishOneTimePreKeys, rotateSignedPreKey, plus shared
//     PreKeyStore / SignedPreKeyRecord / OneTimePreKeyRecord shapes.
//   - X3DH session establishment (task 4.2): establishSession (Alice),
//     acceptSession (Bob), RemotePreKeyBundle / SessionInit /
//     EstablishedSession shapes, InvalidSignedPreKeyError. Phase-3
//     placeholder built on @noble/curves; libsignal swap lands in
//     subsequent 4.x tasks.
//   - broadcast signing (task 7.1): signBroadcastPost,
//     verifyBroadcastPost, canonicalBroadcastMessage — Ed25519 over
//     `(body || roomId || createdAtMs)`.
//   - safety-number (task 4.8): computeSafetyNumber — Signal-style
//     5200-iteration SHA-512 fingerprint over `(identityPub, userId)`
//     pairs, encoded as 60 digits in 12 groups of 5 plus a 60-byte
//     QR payload.
//   - Double Ratchet (task 4.3): initSenderRatchet,
//     initReceiverRatchet, encryptToDevice, decryptFromDevice plus
//     RatchetState / RatchetMessageHeader / DecryptResult shapes.
//     Phase-3 placeholder built on @noble/curves + @noble/hashes +
//     WebCrypto AES-GCM; libsignal swap lands in subsequent 4.x
//     tasks.
//   - Attachment AES-GCM (task 5.1): encryptAttachment,
//     decryptAttachment plus EncryptedAttachment /
//     AttachmentDecryptResult / AttachmentDecryptError shapes.
//     WebCrypto AES-256-GCM with fresh per-attachment 32-byte key
//     and 12-byte IV; tag-failure surface is a typed
//     `invalid_attachment` result that never carries partial bytes.
//   - SignalProtocolStore contract (task 4.4): the
//     `SignalProtocolStore` interface, `SerializedRatchetState`
//     wire shape, plus `serializeRatchetState` /
//     `deserializeRatchetState` helpers used by the Dexie-backed
//     adapter in `apps/web/src/db/repositories/sessions.ts` and
//     by any future in-memory test double.

export * from './identity.js';
export * from './prekeys.js';
export * from './session.js';
export * from './broadcast.js';
export * from './safety-number.js';
export * from './ratchet.js';
export * from './attachment.js';
export * from './store.js';
export * from './passphrase-kdf.js';

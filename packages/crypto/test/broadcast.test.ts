// Tests for task 7.1: broadcast post signing/verification.
//
// Exercises `signBroadcastPost` and `verifyBroadcastPost` against the
// real `@noble/curves` Ed25519 backend; no mocking. Identity keypairs
// come from the standard `getOrCreateIdentity` flow so we sign with the
// same Ed25519 sub-key shape that the rest of the package uses.
//
// Tamper coverage exercises every input that participates in the
// canonical message — body, roomId, createdAtMs — plus the signature
// bytes and the verifier's public key.

import { describe, expect, it } from 'vitest';

import {
  canonicalBroadcastMessage,
  signBroadcastPost,
  verifyBroadcastPost,
} from '../src/broadcast.js';
import {
  MemoryIdentityStore,
  getOrCreateIdentity,
  type IdentityKeyPair,
} from '../src/identity.js';

async function freshIdentity(): Promise<IdentityKeyPair> {
  const store = new MemoryIdentityStore();
  return getOrCreateIdentity(store);
}

describe('canonicalBroadcastMessage', () => {
  it('encodes body, roomId, and a little-endian u64 createdAtMs', () => {
    const bytes = canonicalBroadcastMessage('hi', 'rm', 1);

    // utf8('hi') = [0x68, 0x69]; utf8('rm') = [0x72, 0x6d];
    // u64-le(1)  = [0x01, 0, 0, 0, 0, 0, 0, 0]
    expect(Array.from(bytes)).toEqual([
      0x68, 0x69, 0x72, 0x6d, 0x01, 0, 0, 0, 0, 0, 0, 0,
    ]);
  });

  it('uses 64-bit little-endian for createdAtMs (above 2^32)', () => {
    // 0x0000_0001_0000_0000 = 4294967296 → bytes [0,0,0,0, 1,0,0,0]
    const bytes = canonicalBroadcastMessage('', '', 0x100000000);
    expect(Array.from(bytes)).toEqual([0, 0, 0, 0, 1, 0, 0, 0]);
  });

  it('is stable across calls', () => {
    const a = canonicalBroadcastMessage('hello', 'room-1', 1700000000000);
    const b = canonicalBroadcastMessage('hello', 'room-1', 1700000000000);
    expect(Array.from(a)).toEqual(Array.from(b));
  });
});

describe('signBroadcastPost / verifyBroadcastPost round-trip (requirements 10.4, 10.8)', () => {
  it('verify returns true for a freshly-signed post', async () => {
    const id = await freshIdentity();
    const body = 'hello world';
    const roomId = 'room-abc';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);

    expect(sig.length).toBe(64);
    expect(
      verifyBroadcastPost(body, roomId, createdAtMs, sig, id.ed25519PublicKey),
    ).toBe(true);
  });

  it('signs over (body || roomId || createdAtMs) — verifying with concatenation order swapped fails', async () => {
    const id = await freshIdentity();
    const body = 'a';
    const roomId = 'b';
    const createdAtMs = 7;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);

    // Swap body/roomId roles → different canonical message → must fail.
    expect(
      verifyBroadcastPost(roomId, body, createdAtMs, sig, id.ed25519PublicKey),
    ).toBe(false);
  });
});

describe('verifyBroadcastPost rejects tampering (requirement 10.9)', () => {
  it('tampered body fails verify', async () => {
    const id = await freshIdentity();
    const body = 'original body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);

    expect(
      verifyBroadcastPost(
        'tampered body',
        roomId,
        createdAtMs,
        sig,
        id.ed25519PublicKey,
      ),
    ).toBe(false);
  });

  it('tampered roomId fails verify', async () => {
    const id = await freshIdentity();
    const body = 'body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);

    expect(
      verifyBroadcastPost(body, 'room-2', createdAtMs, sig, id.ed25519PublicKey),
    ).toBe(false);
  });

  it('tampered createdAtMs fails verify (single ms shift)', async () => {
    const id = await freshIdentity();
    const body = 'body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);

    expect(
      verifyBroadcastPost(
        body,
        roomId,
        createdAtMs + 1,
        sig,
        id.ed25519PublicKey,
      ),
    ).toBe(false);
  });

  it('tampered signature (single-byte flip) fails verify', async () => {
    const id = await freshIdentity();
    const body = 'body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);
    const tampered = new Uint8Array(sig);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff;

    expect(
      verifyBroadcastPost(body, roomId, createdAtMs, tampered, id.ed25519PublicKey),
    ).toBe(false);
  });

  it('verify with a different identity public key fails', async () => {
    const a = await freshIdentity();
    const b = await freshIdentity();
    const body = 'body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, a.ed25519PrivateKey);

    expect(
      verifyBroadcastPost(body, roomId, createdAtMs, sig, b.ed25519PublicKey),
    ).toBe(false);
  });

  it('returns false (does not throw) on a malformed signature length', async () => {
    const id = await freshIdentity();
    const body = 'body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    // 10-byte signature is far short of the 64-byte Ed25519 spec.
    const garbage = new Uint8Array(10);

    expect(
      verifyBroadcastPost(body, roomId, createdAtMs, garbage, id.ed25519PublicKey),
    ).toBe(false);
  });

  it('returns false (does not throw) on a malformed public key length', async () => {
    const id = await freshIdentity();
    const body = 'body';
    const roomId = 'room-1';
    const createdAtMs = 1_700_000_000_000;

    const sig = signBroadcastPost(body, roomId, createdAtMs, id.ed25519PrivateKey);
    const badPub = new Uint8Array(8); // not 32 bytes

    expect(verifyBroadcastPost(body, roomId, createdAtMs, sig, badPub)).toBe(
      false,
    );
  });
});

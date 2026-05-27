// Unit tests for the access-token service (task 2.2).
//
// Validates Requirements 1.3 (HS256 access token with claims
// {sub, did, iat, exp}) and the verify-rejects-tampering posture
// implied by 1.6 / 1.7.
//
// Note on scope: the refresh-token store touches Postgres (FOR UPDATE
// row locking, transactional family-revoke). Mocking the pg.Pool
// surface would risk asserting against the test's own SQL strings
// rather than real semantics, so per the task brief the refresh-token
// behaviour will land in `apps/api/test/tokens.integration.spec.ts`
// (run against a real Postgres in CI). Here we only cover the
// access-token service, which is pure CPU + jose calls.

import { describe, expect, it } from 'vitest';

import { createAccessTokenService } from '../src/services/auth/tokens.js';

// 32+ chars to satisfy the same minimum the config schema enforces on
// JWT_ACCESS_SECRET. Two distinct secrets so the wrong-secret test can
// flip between them.
const SECRET_A = 'a'.repeat(32) + '-secret-A';
const SECRET_B = 'b'.repeat(32) + '-secret-B';

describe('createAccessTokenService', () => {
  it('sign + verify round-trip preserves sub and did', async () => {
    const svc = createAccessTokenService(SECRET_A);
    const claimsIn = {
      sub: '11111111-1111-1111-1111-111111111111',
      did: '22222222-2222-2222-2222-222222222222',
    };

    const token = await svc.sign(claimsIn);
    const claimsOut = await svc.verify(token);

    expect(claimsOut.sub).toBe(claimsIn.sub);
    expect(claimsOut.did).toBe(claimsIn.did);
    // iat/exp are populated by jose. exp must be exactly `iat + ttl`.
    expect(claimsOut.iat).toBeGreaterThan(0);
    expect(claimsOut.exp).toBe(claimsOut.iat + 15 * 60);
  });

  it('verify rejects an expired token', async () => {
    // 1-second TTL keeps the test fast; we just need any value < the
    // wait below so jose's clock check trips.
    const svc = createAccessTokenService(SECRET_A, 1);
    const token = await svc.sign({
      sub: '11111111-1111-1111-1111-111111111111',
      did: '22222222-2222-2222-2222-222222222222',
    });

    // Wait past the TTL. jose accepts a small clock skew by default
    // (none for jwtVerify without a tolerance option), so 1.5s is
    // comfortably past expiry.
    await new Promise((r) => setTimeout(r, 1500));

    await expect(svc.verify(token)).rejects.toThrow();
  });

  it('verify rejects a token signed with a different secret', async () => {
    const signer = createAccessTokenService(SECRET_A);
    const verifier = createAccessTokenService(SECRET_B);

    const token = await signer.sign({
      sub: '11111111-1111-1111-1111-111111111111',
      did: '22222222-2222-2222-2222-222222222222',
    });

    await expect(verifier.verify(token)).rejects.toThrow();
  });

  it('rejects non-positive TTLs at construction', () => {
    expect(() => createAccessTokenService(SECRET_A, 0)).toThrow();
    expect(() => createAccessTokenService(SECRET_A, -5)).toThrow();
    expect(() => createAccessTokenService(SECRET_A, 1.5)).toThrow();
  });

  it('rejects empty secrets at construction', () => {
    expect(() => createAccessTokenService('')).toThrow();
  });
});

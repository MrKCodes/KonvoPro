// Tests for task 2.10 — auth state store + signup validation.
//
// Scope:
//   - The access token lives in memory only (Requirement 1.11): no
//     localStorage / sessionStorage write occurs as a side effect of
//     `setAuth` / `setAccessToken`, and the persistence tripwire
//     throws if any other code attempts to put the current token in
//     either web-storage backend.
//   - `validateSignup` blocks submission when the recovery-loss
//     checkbox is unchecked (Requirements 16.1, 16.2) and surfaces
//     the dedicated `recovery_loss_unconfirmed` reason.
//   - `validateSignup` enforces handle / password length and shape
//     (Requirements 1.1, 1.13).

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  __resetAuthStoreForTests,
  authActions,
  getAuthState,
  installPersistenceTripwire,
} from '../src/features/auth/store.js';
import { validateSignup } from '../src/features/auth/validate.js';

beforeEach(() => {
  __resetAuthStoreForTests();
  // Make sure no leftover localStorage from previous tests bleeds in.
  if (typeof localStorage !== 'undefined') localStorage.clear();
  if (typeof sessionStorage !== 'undefined') sessionStorage.clear();
});

afterEach(() => {
  __resetAuthStoreForTests();
});

describe('auth store — token persistence policy (Requirement 1.11)', () => {
  it('starts with no token and no user', () => {
    expect(getAuthState()).toEqual({ accessToken: null, user: null });
  });

  it('setAuth populates the in-memory state', () => {
    authActions.setAuth({
      accessToken: 'tok-abc',
      user: { id: 'u1', handle: 'alice' },
    });
    expect(getAuthState().accessToken).toBe('tok-abc');
    expect(getAuthState().user).toEqual({ id: 'u1', handle: 'alice' });
  });

  it('setAuth does NOT write to localStorage or sessionStorage', () => {
    authActions.setAuth({
      accessToken: 'persisted-token-canary',
      user: { id: 'u1', handle: 'alice' },
    });
    // Defense-in-depth: enumerate every stored key and confirm none
    // carries the token.
    for (const storage of [localStorage, sessionStorage]) {
      for (let i = 0; i < storage.length; i += 1) {
        const k = storage.key(i);
        if (k === null) continue;
        expect(storage.getItem(k)).not.toBe('persisted-token-canary');
        expect(storage.getItem(k) ?? '').not.toContain(
          'persisted-token-canary',
        );
      }
    }
  });

  it('persistence tripwire throws if anything tries to store the token', () => {
    authActions.setAuth({
      accessToken: 'tripwire-token',
      user: { id: 'u1', handle: 'alice' },
    });
    const uninstall = installPersistenceTripwire();
    try {
      expect(() =>
        localStorage.setItem('konvo:rogue', 'tripwire-token'),
      ).toThrow(/refusing to write access token/);
      expect(() =>
        sessionStorage.setItem('konvo:rogue', 'tripwire-token'),
      ).toThrow(/refusing to write access token/);
      // Storing UNRELATED values still works — we only block the
      // current token.
      expect(() =>
        localStorage.setItem('konvo:other', 'something-else'),
      ).not.toThrow();
    } finally {
      uninstall();
    }
  });

  it('clearAuth resets to initial state', () => {
    authActions.setAuth({
      accessToken: 'tok',
      user: { id: 'u1', handle: 'alice' },
    });
    authActions.clearAuth();
    expect(getAuthState()).toEqual({ accessToken: null, user: null });
  });

  it('subscribers fire on state changes and receive prev/next', async () => {
    const seen: Array<{ prevToken: string | null; nextToken: string | null }> = [];
    const { subscribeAuth } = await import('../src/features/auth/store.js');
    const off = subscribeAuth((next, prev) =>
      seen.push({ prevToken: prev.accessToken, nextToken: next.accessToken }),
    );
    authActions.setAccessToken('first');
    authActions.setAccessToken('second');
    off();
    authActions.setAccessToken('third'); // ignored after unsubscribe
    expect(seen).toEqual([
      { prevToken: null, nextToken: 'first' },
      { prevToken: 'first', nextToken: 'second' },
    ]);
  });
});

describe('signup validation — recovery-loss checkbox (Requirements 16.1, 16.2)', () => {
  const validHandle = 'alice_42';
  const validPassword = 'correct horse battery staple';

  it('rejects when handle is invalid (regex miss)', () => {
    const r = validateSignup({
      handle: 'Alice', // uppercase
      password: validPassword,
      recoveryLossConfirmed: true,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) {
      expect(r.reason).toBe('handle_invalid');
    }
  });

  it('rejects when password is too short (Requirement 1.13)', () => {
    const r = validateSignup({
      handle: validHandle,
      password: 'short',
      recoveryLossConfirmed: true,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) {
      expect(r.reason).toBe('password_too_short');
    }
  });

  it('rejects when recovery-loss checkbox is unchecked', () => {
    const r = validateSignup({
      handle: validHandle,
      password: validPassword,
      recoveryLossConfirmed: false,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) {
      expect(r.reason).toBe('recovery_loss_unconfirmed');
      // The validation message must indicate the confirmation is
      // required (Requirement 16.2).
      expect(r.message.toLowerCase()).toContain('confirm');
    }
  });

  it('passes when handle, password, and checkbox are all valid', () => {
    const r = validateSignup({
      handle: validHandle,
      password: validPassword,
      recoveryLossConfirmed: true,
    });
    expect(r.valid).toBe(true);
  });

  it('reports handle/password failures BEFORE the checkbox failure', () => {
    // Both invalid. The implementation reports the first failure in
    // form-input order (handle → password → checkbox).
    const r = validateSignup({
      handle: '', // invalid
      password: 'short',
      recoveryLossConfirmed: false,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) {
      expect(r.reason).toBe('handle_required');
    }
  });
});

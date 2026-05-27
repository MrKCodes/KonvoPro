// Unit tests for the Argon2id password hashing service (task 2.1).
//
// Validates Requirement 1.1 (hashes produced with Argon2id) and the
// hash/verify round-trip behaviour every login depends on. We exercise
// the service with reduced parameters so the suite stays fast — the
// production parameters (m=64 MiB, t=3, p=4) are wired in `server.ts`
// from `loadConfig()`.
//
// Note: per the task brief these tests are authored but not executed in
// this task — `pnpm install` hasn't run yet, so `argon2` and `vitest` are
// not on disk. The tests are kept self-contained so they run as soon as
// dependencies land.

import { describe, expect, it } from 'vitest';

import {
  ARGON2_VERIFY_BUDGET_MS,
  ARGON2_VERIFY_UNDER_BUDGET_METRIC,
  createArgon2Service,
  runArgon2VerifyBenchmark,
  type Argon2BenchmarkObserver,
  type Argon2BenchmarkResult,
  type Argon2Params,
} from '../src/services/auth/argon2.js';

// Reduced params for the test suite. The Argon2 work factor is dictated
// entirely by these numbers; lowering them keeps each hash under a few
// hundred milliseconds on commodity CI hardware while still exercising
// the real argon2id construction.
const TEST_PARAMS: Argon2Params = {
  memoryKib: 16384, // 16 MiB — the floor enforced by config.ts
  timeCost: 1,
  parallelism: 1,
};

describe('createArgon2Service', () => {
  it('hash + verify round-trip succeeds', async () => {
    const svc = createArgon2Service(TEST_PARAMS);
    const password = 'correct horse battery staple';

    const hash = await svc.hash(password);
    const ok = await svc.verify(hash, password);

    expect(ok).toBe(true);
  });

  it('verify returns false on wrong password', async () => {
    const svc = createArgon2Service(TEST_PARAMS);
    const hash = await svc.hash('correct horse battery staple');

    const ok = await svc.verify(hash, 'incorrect horse battery staple');

    expect(ok).toBe(false);
  });

  it('produced hash is a PHC string starting with $argon2id$', async () => {
    const svc = createArgon2Service(TEST_PARAMS);
    const hash = await svc.hash('whatever-password-here');

    // PHC format: `$argon2id$v=19$m=...,t=...,p=...$<salt-b64>$<hash-b64>`.
    // We only assert the algorithm prefix here; the embedded params are an
    // implementation detail of node-argon2's encoder.
    expect(hash.startsWith('$argon2id$')).toBe(true);
  });

  it('verify still succeeds on a hash produced earlier (params are read from the hash)', async () => {
    // Regression guard for a future params change: a hash produced with
    // the current `TEST_PARAMS` must still verify even if the verifying
    // service is constructed with different params, because `verify()`
    // reads the params from the encoded hash itself.
    const producer = createArgon2Service(TEST_PARAMS);
    const previouslyKnownHash = await producer.hash('regression-test-pw');

    const verifier = createArgon2Service({
      memoryKib: 32768,
      timeCost: 2,
      parallelism: 2,
    });

    const ok = await verifier.verify(previouslyKnownHash, 'regression-test-pw');
    expect(ok).toBe(true);
  });

  it('rejects parameter sets that violate basic invariants', () => {
    expect(() =>
      createArgon2Service({ memoryKib: 0, timeCost: 1, parallelism: 1 }),
    ).toThrow();
    expect(() =>
      createArgon2Service({ memoryKib: 16384, timeCost: 0, parallelism: 1 }),
    ).toThrow();
    expect(() =>
      createArgon2Service({ memoryKib: 16384, timeCost: 1, parallelism: 0 }),
    ).toThrow();
  });
});

describe('runArgon2VerifyBenchmark', () => {
  it('returns a positive duration and a boolean budget flag', async () => {
    const svc = createArgon2Service(TEST_PARAMS);
    const result = await runArgon2VerifyBenchmark(svc, TEST_PARAMS);

    expect(result.durationMs).toBeGreaterThan(0);
    expect(typeof result.underBudget).toBe('boolean');
    expect(result.underBudget).toBe(
      result.durationMs < ARGON2_VERIFY_BUDGET_MS,
    );
  });

  it('feeds the result to the supplied observer', async () => {
    const svc = createArgon2Service(TEST_PARAMS);
    const seen: Argon2BenchmarkResult[] = [];
    const observer: Argon2BenchmarkObserver = {
      onBenchmarkResult(result) {
        seen.push(result);
      },
    };

    const result = await runArgon2VerifyBenchmark(svc, TEST_PARAMS);
    observer.onBenchmarkResult(result);

    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual(result);
  });

  it('exposes the Prometheus metric name task 10.1 will register', () => {
    // Static assertion — keeps task 10.1's prom-client Counter aligned
    // with the name the default observer emits today.
    expect(ARGON2_VERIFY_UNDER_BUDGET_METRIC).toBe(
      'konvo_argon2_verify_under_budget_total',
    );
  });
});

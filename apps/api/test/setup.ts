// Vitest setup for `@konvo/api`.
//
// Configures `fast-check`'s global default iteration count from the
// `FAST_CHECK_RUNS` env var so envelope-routing / rate-limit / broadcast
// property tests in this package run with the same cadence as the rest
// of the monorepo (per design.md §16.2 + tasks.md task 4.1):
//
//   - default (CI):           100 iterations per property
//   - nightly tamper / FS:    set `FAST_CHECK_RUNS=500` (or higher)

import * as fc from 'fast-check';

const DEFAULT_NUM_RUNS = 100;
const envRuns = process.env['FAST_CHECK_RUNS'];
const numRuns =
  envRuns !== undefined && envRuns !== ''
    ? Number.parseInt(envRuns, 10)
    : DEFAULT_NUM_RUNS;

if (!Number.isFinite(numRuns) || numRuns < 1) {
  throw new Error(
    `FAST_CHECK_RUNS must be a positive integer, got "${envRuns ?? ''}"`,
  );
}

fc.configureGlobal({ numRuns });

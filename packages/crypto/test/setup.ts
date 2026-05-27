// Vitest setup: expose Node 20's built-in WebCrypto as `globalThis.crypto`
// so the identity module can use the same `crypto.subtle` and
// `crypto.getRandomValues` APIs it relies on in the browser, and seed
// `fast-check`'s global iteration count for property-based tests.
//
// Node 20+ ships WebCrypto as `node:crypto`'s `webcrypto` export AND, since
// Node 19, exposes the same surface on `globalThis.crypto` natively (as a
// getter-only accessor on Node 23+, which makes a direct assignment throw).
// We therefore only install our copy when the runtime hasn't already
// provided one — keeping older Node and non-Node runtimes covered without
// fighting Node 23's accessor descriptor.
//
// `FAST_CHECK_RUNS` (per task 4.1):
//   - default (CI):           100 iterations per property
//   - nightly tamper / FS:    set `FAST_CHECK_RUNS=500` (or higher)
// Per design.md §16.2 each property runs ≥100 iterations in CI and ≥500
// on the nightly job for tamper / forward-secrecy properties.

import { webcrypto } from 'node:crypto';
import * as fc from 'fast-check';

// `as unknown as Crypto`: the Node WebCrypto type is structurally compatible
// with the DOM `Crypto` lib type but TypeScript treats them as nominally
// distinct in some configurations.
if ((globalThis as unknown as { crypto?: Crypto }).crypto === undefined) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto as unknown as Crypto,
    configurable: true,
    writable: true,
  });
}

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

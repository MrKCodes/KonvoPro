// Vitest setup for `@konvo/protocol`.
//
// Two responsibilities:
//
//   1. Expose Node 20's built-in WebCrypto as `globalThis.crypto` so any
//      arbitrary that derives crypto material (e.g. the X25519 keypair
//      arbitrary in `@konvo/crypto/test/arbitraries`) Just Works in Node.
//      Mirrors `packages/crypto/test/setup.ts`.
//
//   2. Configure `fast-check`'s global default iteration count from the
//      `FAST_CHECK_RUNS` env var:
//        - default (CI):           100 iterations per property
//        - nightly tamper / FS:    set `FAST_CHECK_RUNS=500` (or higher)
//      Per design.md §16.2 + tasks.md task 4.1.

import { webcrypto } from 'node:crypto';
import * as fc from 'fast-check';

// `as unknown as Crypto`: the Node WebCrypto type is structurally
// compatible with the DOM `Crypto` lib type but TypeScript treats them as
// nominally distinct in some configurations.
//
// Node 20 exposes `globalThis.crypto` as a writable data property, so
// assigning works directly. Node ≥ 22 / 23 promotes `globalThis.crypto`
// to a non-writable accessor backed by the built-in WebCrypto, in which
// case the assignment throws `TypeError: Cannot set property crypto …
// which has only a getter`. The native value is already a perfectly good
// WebCrypto, so guard the assignment.
if (
  !('crypto' in globalThis) ||
  (globalThis as { crypto?: unknown }).crypto === undefined
) {
  (globalThis as unknown as { crypto: Crypto }).crypto =
    webcrypto as unknown as Crypto;
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

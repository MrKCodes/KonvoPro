// Vitest setup for `apps/web` unit tests.
//
// 1. fake-indexeddb: jsdom doesn't ship an IndexedDB implementation, so
//    Dexie can't open any database in the test environment by default.
//    `fake-indexeddb/auto` patches the missing globals (`indexedDB`,
//    `IDBKeyRange`, etc.) onto `globalThis` for the lifetime of the
//    test process. Each test should construct its own `KonvoDb` with a
//    unique name (or call `db.delete()` in a teardown hook) to avoid
//    cross-test data bleed.
//
// 2. WebCrypto: Node 20 ships WebCrypto under `node:crypto`'s
//    `webcrypto` export. jsdom does NOT bridge it onto `window.crypto`
//    automatically, so `crypto.subtle.generateKey(...)` would fail in
//    the identity repository's `getOrCreateAesKwKey()` path. We assign
//    it explicitly here.

import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';

import * as fc from 'fast-check';

// 3. React 18 act() environment flag. Setting this on the global
//    object before any React module loads tells React's internal
//    `act` plumbing that we're in a test environment and stops the
//    "current testing environment is not configured to support
//    act(...)" warning from firing on every state update during
//    component tests. See
//    https://github.com/reactwg/react-18/discussions/102.
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
  true;

if (typeof globalThis.crypto === 'undefined') {
  // `as unknown as Crypto`: the Node WebCrypto type is structurally
  // compatible with the DOM `Crypto` lib type but TypeScript treats
  // them as nominally distinct in some configurations.
  (globalThis as unknown as { crypto: Crypto }).crypto =
    webcrypto as unknown as Crypto;
}

// 4. fast-check global iteration count. Mirrors `apps/api/test/setup.ts`
//    so the property tests in this package (P22 fingerprint binding,
//    etc.) honour the same FAST_CHECK_RUNS env var as the rest of the
//    monorepo (default 100, nightly 500). Per design.md §16.2 +
//    tasks.md task 4.1.
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

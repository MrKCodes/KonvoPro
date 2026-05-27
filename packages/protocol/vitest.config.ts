import { defineConfig } from 'vitest/config';

// packages/protocol tests are pure type/codec tests; no DOM, no DB, just
// msgpack and the discriminated unions in `src/`. The setup file installs
// Node 20's WebCrypto onto `globalThis.crypto` (so any future test that
// pulls in `@konvo/crypto` arbitraries — e.g. `arbCurve25519KeyPair` —
// works) and seeds `fast-check`'s default `numRuns` from
// `FAST_CHECK_RUNS` (default 100, nightly 500). See `test/setup.ts`.
export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.ts'],
  },
});

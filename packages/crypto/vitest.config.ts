import { defineConfig } from 'vitest/config';

// Per task 2.7 brief: run tests in Node with the built-in WebCrypto polyfill
// installed by `test/setup.ts`. We keep the environment as `node` because
// the identity module only needs `globalThis.crypto`, not a full DOM.
export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.ts'],
  },
});

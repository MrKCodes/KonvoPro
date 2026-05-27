import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Vitest config for `apps/web`.
//
// `environment: 'jsdom'`:
//   Dexie expects browser-like globals (`window`, `self`, `navigator`).
//   jsdom gives us those without spinning up a real browser, which keeps
//   the unit tests fast and CI-friendly.
//
// `setupFiles: ['./test/setup.ts']`:
//   Installs `fake-indexeddb` over `globalThis` so Dexie can open
//   "real-looking" IndexedDB databases in the test environment, and
//   bridges Node 20's WebCrypto onto `globalThis.crypto` for the AES-KW
//   wrapping path used by the identity repository.
//
// Workspace package aliases (mirrors `apps/api/vitest.config.ts`):
//   `@konvo/crypto` and `@konvo/protocol` declare their `exports` entry
//   point as `./dist/index.js`, which is correct for production
//   consumers but doesn't exist in a fresh checkout (no `pnpm build`
//   has run). Vitest/Vite refuse to resolve a package whose exports
//   point at an absent file. Aliasing the package name to the
//   `src/index.ts` source keeps `import { ... } from '@konvo/crypto'`
//   working from tests + Vite dev server without forcing every
//   contributor to pre-build the workspace packages. The alias is
//   dev-time only; production bundles still consume the built `dist/`.
const here = fileURLToPath(new URL('.', import.meta.url));

// `@msgpack/msgpack` is a transitive dependency of `@konvo/protocol`
// (see `packages/protocol/package.json`). The web app reaches it via
// the call-signaling module (task 6.3) which msgpack-encodes the
// inner CALL_* payload before handing it to the ratchet. Vite/Vitest
// cannot follow the bare specifier through the workspace alias
// transparently, so we alias it directly to the hoisted pnpm path —
// the same approach `apps/api/vitest.config.ts` uses for `pino`. The
// alias is dev-only; production bundles consume the package via
// regular npm resolution after `pnpm install`.
const msgpackEntry = resolve(
  here,
  '..',
  '..',
  'node_modules',
  '.pnpm',
  '@msgpack+msgpack@3.1.3',
  'node_modules',
  '@msgpack',
  'msgpack',
  'dist.esm',
  'index.mjs',
);

export default defineConfig({
  resolve: {
    alias: {
      '@konvo/crypto': resolve(here, '..', '..', 'packages', 'crypto', 'src', 'index.ts'),
      '@konvo/protocol': resolve(here, '..', '..', 'packages', 'protocol', 'src', 'index.ts'),
      '@msgpack/msgpack': msgpackEntry,
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
  },
});

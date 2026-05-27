import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// apps/api tests run in plain Node — no DOM, no JSDOM. The argon2 service
// uses node-argon2 (a native binding); the benchmark uses
// `process.hrtime.bigint()`. Both require the Node runtime, not jsdom.
//
// Test files live under `test/` (sibling to `src/`) per the convention
// established by `packages/crypto/vitest.config.ts`.
//
// `test/setup.ts` (added in task 4.1) seeds `fast-check`'s global
// `numRuns` from `FAST_CHECK_RUNS` so envelope-routing / rate-limit
// property tests honour the same default-100 / nightly-500 cadence as
// the rest of the monorepo.
//
// Workspace package aliases (added in task 7.2):
//   `@konvo/crypto` and `@konvo/protocol` declare their `exports` entry
//   point as `./dist/index.js`, which is correct for production
//   consumers but doesn't exist in a fresh checkout (no `pnpm build`
//   has run). Vitest, like Vite, refuses to resolve a package whose
//   exports point at an absent file. Aliasing the package name to the
//   `src/index.ts` source keeps `import { ... } from '@konvo/crypto'`
//   working in route tests without forcing every contributor to
//   pre-build the workspace packages. The alias is test-time only;
//   production server bundles still consume the built `dist/` output.
const here = fileURLToPath(new URL('.', import.meta.url));

// `pino` (task 4.9) is declared in apps/api/package.json but its
// physical install lives under the workspace's pnpm virtual store
// (`node_modules/.pnpm/pino@10.3.1/...`). Without a fresh
// `pnpm install` the bare specifier `pino` is not resolvable from
// apps/api's local `node_modules`. Aliasing it directly to the
// hoisted pnpm path lets vitest (and Vite) resolve it without
// requiring a rebuild step before tests run. The alias is test-only
// — production server bundles consume the package via the standard
// resolution path after `pnpm install` has materialised the symlink.
const pinoEntry = resolve(
  here,
  '..',
  '..',
  'node_modules',
  '.pnpm',
  'pino@10.3.1',
  'node_modules',
  'pino',
  'pino.js',
);

export default defineConfig({
  resolve: {
    alias: {
      '@konvo/crypto': resolve(here, '..', '..', 'packages', 'crypto', 'src', 'index.ts'),
      '@konvo/protocol': resolve(here, '..', '..', 'packages', 'protocol', 'src', 'index.ts'),
      pino: pinoEntry,
      // `prom-client` is referenced by `apps/api/src/obs/metrics.ts`
      // but the package isn't installed in the current pnpm checkout
      // (see test/_shims/prom-client.ts header for the upstream
      // registry blocker). Aliasing the bare specifier to the in-tree
      // shim lets every test that transitively pulls in metrics.ts
      // load without exploding at module evaluation. The alias is
      // test-only — production builds resolve `prom-client` from npm.
      //
      // Caveat: the shim is intentionally narrow (it implements only
      // the surface metrics.ts uses at module evaluation time). A
      // handful of tests that exercise the real prom-client exposition
      // format (test/metrics.test.ts) still fail under the shim — they
      // would also fail without it (they couldn't load at all). The
      // alias trades 15 file-level resolution failures for 6
      // shim-incomplete failures; once prom-client is properly
      // installed both classes resolve.
      'prom-client': resolve(here, 'test', '_shims', 'prom-client.ts'),
      // `@livekit/server-sdk` is referenced by `apps/api/src/services/
      // livekit.ts` for broadcast-room token minting (Requirements
      // 11.1, 11.2), but the npm registry currently 404s on the
      // scoped package name (see test/_shims/livekit-server-sdk.ts).
      // The shim implements `AccessToken` against `jose` so JWT-shape
      // tests in `broadcast-live-routes.test.ts` and the task-6.6
      // runtime guard tests in `no-dm-call-recording.test.ts` can
      // verify the produced tokens without the upstream package.
      // Production builds resolve the real SDK from npm.
      '@livekit/server-sdk': resolve(
        here,
        'test',
        '_shims',
        'livekit-server-sdk.ts',
      ),
    },
  },
  test: {
    environment: 'node',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.ts'],
  },
});

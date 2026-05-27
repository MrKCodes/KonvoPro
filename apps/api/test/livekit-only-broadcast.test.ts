// apps/api/test/livekit-only-broadcast.test.ts
//
// Static-analysis invariant test (task 8.4 — Phase 7).
//
// Realizes Requirements 11.7 and 11.8 — "LiveKit is for broadcast,
// never for 1:1 calls" — by walking the `apps/api/src/` tree at test
// time and asserting that the only files importing
// `@livekit/server-sdk` are the broadcast-related ones (token signer
// service + broadcast LiveKit routes plugin). Every other route or
// service that touches 1:1 DM calls (notably `routes/turn.ts`, the
// coturn TURN credential mint used by `RTCPeerConnection`) MUST NOT
// pull the LiveKit SDK in.
//
// As a forward-looking guard, when `apps/web/src/` is wired with
// LiveKit client SDKs in a later phase, this test also asserts that
// any `@livekit/*` import there is confined to
// `apps/web/src/features/broadcast/`. Until those imports exist the
// web check is a no-op.
//
// Why a CI-time grep instead of a TypeScript-level import boundary?
// The codebase doesn't run a per-package import boundary tool (e.g.
// `dependency-cruiser` or `eslint-plugin-boundaries`), and a vitest
// file is the cheapest portable enforcement: it runs in the same
// `pnpm -F @konvo/api test` command the rest of the suite uses, so
// breaking the invariant fails CI just like a unit-test regression.
//
// Implementation notes:
//   - We match the literal `'@livekit/server-sdk'` / `"@livekit/server-sdk"`
//     string (single OR double quote). This covers static `import ...
//     from '...'`, dynamic `import('...')`, and `require('...')` forms.
//     Comments in services/livekit.ts mention the dash-spelled
//     `livekit-server-sdk` name (the npm package readme spelling) and
//     so don't match this regex; they do not need to be allowlisted.
//   - The walker is hand-rolled with `fs.readdir({ withFileTypes })`
//     to avoid adding `glob` (or any new dep) to `apps/api/package.json`.
//   - `apps/web/src/` may not exist with LiveKit usage yet; the walker
//     handles missing directories by returning an empty file list, so
//     the invariant trivially holds today and only triggers when web
//     code is added in Phase 7.

import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// `import.meta.url` resolves to the file URL of THIS test file under
// the `apps/api/test/` directory. From there we walk up to the
// `apps/api/` package root and into `src/`.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const API_ROOT = path.resolve(HERE, '..');
const API_SRC = path.join(API_ROOT, 'src');
const APPS_ROOT = path.resolve(API_ROOT, '..');
const WEB_ROOT = path.join(APPS_ROOT, 'web');
const WEB_SRC = path.join(WEB_ROOT, 'src');

/**
 * Recursively collect every `.ts` / `.tsx` file under `dir`. Returns
 * an empty array when `dir` does not exist (the web-side invariant
 * relies on this graceful behaviour for forward-compatibility).
 */
async function walkTsFiles(dir: string): Promise<readonly string[]> {
  let entries: Awaited<ReturnType<typeof readdir>>;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  const out: string[] = [];
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      // Skip nested build/output directories defensively. `apps/api/src`
      // doesn't currently contain any (the `dist/` directory lives at
      // package root, outside the src tree), but a future
      // sub-package-style layout shouldn't trip the invariant on
      // generated code.
      if (e.name === 'node_modules' || e.name === 'dist') continue;
      const sub = await walkTsFiles(full);
      out.push(...sub);
    } else if (e.isFile() && (e.name.endsWith('.ts') || e.name.endsWith('.tsx'))) {
      out.push(full);
    }
  }
  return out;
}

/** Path that matches `'@livekit/server-sdk'` or `"@livekit/server-sdk"`
 *  in any of the import / require / dynamic-import forms. */
const SERVER_SDK_LITERAL = /['"]@livekit\/server-sdk['"]/;

/** Path that matches any `@livekit/*` package literal — used by the
 *  web-side invariant which should also reject `@livekit/client`,
 *  `@livekit/components-react`, etc. outside the broadcast feature. */
const ANY_LIVEKIT_LITERAL = /['"]@livekit\/[^'"]+['"]/;

/** Allowed importers of the LiveKit server SDK in `apps/api/src/`.
 *  Paths are relative to `apps/api/` and use forward slashes regardless
 *  of platform separator. */
const API_SERVER_SDK_ALLOWLIST: ReadonlySet<string> = new Set([
  'src/services/livekit.ts',
  'src/routes/broadcast-live.ts',
]);

/** Convert an absolute path to a forward-slash path relative to
 *  `apps/api/`. Lets the assertion message be portable across
 *  Linux CI, macOS dev machines, and (hypothetically) Windows. */
function relApi(abs: string): string {
  return path.relative(API_ROOT, abs).split(path.sep).join('/');
}

/** Forward-slash path relative to `apps/web/`. */
function relWeb(abs: string): string {
  return path.relative(WEB_ROOT, abs).split(path.sep).join('/');
}

describe('LiveKit-only-for-broadcast invariant (Requirements 11.7, 11.8)', () => {
  it('the api/src tree exists (sanity check so a broken walker does not silently pass)', async () => {
    const s = await stat(API_SRC);
    expect(s.isDirectory()).toBe(true);
  });

  it('apps/api/src: @livekit/server-sdk is only imported from services/livekit.ts and routes/broadcast-live.ts', async () => {
    const files = await walkTsFiles(API_SRC);
    // The walker MUST find at least the routes / services we know
    // are present, otherwise a misconfigured path would yield a
    // vacuous pass.
    expect(files.length).toBeGreaterThan(0);

    const violations: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      if (!SERVER_SDK_LITERAL.test(content)) continue;
      const rel = relApi(file);
      if (!API_SERVER_SDK_ALLOWLIST.has(rel)) {
        violations.push(rel);
      }
    }

    expect(
      violations,
      `Files outside the broadcast allowlist must not import @livekit/server-sdk. ` +
        `Allowlist: ${[...API_SERVER_SDK_ALLOWLIST].join(', ')}. ` +
        `Violations: ${violations.join(', ')}`,
    ).toEqual([]);
  });

  it('apps/api/src/routes/turn.ts (1:1 DM TURN-credential route) does not import @livekit/server-sdk', async () => {
    // Explicit assertion called out by Requirement 11.7: the 1:1 call
    // path uses coturn-derived TURN credentials and never the LiveKit
    // SFU. This is implied by the allowlist test above but stated here
    // explicitly so the regression diff is unambiguous.
    const turnPath = path.join(API_SRC, 'routes', 'turn.ts');
    const content = await readFile(turnPath, 'utf8');
    expect(SERVER_SDK_LITERAL.test(content)).toBe(false);
  });

  it('apps/web/src: @livekit/* SDK imports are confined to features/broadcast/ (no-op until web wires LiveKit)', async () => {
    // Forward-looking guard for Requirement 11.8: when the web app
    // adds the LiveKit client SDK in `features/broadcast/`, this test
    // ensures no DM-call code paths (e.g. a future
    // `features/dm-call/`) accidentally pull it in. Until then the
    // walker either finds no matching imports or finds none at all
    // (apps/web/src may not yet exist with LiveKit code), and the
    // assertion is trivially satisfied.
    const files = await walkTsFiles(WEB_SRC);
    if (files.length === 0) return;

    const violations: string[] = [];
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      if (!ANY_LIVEKIT_LITERAL.test(content)) continue;
      const rel = relWeb(file);
      if (!rel.startsWith('src/features/broadcast/')) {
        violations.push(rel);
      }
    }

    expect(
      violations,
      `Files outside apps/web/src/features/broadcast/ must not import @livekit/* SDKs. ` +
        `Violations: ${violations.join(', ')}`,
    ).toEqual([]);
  });
});

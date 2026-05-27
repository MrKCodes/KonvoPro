// e2e/playwright.config.ts
//
// Playwright configuration for the Konvo end-to-end suite (design.md §16.4
// and the verification gate in Requirement 20.6).
//
// Targets:
//   - Headless Chromium only. The platform's WebRTC + WebCrypto + libsignal
//     stack is exercised in Chromium first; cross-browser parity arrives in
//     task 10.24's CI matrix work, not here.
//
// Live-stack toggle:
//   The suite expects a running web app at `KONVO_E2E_WEB_URL`
//   (default `http://localhost:5173`) and an api at `KONVO_E2E_API_URL`
//   (default `http://localhost:3000`). When `KONVO_E2E_LIVE` is unset,
//   tests `test.skip()` themselves with an explanatory annotation so
//   `pnpm test:e2e` is a no-op in environments without the stack
//   (CI integration is task 10.24).
//
// `webServer` is intentionally NOT configured here. Spawning the api would
// require the docker-compose data-plane (Postgres, Redis, MinIO, coturn,
// LiveKit), which is out of scope for this task. Task 10.24 wires that up
// in GitHub Actions via a compose-based job.

import { defineConfig, devices } from '@playwright/test';

const WEB_URL = process.env['KONVO_E2E_WEB_URL'] ?? 'http://localhost:5173';

export default defineConfig({
  testDir: '.',
  // Each test gets its own browser context with a fresh storageState so
  // signup/login runs are independent (Requirement 20.6 — zero skipped or
  // flaky tests). `fullyParallel` lets unrelated specs interleave once
  // task 10.24 brings up isolated stacks per worker.
  fullyParallel: false,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 1 : 0,
  workers: 1,
  reporter: process.env['CI'] ? [['github'], ['list']] : [['list']],
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: WEB_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    // Persist cookies + IndexedDB per test by default; individual tests
    // override via `test.use({ storageState: ... })` when they need a
    // pre-authenticated context.
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

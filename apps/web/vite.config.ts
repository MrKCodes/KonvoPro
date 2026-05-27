import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';

// Vite config for the Konvo PWA.
//
// Service worker (task 9.1):
//   `vite-plugin-pwa` runs in `injectManifest` strategy so our
//   hand-written `apps/web/src/pwa/sw.ts` is the SW source. The
//   plugin walks the build output, generates the precache manifest
//   (HTML, CSS, JS, icons matching the `globPatterns` below), and
//   injects it as `self.__WB_MANIFEST` inside the SW bundle. The
//   resulting `sw.js` is emitted to the build output root and
//   served from `/sw.js` — the URL `register.ts` registers
//   against. The web manifest at `public/manifest.webmanifest` is
//   the source of truth for installability metadata; the plugin's
//   `manifest: false` flag tells it not to generate a competing
//   one (Requirement 14.1).
//
// `globPatterns` mirrors Requirement 14.2's "HTML document, CSS
// bundle, JS bundle, and icon assets". We keep the icon glob
// scoped to `icons/**` rather than `**/*` so non-icon static
// assets (videos, fonts not yet present) don't bloat the
// precache when added later.
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      strategies: 'injectManifest',
      srcDir: 'src/pwa',
      filename: 'sw.ts',
      manifest: false,
      injectManifest: {
        globPatterns: [
          '**/*.html',
          '**/*.css',
          '**/*.js',
          'icons/**/*.{png,svg,webp}',
          'manifest.webmanifest',
        ],
      },
      // The SW is registered manually by `apps/web/src/pwa/register.ts`,
      // so we tell the plugin not to inject its own auto-register
      // shim into the page.
      injectRegister: null,
      devOptions: {
        enabled: false,
      },
    }),
  ],
  server: {
    port: 5173,
    host: '0.0.0.0',
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2022',
  },
});

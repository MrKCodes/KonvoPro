// apps/web/src/App.tsx
//
// PWA shell. Real routing, auth, and DM/broadcast features land in
// subsequent phases under `apps/web/src/routes/` and
// `apps/web/src/features/*`. This module is currently the smallest
// possible host that wires up the cross-cutting "background" work
// the spec mandates: at present, prekey maintenance (task 4.6) plus
// the public broadcast-room read route at `/r/:slug` (task 7.4).
//
// Routing:
//   The PWA does not yet pull in a real router. A pathname-shaped
//   match is sufficient for the public `/r/:slug` route: any path
//   starting with `/r/` followed by a non-empty slug renders the
//   `PublicRoomRoute` host without any auth requirement. Every
//   other path falls back to the (currently placeholder) main
//   shell. When the SPA grows a router (a follow-up task) the same
//   slug-extraction logic moves into the router config without
//   changing the rest of this file.
//
// Lifecycle:
//   - On every render where the auth store reports a logged-in user
//     AND a cached `deviceId` is present, we start the prekey
//     maintenance schedulers (`startPreKeyMaintenance`). The hook
//     returns a stop callback that React's effect cleanup invokes on
//     logout / device clear / unmount, so the schedulers never run
//     past the lifetime of an authenticated session.
//   - The hook is keyed on `(userId, deviceId)` so a user who logs
//     out and back in as someone else (or who re-enrols a device)
//     gets a fresh scheduler instance bound to the new identifiers.
//
// Why prekey maintenance lives here and not inside `LoginForm`:
//   The post-login bootstrap is a cross-cutting concern (auth + DMs +
//   prekey maintenance + future Web Push subscription handling). The
//   login form's responsibility ends at "access token in memory";
//   the App shell owns the side effects that should outlive any
//   particular login form mount.

import { useEffect, useState } from 'react';

import { startPreKeyMaintenance, useAuthStore } from './features/auth';
import { PublicRoomRoute } from './features/broadcast';
import { readStoredDeviceId } from './features/devices';
import { InstallPrompt } from './pwa/InstallPrompt.js';

/** Match a pathname like `/r/some-slug` (slug = `[a-z0-9-]{3,64}`,
 *  matching the server's slug regex). Returns the slug or `null`.
 *  Trailing slash is tolerated. */
export function parsePublicRoomSlug(pathname: string): string | null {
  const m = /^\/r\/([a-z0-9-]{3,64})\/?$/.exec(pathname);
  return m === null ? null : m[1] ?? null;
}

function readInitialPathname(): string {
  if (typeof window === 'undefined') return '/';
  return window.location.pathname;
}

export function App(): JSX.Element {
  const userId = useAuthStore((s) => s.user?.id ?? null);
  const [pathname, setPathname] = useState<string>(readInitialPathname);

  // Keep `pathname` in sync with browser back/forward navigation so
  // a user clicking the back button out of `/r/:slug` returns to the
  // shell without a full reload. Real router work lands later; this
  // is the minimum needed for the `/r/:slug` deep-link contract.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onPop = (): void => setPathname(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  useEffect(() => {
    if (userId === null) {
      return;
    }
    const deviceId = readStoredDeviceId();
    if (deviceId === null) {
      return;
    }
    const stop = startPreKeyMaintenance({
      deviceId,
      onError: (err: unknown): void => {
        // Background work — surface to the console only. A future
        // task wires this into the structured logger / Sentry.
        console.warn('prekey-maintenance:', err);
      },
    });
    return stop;
  }, [userId]);

  const publicRoomSlug = parsePublicRoomSlug(pathname);
  if (publicRoomSlug !== null) {
    return <PublicRoomRoute slug={publicRoomSlug} />;
  }

  return (
    <main>
      Konvo
      <InstallPrompt />
    </main>
  );
}

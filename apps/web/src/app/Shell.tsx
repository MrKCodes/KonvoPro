// apps/web/src/app/Shell.tsx
//
// Three-pane shell composition (rail | list | detail), gated by an
// auth check. Routes that require auth (DM, Calls, Settings,
// authenticated Broadcast room view) redirect to /login when the
// user is not signed in. The public-room route bypasses the gate
// entirely.

import { useEffect } from 'react';

import { startPreKeyMaintenance, useAuthStore } from '../features/auth/index.js';
import { readStoredDeviceId } from '../features/devices/enrollment.js';
import { InstallPrompt } from '../pwa/InstallPrompt.js';
import { ThemeToggle } from '../features/settings/ThemeToggle.js';

import { OfflineBanner } from './OfflineBanner.js';
import { Rail } from './Rail.js';
import { LogoutIcon } from './Icons.js';
import { navigate, useRoute, type Route } from './router.js';
import { authActions } from '../features/auth/store.js';
import { AuthScreen } from './screens/AuthScreen.js';
import { BroadcastScreen } from './screens/BroadcastScreen.js';
import { CallsScreen } from './screens/CallsScreen.js';
import { DmScreen } from './screens/DmScreen.js';
import { PublicRoomScreen } from './screens/PublicRoomScreen.js';
import { SettingsScreen } from './screens/SettingsScreen.js';

import '../styles/shell.css';

function isAuthRoute(r: Route): boolean {
  return r.kind === 'auth-login' || r.kind === 'auth-signup';
}

function isPublicRoute(r: Route): boolean {
  return r.kind === 'public-room';
}

function isDetailFocused(r: Route): boolean {
  // On tablet/phone, when an item is open we focus the detail pane.
  return (
    r.kind === 'dm-thread' ||
    r.kind === 'broadcast-room' ||
    (r.kind === 'settings' && r.section !== undefined)
  );
}

export function Shell(): JSX.Element {
  const route = useRoute();
  const userId = useAuthStore((s) => s.user?.id ?? null);
  const userHandle = useAuthStore((s) => s.user?.handle ?? null);

  // Cross-cutting prekey-maintenance side effect: kick the
  // schedulers when an authenticated user has a cached device id.
  useEffect(() => {
    if (userId === null) return;
    const deviceId = readStoredDeviceId();
    if (deviceId === null) return;
    const stop = startPreKeyMaintenance({
      deviceId,
      onError: (err) => console.warn('prekey-maintenance:', err),
    });
    return stop;
  }, [userId]);

  // Public room: no auth gate.
  if (isPublicRoute(route) && route.kind === 'public-room') {
    return <PublicRoomScreen slug={route.slug} />;
  }

  // Auth screens: render alone without the rail/list/detail shell.
  if (isAuthRoute(route)) {
    return (
      <AuthScreen initialTab={route.kind === 'auth-signup' ? 'signup' : 'login'} />
    );
  }

  // Anywhere else without a session → bounce to login.
  if (userId === null) {
    return <AuthScreen initialTab="login" />;
  }

  // Pick the screen for the active route.
  const screen =
    route.kind === 'broadcast-list' || route.kind === 'broadcast-room'
      ? BroadcastScreen({ route })
      : route.kind === 'calls'
        ? CallsScreen()
        : route.kind === 'settings'
          ? SettingsScreen()
          : DmScreen({ route });

  const pane = isDetailFocused(route) ? 'detail' : 'list';

  return (
    <div className="shell" data-pane={pane}>
      <a className="skip-link" href="#detail">
        Skip to content
      </a>

      <div className="shell__offline">
        <OfflineBanner />
      </div>

      <Rail
        route={route}
        bottom={
          <>
            <ThemeToggle />
            <button
              type="button"
              className="rail__btn"
              aria-label={`Sign out${userHandle === null ? '' : ` ${userHandle}`}`}
              title={userHandle === null ? 'Sign out' : `Sign out · ${userHandle}`}
              onClick={() => {
                authActions.clearAuth();
                navigate('/login');
              }}
            >
              <LogoutIcon label="Sign out" />
            </button>
          </>
        }
      />

      <div className="shell__list">{screen.list}</div>
      <main id="detail" className="shell__detail" aria-label="Content">
        {screen.detail}
      </main>

      <InstallPrompt />
    </div>
  );
}

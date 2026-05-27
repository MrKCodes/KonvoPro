// apps/web/src/app/router.tsx
//
// Tiny path-based router. No third-party dep — we don't want to lock
// the SPA into a router framework yet, and the route table is small.
//
// Public surface:
//   - useRoute()      → { kind, params } discriminated union for the
//                       current pathname.
//   - navigate(url)   → pushState + emit popstate so subscribers
//                       update.
//
// Routes (pathname-shaped):
//   /                            → home (DM list, default landing
//                                   when authed)
//   /login                       → auth screen (login tab)
//   /signup                      → auth screen (signup tab)
//   /dm                          → DM list
//   /dm/:peerUserId              → DM thread for a peer
//   /broadcast                   → broadcast room list
//   /broadcast/:slug             → broadcast room (admin/subscriber view)
//   /r/:slug                     → public-read broadcast view (no auth)
//   /calls                       → calls index (active call shows here)
//   /settings                    → settings root
//   /settings/devices            → devices section
//
// The slug regex matches the server's `[a-z0-9-]{3,64}`.

import { useEffect, useState } from 'react';

const SLUG_RE = /^[a-z0-9-]{3,64}$/;
const PEER_RE = /^[a-z0-9_-]{1,64}$/;

export type Route =
  | { kind: 'home' }
  | { kind: 'auth-login' }
  | { kind: 'auth-signup' }
  | { kind: 'dm-list' }
  | { kind: 'dm-thread'; peerUserId: string }
  | { kind: 'broadcast-list' }
  | { kind: 'broadcast-room'; slug: string }
  | { kind: 'public-room'; slug: string }
  | { kind: 'calls' }
  | { kind: 'settings'; section?: string }
  | { kind: 'not-found' };

export function parseRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/g, '') || '/';
  if (path === '/' || path === '') return { kind: 'home' };
  if (path === '/login') return { kind: 'auth-login' };
  if (path === '/signup') return { kind: 'auth-signup' };
  if (path === '/dm') return { kind: 'dm-list' };
  if (path.startsWith('/dm/')) {
    const peer = path.slice(4);
    if (PEER_RE.test(peer)) return { kind: 'dm-thread', peerUserId: peer };
  }
  if (path === '/broadcast') return { kind: 'broadcast-list' };
  if (path.startsWith('/broadcast/')) {
    const slug = path.slice('/broadcast/'.length);
    if (SLUG_RE.test(slug)) return { kind: 'broadcast-room', slug };
  }
  if (path.startsWith('/r/')) {
    const slug = path.slice(3);
    if (SLUG_RE.test(slug)) return { kind: 'public-room', slug };
  }
  if (path === '/calls') return { kind: 'calls' };
  if (path === '/settings') return { kind: 'settings' };
  if (path.startsWith('/settings/')) {
    const section = path.slice('/settings/'.length);
    return { kind: 'settings', section };
  }
  return { kind: 'not-found' };
}

/** Navigate via pushState. The router's `useRoute` listens for both
 *  popstate (back/forward) and a custom `konvo:nav` event so this
 *  helper triggers re-render in subscribers. */
export function navigate(url: string): void {
  if (typeof window === 'undefined') return;
  if (window.location.pathname === url) return;
  window.history.pushState(null, '', url);
  window.dispatchEvent(new Event('konvo:nav'));
}

function readPathname(): string {
  if (typeof window === 'undefined') return '/';
  return window.location.pathname;
}

export function useRoute(): Route {
  const [pathname, setPathname] = useState<string>(readPathname);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onPop = (): void => setPathname(window.location.pathname);
    window.addEventListener('popstate', onPop);
    window.addEventListener('konvo:nav', onPop);
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener('konvo:nav', onPop);
    };
  }, []);
  return parseRoute(pathname);
}

// apps/web/src/app/OfflineBanner.tsx
//
// Persistent thin strip at the top of the shell when the browser
// reports `navigator.onLine === false` (Requirement 14.2 / SW
// offline UX).
//
// Uses `useSyncExternalStore` so the banner re-renders exactly when
// `online`/`offline` events fire, with no stale closure.

import { useSyncExternalStore } from 'react';

function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => undefined;
  window.addEventListener('online', onChange);
  window.addEventListener('offline', onChange);
  return () => {
    window.removeEventListener('online', onChange);
    window.removeEventListener('offline', onChange);
  };
}

function getSnapshot(): boolean {
  if (typeof navigator === 'undefined') return true;
  return navigator.onLine;
}

export function useOnline(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, () => true);
}

export function OfflineBanner(): JSX.Element | null {
  const online = useOnline();
  if (online) return null;
  return (
    <div role="status" aria-live="polite" className="offline-banner">
      You're offline. Sends will queue and deliver on reconnect.
    </div>
  );
}

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { installReconnectHook, registerServiceWorker } from './pwa';
import { applyTheme, resolveInitialTheme } from './styles/theme';
import './styles/theme.css';

// Apply the persisted theme (or the dark default) to
// `documentElement.dataset.theme` BEFORE the first React render so
// the initial paint uses the right palette and we avoid a
// flash-of-wrong-theme on reload (Requirements 14.5, 15.4).
applyTheme(resolveInitialTheme());

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Konvo web shell: missing #root element in index.html');
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Register the Workbox SW and wire offline → online reconciliation
// (task 9.1, Requirements 14.1, 14.2, 14.8, 14.9). Both calls are
// non-throwing: SW registration returns a typed result on failure,
// and the reconnect hook is a no-op when `navigator` is unavailable
// (e.g. SSR / non-browser shells). Skip both in test environments —
// jsdom doesn't ship a service-worker implementation, and tests
// drive registerServiceWorker() / installReconnectHook() directly.
if (typeof window !== 'undefined' && window.location.hostname !== 'test') {
  void registerServiceWorker();
  installReconnectHook();
}

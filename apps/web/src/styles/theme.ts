// apps/web/src/styles/theme.ts
//
// Theme primitives for the PWA (task 9.2 — Requirement 15.4 +
// Requirement 14.5/14.6/14.7).
//
// Two-state model — `light` | `dark` — with `dark` as the default.
// The active theme is exposed to CSS by setting
// `document.documentElement.dataset.theme`, which CSS in
// `theme.css` selects against (`html[data-theme="dark"]` etc.) to
// flip the color tokens.
//
// Why a `dataset` attribute and not a `class`:
//   - Persistence: the value is exposed verbatim in DevTools and
//     in `document.documentElement.outerHTML`, which makes
//     debugging "why is the page light when localStorage says
//     dark?" trivial. With a class we'd have to enumerate the
//     class list.
//   - Specificity: `[data-theme=dark]` and `[data-theme=light]`
//     share the same specificity weight, so neither selector
//     "wins" by accident in cascade ordering.
//
// Storage key — `konvo:theme` — namespaced so a future Konvo
// preference doesn't collide and so a developer hand-editing
// localStorage in DevTools can spot it instantly.

/** Allowed theme values. */
export type Theme = 'light' | 'dark';

/** Default theme when no user preference is recorded — Requirement
 *  14.5 / 15.4 mandate dark default. */
export const DEFAULT_THEME: Theme = 'dark';

/** localStorage key the theme is persisted under. Exported so
 *  tests assert the contract without copy-pasting the string. */
export const THEME_STORAGE_KEY = 'konvo:theme' as const;

/** Type guard. Used both at the storage-read seam (defensive
 *  against tampered values) and at the public-API seam (so
 *  callers can `applyTheme(unknownValue as Theme)` safely). */
export function isTheme(value: unknown): value is Theme {
  return value === 'light' || value === 'dark';
}

/** Read the persisted theme. Returns `null` when no value is
 *  stored OR when the stored value is not a recognized theme
 *  (defensive: a stale schema value should fall back to the
 *  default rather than crash). Tests inject a `storage` to assert
 *  the exact read shape; production callers omit it and we read
 *  from `globalThis.localStorage`.
 *
 *  Storage access is wrapped in a try/catch because some browsers
 *  throw `SecurityError` from `localStorage` access in private
 *  mode / on file:// origins. We treat any throw as "no stored
 *  value" and fall back to the default. */
export function readStoredTheme(storage?: Storage): Theme | null {
  const store = storage ?? safeLocalStorage();
  if (store === null) return null;
  try {
    const raw = store.getItem(THEME_STORAGE_KEY);
    if (raw === null) return null;
    return isTheme(raw) ? raw : null;
  } catch {
    return null;
  }
}

/** Persist the theme. Silently no-ops when storage is
 *  unavailable (private mode etc.); the in-memory + DOM state
 *  is still applied by `applyTheme`, so the page renders
 *  correctly for the duration of the session. */
export function writeStoredTheme(theme: Theme, storage?: Storage): void {
  const store = storage ?? safeLocalStorage();
  if (store === null) return;
  try {
    store.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Quota exceeded / SecurityError / readonly storage — nothing
    // useful to do; the dataset attribute is still set so the
    // current tab keeps the chosen theme.
  }
}

/** Apply the theme to the document. Sets
 *  `document.documentElement.dataset.theme = theme`. SSR-safe:
 *  when `document` is undefined (Node outside jsdom), the call
 *  is a no-op so importers don't need to gate on `typeof
 *  document`.
 *
 *  Consumers that want to persist the choice should call
 *  `writeStoredTheme` before or after `applyTheme`; this function
 *  intentionally does not touch storage so the two concerns can
 *  be tested independently. */
export function applyTheme(theme: Theme, doc?: Document): void {
  const d = doc ?? (typeof document !== 'undefined' ? document : null);
  if (d === null) return;
  d.documentElement.dataset['theme'] = theme;
}

/** Resolve the initial theme: stored value if present, otherwise
 *  `DEFAULT_THEME`. Exported so the bootstrap path in
 *  `main.tsx` can apply the persisted theme before the first
 *  paint (avoids a flash-of-wrong-theme on reload). */
export function resolveInitialTheme(storage?: Storage): Theme {
  return readStoredTheme(storage) ?? DEFAULT_THEME;
}

/** Best-effort access to `localStorage`. Returns `null` when the
 *  global is undefined OR when access throws (Safari private
 *  browsing). */
function safeLocalStorage(): Storage | null {
  try {
    if (typeof localStorage === 'undefined') return null;
    return localStorage;
  } catch {
    return null;
  }
}

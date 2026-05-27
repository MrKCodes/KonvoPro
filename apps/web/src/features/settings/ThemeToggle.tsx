// apps/web/src/features/settings/ThemeToggle.tsx
//
// Theme toggle widget (task 9.2 — Requirements 14.5, 15.4).
//
// Behaviour contract:
//   - Reads the persisted theme from `localStorage['konvo:theme']`
//     on mount; falls back to `dark` (Requirement 14.5).
//   - Exposes a button that flips light↔dark.
//   - On every change: applies the new theme to the document via
//     `applyTheme` AND persists the value via `writeStoredTheme`.
//   - The button reports its current pressed state via
//     `aria-pressed` so screen readers announce the toggle's
//     state. The label always reflects the *next* state ("Switch
//     to light theme" when current is dark) so the affordance is
//     explicit.
//
// Test seam:
//   - The component accepts an optional `storage` prop so unit
//     tests can drive a custom Storage-shaped object without
//     leaking into `globalThis.localStorage` (jsdom gives every
//     test process the same in-memory store, and we want isolated
//     state per test). The `doc` prop mirrors that for the DOM
//     side-effect.
//
// Accessibility:
//   - `<button type="button">` is the canonical interactive
//     element so keyboard activation (Enter / Space) works for
//     free.
//   - The visible focus ring is provided globally by
//     `theme.css`; this component does not override it.

import { useCallback, useEffect, useState, type JSX } from 'react';

import {
  applyTheme,
  readStoredTheme,
  writeStoredTheme,
  DEFAULT_THEME,
  type Theme,
} from '../../styles/theme.js';

export interface ThemeToggleProps {
  /** Override the storage backend (tests). */
  readonly storage?: Storage;
  /** Override the document the dataset is applied to (tests). */
  readonly doc?: Document;
}

export function ThemeToggle(props: ThemeToggleProps): JSX.Element {
  // Initialise from storage, falling back to the spec default.
  // The lazy initializer runs once per mount; on remount in a
  // fresh tab the same lookup occurs so persistence across
  // sessions is automatic.
  const [theme, setTheme] = useState<Theme>(
    () => readStoredTheme(props.storage) ?? DEFAULT_THEME,
  );

  // Apply the theme to the DOM whenever it changes (including on
  // first mount). Keeping this in an effect rather than computing
  // it inline keeps the render pure.
  useEffect(() => {
    applyTheme(theme, props.doc);
  }, [theme, props.doc]);

  const onToggle = useCallback((): void => {
    setTheme((prev) => {
      const next: Theme = prev === 'dark' ? 'light' : 'dark';
      writeStoredTheme(next, props.storage);
      // Apply immediately as well so tests that read
      // `documentElement.dataset.theme` straight after the click
      // see the new value without waiting for the effect.
      applyTheme(next, props.doc);
      return next;
    });
  }, [props.storage, props.doc]);

  // The label communicates the *next* action; `aria-pressed`
  // reports the current state. Together they make the button
  // self-describing for assistive tech.
  const nextLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';

  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={theme === 'dark'}
      aria-label={nextLabel}
      data-testid="theme-toggle"
      data-theme-state={theme}
    >
      {nextLabel}
    </button>
  );
}

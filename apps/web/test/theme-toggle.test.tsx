// apps/web/test/theme-toggle.test.tsx
//
// Unit tests for `apps/web/src/features/settings/ThemeToggle.tsx`
// + `apps/web/src/styles/theme.ts` (task 9.2 — Requirements 14.5,
// 15.4).
//
// Coverage:
//   - Default theme is `dark` when no value is persisted
//     (Requirement 14.5).
//   - Clicking the toggle flips theme dark↔light AND writes the
//     new value to the injected storage.
//   - The persisted value is honored on remount: a new instance
//     with the same storage instance picks up the previously
//     written value rather than the default.
//   - Applying a theme sets `documentElement.dataset.theme` to
//     the matching value.
//
// We use an in-memory `MemoryStorage` rather than the global
// `localStorage` because jsdom shares one localStorage instance
// across the test process, which would couple tests to each
// other's writes.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ThemeToggle } from '../src/features/settings/ThemeToggle.js';
import {
  applyTheme,
  DEFAULT_THEME,
  isTheme,
  readStoredTheme,
  resolveInitialTheme,
  THEME_STORAGE_KEY,
  writeStoredTheme,
} from '../src/styles/theme.js';

class MemoryStorage implements Storage {
  private readonly map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
}

interface Mounted {
  readonly container: HTMLDivElement;
  readonly root: Root;
}

let mounted: Mounted | null = null;

function mount(node: React.ReactNode): Mounted {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(node);
  });
  const m: Mounted = { container, root };
  mounted = m;
  return m;
}

function unmount(): void {
  if (mounted === null) return;
  act(() => {
    mounted!.root.unmount();
  });
  mounted.container.remove();
  mounted = null;
}

beforeEach(() => {
  // Ensure each test starts with a clean documentElement.dataset
  // so a stray write from a prior test doesn't affect assertions.
  if (document.documentElement.dataset['theme'] !== undefined) {
    delete document.documentElement.dataset['theme'];
  }
});

afterEach(() => {
  unmount();
});

describe('theme primitives', () => {
  it('isTheme accepts only "light" and "dark"', () => {
    expect(isTheme('light')).toBe(true);
    expect(isTheme('dark')).toBe(true);
    expect(isTheme('purple')).toBe(false);
    expect(isTheme(undefined)).toBe(false);
    expect(isTheme(null)).toBe(false);
    expect(isTheme(123)).toBe(false);
  });

  it('readStoredTheme returns null when storage is empty', () => {
    const storage = new MemoryStorage();
    expect(readStoredTheme(storage)).toBeNull();
  });

  it('readStoredTheme returns null when stored value is unrecognized', () => {
    const storage = new MemoryStorage();
    storage.setItem(THEME_STORAGE_KEY, 'oklab');
    expect(readStoredTheme(storage)).toBeNull();
  });

  it('writeStoredTheme persists under the namespaced key', () => {
    const storage = new MemoryStorage();
    writeStoredTheme('light', storage);
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('light');
    writeStoredTheme('dark', storage);
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('dark');
  });

  it('resolveInitialTheme falls back to dark when storage is empty', () => {
    const storage = new MemoryStorage();
    expect(resolveInitialTheme(storage)).toBe('dark');
    expect(DEFAULT_THEME).toBe('dark');
  });

  it('resolveInitialTheme reads persisted value', () => {
    const storage = new MemoryStorage();
    writeStoredTheme('light', storage);
    expect(resolveInitialTheme(storage)).toBe('light');
  });

  it('applyTheme sets documentElement.dataset.theme', () => {
    applyTheme('light');
    expect(document.documentElement.dataset['theme']).toBe('light');
    applyTheme('dark');
    expect(document.documentElement.dataset['theme']).toBe('dark');
  });
});

describe('ThemeToggle', () => {
  it('defaults to dark when no value is persisted (Requirement 14.5)', () => {
    const storage = new MemoryStorage();
    const m = mount(<ThemeToggle storage={storage} />);

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="theme-toggle"]',
    );
    expect(btn).not.toBeNull();
    expect(btn!.getAttribute('data-theme-state')).toBe('dark');
    // aria-pressed reports the current binary state — dark = true.
    expect(btn!.getAttribute('aria-pressed')).toBe('true');
    // Document carries the dark theme via the dataset attribute.
    expect(document.documentElement.dataset['theme']).toBe('dark');
  });

  it('clicking the toggle flips dark → light AND persists', () => {
    const storage = new MemoryStorage();
    const m = mount(<ThemeToggle storage={storage} />);

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="theme-toggle"]',
    );
    act(() => {
      btn!.click();
    });

    expect(btn!.getAttribute('data-theme-state')).toBe('light');
    expect(btn!.getAttribute('aria-pressed')).toBe('false');
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(document.documentElement.dataset['theme']).toBe('light');
  });

  it('clicking twice flips dark → light → dark', () => {
    const storage = new MemoryStorage();
    const m = mount(<ThemeToggle storage={storage} />);

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="theme-toggle"]',
    );
    act(() => {
      btn!.click();
    });
    act(() => {
      btn!.click();
    });

    expect(btn!.getAttribute('data-theme-state')).toBe('dark');
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('dark');
    expect(document.documentElement.dataset['theme']).toBe('dark');
  });

  it('persists value across remount with the same storage', () => {
    // First mount: pick light, then unmount.
    const storage = new MemoryStorage();
    const m1 = mount(<ThemeToggle storage={storage} />);
    const btn1 = m1.container.querySelector<HTMLButtonElement>(
      '[data-testid="theme-toggle"]',
    );
    act(() => {
      btn1!.click();
    });
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('light');
    unmount();

    // Reset documentElement state to prove the *next* mount drives
    // the dataset back to the persisted value rather than relying
    // on residual side-effects from the prior mount.
    delete document.documentElement.dataset['theme'];

    // Second mount with the SAME storage: the stored "light" wins
    // over the dark default.
    const m2 = mount(<ThemeToggle storage={storage} />);
    const btn2 = m2.container.querySelector<HTMLButtonElement>(
      '[data-testid="theme-toggle"]',
    );
    expect(btn2!.getAttribute('data-theme-state')).toBe('light');
    expect(document.documentElement.dataset['theme']).toBe('light');
  });

  it('button label always describes the next action', () => {
    const storage = new MemoryStorage();
    const m = mount(<ThemeToggle storage={storage} />);
    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="theme-toggle"]',
    );
    // Default = dark — label offers light.
    expect(btn!.textContent).toBe('Switch to light theme');
    expect(btn!.getAttribute('aria-label')).toBe('Switch to light theme');

    act(() => {
      btn!.click();
    });
    // Now light — label offers dark.
    expect(btn!.textContent).toBe('Switch to dark theme');
    expect(btn!.getAttribute('aria-label')).toBe('Switch to dark theme');
  });
});

// apps/web/src/features/auth/store.ts
//
// Web_Client auth state store (task 2.10).
//
// Realizes Requirement 1.11 / 16.4: the access token MUST live in memory
// only — never in `localStorage`, never in `sessionStorage`, never in
// `IndexedDB`, never in a `document.cookie` write. The refresh token is
// already an `httpOnly` cookie set by the API_Gateway and is therefore
// invisible to JavaScript by construction; we never read or write it
// here.
//
// Why a hand-rolled "zustand-shaped" store and not `zustand` itself:
//   - The package.json declares `zustand` as a dependency, but the task
//     brief says "DO NOT run pnpm install" so we can't actually import
//     it yet. The store below mirrors zustand's vanilla `getState` /
//     `setState` / `subscribe` surface plus a React `useStore(selector)`
//     hook built on `useSyncExternalStore`. When `zustand` lands in
//     node_modules a follow-up patch can replace `createStore` with
//     `import { createStore } from 'zustand/vanilla'` and
//     `useSyncExternalStoreWithSelector` with `zustand`'s `useStore` —
//     no call-site changes required.
//   - Confining persistence policy to ONE file (this one) makes it
//     auditable: a future contributor only has to read this header
//     comment to know that the access token cannot, by construction,
//     be persisted.
//
// Persistence-prevention guarantees:
//   1. The state object lives in a closed-over `let` inside this
//      module. There's no way for another module to mutate it except
//      via the exported `setState`.
//   2. We never call `localStorage.setItem`, `sessionStorage.setItem`,
//      `document.cookie =`, or any `IDBDatabase.put` from here. A
//      grep over this file is sufficient evidence.
//   3. The optional dev-mode guard (`installPersistenceTripwire`) wraps
//      `localStorage.setItem` and `sessionStorage.setItem` with a
//      checker that THROWS if any caller tries to store the current
//      access token. It's enabled in tests (so a regression fails
//      loudly) and opt-in for production.

import { useSyncExternalStore } from 'react';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Authenticated user identity returned by `/auth/login` / `/auth/refresh`. */
export interface AuthUser {
  readonly id: string;
  readonly handle: string;
}

/** In-memory auth state. `accessToken` is the 15-min HS256 JWT; `null`
 *  when logged out. `user` mirrors the login response payload. The
 *  refresh token deliberately does NOT appear here — it lives in an
 *  `httpOnly` cookie set by the API_Gateway. */
export interface AuthState {
  readonly accessToken: string | null;
  readonly user: AuthUser | null;
}

/** Mutators exposed alongside the readable state. They're declared on a
 *  sibling type rather than on `AuthState` so a `useAuthStore(selector)`
 *  reader can't accidentally call them as if they were data. */
export interface AuthActions {
  /** Set both the access token and the user identity (login / refresh). */
  setAuth(next: { accessToken: string; user: AuthUser }): void;
  /** Replace just the access token (silent refresh). */
  setAccessToken(token: string): void;
  /** Clear everything (logout, 401 from API). */
  clearAuth(): void;
}

// ---------------------------------------------------------------------------
// Vanilla store — zustand-shaped, hand-rolled
// ---------------------------------------------------------------------------

type Listener<T> = (state: T, prev: T) => void;

interface VanillaStore<T> {
  getState(): T;
  setState(
    updater: Partial<T> | ((current: T) => Partial<T> | T),
  ): void;
  subscribe(listener: Listener<T>): () => void;
}

function createStore<T extends object>(initial: T): VanillaStore<T> {
  let state: T = initial;
  const listeners = new Set<Listener<T>>();
  return {
    getState: () => state,
    setState: (updater) => {
      const patch =
        typeof updater === 'function'
          ? (updater as (s: T) => Partial<T> | T)(state)
          : updater;
      const prev = state;
      // We always shallow-merge — the store value is a flat record
      // and there are no nested-object mutations to worry about.
      state = { ...state, ...patch } as T;
      // Bail out if nothing actually changed (referential equality on
      // the merged object is enough — any field-level change produced
      // a new top-level reference above).
      if (Object.is(prev, state)) {
        return;
      }
      for (const listener of listeners) {
        listener(state, prev);
      }
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

// ---------------------------------------------------------------------------
// The actual store
// ---------------------------------------------------------------------------

const INITIAL_STATE: AuthState = {
  accessToken: null,
  user: null,
};

const store: VanillaStore<AuthState> = createStore(INITIAL_STATE);

/** Auth actions. Defined as a frozen const so a stray
 *  `actions.setAuth = noop` from a test or a malicious devtools
 *  injection is rejected. */
export const authActions: AuthActions = Object.freeze({
  setAuth: ({ accessToken, user }: { accessToken: string; user: AuthUser }) => {
    store.setState({ accessToken, user });
  },
  setAccessToken: (accessToken: string) => {
    store.setState({ accessToken });
  },
  clearAuth: () => {
    store.setState({ accessToken: null, user: null });
  },
});

/** Direct access to the current state. Prefer `useAuthStore(selector)`
 *  in React render paths (it subscribes for re-renders); use this from
 *  imperative code such as fetch interceptors. */
export function getAuthState(): AuthState {
  return store.getState();
}

/** Subscribe to state changes. Returns an unsubscribe callback. */
export function subscribeAuth(
  listener: (state: AuthState, prev: AuthState) => void,
): () => void {
  return store.subscribe(listener);
}

/** React hook with a selector. Subscribes for re-renders only when the
 *  selected slice changes (Object.is comparison). Mirrors zustand's
 *  `useStore(store, selector)` ergonomics. */
export function useAuthStore<T>(selector: (state: AuthState) => T): T {
  // useSyncExternalStore expects a `getSnapshot` returning a stable
  // reference when nothing changed. Our store mutates by replacing the
  // top-level object so the selected slice is referentially stable
  // across "no-op" setState calls.
  return useSyncExternalStore(
    (onChange) => store.subscribe(() => onChange()),
    () => selector(store.getState()),
    () => selector(INITIAL_STATE),
  );
}

// ---------------------------------------------------------------------------
// Test-only reset
// ---------------------------------------------------------------------------

/** Reset the store to its initial state. Tests use this in
 *  `beforeEach`. Production code should never call this — use
 *  `authActions.clearAuth()` for logout. */
export function __resetAuthStoreForTests(): void {
  store.setState(INITIAL_STATE);
}

// ---------------------------------------------------------------------------
// Persistence tripwire — fail-loud guard for Requirement 1.11 / 16.4
// ---------------------------------------------------------------------------

/** Install a runtime tripwire that throws if any code attempts to
 *  store the current access token in `localStorage` or `sessionStorage`.
 *
 *  This is defense-in-depth on top of the architectural guarantee that
 *  this module never persists. A future contributor who introduces a
 *  `localStorage.setItem('accessToken', ...)` somewhere will see a hard
 *  test failure rather than a silent regression.
 *
 *  Returns an `uninstall` callback that restores the original
 *  `setItem`. The function is a no-op when `localStorage` /
 *  `sessionStorage` are not available (SSR, some unit-test
 *  environments).
 *
 *  Implementation note: in jsdom the `Storage` interface exposes
 *  `setItem` via the prototype (and `localStorage` itself is a getter
 *  that returns the proxy each time). Assigning `storage.setItem = fn`
 *  silently fails in some jsdom builds. We patch the prototype method
 *  instead so the wrapper applies to every `Storage` instance the page
 *  ever sees. */
export function installPersistenceTripwire(): () => void {
  const restorers: Array<() => void> = [];

  // Prefer the prototype path (jsdom + browsers): patches the method
  // for every Storage instance in one shot. Fall back to per-instance
  // assignment when the prototype isn't reachable (some Node test
  // environments).
  const Storage = (globalThis as unknown as { Storage?: typeof globalThis.Storage })
    .Storage;
  if (typeof Storage === 'function') {
    const originalSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key: string, value: string): void {
      const token = store.getState().accessToken;
      if (token !== null && (value === token || value.includes(token))) {
        // `this === localStorage | sessionStorage`. We don't try to
        // tell them apart in the message — both are equally bad.
        throw new Error(
          `auth-store tripwire: refusing to write access token to web storage (key=${key})`,
        );
      }
      originalSetItem.call(this, key, value);
    };
    restorers.push(() => {
      Storage.prototype.setItem = originalSetItem;
    });
  } else {
    for (const storageName of ['localStorage', 'sessionStorage'] as const) {
      const storage = (globalThis as unknown as Record<string, Storage | undefined>)[
        storageName
      ];
      if (storage === undefined) continue;
      const original = storage.setItem.bind(storage);
      storage.setItem = (key: string, value: string) => {
        const token = store.getState().accessToken;
        if (token !== null && (value === token || value.includes(token))) {
          throw new Error(
            `auth-store tripwire: refusing to write access token to ${storageName} (key=${key})`,
          );
        }
        original(key, value);
      };
      restorers.push(() => {
        storage.setItem = original;
      });
    }
  }
  return () => {
    for (const r of restorers) r();
  };
}

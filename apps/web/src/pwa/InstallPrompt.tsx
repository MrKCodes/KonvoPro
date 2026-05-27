// apps/web/src/pwa/InstallPrompt.tsx
//
// Install-prompt UI (task 9.2 — Requirement 14.1 surface).
//
// Browsers that meet the PWA installability criteria fire a
// `beforeinstallprompt` event on the window. The default browser
// UX hides the prompt behind an address-bar affordance; a richer
// PWA shell can intercept the event, defer it, and surface its
// own "Install" button so the user discovers the option in
// context.
//
// Contract:
//   - On mount, install a `beforeinstallprompt` listener on the
//     target (`window` by default; tests inject a fake target).
//   - When the event fires we (a) call `event.preventDefault()`
//     so the browser's native UI doesn't compete with ours,
//     (b) stash the deferred event, and (c) render an "Install
//     Konvo" button.
//   - When the user clicks the button we call `prompt()` to show
//     the platform-native install dialog and await `userChoice`.
//     Either outcome (`accepted` / `dismissed`) clears the
//     deferred event so we don't show a stale prompt — the
//     browser will fire a fresh `beforeinstallprompt` if the app
//     becomes installable again.
//   - When the app installs (the browser fires `appinstalled`),
//     we hide the prompt regardless.
//
// `BeforeInstallPromptEvent` is only spec'd in the W3C PWA TR;
// TypeScript's lib.dom doesn't include it yet, so we declare a
// minimal interface here. Casting in callers stays narrow.

import {
  useCallback,
  useEffect,
  useState,
  type JSX,
} from 'react';

/** Subset of the PWA-installability `BeforeInstallPromptEvent`
 *  surface we actually use. `preventDefault` is inherited from
 *  the base `Event`; we list it here for self-documentation. */
export interface BeforeInstallPromptEventLike extends Event {
  readonly userChoice: Promise<{
    readonly outcome: 'accepted' | 'dismissed';
    readonly platform: string;
  }>;
  prompt(): Promise<void>;
}

export interface InstallPromptProps {
  /** Override the event target (tests). Defaults to `window`. */
  readonly target?: EventTarget;
  /** Optional callback fired with the user's choice after the
   *  native prompt resolves. Useful for analytics-free metrics
   *  (we count install acceptance locally to drive the "thanks
   *  for installing" toast in a future task). */
  readonly onChoice?: (outcome: 'accepted' | 'dismissed') => void;
}

export function InstallPrompt(props: InstallPromptProps): JSX.Element | null {
  const [deferred, setDeferred] = useState<BeforeInstallPromptEventLike | null>(
    null,
  );
  const [installed, setInstalled] = useState<boolean>(false);

  useEffect(() => {
    const target = props.target ?? (typeof window !== 'undefined' ? window : null);
    if (target === null) return;

    const onBeforeInstall = (ev: Event): void => {
      // Suppress the browser's automatic mini-infobar; we'll
      // surface our own affordance.
      ev.preventDefault();
      setDeferred(ev as BeforeInstallPromptEventLike);
    };
    const onInstalled = (): void => {
      // App installed — hide the button and drop the deferred
      // event so the next render is a no-op.
      setInstalled(true);
      setDeferred(null);
    };

    target.addEventListener('beforeinstallprompt', onBeforeInstall);
    target.addEventListener('appinstalled', onInstalled);
    return (): void => {
      target.removeEventListener('beforeinstallprompt', onBeforeInstall);
      target.removeEventListener('appinstalled', onInstalled);
    };
  }, [props.target]);

  const onClick = useCallback(async (): Promise<void> => {
    if (deferred === null) return;
    try {
      // `prompt()` returns a promise that resolves after the
      // native dialog has been shown; the actual user choice
      // arrives via `userChoice` (separate promise on the same
      // event). Both promises must be awaited to fully consume
      // the deferred event.
      await deferred.prompt();
      const choice = await deferred.userChoice;
      props.onChoice?.(choice.outcome);
    } catch {
      // The browser rejects `prompt()` if it has been called
      // before, or if too much time has elapsed since the
      // beforeinstallprompt fired. Either way, dropping the
      // deferred event is the right cleanup.
    }
    setDeferred(null);
  }, [deferred, props]);

  if (installed || deferred === null) {
    return null;
  }

  return (
    <button
      type="button"
      onClick={(): void => {
        void onClick();
      }}
      data-testid="install-prompt-button"
      aria-label="Install Konvo as an app"
    >
      Install Konvo
    </button>
  );
}

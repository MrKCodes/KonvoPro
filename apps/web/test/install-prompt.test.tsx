// apps/web/test/install-prompt.test.tsx
//
// Unit tests for `apps/web/src/pwa/InstallPrompt.tsx` (task 9.2 —
// surface for Requirement 14.1 / install affordance).
//
// Coverage:
//   - The button is hidden until `beforeinstallprompt` fires on
//     the target.
//   - When `beforeinstallprompt` fires, the component calls
//     `event.preventDefault()` (so the browser's native mini
//     infobar is suppressed) and renders the "Install Konvo"
//     button.
//   - Clicking the button invokes `event.prompt()` exactly once
//     and awaits `event.userChoice`.
//   - After the user choice resolves, the button is removed
//     from the DOM (one-shot prompt).
//   - The `appinstalled` event hides the prompt.
//
// No `@testing-library/react` — we mirror the harness used by
// `in-call-safety-number.test.tsx`.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { InstallPrompt } from '../src/pwa/InstallPrompt.js';

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

afterEach(() => {
  unmount();
});

/** Construct a deferred BeforeInstallPromptEvent stand-in.
 *  Exposes `prompt` + `userChoice` (the only two surfaces the
 *  component reads), plus a `preventDefault` spy so tests can
 *  assert the SPA suppressed the browser's automatic mini
 *  infobar. */
function makeBipEvent(opts: {
  readonly outcome: 'accepted' | 'dismissed';
}): {
  readonly event: Event;
  readonly prompt: ReturnType<typeof vi.fn>;
  readonly userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
} {
  const userChoice = Promise.resolve({
    outcome: opts.outcome,
    platform: 'web',
  });
  const promptFn = vi.fn().mockResolvedValue(undefined);
  const event = new Event('beforeinstallprompt') as Event & {
    prompt: typeof promptFn;
    userChoice: typeof userChoice;
  };
  Object.defineProperty(event, 'prompt', { value: promptFn });
  Object.defineProperty(event, 'userChoice', { value: userChoice });
  return { event, prompt: promptFn, userChoice };
}

async function flushAsync(times = 5): Promise<void> {
  for (let i = 0; i < times; i += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

describe('InstallPrompt', () => {
  it('does not render the button before beforeinstallprompt fires', () => {
    const target = new EventTarget();
    const m = mount(<InstallPrompt target={target} />);
    expect(
      m.container.querySelector('[data-testid="install-prompt-button"]'),
    ).toBeNull();
  });

  it('renders the button when beforeinstallprompt fires (and suppresses default)', async () => {
    const target = new EventTarget();
    const m = mount(<InstallPrompt target={target} />);

    const { event } = makeBipEvent({ outcome: 'accepted' });
    const preventSpy = vi.spyOn(event, 'preventDefault');
    act(() => {
      target.dispatchEvent(event);
    });
    await flushAsync();

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="install-prompt-button"]',
    );
    expect(btn).not.toBeNull();
    expect(btn!.textContent).toBe('Install Konvo');
    expect(preventSpy).toHaveBeenCalledTimes(1);
  });

  it('clicking the button calls prompt() and resolves with userChoice', async () => {
    const target = new EventTarget();
    const onChoice = vi.fn();
    const m = mount(<InstallPrompt target={target} onChoice={onChoice} />);

    const { event, prompt } = makeBipEvent({ outcome: 'accepted' });
    act(() => {
      target.dispatchEvent(event);
    });
    await flushAsync();

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="install-prompt-button"]',
    );
    expect(btn).not.toBeNull();

    await act(async () => {
      btn!.click();
      await Promise.resolve();
    });
    await flushAsync();

    expect(prompt).toHaveBeenCalledTimes(1);
    expect(onChoice).toHaveBeenCalledWith('accepted');

    // The prompt is one-shot — the button hides after the
    // userChoice resolves.
    expect(
      m.container.querySelector('[data-testid="install-prompt-button"]'),
    ).toBeNull();
  });

  it('handles dismiss outcome and hides the button', async () => {
    const target = new EventTarget();
    const onChoice = vi.fn();
    const m = mount(<InstallPrompt target={target} onChoice={onChoice} />);

    const { event } = makeBipEvent({ outcome: 'dismissed' });
    act(() => {
      target.dispatchEvent(event);
    });
    await flushAsync();

    const btn = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="install-prompt-button"]',
    );
    expect(btn).not.toBeNull();

    await act(async () => {
      btn!.click();
      await Promise.resolve();
    });
    await flushAsync();

    expect(onChoice).toHaveBeenCalledWith('dismissed');
    expect(
      m.container.querySelector('[data-testid="install-prompt-button"]'),
    ).toBeNull();
  });

  it('hides the button when appinstalled fires', async () => {
    const target = new EventTarget();
    const m = mount(<InstallPrompt target={target} />);

    const { event } = makeBipEvent({ outcome: 'accepted' });
    act(() => {
      target.dispatchEvent(event);
    });
    await flushAsync();

    expect(
      m.container.querySelector('[data-testid="install-prompt-button"]'),
    ).not.toBeNull();

    act(() => {
      target.dispatchEvent(new Event('appinstalled'));
    });
    await flushAsync();

    expect(
      m.container.querySelector('[data-testid="install-prompt-button"]'),
    ).toBeNull();
  });
});

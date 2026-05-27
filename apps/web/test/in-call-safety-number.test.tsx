// apps/web/test/in-call-safety-number.test.tsx
//
// Unit tests for `apps/web/src/features/calls/InCallSafetyNumber.tsx`
// (task 6.5 — UI half of requirement 7.6).
//
// Coverage:
//   - With two known 32-byte identity public keys + user IDs, the
//     rendered digits exactly equal the value `computeSafetyNumber`
//     produces. We delegate the expected value to the same crypto
//     primitive rather than hard-coding a fixture so any future
//     change to the data layer (e.g. a different iteration count)
//     is caught by the existing crypto property tests, not by a
//     stale UI snapshot.
//   - The rendered region exposes a `data-qr-payload` attribute
//     equal to the base64 encoding of the QR payload bytes — this
//     is the contract the QR-rendering path relies on.
//   - The close button invokes the `onClose` prop exactly once.
//
// Test-environment notes:
//   - Tests run under jsdom + fake-indexeddb (see test/setup.ts).
//   - We use `react-dom/client`'s `createRoot` directly rather than
//     pulling in `@testing-library/react`; the assertions only
//     need `querySelector` access to a few `data-testid`s, and
//     keeping the dependency surface small mirrors the rest of
//     `apps/web/test/`.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { computeSafetyNumber } from '@konvo/crypto';

import { InCallSafetyNumber } from '../src/features/calls/InCallSafetyNumber.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface Mounted {
  readonly container: HTMLDivElement;
  readonly root: Root;
}

let mounted: Mounted | null = null;

function mount(node: React.ReactNode): Mounted {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  // act() is required so React commits the initial render before
  // we read the DOM. We intentionally cast to `any` only to satisfy
  // act's loose return-type contract; the function we pass returns
  // void.
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

/** Spin the microtask queue under `act` until the predicate is
 *  true or `attempts` ticks have elapsed. The component does its
 *  compute in a chained `useEffect → async IIFE → setState`, so we
 *  need at least 3 microtask flushes for the `ready` state to
 *  paint. The default `attempts: 50` is far in excess of that.
 *
 *  Wrapping each tick in `act` (and using `await act(async () =>
 *  ...)` so async settlements within the callback also count as
 *  "inside act") ensures React's internal flush + post-effect work
 *  runs synchronously to the test boundary; without this, the
 *  async `setState` inside the component's `useEffect` chain
 *  prints a "not wrapped in act" warning. */
async function waitFor(
  pred: () => boolean,
  attempts = 50,
): Promise<void> {
  for (let i = 0; i < attempts; i += 1) {
    // Probe under act so any pending effect work flushes before we
    // read state.
    let ok = false;
    await act(async () => {
      // Yield once per tick so queued microtasks (async
      // computeSafetyNumber → setState) run.
      await Promise.resolve();
      ok = pred();
    });
    if (ok) return;
  }
  throw new Error('waitFor: predicate never became true');
}

// ---------------------------------------------------------------------------
// Fixture identity keys
// ---------------------------------------------------------------------------

/** 32-byte identity-key fixtures. The bytes are deterministic
 *  (filled with constants) so the test is fully reproducible. The
 *  values themselves are arbitrary; safety-number computation
 *  doesn't validate that they're real Curve25519 points. */
function localIk(): Uint8Array {
  const ik = new Uint8Array(32);
  ik.fill(0x11);
  return ik;
}

function remoteIk(): Uint8Array {
  const ik = new Uint8Array(32);
  ik.fill(0xaa);
  return ik;
}

const LOCAL_USER = 'alice-uuid';
const REMOTE_USER = 'bob-uuid';

// Standard-base64 encode mirroring the helper inside the component.
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('InCallSafetyNumber', () => {
  beforeEach(() => {
    // Component is exhibitionist about errors via `role="alert"`;
    // tests fail loudly on unhandled rejections regardless.
  });

  it('renders the digits exactly equal to computeSafetyNumber output', async () => {
    const expected = await computeSafetyNumber(
      localIk(),
      LOCAL_USER,
      remoteIk(),
      REMOTE_USER,
    );

    const m = mount(
      <InCallSafetyNumber
        localIdentityPub={localIk()}
        localUserId={LOCAL_USER}
        remoteIdentityPub={remoteIk()}
        remoteUserId={REMOTE_USER}
        peerHandle="bob"
        onClose={() => {}}
      />,
    );

    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="in-call-safety-number-digits"]',
        ) !== null,
    );

    const digitsEl = m.container.querySelector(
      '[data-testid="in-call-safety-number-digits"] pre',
    );
    expect(digitsEl).not.toBeNull();
    // Exact-equal: 12 groups of 5, single-space separator.
    expect(digitsEl!.textContent).toBe(expected.digits);

    // Sanity: format constant from requirements 7.6 / 8.3.
    expect(digitsEl!.textContent).toMatch(
      /^[0-9]{5}( [0-9]{5}){11}$/,
    );

    // QR payload region carries the base64 of the qrPayload bytes.
    const qrEl = m.container.querySelector(
      '[data-testid="in-call-safety-number-qr"]',
    );
    expect(qrEl).not.toBeNull();
    expect(qrEl!.getAttribute('data-qr-payload')).toBe(
      bytesToBase64(expected.qrPayload),
    );

    // QR section embeds an inline SVG — proves the qrcode library
    // ran and produced something parseable.
    const svg = qrEl!.querySelector('svg');
    expect(svg).not.toBeNull();
  });

  it('includes the peer handle in the heading when provided', async () => {
    const m = mount(
      <InCallSafetyNumber
        localIdentityPub={localIk()}
        localUserId={LOCAL_USER}
        remoteIdentityPub={remoteIk()}
        remoteUserId={REMOTE_USER}
        peerHandle="bob"
        onClose={() => {}}
      />,
    );

    await waitFor(
      () =>
        m.container.querySelector('#in-call-safety-number-heading') !== null,
    );
    const heading = m.container.querySelector(
      '#in-call-safety-number-heading',
    );
    expect(heading?.textContent).toContain('bob');
  });

  it('falls back to a generic peer label when peerHandle is omitted', async () => {
    const m = mount(
      <InCallSafetyNumber
        localIdentityPub={localIk()}
        localUserId={LOCAL_USER}
        remoteIdentityPub={remoteIk()}
        remoteUserId={REMOTE_USER}
        onClose={() => {}}
      />,
    );

    await waitFor(
      () =>
        m.container.querySelector('#in-call-safety-number-heading') !== null,
    );
    const heading = m.container.querySelector(
      '#in-call-safety-number-heading',
    );
    // Generic fallback — not "undefined" or empty.
    expect(heading?.textContent).toContain('this peer');
  });

  it('invokes onClose when the close button is clicked', async () => {
    const onClose = vi.fn();

    const m = mount(
      <InCallSafetyNumber
        localIdentityPub={localIk()}
        localUserId={LOCAL_USER}
        remoteIdentityPub={remoteIk()}
        remoteUserId={REMOTE_USER}
        onClose={onClose}
      />,
    );

    // Drain the async compute / setState chain before clicking so
    // the click event itself isn't racing the `ready` state
    // transition (which would surface as a "not wrapped in act"
    // warning even though the assertion would still pass).
    await waitFor(
      () =>
        m.container.querySelector(
          '[data-testid="in-call-safety-number-digits"]',
        ) !== null,
    );

    const close = m.container.querySelector<HTMLButtonElement>(
      '[data-testid="in-call-safety-number-close"]',
    );
    expect(close).not.toBeNull();

    act(() => {
      close!.click();
    });

    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

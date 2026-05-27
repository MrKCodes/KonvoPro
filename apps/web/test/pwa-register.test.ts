// apps/web/test/pwa-register.test.ts
//
// Unit tests for `apps/web/src/pwa/register.ts` (task 9.1).
//
// Coverage:
//   - registerServiceWorker resolves successfully on registration
//     success (Requirement 14.1).
//   - registerServiceWorker resolves with a typed `'failed'` result
//     (no throw to caller) on registration error AND emits a
//     structured-log record (Requirement 14.8).
//   - registerServiceWorker resolves with `'unsupported'` when
//     `navigator.serviceWorker` is absent (legacy browsers).
//   - installReconnectHook dispatches `RECONNECT_EVENT_NAME` on
//     offline → online transitions and is silent for online-only
//     drift (Requirement 14.9).
//   - installReconnectHook returns an idempotent unsubscribe
//     callback.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  installReconnectHook,
  onReconnect,
  RECONNECT_EVENT_NAME,
  registerServiceWorker,
  resetPwaLogSink,
  setPwaLogSink,
  type PwaLogRecord,
} from '../src/pwa/index.js';

// -----------------------------------------------------------------
// Test fixtures: a synthetic Navigator + an EventTarget that
// pretends to be the browser globalThis. The reconnect hook reads
// `target.navigator.onLine`, listens for `online` / `offline`
// events on `target`, and dispatches `konvo:reconnect` on the same
// target. We construct a minimal harness matching that contract.
// -----------------------------------------------------------------

interface FakeNavigator {
  onLine: boolean;
  serviceWorker?: {
    register(url: string): Promise<ServiceWorkerRegistration>;
  };
}

class FakeTarget extends EventTarget {
  navigator: FakeNavigator;
  constructor(navigator: FakeNavigator) {
    super();
    this.navigator = navigator;
  }
}

let logRecords: PwaLogRecord[] = [];
beforeEach(() => {
  logRecords = [];
  setPwaLogSink((r) => {
    logRecords.push(r);
  });
});
afterEach(() => {
  resetPwaLogSink();
});

// -----------------------------------------------------------------
// registerServiceWorker
// -----------------------------------------------------------------

describe('registerServiceWorker', () => {
  it('resolves to { kind: "registered" } when navigator.serviceWorker.register succeeds', async () => {
    const fakeRegistration = {
      scope: 'https://example.com/',
    } as ServiceWorkerRegistration;
    const register = vi.fn().mockResolvedValue(fakeRegistration);
    const navigator: FakeNavigator = {
      onLine: true,
      serviceWorker: { register },
    };
    const result = await registerServiceWorker({
      navigator: navigator as unknown as Navigator,
      url: '/sw.js',
    });
    expect(register).toHaveBeenCalledWith('/sw.js');
    expect(result).toEqual({ kind: 'registered', registration: fakeRegistration });
    // A success record was logged.
    expect(logRecords.some((r) => r.msg === 'sw.registered')).toBe(true);
  });

  it('resolves to { kind: "failed" } and logs (does NOT throw) on registration error', async () => {
    const error = new Error('ServiceWorker quota exceeded');
    const register = vi.fn().mockRejectedValue(error);
    const navigator: FakeNavigator = {
      onLine: true,
      serviceWorker: { register },
    };
    const result = await registerServiceWorker({
      navigator: navigator as unknown as Navigator,
    });
    expect(result.kind).toBe('failed');
    if (result.kind === 'failed') {
      expect(result.error).toBe(error);
    }
    // Failure was logged via the structured logger (Requirement 14.8).
    const failureRecord = logRecords.find((r) => r.msg === 'sw.register_failed');
    expect(failureRecord).toBeDefined();
    expect(failureRecord?.level).toBe('warn');
  });

  it('resolves to { kind: "unsupported" } when navigator.serviceWorker is absent', async () => {
    const navigator: FakeNavigator = { onLine: true };
    const result = await registerServiceWorker({
      navigator: navigator as unknown as Navigator,
    });
    expect(result).toEqual({ kind: 'unsupported' });
    expect(logRecords.some((r) => r.msg === 'sw.unsupported')).toBe(true);
  });
});

// -----------------------------------------------------------------
// installReconnectHook + onReconnect
// -----------------------------------------------------------------

describe('installReconnectHook', () => {
  it('dispatches the reconnect event when offline → online transitions', () => {
    const navigator: FakeNavigator = { onLine: false };
    const target = new FakeTarget(navigator);
    const dispatched: number[] = [];
    target.addEventListener(RECONNECT_EVENT_NAME, (ev) => {
      const e = ev as CustomEvent<{ at: number }>;
      dispatched.push(e.detail.at);
    });

    const stop = installReconnectHook({
      target: target as unknown as EventTarget & { navigator?: Navigator },
      navigator: navigator as unknown as Navigator,
    });
    // Simulate a transition: navigator flips to online, then the
    // browser fires the `online` event.
    navigator.onLine = true;
    target.dispatchEvent(new Event('online'));
    expect(dispatched).toHaveLength(1);
    stop();
  });

  it('does NOT dispatch when the page was already online (no offline → online transition)', () => {
    const navigator: FakeNavigator = { onLine: true };
    const target = new FakeTarget(navigator);
    const dispatched: number[] = [];
    target.addEventListener(RECONNECT_EVENT_NAME, () => {
      dispatched.push(Date.now());
    });

    const stop = installReconnectHook({
      target: target as unknown as EventTarget & { navigator?: Navigator },
      navigator: navigator as unknown as Navigator,
    });
    // Spurious `online` event (some browsers fire on tab focus).
    target.dispatchEvent(new Event('online'));
    expect(dispatched).toHaveLength(0);
    stop();
  });

  it('dispatches once per offline→online transition, even across multiple cycles', () => {
    const navigator: FakeNavigator = { onLine: true };
    const target = new FakeTarget(navigator);
    const dispatched: number[] = [];
    target.addEventListener(RECONNECT_EVENT_NAME, () => {
      dispatched.push(Date.now());
    });

    const stop = installReconnectHook({
      target: target as unknown as EventTarget & { navigator?: Navigator },
      navigator: navigator as unknown as Navigator,
    });
    // Cycle 1: go offline then online.
    navigator.onLine = false;
    target.dispatchEvent(new Event('offline'));
    navigator.onLine = true;
    target.dispatchEvent(new Event('online'));
    // Cycle 2: same again.
    navigator.onLine = false;
    target.dispatchEvent(new Event('offline'));
    navigator.onLine = true;
    target.dispatchEvent(new Event('online'));
    expect(dispatched).toHaveLength(2);
    stop();
  });

  it('returns an idempotent unsubscribe callback', () => {
    const navigator: FakeNavigator = { onLine: false };
    const target = new FakeTarget(navigator);
    const stop = installReconnectHook({
      target: target as unknown as EventTarget & { navigator?: Navigator },
      navigator: navigator as unknown as Navigator,
    });
    expect(() => {
      stop();
      stop();
    }).not.toThrow();
  });

  it('after unsubscribe, no further events are dispatched', () => {
    const navigator: FakeNavigator = { onLine: false };
    const target = new FakeTarget(navigator);
    const dispatched: number[] = [];
    target.addEventListener(RECONNECT_EVENT_NAME, () => {
      dispatched.push(1);
    });
    const stop = installReconnectHook({
      target: target as unknown as EventTarget & { navigator?: Navigator },
      navigator: navigator as unknown as Navigator,
    });
    stop();
    navigator.onLine = true;
    target.dispatchEvent(new Event('online'));
    expect(dispatched).toHaveLength(0);
  });
});

describe('onReconnect', () => {
  it('subscribes a listener to the reconnect event with detail.at', () => {
    const target = new EventTarget();
    const calls: number[] = [];
    const stop = onReconnect((info) => calls.push(info.at), target);
    target.dispatchEvent(
      new CustomEvent(RECONNECT_EVENT_NAME, { detail: { at: 12345 } }),
    );
    expect(calls).toEqual([12345]);
    stop();
  });

  it('returns an unsubscribe that detaches the listener', () => {
    const target = new EventTarget();
    const calls: number[] = [];
    const stop = onReconnect((info) => calls.push(info.at), target);
    stop();
    target.dispatchEvent(
      new CustomEvent(RECONNECT_EVENT_NAME, { detail: { at: 1 } }),
    );
    expect(calls).toEqual([]);
  });
});

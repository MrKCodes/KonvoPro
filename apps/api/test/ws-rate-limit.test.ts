// apps/api/test/ws-rate-limit.test.ts
//
// Unit + property tests for the per-device WebSocket token-bucket rate
// limiter (`apps/api/src/ws/rate-limit.ts`). Validates the bucket
// behaviour the SEND_ENVELOPE handler relies on for Requirement 12.4
// / 19.4.

import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';

import {
  SEND_ENVELOPE_BUCKET,
  resetBuckets,
  tryConsume,
  type TokenBucketState,
} from '../src/ws/rate-limit.js';

describe('tryConsume — basic behaviour', () => {
  it('starts with a full bucket and accepts up to `capacity` calls in a single tick', () => {
    const buckets = new Map<string, TokenBucketState>();
    const opts = { capacity: 5, refillPerSecond: 1 };

    // Same wall-clock for all 5 calls -> no refill possible.
    for (let i = 0; i < 5; i++) {
      expect(tryConsume(buckets, 'd', 1000, opts)).toBe(true);
    }
    expect(tryConsume(buckets, 'd', 1000, opts)).toBe(false);
  });

  it('refills `refillPerSecond` tokens per second of elapsed wall-clock', () => {
    const buckets = new Map<string, TokenBucketState>();
    const opts = { capacity: 2, refillPerSecond: 2 };

    expect(tryConsume(buckets, 'd', 0, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 0, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 0, opts)).toBe(false);

    // 500ms later: refill = 0.5s * 2 = 1 token.
    expect(tryConsume(buckets, 'd', 500, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 500, opts)).toBe(false);
  });

  it('clamps refilled tokens at `capacity` (long idle does not give an oversized burst)', () => {
    const buckets = new Map<string, TokenBucketState>();
    const opts = { capacity: 3, refillPerSecond: 100 };

    // Initialize with one consume.
    expect(tryConsume(buckets, 'd', 0, opts)).toBe(true);
    // After 1 hour idle the bucket should be at `capacity`, not at
    // capacity + 100 * 3600.
    expect(tryConsume(buckets, 'd', 3_600_000, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 3_600_000, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 3_600_000, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 3_600_000, opts)).toBe(false);
  });

  it('isolates buckets per deviceId — one device exhausting its quota does not affect another', () => {
    const buckets = new Map<string, TokenBucketState>();
    const opts = { capacity: 1, refillPerSecond: 0 };

    expect(tryConsume(buckets, 'a', 0, opts)).toBe(true);
    expect(tryConsume(buckets, 'a', 0, opts)).toBe(false);
    // Device b still has its full bucket.
    expect(tryConsume(buckets, 'b', 0, opts)).toBe(true);
  });

  it('treats backwards clock jumps as zero elapsed time (no token refund)', () => {
    const buckets = new Map<string, TokenBucketState>();
    const opts = { capacity: 1, refillPerSecond: 1 };

    expect(tryConsume(buckets, 'd', 1000, opts)).toBe(true);
    // Clock jumps backwards by 100s — the bucket must not refill.
    expect(tryConsume(buckets, 'd', 0, opts)).toBe(false);
  });

  it('resetBuckets() clears all per-device state', () => {
    const buckets = new Map<string, TokenBucketState>();
    const opts = { capacity: 1, refillPerSecond: 0 };

    expect(tryConsume(buckets, 'd', 0, opts)).toBe(true);
    expect(tryConsume(buckets, 'd', 0, opts)).toBe(false);

    resetBuckets(buckets);
    // After reset, the device gets a fresh full bucket.
    expect(tryConsume(buckets, 'd', 0, opts)).toBe(true);
  });
});

describe('SEND_ENVELOPE_BUCKET constant', () => {
  it('matches the spec values 50 burst / 10 sustained per second', () => {
    expect(SEND_ENVELOPE_BUCKET).toEqual({ capacity: 50, refillPerSecond: 10 });
  });

  it('admits exactly 50 sends in a single tick at the spec params (Requirement 19.4 / P16)', () => {
    const buckets = new Map<string, TokenBucketState>();
    let accepted = 0;
    for (let i = 0; i < 100; i++) {
      if (tryConsume(buckets, 'd', 0, SEND_ENVELOPE_BUCKET)) accepted++;
    }
    expect(accepted).toBe(50);
  });

  it('replenishes 10 tokens per second after a burst', () => {
    const buckets = new Map<string, TokenBucketState>();
    // Drain the bucket.
    for (let i = 0; i < 50; i++) {
      tryConsume(buckets, 'd', 0, SEND_ENVELOPE_BUCKET);
    }
    expect(tryConsume(buckets, 'd', 0, SEND_ENVELOPE_BUCKET)).toBe(false);

    // 1s later: 10 tokens refilled.
    let accepted = 0;
    for (let i = 0; i < 20; i++) {
      if (tryConsume(buckets, 'd', 1000, SEND_ENVELOPE_BUCKET)) accepted++;
    }
    expect(accepted).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

describe('tryConsume — properties', () => {
  it('never accepts more than `capacity` consumes within a single zero-elapsed tick', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 100 }),
        fc.integer({ min: 0, max: 1000 }),
        (capacity, attempts) => {
          const buckets = new Map<string, TokenBucketState>();
          let accepted = 0;
          for (let i = 0; i < attempts; i++) {
            if (tryConsume(buckets, 'd', 0, { capacity, refillPerSecond: 0 })) {
              accepted++;
            }
          }
          expect(accepted).toBe(Math.min(capacity, attempts));
        },
      ),
    );
  });

  it('after T seconds with rate r, total accepted ≤ capacity + r*T (over any sequence of consumes)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 50 }),
        fc.integer({ min: 1, max: 50 }),
        fc.integer({ min: 0, max: 60 }),
        fc.integer({ min: 1, max: 200 }),
        (capacity, rate, seconds, attempts) => {
          const buckets = new Map<string, TokenBucketState>();
          const opts = { capacity, refillPerSecond: rate };
          let accepted = 0;
          // Spread `attempts` calls evenly over `seconds` seconds.
          for (let i = 0; i < attempts; i++) {
            const tMs = Math.floor((i / Math.max(1, attempts)) * seconds * 1000);
            if (tryConsume(buckets, 'd', tMs, opts)) accepted++;
          }
          // Conservation: never accept more than initial-burst +
          // sustained-refill across the entire window.
          expect(accepted).toBeLessThanOrEqual(capacity + rate * seconds);
        },
      ),
    );
  });
});

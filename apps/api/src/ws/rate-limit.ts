// apps/api/src/ws/rate-limit.ts
//
// Per-device WebSocket token-bucket rate limiter for `SEND_ENVELOPE`.
// Realizes Requirements 12.4, 19.4 and design.md §10 (`WSContext.tokenBucket`).
//
// Capacity 50 / refill 10 per second / per device:
//
//   - "burst 50" lets a client flush an outbox of up to 50 envelopes
//     in a single tick after a long offline window without being
//     immediately rate-limited.
//   - "sustained 10/s" matches the human-rate ceiling for typing /
//     sending DMs across a multi-device fan-out (one logical message
//     fans out to N≤5 recipient devices, so at 10/s sustained the
//     effective logical rate is ~2 msg/s — well above any human-
//     plausible composition rate).
//
// State is held in a module-level Map keyed by `deviceId`. We do NOT
// allocate the bucket per `WSContext` because a same-device reconnect
// must not reset the bucket — otherwise a disconnect/reconnect storm
// would trivially defeat the limiter (Requirement 12.4 / property P16
// both require the limit to hold "per device", not "per connection").
//
// The bucket is purely in-process. design.md §18.3 acknowledges this:
// the production deployment runs a single api replica per host so
// in-process suffices; if we ever scale horizontally the bucket
// promotes to Redis (`konvo_ratelimit:{deviceId}` keys with a Lua
// CAS) without changing the handler contract.

/** A single device's token-bucket state. */
export interface TokenBucketState {
  /** Tokens currently available. Float — refills accumulate
   *  fractionally between calls. */
  tokens: number;
  /** Wall-clock time (ms epoch) at which `tokens` was last refilled. */
  lastRefillMs: number;
}

/** Configuration for `tryConsume`. Capacity is the burst ceiling; the
 *  refill rate is in tokens-per-second. Both are runtime constants
 *  from Requirement 19.4 but exposed here so unit tests can override
 *  them with smaller values for deterministic timing. */
export interface TokenBucketOpts {
  readonly capacity: number;
  readonly refillPerSecond: number;
}

/** Spec-mandated bucket parameters per Requirement 19.4 / design.md §17.6. */
export const SEND_ENVELOPE_BUCKET: TokenBucketOpts = {
  capacity: 50,
  refillPerSecond: 10,
};

/**
 * Atomically refill and attempt to consume one token from the bucket
 * keyed by `deviceId`. Returns `true` iff a token was consumed.
 *
 * Refill formula (continuous, not discrete): on every call we add
 *   (now - lastRefillMs) / 1000 * refillPerSecond
 * tokens, clamping to `capacity`. This means a device that was idle
 * for 10s will see its bucket fully replenished on the next call —
 * we don't need a periodic timer to refill — and a device hammering
 * the gateway 100x in 10ms will see almost zero refill, exhausting
 * its 50-token burst within the first 50 calls.
 *
 * Postconditions:
 *   - On `true`: `state.tokens` is decremented by exactly 1 (after
 *     refill); `state.lastRefillMs === now`.
 *   - On `false`: `state.tokens < 1` strictly; `state.lastRefillMs ===
 *     now` (the refill still ran; we just couldn't fit a consume).
 *
 * Time monotonicity: callers should pass `Date.now()` (or a
 * test-injected monotonic source). If `now < state.lastRefillMs`
 * (clock jumped backwards), we treat the elapsed window as zero rather
 * than refunding tokens — backwards clock jumps must not give a client
 * extra burst.
 */
export function tryConsume(
  buckets: Map<string, TokenBucketState>,
  deviceId: string,
  now: number,
  opts: TokenBucketOpts,
): boolean {
  let state = buckets.get(deviceId);
  if (state === undefined) {
    // First call for this device: start with a full bucket and
    // record `now` as the refill anchor.
    state = { tokens: opts.capacity, lastRefillMs: now };
    buckets.set(deviceId, state);
  } else {
    // Continuous refill since last call. `Math.max(0, ...)` guards
    // against backwards clock jumps (see header comment).
    const elapsedMs = Math.max(0, now - state.lastRefillMs);
    const refilled = (elapsedMs / 1000) * opts.refillPerSecond;
    state.tokens = Math.min(opts.capacity, state.tokens + refilled);
    state.lastRefillMs = now;
  }

  if (state.tokens >= 1) {
    state.tokens -= 1;
    return true;
  }
  return false;
}

/** Reset the bucket map. Test-only — production code never calls
 *  this; the buckets persist for the lifetime of the api process. */
export function resetBuckets(buckets: Map<string, TokenBucketState>): void {
  buckets.clear();
}

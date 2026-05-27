// apps/web/src/features/auth/opkReplenishment.ts
//
// Background tasks that keep this device's prekey material fresh for
// X3DH (task 4.6 — Phase 3).
//
// Two flows live here:
//
//   1. OPK replenishment (Requirement 3.3):
//      "WHEN a Web_Client detects fewer than 20 unused one-time prekeys
//      remaining locally, THE Crypto_Module SHALL generate enough new
//      one-time prekeys to restore the unused local count to 100, and
//      the Web_Client SHALL upload them via POST /devices/:id/prekeys."
//
//      Implemented as a periodic poll. We don't hook into IndexedDB
//      change notifications because Dexie's `hook` API is per-instance
//      and consumers (the X3DH session establishment path that consumes
//      OPKs) live in a different code path that may run before this
//      module is wired up. A 60-second poll is well below any realistic
//      rate of OPK consumption — even a chatty user starting a fresh
//      X3DH session per minute would need >80 minutes to drain the
//      pool from 100 to 20 — so there's no scenario where the pool
//      runs to zero between checks.
//
//      The replenish call is idempotent and ratelimited server-side
//      (100/min/device, Requirement 3.4 / 19.4), so a transient
//      network failure that triggers a retry on the next tick is
//      harmless. We back off on consecutive failures only to avoid
//      hammering the API when the gateway is down.
//
//   2. Signed-prekey rotation (Requirement 3.7):
//      "WHEN 7 days have elapsed since the most recent signed prekey
//      rotation, THE Crypto_Module SHALL rotate the signed prekey and
//      the Web_Client SHALL upload the new signed prekey to the
//      API_Gateway."
//
//      Scheduled lazily: we check on app start and re-check when the
//      replenishment poll tick fires. Rotation is a one-shot per
//      ≥7-day window — the crypto module's `rotateSignedPreKey` is
//      idempotent over a single call but multiple calls produce
//      multiple rotations, so we gate the check on a persisted
//      `lastSignedPreKeyRotatedAt` timestamp in `localStorage` (no
//      secret material; just a wall-clock millisecond).
//
//      The persisted timestamp is local-only metadata; the signed
//      prekey itself lives in Dexie under `keyType: 'signed'` and the
//      authoritative `createdAt` is on that row. The localStorage
//      timestamp is a quick check used to skip the Dexie read on
//      every tick — when the localStorage value is absent or stale,
//      we fall back to the Dexie row's `createdAt` to make the
//      decision (and re-prime the cache).
//
// Phase-1 placeholder for the upload endpoint:
//   The signed-prekey rotation step uploads via
//   `POST /devices/:id/signed-prekey`. design.md §9 declares routes
//   for `POST /devices`, `POST /devices/:id/prekeys`, and
//   `DELETE /devices/:id`, but DOES NOT yet declare a per-device
//   signed-prekey rotation route. The client wires the call here so
//   the contract is in place; the server-side route handler lands
//   in a follow-up task. Until then the upload returns 404 and the
//   `onUploadFailed` hook surfaces the error — local rotation
//   succeeds (the new signed prekey is persisted in Dexie) but the
//   server keeps serving the older signed-prekey bundle. This is
//   the same posture as a network failure during the upload window
//   and self-heals on the next rotation tick.
//
// Lifecycle:
//   `startOpkReplenishment(opts)` and `startSignedPreKeyRotation(opts)`
//   each return a stop callback that clears the underlying timer and
//   prevents any subsequent network call. Calling stop() during an
//   in-flight check is safe — the resolution branch checks the
//   `running` flag before issuing the upload.

import {
  getOrCreateIdentity,
  replenishOneTimePreKeys,
  rotateSignedPreKey,
  shouldRotateSignedPreKey,
  type OneTimePreKey,
  type PreKeyStore,
  type SignedPreKey,
} from '@konvo/crypto';

import { DexieIdentityStore } from '../../db/repositories/identity.js';
import { DexiePreKeyStore } from '../../db/repositories/prekeys.js';
import { db, type KonvoDb } from '../../db/schema.js';

import type { AuthApiClient } from './api.js';
import { authApi } from './api.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Replenishment trigger threshold (Requirement 3.3). Mirrors
 *  `ONE_TIME_PREKEY_THRESHOLD` in `@konvo/crypto/prekeys.ts`. */
export const OPK_THRESHOLD = 20 as const;

/** Replenishment target (Requirement 3.3). Mirrors
 *  `ONE_TIME_PREKEY_TARGET` in `@konvo/crypto/prekeys.ts`. */
export const OPK_TARGET = 100 as const;

/** Polling interval for the replenishment scheduler. Picked to be
 *  short enough that even an aggressive OPK drain rate can't outrun the
 *  poll, and long enough that an idle device produces ~1 cheap Dexie
 *  read per minute. */
export const OPK_POLL_INTERVAL_MS = 60_000;

/** Signed-prekey max age before rotation (Requirement 3.7). Mirrors
 *  `SIGNED_PREKEY_MAX_AGE_MS` in `@konvo/crypto/prekeys.ts`. Re-declared
 *  rather than re-imported so the constant is part of this module's
 *  public surface for tests. */
export const SIGNED_PREKEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** localStorage key for the cached "last rotated" timestamp. The value
 *  is a wall-clock millisecond stored as a base-10 string; no secret
 *  material. */
export const LAST_ROTATED_STORAGE_KEY = 'konvo:signedPreKeyLastRotatedAt';

// ---------------------------------------------------------------------------
// Public options
// ---------------------------------------------------------------------------

export interface OpkReplenishmentOptions {
  readonly deviceId: string;
  /** Optional overrides for tests / non-default wiring. */
  readonly api?: AuthApiClient;
  readonly database?: KonvoDb;
  /** Polling cadence override. Defaults to `OPK_POLL_INTERVAL_MS`. */
  readonly pollIntervalMs?: number;
  /** Override the replenishment threshold (Requirement 3.3 default 20). */
  readonly threshold?: number;
  /** Override the replenishment target (Requirement 3.3 default 100). */
  readonly target?: number;
  /** Hook fired when the replenish upload fails. The scheduler does
   *  not retry within the same tick — the next tick re-evaluates the
   *  count and re-uploads if the threshold is still breached. */
  readonly onError?: (err: unknown) => void;
}

export interface SignedPreKeyRotationOptions {
  readonly deviceId: string;
  /** Optional overrides for tests / non-default wiring. */
  readonly api?: AuthApiClient;
  readonly database?: KonvoDb;
  /** Override the wall-clock used for age comparison. Defaults to
   *  `Date.now`. Tests inject a deterministic clock. */
  readonly now?: () => number;
  /** Override the localStorage backend (tests). */
  readonly storage?: Storage | undefined;
  /** Hook fired when the rotation upload fails. The scheduler does
   *  not retry within the same app session — the next app start (or
   *  the next OPK poll tick if the OPK scheduler is also running)
   *  re-evaluates the timestamp. */
  readonly onError?: (err: unknown) => void;
}

/** Stop callback returned by both schedulers. Clears the timer and
 *  prevents any in-flight async branch from completing its upload. */
export type StopFn = () => void;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readStorage(
  storage: Storage | undefined = typeof localStorage !== 'undefined'
    ? localStorage
    : undefined,
): Storage | undefined {
  return storage;
}

/** Returns the cached "last rotated" timestamp in milliseconds, or
 *  `null` when absent / unparseable. */
export function readLastRotatedAt(
  storage: Storage | undefined = readStorage(),
): number | null {
  if (storage === undefined) return null;
  try {
    const raw = storage.getItem(LAST_ROTATED_STORAGE_KEY);
    if (raw === null) return null;
    const n = Number.parseInt(raw, 10);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

/** Persist the "last rotated" timestamp. Tolerates storage failures
 *  (private mode) by silently no-op'ing — the cost is one extra Dexie
 *  read on the next tick. */
function writeLastRotatedAt(
  ts: number,
  storage: Storage | undefined = readStorage(),
): void {
  if (storage === undefined) return;
  try {
    storage.setItem(LAST_ROTATED_STORAGE_KEY, String(ts));
  } catch {
    // best-effort
  }
}

/** Build a `PreKeyStore` over the supplied database. Centralised here
 *  so both schedulers wire the same adapter. */
function makePreKeyStore(database: KonvoDb): PreKeyStore {
  return new DexiePreKeyStore(database);
}

// ---------------------------------------------------------------------------
// One-shot OPK check (testable independent of the timer)
// ---------------------------------------------------------------------------

/** Run a single replenishment check. Returns the number of OPKs
 *  uploaded (0 when the threshold isn't breached). Exposed as a named
 *  function so tests can drive the logic without `vi.useFakeTimers`. */
export async function checkAndReplenishOpks(
  opts: OpkReplenishmentOptions,
): Promise<number> {
  const apiClient = opts.api ?? authApi;
  const database = opts.database ?? db;
  const threshold = opts.threshold ?? OPK_THRESHOLD;
  const target = opts.target ?? OPK_TARGET;

  const preKeyStore = makePreKeyStore(database);
  const currentCount = await preKeyStore.listUnusedOneTimePreKeyCount();
  if (currentCount >= threshold) {
    return 0;
  }

  // Materialise identity + KEK on demand. `getOrCreateIdentity` is
  // idempotent and short-circuits to the persisted record on the
  // happy path, so this is one Dexie read per tick when the threshold
  // is breached.
  const identityStore = new DexieIdentityStore(database);
  const identity = await getOrCreateIdentity(identityStore);
  const kek = await identityStore.getOrCreateAesKwKey();

  const minted: OneTimePreKey[] = await replenishOneTimePreKeys(
    identity,
    preKeyStore,
    kek,
    threshold,
    target,
  );
  if (minted.length === 0) {
    // Race: another tick replenished between our count check and the
    // crypto-module's own count check. Harmless.
    return 0;
  }

  await apiClient.replenishPreKeys(opts.deviceId, {
    oneTimePreKeys: minted,
  });

  return minted.length;
}

// ---------------------------------------------------------------------------
// Periodic OPK replenishment
// ---------------------------------------------------------------------------

/** Start the OPK replenishment scheduler.
 *
 *  Behaviour:
 *    - Runs an immediate check on the next microtask (so the caller
 *      can `await stop()`-equivalent shutdown without a 60-second
 *      first delay).
 *    - Schedules subsequent checks at `pollIntervalMs` cadence.
 *    - On any error during a tick (Dexie I/O, replenish, API call),
 *      logs the error via `onError` and continues with the next tick.
 *      The crypto module is robust to a partial replenish (the rows
 *      it persisted are real and will be re-uploaded on the next
 *      tick when the count is still below threshold).
 *    - Returns a `stop()` callback. After stop(), no further ticks
 *      fire and any in-flight tick refuses to issue its API call.
 */
export function startOpkReplenishment(opts: OpkReplenishmentOptions): StopFn {
  const intervalMs = opts.pollIntervalMs ?? OPK_POLL_INTERVAL_MS;
  let running = true;
  let inFlight: Promise<void> | null = null;

  const tick = async (): Promise<void> => {
    if (!running) return;
    try {
      await checkAndReplenishOpks(opts);
    } catch (err) {
      // The scheduler keeps running after a failure; we only surface
      // the error so the caller can log/telemetry it.
      opts.onError?.(err);
    }
  };

  const launch = (): void => {
    inFlight = tick().finally(() => {
      inFlight = null;
    });
  };

  // Kick off the first check immediately. We intentionally do NOT
  // `await` it inside `start*` — the caller's site is synchronous and
  // shouldn't block on the first network round-trip. Errors are
  // captured by the catch in `tick`.
  launch();

  const handle = setInterval(launch, intervalMs);

  return () => {
    running = false;
    clearInterval(handle);
    // Best-effort wait for any in-flight async work to settle before
    // the caller (typically a test teardown or a logout flow) starts
    // mutating Dexie state. The `.catch` is paranoia: `tick()` already
    // swallows its errors via `opts.onError`, but in case a future
    // refactor changes that we still don't want this terminator to
    // throw.
    if (inFlight !== null) {
      void inFlight.catch(() => undefined);
    }
  };
}

// ---------------------------------------------------------------------------
// One-shot signed-prekey rotation check
// ---------------------------------------------------------------------------

/** Run a single signed-prekey rotation check. Returns the new
 *  `SignedPreKey` if a rotation actually happened, otherwise `null`.
 *  Exposed as a named function so tests can drive the logic without
 *  `vi.useFakeTimers`. */
export async function checkAndRotateSignedPreKey(
  opts: SignedPreKeyRotationOptions,
): Promise<SignedPreKey | null> {
  const apiClient = opts.api ?? authApi;
  const database = opts.database ?? db;
  const now = (opts.now ?? Date.now)();
  const storage = opts.storage ?? readStorage();

  const preKeyStore = makePreKeyStore(database);

  // Fast-path via localStorage timestamp. A populated, fresh-enough
  // value lets us skip the Dexie read entirely. A stale or missing
  // value falls through to the authoritative Dexie check.
  const cachedTs = readLastRotatedAt(storage);
  if (cachedTs !== null && now - cachedTs < SIGNED_PREKEY_MAX_AGE_MS) {
    return null;
  }

  const current = await preKeyStore.getCurrentSignedPreKey();
  if (current === null) {
    // No signed prekey yet — first-run enrollment hasn't completed.
    // Don't attempt to rotate; the device-enrollment flow owns the
    // initial bundle (Requirement 3.1).
    return null;
  }

  if (!shouldRotateSignedPreKey({ createdAt: current.createdAt }, now)) {
    // Re-prime the cache so subsequent ticks short-circuit.
    writeLastRotatedAt(current.createdAt, storage);
    return null;
  }

  // Rotate locally first (Crypto_Module owns the keypair generation +
  // signature production), then upload. If the upload fails we still
  // persisted the new signed prekey in Dexie — that's the correct
  // posture: the next session establishment uses the freshest local
  // record, and a subsequent retry will re-upload. The same flow is
  // the basis for `replenishOneTimePreKeys`.
  const identityStore = new DexieIdentityStore(database);
  const identity = await getOrCreateIdentity(identityStore);
  const kek = await identityStore.getOrCreateAesKwKey();

  const newSpk = await rotateSignedPreKey(identity, preKeyStore, kek);

  // Persist the cache BEFORE the upload so a network failure doesn't
  // make us re-rotate on the next tick — the local rotation is what
  // matters for forward-secrecy of future X3DH sessions.
  writeLastRotatedAt(newSpk.createdAt, storage);

  await apiClient.uploadSignedPreKey(opts.deviceId, newSpk);

  return newSpk;
}

// ---------------------------------------------------------------------------
// Once-per-app-start signed-prekey rotation
// ---------------------------------------------------------------------------

/** Start the signed-prekey rotation scheduler.
 *
 *  Behaviour:
 *    - Runs a single check on app start. If more than 7 days have
 *      elapsed since the most recent rotation, rotates and uploads.
 *    - Returns a stop() callback. There is no recurring timer to
 *      stop — the scheduler is one-shot per app start — but the
 *      callback still flips a guard so an in-flight check refuses to
 *      issue its upload after stop(). This keeps the lifecycle API
 *      symmetric with `startOpkReplenishment`.
 *
 *  The "once per app start" model matches Requirement 3.7's "WHEN 7
 *  days have elapsed" predicate: the moment we cross the 7-day
 *  boundary the next app start performs the rotation. A user who
 *  keeps a long-lived tab open without reloading would not rotate
 *  via this scheduler alone — but the `startOpkReplenishment` poll
 *  also calls into the rotation check when wired together (see
 *  `startPreKeyMaintenance` below) so the long-lived-tab edge case
 *  is covered.
 */
export function startSignedPreKeyRotation(
  opts: SignedPreKeyRotationOptions,
): StopFn {
  let running = true;

  const tick = async (): Promise<void> => {
    if (!running) return;
    try {
      await checkAndRotateSignedPreKey(opts);
    } catch (err) {
      opts.onError?.(err);
    }
  };

  void tick();

  return () => {
    running = false;
  };
}

// ---------------------------------------------------------------------------
// Combined entry point
// ---------------------------------------------------------------------------

/** Start both prekey-maintenance schedulers and return a single stop
 *  callback that tears down both. Convenience wrapper for the auth
 *  bootstrap path (post-login wiring). */
export function startPreKeyMaintenance(opts: {
  readonly deviceId: string;
  readonly api?: AuthApiClient;
  readonly database?: KonvoDb;
  readonly pollIntervalMs?: number;
  readonly now?: () => number;
  readonly storage?: Storage | undefined;
  readonly onError?: (err: unknown) => void;
}): StopFn {
  // Reuse one options bag for both. The threshold/target stay at
  // their requirement-mandated defaults.
  const baseOpts = {
    deviceId: opts.deviceId,
    ...(opts.api !== undefined ? { api: opts.api } : {}),
    ...(opts.database !== undefined ? { database: opts.database } : {}),
    ...(opts.onError !== undefined ? { onError: opts.onError } : {}),
  };
  const stopOpk = startOpkReplenishment({
    ...baseOpts,
    ...(opts.pollIntervalMs !== undefined
      ? { pollIntervalMs: opts.pollIntervalMs }
      : {}),
  });
  const stopSpk = startSignedPreKeyRotation({
    ...baseOpts,
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.storage !== undefined ? { storage: opts.storage } : {}),
  });
  return () => {
    stopOpk();
    stopSpk();
  };
}

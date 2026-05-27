// apps/web/src/features/devices/enrollment.ts
//
// First-run device enrollment flow (task 2.10).
//
// On the very first run of the Web_Client on a fresh browser (no
// wrapped identity in IndexedDB, no stored deviceId), the SPA must:
//
//   1. Generate a Curve25519 identity keypair + Ed25519 sub-key + a
//      registration ID, persist them under AES-KW wrapping
//      (Requirements 2.1, 2.2, 2.3, 2.11) — handled by
//      `getOrCreateIdentity` from `@konvo/crypto`.
//   2. Generate the initial prekey bundle (1 signed prekey + 100
//      OPKs), persist to Dexie (Requirements 3.1, 3.2) — handled by
//      `generateInitialBundle` from `@konvo/crypto`.
//   3. POST that bundle to `/devices` with a human-readable name
//      (Requirements 2.4, 2.7, 2.10) and remember the resulting
//      `deviceId` locally so subsequent sessions reuse it.
//
// This module owns step 3's orchestration plus the local persistence
// of the assigned `deviceId`. Steps 1–2 are delegated to existing
// helpers from `@konvo/crypto` and the Dexie repositories from
// `apps/web/src/db/repositories/`.
//
// The `deviceId` is stored in `localStorage` under
// `konvo:deviceId`. That key carries no secret material — it's a
// server-issued UUID — so it doesn't violate Requirement 1.11 (which
// is specifically about the access token). The device's IDENTITY
// PRIVATE KEY material lives only in IndexedDB under AES-KW wrap;
// nothing sensitive lands in localStorage.
//
// The flow is idempotent: re-running on a browser that already has
// an enrolled device short-circuits and returns the cached
// `deviceId`. A re-run that finds an identity in Dexie but no cached
// `deviceId` (interrupted enrollment) will RE-ENROLL with the
// existing identity, which is the same behaviour as a server-side
// row that's never been linked.

import {
  generateInitialBundle,
  getOrCreateIdentity,
  type PreKeyBundleUpload,
} from '@konvo/crypto';

import { DexieIdentityStore } from '../../db/repositories/identity.js';
import { DexiePreKeyStore } from '../../db/repositories/prekeys.js';
import { db, type KonvoDb } from '../../db/schema.js';

import type { AuthApiClient } from '../auth/api.js';
import { authApi } from '../auth/api.js';

// ---------------------------------------------------------------------------
// Local-storage key for the device id
// ---------------------------------------------------------------------------

const DEVICE_ID_STORAGE_KEY = 'konvo:deviceId';

/** Read the cached device id from localStorage, or `null` when this
 *  browser hasn't enrolled yet. Returns `null` (not throws) when
 *  `localStorage` is unavailable (e.g. private mode where the API is
 *  disabled). */
export function readStoredDeviceId(
  storage: Storage | undefined = typeof localStorage !== 'undefined'
    ? localStorage
    : undefined,
): string | null {
  if (storage === undefined) return null;
  try {
    const v = storage.getItem(DEVICE_ID_STORAGE_KEY);
    return v === null || v.length === 0 ? null : v;
  } catch {
    // SecurityError under "block third-party cookies" or quota errors —
    // treat as "not enrolled" so the flow re-enrolls rather than
    // failing closed.
    return null;
  }
}

/** Persist the device id to localStorage. Tolerates storage failures
 *  (private mode) by silently no-op'ing — the flow can still proceed,
 *  the cost is that subsequent reloads will re-enroll a fresh device. */
function writeStoredDeviceId(
  deviceId: string,
  storage: Storage | undefined = typeof localStorage !== 'undefined'
    ? localStorage
    : undefined,
): void {
  if (storage === undefined) return;
  try {
    storage.setItem(DEVICE_ID_STORAGE_KEY, deviceId);
  } catch {
    // Best effort.
  }
}

/** Clear the stored device id (used on logout / device revocation). */
export function clearStoredDeviceId(
  storage: Storage | undefined = typeof localStorage !== 'undefined'
    ? localStorage
    : undefined,
): void {
  if (storage === undefined) return;
  try {
    storage.removeItem(DEVICE_ID_STORAGE_KEY);
  } catch {
    // Best effort.
  }
}

// ---------------------------------------------------------------------------
// Device naming
// ---------------------------------------------------------------------------

/** Best-effort human-readable device name for the UI's "Settings →
 *  Devices" listing. Format: `"<browser> on <platform>"`. We fall
 *  back to a generic "Konvo Web" when navigator UA inspection isn't
 *  available (server-side rendering, jsdom in some test profiles).
 *
 *  We deliberately keep this as a heuristic rather than parsing the
 *  full UA — `navigator.userAgentData` is now the recommended path in
 *  Chromium-derived browsers and degrades gracefully on Safari /
 *  Firefox. The 64-char cap matches the server-side `name` validator
 *  in `apps/api/src/routes/devices.ts`. */
export function defaultDeviceName(
  nav: { userAgent?: string; platform?: string } = typeof navigator !==
  'undefined'
    ? navigator
    : {},
): string {
  const ua = typeof nav.userAgent === 'string' ? nav.userAgent : '';
  const platform = typeof nav.platform === 'string' ? nav.platform : '';

  let browser = 'Browser';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) browser = 'Chrome';
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';

  const platformLabel = platform.length > 0 ? platform : 'Konvo Web';
  const candidate = `${browser} on ${platformLabel}`;
  return candidate.length > 64 ? candidate.slice(0, 64) : candidate;
}

// ---------------------------------------------------------------------------
// Bundle → DeviceCreate DTO
// ---------------------------------------------------------------------------

/** Adapt the Crypto_Module's `PreKeyBundleUpload` into the
 *  `DeviceCreate` shape expected by `POST /devices`. The two shapes
 *  match field-for-field (modulo `name`), so this is a pass-through
 *  with the human-readable name attached. */
function bundleToDeviceCreate(
  bundle: PreKeyBundleUpload,
  name: string,
): import('@konvo/protocol').DeviceCreate {
  return {
    name,
    identityPub: bundle.identityPub,
    identityEdPub: bundle.identityEdPub,
    registrationId: bundle.registrationId,
    signedPreKey: bundle.signedPreKey,
    oneTimePreKeys: bundle.oneTimePreKeys,
  };
}

// ---------------------------------------------------------------------------
// Public flow
// ---------------------------------------------------------------------------

export interface EnrollmentResult {
  readonly deviceId: string;
  readonly created: boolean;
}

export interface EnrollDeviceOptions {
  readonly api?: AuthApiClient;
  readonly database?: KonvoDb;
  /** Override the device name. Defaults to `defaultDeviceName()`. */
  readonly name?: string;
  /** Override the storage layer for the cached device id. Tests pass
   *  an in-memory shim. */
  readonly storage?: Storage | undefined;
}

/** Ensure this browser is enrolled as a device for the currently
 *  authenticated user. Returns the device id.
 *
 *  - If a `konvo:deviceId` is already stored in localStorage, returns
 *    it without contacting the server (`created: false`).
 *  - Otherwise generates the identity + bundle via `@konvo/crypto`,
 *    POSTs to `/devices`, persists the returned id to localStorage,
 *    and returns it (`created: true`).
 *
 *  Pre-conditions:
 *    - The auth store must hold a valid access token (caller has
 *      already logged in).
 *
 *  Post-conditions:
 *    - The IndexedDB `identity` row exists (idempotent — see
 *      `getOrCreateIdentity`).
 *    - The IndexedDB `prekeys` table holds 1 signed prekey + 100
 *      unused OPKs IFF this call was the one that ran
 *      `generateInitialBundle`. Re-runs (`created: false`) leave
 *      Dexie untouched.
 *    - The deviceId is in localStorage under `konvo:deviceId`.
 *
 *  On failure mid-flight (network error after `generateInitialBundle`
 *  but before `POST /devices` succeeds), the local Dexie state holds
 *  the bundle but no device id is cached. A subsequent retry will
 *  refuse to re-run `generateInitialBundle` (the store is non-empty,
 *  see crypto/src/prekeys.ts) so the caller must surface a recovery
 *  UI. The current implementation returns the AuthApiError without
 *  attempting recovery; design.md §10 / requirements 2.10 don't
 *  mandate a specific retry policy and the operator can re-create
 *  the device by clearing localStorage. */
export async function enrollDeviceIfNeeded(
  options: EnrollDeviceOptions = {},
): Promise<EnrollmentResult> {
  const apiClient = options.api ?? authApi;
  const database = options.database ?? db;
  const storage = options.storage ?? (typeof localStorage !== 'undefined' ? localStorage : undefined);

  const cachedId = readStoredDeviceId(storage);
  if (cachedId !== null) {
    return { deviceId: cachedId, created: false };
  }

  // 1. Identity + KEK (idempotent — returns existing record if present).
  const identityStore = new DexieIdentityStore(database);
  const prekeyStore = new DexiePreKeyStore(database);
  const identity = await getOrCreateIdentity(identityStore);
  const kek = await identityStore.getOrCreateAesKwKey();

  // 2. Initial prekey bundle. Throws if the store already holds prekeys
  //    (a partial recovery state); when that happens we wipe the local
  //    crypto state and re-mint the bundle. The previous bundle was
  //    never registered with the server (no cached deviceId), so
  //    nothing on the server side is invalidated by the wipe and the
  //    user keeps a usable account.
  let bundle: PreKeyBundleUpload;
  try {
    bundle = await generateInitialBundle(identity, prekeyStore, kek);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('store is not empty')) {
      await database.transaction('rw', database.prekeys, async () => {
        await database.prekeys.clear();
      });
      bundle = await generateInitialBundle(identity, prekeyStore, kek);
    } else {
      throw err;
    }
  }

  // 3. Upload via POST /devices.
  const name = options.name ?? defaultDeviceName();
  const dto = bundleToDeviceCreate(bundle, name);
  const response = await apiClient.createDevice(dto);

  writeStoredDeviceId(response.deviceId, storage);

  return { deviceId: response.deviceId, created: true };
}

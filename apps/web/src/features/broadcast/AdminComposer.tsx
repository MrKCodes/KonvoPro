// apps/web/src/features/broadcast/AdminComposer.tsx
//
// Composer affordance for room admins. Signs posts locally with the
// device's Ed25519 identity sub-key and submits them to
// `POST /rooms/:slug/messages`.
//
// Sign-then-POST flow (Requirements 10.4, 10.8):
//   1. Read the persisted identity row (`db.identity.get('me')`).
//      Unwrap the Ed25519 private key under the AES-KW KEK.
//   2. Capture `createdAtMs = Date.now()`. The server enforces a
//      ±60 s window against its own clock (Requirement 10.4); using
//      `Date.now()` aligns the signed timestamp with the wall clock
//      we'll be checked against.
//   3. Call `signBroadcastPost(body, roomId, createdAtMs,
//      identityEdPriv)` to produce the 64-byte Ed25519 signature.
//      The resulting signature lives only in memory long enough to
//      POST.
//   4. POST `{body, signature: base64, createdAtMs, deviceId}` to
//      `/rooms/:slug/messages`. The server verifies the signature
//      against the device's `identity_ed_pub`; fan-out to subscribers
//      arrives via `S2C.ROOM_POST`, which `RoomView` is already
//      listening for.
//
// What this component does NOT own:
//   - Role enforcement. The server returns 403 for non-admins
//     (Requirement 10.5); we surface that as a user-visible error
//     rather than gating the UI client-side. The parent route can
//     hide the composer for known-non-admin sessions, but we never
//     rely on that for security.
//   - Optimistic insertion. The server's WS fan-out handles render;
//     the composer waits for HTTP success and clears the textarea.
//     Optimistic UI can be added later without breaking this
//     contract.

import { useCallback, useState } from 'react';

import {
  signBroadcastPost,
  unwrapStoredPrekeyPrivate,
  IdentityPrivateKey,
} from '@konvo/crypto';

import { db, type IdentityRow } from '../../db/schema.js';
import { DexieIdentityStore } from '../../db/repositories/identity.js';
import {
  BroadcastApiClient,
  broadcastApi,
  BroadcastApiError,
} from './api.js';

/** Hard cap on body byte length — matches the server's 4 KiB UTF-8
 *  limit (Requirement 10.7). The server is the authoritative
 *  enforcer; we reject early purely as a UX courtesy so the user
 *  doesn't wait for an HTTP 413. */
const BODY_BYTE_LIMIT = 4 * 1024;

const BODY_LENGTH_ENCODER = new TextEncoder();
function utf8ByteLength(s: string): number {
  return BODY_LENGTH_ENCODER.encode(s).length;
}

/** Identity-row + KEK loader signature. Dependency-injected so tests
 *  can substitute a deterministic keypair without a real Dexie row. */
export interface IdentityLoader {
  /** Returns the Ed25519 private key bytes (32 bytes) for this
   *  device. Caller is responsible for scrubbing the returned
   *  buffer when done — we wrap it in `IdentityPrivateKey` and
   *  scrub our local copy after signing returns. */
  loadEd25519Private(): Promise<Uint8Array>;
}

/** Default loader: reads `identity.me` from the shared `db` and
 *  unwraps the Ed25519 private bytes under the AES-KW KEK. Throws
 *  when the identity row is missing — the SPA shouldn't render
 *  AdminComposer pre-enrolment. */
async function defaultLoadEd25519Private(): Promise<Uint8Array> {
  const row: IdentityRow | undefined = await db.identity.get('me');
  if (row === undefined) {
    throw new Error('AdminComposer: identity row missing — enrol device first');
  }
  const store = new DexieIdentityStore(db);
  const kek = await store.getOrCreateAesKwKey();
  return unwrapStoredPrekeyPrivate(row.wrappedEd25519PrivateKey, kek);
}

const defaultIdentityLoader: IdentityLoader = {
  loadEd25519Private: defaultLoadEd25519Private,
};

export interface AdminComposerProps {
  readonly slug: string;
  /** UUID of the room (covered by the signature alongside body and
   *  timestamp). Sourced from `RoomDto.id` upstream. */
  readonly roomId: string;
  /** UUID of THIS device. Required by the server to look up the
   *  signing device's `identity_ed_pub` for verification
   *  (Requirement 10.4 wire shape). The auth/devices feature
   *  surfaces this via `readStoredDeviceId()`. */
  readonly deviceId: string;
  /** Override the broadcast API client (tests). */
  readonly api?: BroadcastApiClient;
  /** Override the identity loader (tests). */
  readonly identityLoader?: IdentityLoader;
  /** Optional millisecond clock (tests). Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Fired after a successful post. The parent can use this to,
   *  e.g., clear an "unread" badge — RoomView itself handles render
   *  via the WS fan-out path. */
  readonly onPosted?: (postId: string) => void;
}

export function AdminComposer(props: AdminComposerProps): JSX.Element {
  const api = props.api ?? broadcastApi;
  const loader = props.identityLoader ?? defaultIdentityLoader;
  const now = props.now ?? (() => Date.now());

  const [body, setBody] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setError(null);
      const trimmed = body.trim();
      if (trimmed.length === 0) {
        setError('Post body is empty.');
        return;
      }
      if (utf8ByteLength(trimmed) > BODY_BYTE_LIMIT) {
        setError('Post body exceeds 4 KiB.');
        return;
      }

      setSubmitting(true);
      let edPriv: Uint8Array | null = null;
      try {
        edPriv = await loader.loadEd25519Private();
        const wrapped = new IdentityPrivateKey(edPriv);
        const createdAtMs = now();
        const signature = signBroadcastPost(
          trimmed,
          props.roomId,
          createdAtMs,
          wrapped,
        );
        const result = await api.postMessage(props.slug, {
          body: trimmed,
          signature,
          createdAtMs,
          deviceId: props.deviceId,
        });
        setBody('');
        props.onPosted?.(result.id);
      } catch (err) {
        let msg: string;
        if (err instanceof BroadcastApiError) {
          if (err.status === 403) {
            msg = 'Forbidden: only room admins may post.';
          } else if (err.status === 413) {
            msg = 'Post body too large (4 KiB max).';
          } else if (err.status === 429) {
            msg = 'Posting too fast — try again in a moment.';
          } else {
            msg = err.serverError ?? `HTTP ${err.status ?? '?'}`;
          }
        } else {
          msg = (err as Error).message;
        }
        setError(msg);
      } finally {
        // Best-effort scrub of the unwrapped Ed25519 private bytes.
        // `IdentityPrivateKey` already made a defensive copy at
        // construction; this only zeros our own local view.
        if (edPriv !== null) edPriv.fill(0);
        setSubmitting(false);
      }
    },
    [body, loader, now, api, props.slug, props.roomId, props.deviceId, props.onPosted],
  );

  return (
    <form
      data-testid="admin-composer"
      onSubmit={(e) => {
        void handleSubmit(e);
      }}
    >
      <label htmlFor={`admin-composer-body-${props.slug}`}>
        New post
      </label>
      <textarea
        id={`admin-composer-body-${props.slug}`}
        data-testid="admin-composer-body"
        value={body}
        onChange={(e) => setBody(e.target.value)}
        rows={4}
        maxLength={BODY_BYTE_LIMIT}
        disabled={submitting}
      />
      <button
        type="submit"
        data-testid="admin-composer-submit"
        disabled={submitting || body.trim().length === 0}
      >
        {submitting ? 'Signing…' : 'Post'}
      </button>
      {error !== null ? (
        <p
          role="alert"
          data-testid="admin-composer-error"
          style={{ color: 'red' }}
        >
          {error}
        </p>
      ) : null}
    </form>
  );
}

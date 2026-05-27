// apps/web/src/features/attachments/AttachmentView.tsx
//
// React component that renders a downloaded + decrypted attachment
// (task 5.3, requirements 6.5, 6.9, 6.10).
//
// Render branches:
//   - `'loading'`     — fetch / decrypt in-flight
//   - `'ok'`          — bytes verified; render an `<img>`,
//                        `<audio>`, or `<a download>` based on MIME
//   - `'tag_failed'`  — AES-GCM auth failure: render the inert
//                        "attachment couldn't be decrypted" placeholder
//                        (req 6.9). No partial bytes shown.
//   - `'not_found'`   — server returned 404: render the inert
//                        "attachment unavailable" placeholder (req 6.10).
//                        The envelope itself is preserved by the
//                        caller — this component just renders.
//   - `'error'`       — transient errors (network, 5xx, 403). The
//                        component shows a short message; the parent
//                        can offer a retry button.
//
// The component owns:
//   - The fetch + decrypt lifecycle (via a pluggable `download`
//     dependency so tests can inject a stub).
//   - The blob-URL / object-URL bookkeeping. We `URL.createObjectURL`
//     on a successful decrypt and revoke it on unmount to avoid
//     leaks.
//   - Defensive cleanup against StrictMode double-effects.
//
// The component does NOT own:
//   - Cache writes / reads. The download path is wrapped in an
//     optional `cache` parameter; callers wire `LocalAttachmentsStore`
//     when they want persistence. In tests we either pass a real
//     store backed by `fake-indexeddb` or omit it entirely.
//
// Accessibility:
//   - The placeholder branches use `role="alert"` so screen readers
//     announce them when they appear.
//   - `<img>` carries an `alt` derived from the filename.
//   - `<audio>` exposes native controls.
//   - The fallback `<a download>` uses the filename as the link text
//     and `download` attribute, matching browser conventions.

import { useEffect, useState, type JSX } from 'react';

import type { AttachmentRef } from '@konvo/protocol';

import {
  AttachmentDownloadError,
  downloadAttachment as defaultDownload,
  type DownloadAttachmentOptions,
  type DownloadResult,
} from './download.js';
import type { LocalAttachmentsStore } from './cache.js';

// ---------------------------------------------------------------------------
// User-facing strings
// ---------------------------------------------------------------------------

/** Inert placeholder text rendered on AES-GCM auth failure
 *  (Requirement 6.9). Exported so tests assert against the same
 *  constant the renderer uses. */
export const TAG_FAILURE_PLACEHOLDER =
  "attachment couldn't be decrypted";

/** Inert placeholder text rendered on HTTP 404 (Requirement 6.10).
 *  Exported for the same reason as `TAG_FAILURE_PLACEHOLDER`. */
export const NOT_FOUND_PLACEHOLDER = 'attachment unavailable';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface AttachmentViewProps {
  /** AES-GCM key/iv/tag carried inside the E2EE envelope plus the
   *  server-assigned attachment id. */
  readonly ref: AttachmentRef;
  /** MIME type from the inner payload. Drives which element type
   *  renders on success. The server's stored MIME is not trusted
   *  here — the inner payload is the canonical source. */
  readonly mime: string;
  /** Filename from the inner payload (≤ 255 chars per req 6.4). */
  readonly filename: string;
  /** Optional persistent cache. Hits short-circuit the fetch +
   *  decrypt; misses populate after a successful download. */
  readonly cache?: LocalAttachmentsStore;
  /** Override the download function for tests. Defaults to the real
   *  `downloadAttachment` over `fetch`. */
  readonly download?: (
    ref: AttachmentRef,
    options?: DownloadAttachmentOptions,
  ) => Promise<DownloadResult>;
  /** Token + endpoint passed through to the default download impl.
   *  Ignored when `download` is overridden. */
  readonly downloadOptions?: DownloadAttachmentOptions;
}

type ViewState =
  | { kind: 'loading' }
  | { kind: 'ok'; blobUrl: string }
  | { kind: 'tag_failed' }
  | { kind: 'not_found' }
  | { kind: 'error'; message: string };

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AttachmentView(props: AttachmentViewProps): JSX.Element {
  const [state, setState] = useState<ViewState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    let createdUrl: string | null = null;

    const run = async (): Promise<void> => {
      // 1. Try the cache. A hit with a non-null `plaintext` is a
      //    direct render; a hit with only ciphertext means the
      //    decrypt has not been attempted yet for this row, so we
      //    fall through to a fetch which may itself replay against
      //    the cached ciphertext (the server hop is still there
      //    today; a future patch can shortcut it).
      if (props.cache !== undefined) {
        try {
          const hit = await props.cache.getByAttachmentId(
            props.ref.attachmentId,
          );
          if (cancelled) return;
          if (hit !== null && hit.plaintext !== null) {
            const url = blobUrlFor(hit.plaintext, props.mime);
            createdUrl = url;
            setState({ kind: 'ok', blobUrl: url });
            return;
          }
        } catch {
          // Cache failures are non-fatal — fall through to the
          // network path. We deliberately don't surface cache
          // errors to the user.
        }
      }

      // 2. Fetch + decrypt over the network.
      const downloader = props.download ?? defaultDownload;
      let result: DownloadResult;
      try {
        result = await downloader(props.ref, props.downloadOptions);
      } catch (err) {
        if (cancelled) return;
        // 403 / 5xx / network. The placeholder / retry surface is
        // a transient-error UI rather than the inert
        // tag-failure / not-found placeholder.
        const msg =
          err instanceof AttachmentDownloadError
            ? err.message
            : 'attachment download failed';
        setState({ kind: 'error', message: msg });
        return;
      }
      if (cancelled) return;

      if (result.kind === 'not_found') {
        setState({ kind: 'not_found' });
        return;
      }
      if (result.kind === 'decrypt_failed') {
        setState({ kind: 'tag_failed' });
        return;
      }
      // 3. Success path. Update cache (best-effort) and surface a
      //    fresh blob URL.
      const url = blobUrlFor(result.plaintext, props.mime);
      createdUrl = url;
      if (props.cache !== undefined) {
        try {
          await props.cache.putPlaintext({
            attachmentId: props.ref.attachmentId,
            plaintext: result.plaintext,
          });
        } catch {
          // Cache writes are best-effort; a failure does not
          // affect the render.
        }
      }
      setState({ kind: 'ok', blobUrl: url });
    };

    void run();
    return (): void => {
      cancelled = true;
      if (createdUrl !== null) {
        // Releasing the object URL frees the underlying blob.
        // Safe to call even if the consumer's <img> is still in
        // flight — the browser keeps the blob alive for any
        // outstanding load.
        URL.revokeObjectURL(createdUrl);
      }
    };
  }, [
    props.ref.attachmentId,
    // The key/iv/tag should be referentially stable per envelope
    // but we list them here so React re-runs the effect if the
    // caller swaps the ref instance (e.g. upon re-decrypting an
    // updated envelope).
    props.ref.key,
    props.ref.iv,
    props.ref.tag,
    props.mime,
    props.cache,
    props.download,
  ]);

  if (state.kind === 'loading') {
    return (
      <div data-testid="attachment-loading" aria-busy="true">
        loading attachment…
      </div>
    );
  }

  if (state.kind === 'tag_failed') {
    return (
      <div
        data-testid="attachment-tag-failed"
        role="alert"
        className="attachment-placeholder attachment-placeholder--tag-failed"
      >
        {TAG_FAILURE_PLACEHOLDER}
      </div>
    );
  }

  if (state.kind === 'not_found') {
    return (
      <div
        data-testid="attachment-not-found"
        role="alert"
        className="attachment-placeholder attachment-placeholder--not-found"
      >
        {NOT_FOUND_PLACEHOLDER}
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div
        data-testid="attachment-error"
        role="alert"
        className="attachment-placeholder attachment-placeholder--error"
      >
        couldn't load attachment: {state.message}
      </div>
    );
  }

  // Success branch — pick the right element by MIME family.
  const family = mimeFamily(props.mime);
  if (family === 'image') {
    return (
      <img
        data-testid="attachment-image"
        src={state.blobUrl}
        alt={props.filename}
      />
    );
  }
  if (family === 'audio') {
    return (
      <audio
        data-testid="attachment-audio"
        src={state.blobUrl}
        controls
      />
    );
  }
  return (
    <a
      data-testid="attachment-download"
      href={state.blobUrl}
      download={props.filename}
    >
      {props.filename}
    </a>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function blobUrlFor(bytes: Uint8Array, mime: string): string {
  // Wrapping in a `Blob` rather than a typed array gives us the
  // `URL.createObjectURL` path supported by both browsers and jsdom.
  //
  // The `as BlobPart` cast bridges a TypeScript lib quirk: the
  // current `lib.dom.d.ts` types `BlobPart` as `BufferSource | Blob
  // | string`, where `BufferSource` is `ArrayBufferView<ArrayBuffer>
  // | ArrayBuffer`. A `Uint8Array<ArrayBufferLike>` (the new strict
  // typed-array generic) widens through `ArrayBufferLike`, which
  // includes `SharedArrayBuffer`, so the structural assignability
  // check trips on the `Symbol.toStringTag` field. The runtime
  // value is a perfectly valid `BlobPart`; this cast is purely a
  // type-system bridge.
  const blob = new Blob([bytes as unknown as BlobPart], { type: mime });
  return URL.createObjectURL(blob);
}

type MimeFamily = 'image' | 'audio' | 'other';

function mimeFamily(mime: string): MimeFamily {
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('audio/')) return 'audio';
  return 'other';
}

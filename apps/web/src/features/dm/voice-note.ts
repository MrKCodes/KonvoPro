// apps/web/src/features/dm/voice-note.ts
//
// Voice-note recorder + retrying upload pipeline (task 5.4).
//
// Realises Requirement 5.1–5.9 + design.md §13.3 (the
// attachment encrypt/upload pseudocode reused here verbatim
// for the audio path):
//
//   hold-to-record gesture  ──▶  MediaRecorder (Opus/WebM)
//                                       │
//                                       ▼
//                          on stop / 120 s autoStop
//                                       │
//                                       ▼
//                              < 1 s release? ──▶  discard (no upload, no envelope)
//                                       │
//                                       ▼ ≥ 1 s
//                          encryptAttachment (fresh AES-GCM
//                              256-bit key + 96-bit IV, every clip)
//                                       │
//                                       ▼
//                          uploadAttachment with ≤ 3 retries +
//                              exponential backoff
//                                       │
//                                       ▼
//                          AttachmentRef (key/iv/tag) for the
//                              caller to embed inside an
//                              InnerType.VOICE_NOTE inner payload
//                                       │
//                                       ▼
//                          terminal upload failure ──▶  state: 'failed'
//                                                       (caller emits NO envelope —
//                                                        Requirement 5.9)
//
// What this module owns
// ---------------------
//   - The MediaRecorder lifecycle: getUserMedia → start →
//     gather chunks → stop → finalise Blob.
//   - The hold-to-record state machine. The button component
//     calls `start()` on pointer-down / Space-down and `stop()`
//     on pointer-up / Space-up; this module enforces:
//       * < 1 s release: discard, no upload, no envelope (req 5.8).
//       * ≥ 120 s recording: auto-stop and finalise (req 5.2).
//       * Permission denied/revoked at start: surface the
//         `permission-required` outcome and never begin
//         recording (req 5.7).
//   - The AES-GCM encrypt step. Each clip uses
//     `encryptAttachment` — which by construction (`task 5.1`)
//     mints a fresh 32-byte key + 12-byte IV per call. The key
//     is therefore *necessarily* fresh per recording (req 5.3 +
//     6.1's "never reused" invariant); we do not reuse a
//     long-lived key under a counter-style IV scheme.
//   - The upload retry loop: up to 3 retries of `POST /attachments`
//     (task 5.3's `uploadAttachment`), with exponential backoff
//     (250 ms, 500 ms, 1 s). On terminal failure the recorder
//     emits the `'failed'` state; the caller MUST NOT send any
//     envelope on this branch (req 5.9).
//   - Producing an `AttachmentRef` (with `key`/`iv`/`tag`
//     spliced from the encrypt step) so the DM controller can
//     embed it inside an E2EE `InnerType.VOICE_NOTE` payload.
//     This module DOES NOT itself send the envelope — that's
//     the controller / wire layer's job, exactly mirroring the
//     attachment flow (task 5.3).
//
// What this module does NOT own
// -----------------------------
//   - libsignal encryption / envelope routing. The caller
//     embeds the produced `AttachmentRef` (+ duration) inside
//     an `InnerType.VOICE_NOTE` payload, encodes it, and feeds
//     it through the DM controller's
//     `encryptToDevice` → outbox path. We expose the
//     `attachmentRef` + `durationMs` on the success outcome so
//     the caller has everything it needs.
//   - Playback. The `VoiceNotePlayer` component handles the
//     recipient-side decrypt + waveform render.
//   - Local cache writes. Future work can pre-warm the
//     `LocalAttachmentsStore` with the fresh plaintext so the
//     sender can listen back to their own clip without
//     re-decrypting; we leave that to the call site.
//
// Threading / concurrency
// -----------------------
//   - The recorder is single-instance per `VoiceNoteRecorder`
//     handle. `start()` while a recording is in flight is a
//     programmer error and throws.
//   - The auto-stop watchdog (120 s) is set inside `start()`
//     and cleared on every terminal transition (success,
//     short-release discard, failure). Re-entrant timer fires
//     after teardown bail out at the top of the handler.

import {
  encryptAttachment,
  type EncryptedAttachment,
} from '@konvo/crypto';
import type { AttachmentRef } from '@konvo/protocol';

import {
  uploadAttachment,
  AttachmentUploadError,
  type UploadAttachmentOptions,
} from '../attachments/upload.js';

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/** Maximum recording length before auto-stop (Requirement 5.2). */
export const MAX_RECORDING_MS = 120_000;

/** Minimum hold duration; releases shorter than this discard the
 *  clip without uploading or producing an envelope (Requirement 5.8). */
export const MIN_HOLD_MS = 1_000;

/** Upload retry budget after the initial attempt (Requirement 5.9 —
 *  "retry up to 3 times with exponential backoff"). The first attempt
 *  is not counted toward the 3, mirroring "3 retries" English usage:
 *  one initial attempt + three retries = up to four total POSTs. */
export const UPLOAD_MAX_RETRIES = 3;

/** Initial backoff delay between retries. The schedule is 250 ms,
 *  500 ms, 1 s — capped at 1 s to keep total worst-case time short
 *  enough that the user sees a `failed` state within a few seconds
 *  rather than half a minute. */
export const UPLOAD_BACKOFF_BASE_MS = 250;

/** MIME type the recorder asks `MediaRecorder` for. Per Requirement
 *  5.1 + design.md §21 Phase 4 we use Opus encoded inside a WebM
 *  container. Browsers that don't support this exact string will
 *  surface `MediaRecorder.isTypeSupported(...) === false`; we fall
 *  back to whichever audio MIME the runtime offers, but reject
 *  recording if no audio MIME is supported. */
export const PREFERRED_MIME = 'audio/webm;codecs=opus';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Discriminated outcome of `stop()`.
 *
 *  - `'discarded'`: the user released before the 1 s threshold; the
 *    recorder produced no Blob, ran no upload, and the caller MUST
 *    NOT send any envelope (req 5.8).
 *  - `'permission_denied'`: getUserMedia rejected with
 *    NotAllowedError (or equivalent). Also surfaces the same
 *    outcome on `start()` itself; the renderer shows the
 *    permission-required prompt (req 5.7). The caller MUST NOT send
 *    any envelope.
 *  - `'failed'`: encrypt or upload-after-retries failed. The
 *    `details` field carries a short diagnostic string for
 *    surfacing to the user (e.g. "upload failed", "encryption
 *    failed"). The caller MUST NOT send any envelope (req 5.9).
 *  - `'ok'`: clip recorded, encrypted, and uploaded successfully.
 *    Carries the `AttachmentRef` (with key/iv/tag), the recording
 *    `durationMs`, the negotiated `mime` (so the player can
 *    decode), and the freshly encrypted plaintext bytes (so the
 *    caller can pre-warm a local cache or render an immediate
 *    self-playback without re-decrypting). */
export type VoiceNoteOutcome =
  | { readonly kind: 'ok';
      readonly attachmentRef: AttachmentRef;
      readonly durationMs: number;
      readonly mime: string;
      readonly plaintext: Uint8Array;
    }
  | { readonly kind: 'discarded'; readonly heldMs: number }
  | { readonly kind: 'permission_denied' }
  | { readonly kind: 'failed'; readonly details: string };

/** Live status pushed by the recorder during a recording. The
 *  button component subscribes to this so it can render the
 *  per-second elapsed time and the "approaching auto-stop" hint. */
export type VoiceNoteStatus =
  | { readonly kind: 'idle' }
  | { readonly kind: 'recording'; readonly elapsedMs: number }
  | { readonly kind: 'finalizing' }
  | { readonly kind: 'uploading'; readonly attempt: number };

export type VoiceNoteStatusListener = (status: VoiceNoteStatus) => void;

/** Optional configuration. Every field has a sensible production
 *  default; tests inject lightweight stubs. */
export interface VoiceNoteRecorderOptions {
  /** Override the recipient device ids passed through to the
   *  upload step. Mirrors `uploadAttachment`'s shape — the route
   *  uses this to pre-authorize the recipients per design.md §9. */
  readonly allowedRecipientIds: readonly string[];
  /** Override `navigator.mediaDevices.getUserMedia`. Defaults to
   *  the global. Tests pass a fake. */
  readonly getUserMedia?: (
    constraints: MediaStreamConstraints,
  ) => Promise<MediaStream>;
  /** Override the `MediaRecorder` constructor. Defaults to the
   *  global. Tests pass a stub class so `start`, `stop`,
   *  `ondataavailable`, and `onstop` can be driven deterministically. */
  readonly mediaRecorderCtor?: new (
    stream: MediaStream,
    options?: MediaRecorderOptions,
  ) => MediaRecorder;
  /** Override the `MediaRecorder.isTypeSupported` static method.
   *  Defaults to the global. */
  readonly isTypeSupported?: (mime: string) => boolean;
  /** Override `encryptAttachment`. Defaults to the real impl;
   *  tests stub this so they don't need WebCrypto running. */
  readonly encryptImpl?: (plaintext: Uint8Array) => Promise<EncryptedAttachment>;
  /** Override `uploadAttachment`. Defaults to the real impl;
   *  tests pass a fake that returns or throws on demand. */
  readonly uploadImpl?: (
    file: File,
    allowedRecipientIds: readonly string[],
    options?: UploadAttachmentOptions,
  ) => Promise<AttachmentRef>;
  /** Forwarded to the default `uploadImpl`. Ignored when
   *  `uploadImpl` is overridden. */
  readonly uploadOptions?: UploadAttachmentOptions;
  /** Wall-clock supplier for elapsed-time + tag-fresh checks.
   *  Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Timer hooks. Defaults to the globals. Tests inject fakes
   *  so the 120 s auto-stop and the retry backoff can run
   *  deterministically. */
  readonly setTimeoutImpl?: (
    fn: () => void,
    ms: number,
  ) => ReturnType<typeof setTimeout>;
  readonly clearTimeoutImpl?: (
    handle: ReturnType<typeof setTimeout>,
  ) => void;
  /** Maximum recording duration before auto-stop. Defaults to
   *  `MAX_RECORDING_MS`. Exposed so tests can shorten the
   *  watchdog without sleeping for two minutes. */
  readonly maxRecordingMs?: number;
  /** Minimum hold duration before producing a clip. Defaults to
   *  `MIN_HOLD_MS`. Exposed so tests can drop below the 1 s
   *  threshold without timing-sensitive sleeps. */
  readonly minHoldMs?: number;
  /** Override the upload retry budget. Defaults to
   *  `UPLOAD_MAX_RETRIES`. */
  readonly maxRetries?: number;
  /** Override the base backoff delay. Defaults to
   *  `UPLOAD_BACKOFF_BASE_MS`. */
  readonly backoffBaseMs?: number;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

type RecorderState =
  | { kind: 'idle' }
  | {
      kind: 'recording';
      stream: MediaStream;
      recorder: MediaRecorder;
      mime: string;
      chunks: Blob[];
      startedAt: number;
      autoStopTimer: ReturnType<typeof setTimeout> | null;
      stopPromise: Promise<{ blob: Blob; durationMs: number; mime: string }>;
      cancelled: boolean;
    };

/**
 * VoiceNoteRecorder: hold-to-record audio capture with E2EE
 * encryption + upload. Created once per composer; a single
 * instance can be used for many sequential recordings.
 *
 * Lifecycle:
 *   const r = new VoiceNoteRecorder({ allowedRecipientIds });
 *   await r.start();                 // pointer-down / Space-down
 *   // ... user holds ...
 *   const out = await r.stop();      // pointer-up / Space-up
 *   //   - out.kind === 'ok'             → embed `attachmentRef`
 *   //                                      in an InnerType.VOICE_NOTE
 *   //                                      payload and send
 *   //   - out.kind === 'discarded'      → render nothing
 *   //   - out.kind === 'permission_denied'
 *   //                                   → show prompt
 *   //   - out.kind === 'failed'         → mark failed in UI;
 *   //                                      DO NOT send any envelope
 *   //                                      (req 5.9)
 */
export class VoiceNoteRecorder {
  readonly #allowedRecipientIds: readonly string[];
  readonly #getUserMedia: (
    c: MediaStreamConstraints,
  ) => Promise<MediaStream>;
  readonly #mediaRecorderCtor: new (
    stream: MediaStream,
    options?: MediaRecorderOptions,
  ) => MediaRecorder;
  readonly #isTypeSupported: (mime: string) => boolean;
  readonly #encryptImpl: (
    plaintext: Uint8Array,
  ) => Promise<EncryptedAttachment>;
  readonly #uploadImpl: (
    file: File,
    allowedRecipientIds: readonly string[],
    options?: UploadAttachmentOptions,
  ) => Promise<AttachmentRef>;
  readonly #uploadOptions: UploadAttachmentOptions | undefined;
  readonly #now: () => number;
  readonly #setTimeout: (
    fn: () => void,
    ms: number,
  ) => ReturnType<typeof setTimeout>;
  readonly #clearTimeout: (h: ReturnType<typeof setTimeout>) => void;
  readonly #maxRecordingMs: number;
  readonly #minHoldMs: number;
  readonly #maxRetries: number;
  readonly #backoffBaseMs: number;

  #state: RecorderState = { kind: 'idle' };
  readonly #listeners: VoiceNoteStatusListener[] = [];
  #ticker: ReturnType<typeof setInterval> | null = null;

  constructor(opts: VoiceNoteRecorderOptions) {
    this.#allowedRecipientIds = opts.allowedRecipientIds;
    this.#getUserMedia =
      opts.getUserMedia ??
      ((c): Promise<MediaStream> =>
        navigator.mediaDevices.getUserMedia(c));
    this.#mediaRecorderCtor =
      opts.mediaRecorderCtor ??
      (globalThis as unknown as {
        MediaRecorder: new (
          stream: MediaStream,
          options?: MediaRecorderOptions,
        ) => MediaRecorder;
      }).MediaRecorder;
    this.#isTypeSupported =
      opts.isTypeSupported ??
      ((mime: string): boolean => {
        const Ctor = (globalThis as unknown as {
          MediaRecorder?: { isTypeSupported?: (m: string) => boolean };
        }).MediaRecorder;
        if (Ctor === undefined || typeof Ctor.isTypeSupported !== 'function') {
          // Pessimistic default: if the environment doesn't expose
          // isTypeSupported we accept the requested MIME and let the
          // constructor reject if it really is unsupported.
          return true;
        }
        return Ctor.isTypeSupported(mime);
      });
    this.#encryptImpl = opts.encryptImpl ?? encryptAttachment;
    this.#uploadImpl = opts.uploadImpl ?? uploadAttachment;
    this.#uploadOptions = opts.uploadOptions;
    this.#now = opts.now ?? ((): number => Date.now());
    this.#setTimeout =
      opts.setTimeoutImpl ?? ((fn, ms): ReturnType<typeof setTimeout> => setTimeout(fn, ms));
    this.#clearTimeout =
      opts.clearTimeoutImpl ?? ((h): void => clearTimeout(h));
    this.#maxRecordingMs = opts.maxRecordingMs ?? MAX_RECORDING_MS;
    this.#minHoldMs = opts.minHoldMs ?? MIN_HOLD_MS;
    this.#maxRetries = opts.maxRetries ?? UPLOAD_MAX_RETRIES;
    this.#backoffBaseMs = opts.backoffBaseMs ?? UPLOAD_BACKOFF_BASE_MS;
  }

  /** Subscribe to status changes (idle / recording / uploading
   *  / finalizing). Returns an unsubscribe callback. */
  subscribe(listener: VoiceNoteStatusListener): () => void {
    this.#listeners.push(listener);
    return (): void => {
      const idx = this.#listeners.indexOf(listener);
      if (idx >= 0) this.#listeners.splice(idx, 1);
    };
  }

  /** True iff a recording is currently in progress. */
  isRecording(): boolean {
    return this.#state.kind === 'recording';
  }

  /**
   * Begin a new recording. Resolves once `MediaRecorder.start`
   * has been called and the auto-stop watchdog is armed.
   *
   * Requirement 5.7: a permission rejection here surfaces as a
   * `'permission_denied'` outcome — the caller renders the
   * "permission required" prompt and does NOT begin recording.
   * We model this by resolving `start()` to a discriminated
   * status object rather than throwing, so a rejection during
   * the gesture is a regular UX state and not an exception.
   */
  async start(): Promise<
    | { readonly kind: 'started' }
    | { readonly kind: 'permission_denied' }
    | { readonly kind: 'unsupported' }
  > {
    if (this.#state.kind !== 'idle') {
      throw new Error('VoiceNoteRecorder.start: already recording');
    }
    // Pick the best supported MIME. Preferred is `audio/webm;codecs=opus`
    // (req 5.1). If that's not supported, fall back to the
    // container-only form, then to the platform default.
    const mime = pickSupportedMime(this.#isTypeSupported);
    if (mime === null) {
      return { kind: 'unsupported' };
    }
    let stream: MediaStream;
    try {
      stream = await this.#getUserMedia({ audio: true });
    } catch (err) {
      if (isPermissionDenied(err)) {
        return { kind: 'permission_denied' };
      }
      // Other media errors (no device, OS lock) collapse to the
      // same "permission_denied" outcome from the user's
      // perspective — they cannot record. Surfacing a distinct
      // kind would be a UX nuance the spec doesn't ask for.
      return { kind: 'permission_denied' };
    }

    let recorder: MediaRecorder;
    try {
      recorder = new this.#mediaRecorderCtor(stream, { mimeType: mime });
    } catch {
      // Some platforms fail at the ctor when the requested mime
      // is unsupported even though `isTypeSupported` returned
      // true (older Safari + Firefox quirks). Stop the stream
      // tracks and surface `unsupported`.
      stopStream(stream);
      return { kind: 'unsupported' };
    }
    const chunks: Blob[] = [];
    let resolveStop!: (
      v: { blob: Blob; durationMs: number; mime: string },
    ) => void;
    let rejectStop!: (e: Error) => void;
    const stopPromise = new Promise<{ blob: Blob; durationMs: number; mime: string }>(
      (resolve, reject) => {
        resolveStop = resolve;
        rejectStop = reject;
      },
    );

    recorder.ondataavailable = (ev: BlobEvent): void => {
      // Only push non-empty chunks. Some browsers emit an empty
      // chunk on stop if the stream had not produced any audio
      // yet — we don't want to surface a 0-byte clip as a real
      // recording.
      if (ev.data && ev.data.size > 0) {
        chunks.push(ev.data);
      }
    };
    recorder.onstop = (): void => {
      const startedAt =
        this.#state.kind === 'recording' ? this.#state.startedAt : this.#now();
      const durationMs = Math.max(0, this.#now() - startedAt);
      const finalBlob = new Blob(chunks, { type: mime });
      stopStream(stream);
      resolveStop({ blob: finalBlob, durationMs, mime });
    };
    recorder.onerror = (ev: Event): void => {
      stopStream(stream);
      const errLike = (ev as unknown as { error?: { message?: string } }).error;
      const message =
        errLike !== undefined && typeof errLike.message === 'string'
          ? errLike.message
          : 'media-recorder error';
      rejectStop(new Error(message));
    };

    const startedAt = this.#now();

    // Auto-stop watchdog (req 5.2). On fire, request the
    // recorder to stop and let the normal `onstop` flow finalise
    // the blob.
    const autoStopTimer = this.#setTimeout(() => {
      const cur = this.#state;
      if (cur.kind !== 'recording') return;
      try {
        cur.recorder.stop();
      } catch {
        // Some browsers throw if the recorder is already
        // stopping; that's fine — `onstop` will still fire.
      }
    }, this.#maxRecordingMs);

    try {
      recorder.start();
    } catch (err) {
      this.#clearTimeout(autoStopTimer);
      stopStream(stream);
      const msg = err instanceof Error ? err.message : 'recorder start failed';
      throw new Error(`VoiceNoteRecorder.start: ${msg}`);
    }

    this.#state = {
      kind: 'recording',
      stream,
      recorder,
      mime,
      chunks,
      startedAt,
      autoStopTimer,
      stopPromise,
      cancelled: false,
    };

    this.#startTicker();
    this.#emit({ kind: 'recording', elapsedMs: 0 });
    return { kind: 'started' };
  }

  /**
   * Finalise the in-flight recording. Returns a discriminated
   * outcome per `VoiceNoteOutcome`. See the type docs above for
   * the per-branch contract. Calling `stop` while idle returns
   * `{ kind: 'discarded', heldMs: 0 }` so the caller's release
   * handler is idempotent against double-fire (e.g. blur +
   * pointerup arriving on the same gesture).
   */
  async stop(): Promise<VoiceNoteOutcome> {
    const state = this.#state;
    if (state.kind !== 'recording') {
      return { kind: 'discarded', heldMs: 0 };
    }
    const heldMs = this.#now() - state.startedAt;
    this.#stopTicker();

    // Always cancel the auto-stop timer; if 120 s elapses while
    // we're awaiting the user's release, the timer's own handler
    // already requested `recorder.stop()` and we just observe
    // the resulting `onstop`.
    if (state.autoStopTimer !== null) {
      this.#clearTimeout(state.autoStopTimer);
      state.autoStopTimer = null;
    }

    // Short-release path: discard without uploading or producing
    // an envelope (req 5.8).
    if (heldMs < this.#minHoldMs) {
      // Mark the in-flight recording as cancelled BEFORE we
      // request the recorder to stop. The `onstop` handler will
      // still resolve `stopPromise`, but we ignore the resulting
      // blob.
      state.cancelled = true;
      try {
        if (state.recorder.state !== 'inactive') {
          state.recorder.stop();
        }
      } catch {
        // Same as above — some browsers throw if already
        // stopping. Stream is cleaned up by `onstop`.
      }
      // Drain `stopPromise` to release any pending resources
      // (some MediaRecorder implementations buffer the final
      // chunk until the consumer awaits the stop signal).
      try {
        await state.stopPromise;
      } catch {
        // Ignore — the cancellation path is best-effort cleanup.
      }
      this.#state = { kind: 'idle' };
      this.#emit({ kind: 'idle' });
      return { kind: 'discarded', heldMs };
    }

    // Long-press path: stop the recorder, await the final blob,
    // encrypt + upload.
    this.#emit({ kind: 'finalizing' });
    try {
      if (state.recorder.state !== 'inactive') {
        state.recorder.stop();
      }
    } catch {
      // Same as above.
    }

    let final: { blob: Blob; durationMs: number; mime: string };
    try {
      final = await state.stopPromise;
    } catch (err) {
      this.#state = { kind: 'idle' };
      this.#emit({ kind: 'idle' });
      const msg = err instanceof Error ? err.message : 'recorder finalisation failed';
      return { kind: 'failed', details: `recording failed: ${msg}` };
    }
    this.#state = { kind: 'idle' };

    // Read bytes for the encrypt step.
    let plaintext: Uint8Array;
    try {
      plaintext = await blobToBytes(final.blob);
    } catch (err) {
      this.#emit({ kind: 'idle' });
      const msg = err instanceof Error ? err.message : 'blob read failed';
      return { kind: 'failed', details: `read failed: ${msg}` };
    }
    if (plaintext.length === 0) {
      // The recorder emitted an empty blob (e.g. the OS revoked
      // the mic mid-recording). Treat as failed; do NOT send any
      // envelope.
      this.#emit({ kind: 'idle' });
      return { kind: 'failed', details: 'empty recording' };
    }

    // Encrypt with a freshly minted AES-GCM key + IV (req 5.3 +
    // 6.1). `encryptAttachment` mints both per call, so the
    // freshness invariant is satisfied by construction.
    let enc: EncryptedAttachment;
    try {
      enc = await this.#encryptImpl(plaintext);
    } catch (err) {
      this.#emit({ kind: 'idle' });
      const msg = err instanceof Error ? err.message : 'encrypt failed';
      return { kind: 'failed', details: `encryption failed: ${msg}` };
    }

    // Upload with retry. The `upload.ts` helper already builds
    // the multipart form + base64-encodes (iv, tag); we wrap a
    // fresh `File` per attempt because `FormData` consumes the
    // file part on the first POST.
    const filename = `voice-note-${this.#now()}.webm`;
    let attachmentRef: AttachmentRef | null = null;
    let lastError: Error | null = null;
    const totalAttempts = this.#maxRetries + 1; // initial + retries
    for (let attempt = 1; attempt <= totalAttempts; attempt += 1) {
      this.#emit({ kind: 'uploading', attempt });
      // Upload accepts a `File` whose .type drives the server's
      // stored MIME column. The recorder's `mime` carries the
      // codec param (`audio/webm;codecs=opus`); the route stores
      // up to 255 chars and the player layer will read this back
      // to pick the right `<audio>` element.
      const file = ciphertextAsFile(enc.ciphertext, filename, final.mime);
      try {
        // We DO NOT route through the production
        // `uploadAttachment` here — that helper does its own
        // encrypt + upload. We've already encrypted, so we need
        // to ship the ciphertext directly. The hand-off is done
        // via the test injection point: the production
        // `uploadImpl` is `uploadAttachment`, which re-encrypts
        // anyway, but we handle that by short-circuiting through
        // a tiny wrapper below.
        const ref = await this.#uploadCiphertext(
          file,
          enc,
          plaintext.length,
        );
        attachmentRef = ref;
        lastError = null;
        break;
      } catch (err) {
        lastError =
          err instanceof Error ? err : new Error(String(err));
        // Oversize is terminal — no retry buys anything.
        if (
          err instanceof AttachmentUploadError &&
          err.kind === 'oversize'
        ) {
          break;
        }
        if (attempt < totalAttempts) {
          // Exponential backoff: base * 2^(attempt-1). Cap
          // implicit at the next attempt's wait, since after
          // `totalAttempts` we exit.
          const delay = this.#backoffBaseMs * Math.pow(2, attempt - 1);
          await sleep(delay, this.#setTimeout);
        }
      }
    }

    if (attachmentRef === null) {
      this.#emit({ kind: 'idle' });
      const msg =
        lastError !== null ? lastError.message : 'upload failed';
      return { kind: 'failed', details: `upload failed: ${msg}` };
    }

    this.#emit({ kind: 'idle' });
    return {
      kind: 'ok',
      attachmentRef,
      durationMs: final.durationMs,
      mime: final.mime,
      plaintext,
    };
  }

  /**
   * Cancel an in-flight recording without producing a clip. Used
   * by the button component when the gesture is interrupted
   * (e.g. window blur during a hold). Idempotent.
   */
  cancel(): void {
    const state = this.#state;
    if (state.kind !== 'recording') return;
    state.cancelled = true;
    if (state.autoStopTimer !== null) {
      this.#clearTimeout(state.autoStopTimer);
      state.autoStopTimer = null;
    }
    this.#stopTicker();
    try {
      if (state.recorder.state !== 'inactive') {
        state.recorder.stop();
      }
    } catch {
      // Best-effort.
    }
    stopStream(state.stream);
    this.#state = { kind: 'idle' };
    this.#emit({ kind: 'idle' });
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /**
   * Upload the already-encrypted ciphertext. The default
   * `uploadAttachment` helper would re-encrypt, so when no
   * override is provided we ship a small purpose-built upload
   * routine that mirrors `upload.ts` but skips the encrypt step.
   *
   * Tests inject `uploadImpl` to short-circuit this entirely.
   */
  async #uploadCiphertext(
    file: File,
    enc: EncryptedAttachment,
    sizeBytes: number,
  ): Promise<AttachmentRef> {
    // If the caller injected a fake `uploadImpl`, defer to it.
    // The fake is responsible for returning a populated
    // `AttachmentRef`.
    if (this.#uploadImpl !== uploadAttachment) {
      const ref = await this.#uploadImpl(
        file,
        this.#allowedRecipientIds,
        this.#uploadOptions,
      );
      // Splice key/iv/tag from our local encrypt onto whatever
      // attachmentId the upstream returned. The fake is allowed
      // to omit them.
      return {
        attachmentId: ref.attachmentId,
        key: enc.key,
        iv: enc.iv,
        tag: enc.tag,
        sizeBytes,
      };
    }
    // Production path: hit the route directly with a multipart
    // form carrying the already-encrypted ciphertext + key/iv/tag
    // metadata. We mirror the form fields used by
    // `apps/web/src/features/attachments/upload.ts` so the
    // server's `multipartUploadParser` accepts the request
    // unchanged.
    return uploadCiphertextDirect({
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      tag: enc.tag,
      mime: file.type.length > 0 ? file.type : 'audio/webm',
      sizeBytes,
      filename: file.name,
      allowedRecipientIds: this.#allowedRecipientIds,
      key: enc.key,
      options: this.#uploadOptions,
    });
  }

  #emit(status: VoiceNoteStatus): void {
    const snapshot = this.#listeners.slice();
    for (const fn of snapshot) {
      try {
        fn(status);
      } catch {
        // Listener errors are swallowed — see DM controller's
        // approach.
      }
    }
  }

  #startTicker(): void {
    if (this.#ticker !== null) return;
    this.#ticker = setInterval((): void => {
      const state = this.#state;
      if (state.kind !== 'recording') return;
      const elapsedMs = this.#now() - state.startedAt;
      this.#emit({ kind: 'recording', elapsedMs });
    }, 200);
  }

  #stopTicker(): void {
    if (this.#ticker !== null) {
      clearInterval(this.#ticker);
      this.#ticker = null;
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pickSupportedMime(
  isSupported: (mime: string) => boolean,
): string | null {
  // Preferred: Opus inside WebM (req 5.1). Falls back to the
  // container-only form (some Firefox versions only accept
  // 'audio/webm') and finally to a generic Opus container.
  for (const candidate of [
    PREFERRED_MIME,
    'audio/webm',
    'audio/ogg;codecs=opus',
    'audio/ogg',
  ]) {
    if (isSupported(candidate)) return candidate;
  }
  return null;
}

function isPermissionDenied(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const name = (err as { name?: unknown }).name;
  return (
    name === 'NotAllowedError' ||
    name === 'PermissionDeniedError' ||
    name === 'SecurityError'
  );
}

function stopStream(stream: MediaStream): void {
  for (const track of stream.getTracks()) {
    try {
      track.stop();
    } catch {
      // MediaStreamTrack.stop is spec'd to not throw, but
      // some test fakes do; ignore.
    }
  }
}

async function blobToBytes(blob: Blob): Promise<Uint8Array> {
  // Mirror `attachments/upload.ts`'s feature-detection for
  // jsdom's older Blob shape.
  const maybe = (blob as Blob & { arrayBuffer?: () => Promise<ArrayBuffer> })
    .arrayBuffer;
  if (typeof maybe === 'function') {
    return new Uint8Array(await maybe.call(blob));
  }
  const FileReaderCtor = (globalThis as unknown as {
    FileReader?: typeof FileReader;
  }).FileReader;
  if (FileReaderCtor === undefined) {
    throw new Error(
      'voice-note: neither Blob.arrayBuffer nor FileReader is available',
    );
  }
  return new Promise<Uint8Array>((resolve, reject) => {
    const reader = new FileReaderCtor();
    reader.onload = (): void => {
      const r = reader.result;
      if (r instanceof ArrayBuffer) resolve(new Uint8Array(r));
      else reject(new Error('voice-note: FileReader returned non-ArrayBuffer'));
    };
    reader.onerror = (): void => {
      reject(reader.error ?? new Error('voice-note: FileReader failed'));
    };
    reader.readAsArrayBuffer(blob);
  });
}

function ciphertextAsFile(
  ciphertext: Uint8Array,
  filename: string,
  mime: string,
): File {
  // Wrap the bytes in a File so the upload helpers' size guards
  // and FormData encoders behave the same way they do for
  // attachments. The MIME we hand out here is the recorded MIME
  // (e.g. `audio/webm;codecs=opus`); the server stores up to 255
  // chars and the player reads it back to pick the right
  // `<audio>` element.
  const blob = new Blob([ciphertext as unknown as BlobPart], {
    type: mime,
  });
  return new File([blob], filename, { type: mime });
}

async function sleep(
  ms: number,
  setTimeoutImpl: (
    fn: () => void,
    ms: number,
  ) => ReturnType<typeof setTimeout>,
): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeoutImpl(resolve, ms);
  });
}

// ---------------------------------------------------------------------------
// Production-path multipart uploader
// ---------------------------------------------------------------------------

interface UploadCiphertextDirectArgs {
  readonly ciphertext: Uint8Array;
  readonly iv: Uint8Array;
  readonly tag: Uint8Array;
  readonly mime: string;
  readonly sizeBytes: number;
  readonly filename: string;
  readonly allowedRecipientIds: readonly string[];
  readonly key: Uint8Array;
  readonly options: UploadAttachmentOptions | undefined;
}

/**
 * Mirror of `apps/web/src/features/attachments/upload.ts`'s
 * production POST path, except we ship already-encrypted
 * ciphertext rather than encrypting inside this function.
 *
 * Field names match the server's `multipartUploadParser` in
 * `apps/api/src/routes/attachments.ts` so the route accepts the
 * request unchanged. The key is spliced into the returned
 * `AttachmentRef` from the caller's local encrypt; it never
 * leaves the client in cleartext.
 */
async function uploadCiphertextDirect(
  args: UploadCiphertextDirectArgs,
): Promise<AttachmentRef> {
  const fetchImpl = args.options?.fetchImpl ?? fetch.bind(globalThis);
  const endpoint = args.options?.endpoint ?? '/attachments';

  const MAX_BYTES = 25 * 1024 * 1024;
  if (args.ciphertext.length > MAX_BYTES) {
    throw new AttachmentUploadError(
      'oversize',
      `voice note exceeds 25 MiB cap (got ${args.ciphertext.length} bytes)`,
    );
  }

  const form = new FormData();
  const ciphertextBlob = new Blob(
    [args.ciphertext as unknown as BlobPart],
    { type: 'application/octet-stream' },
  );
  form.append('ciphertext', ciphertextBlob, 'ciphertext.bin');
  form.append('mime', args.mime);
  form.append('sizeBytes', String(args.sizeBytes));
  form.append('contentIv', uint8ArrayToBase64(args.iv));
  form.append('contentTag', uint8ArrayToBase64(args.tag));
  if (args.allowedRecipientIds.length > 0) {
    form.append('allowedRecipients', args.allowedRecipientIds.join(','));
  }

  const headers: Record<string, string> = {};
  const token = args.options?.tokenProvider?.() ?? null;
  if (token !== null) headers['authorization'] = `Bearer ${token}`;
  const csrf =
    args.options?.csrfTokenProvider !== undefined
      ? args.options.csrfTokenProvider()
      : readCsrfFromCookie();
  if (csrf !== null) headers['x-csrf-token'] = csrf;

  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      headers,
      body: form,
      credentials: 'include',
    });
  } catch (err) {
    throw new AttachmentUploadError(
      'network',
      `voice note upload network failure: ${(err as Error).message}`,
    );
  }

  if (response.status === 413) {
    throw new AttachmentUploadError(
      'oversize',
      'server rejected voice note as oversize',
      413,
    );
  }
  if (!response.ok) {
    throw new AttachmentUploadError(
      'http',
      `voice note upload failed with HTTP ${response.status}`,
      response.status,
    );
  }

  const parsed = (await response.json()) as { attachmentId?: unknown };
  if (typeof parsed.attachmentId !== 'string') {
    throw new AttachmentUploadError(
      'http',
      'voice note upload reply missing attachmentId',
      response.status,
    );
  }
  return {
    attachmentId: parsed.attachmentId,
    key: args.key,
    iv: args.iv,
    tag: args.tag,
    sizeBytes: args.sizeBytes,
  };
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

function readCsrfFromCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const header = document.cookie;
  if (header.length === 0) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (k !== 'konvo_csrf') continue;
    const v = part.slice(eq + 1).trim();
    return v.length === 0 ? null : v;
  }
  return null;
}

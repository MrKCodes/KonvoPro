// apps/web/src/features/dm/VoiceNotePlayer.tsx
//
// Voice-note playback (task 5.4, requirement 5.6).
//
// Realises:
//   "WHEN a recipient plays back a voice note, the Web_Client
//   SHALL decrypt the ciphertext using the AES-GCM key, IV,
//   and tag from the envelope, then render a scrubable
//   waveform from the decrypted audio."
//
// Architecture:
//   1. Fetch + AES-GCM decrypt the ciphertext via `downloadAttachment`
//      (task 5.3 — already authored).
//   2. Decode the resulting Opus/WebM bytes through
//      `AudioContext.decodeAudioData` to obtain PCM samples.
//   3. Render a scrubable waveform on a `<canvas>` from the PCM
//      samples (downsampled to one bucket per pixel, mono mix).
//   4. Wrap a hidden `<audio>` element for play / pause / seek
//      under a blob URL of the decrypted bytes; the `<audio>`
//      element supplies keyboard playback semantics for free.
//   5. The canvas is overlaid with a scrubber: clicking or
//      dragging on the canvas moves `audio.currentTime`. Keyboard
//      arrow-left / arrow-right step ±5 s, with Space toggling
//      play/pause (matching the WAI-ARIA `slider` pattern).
//
// What this component does NOT own:
//   - The fetch retry / 404 placeholder. We reuse `downloadAttachment`
//     which already returns a typed `not_found` / `decrypt_failed`
//     outcome (task 5.3).
//   - The DM thread row state machine. The parent renders the
//     row and decides whether to mount this component.
//
// Accessibility:
//   - The `<audio>` element exposes native controls when
//     `controls` is set; we keep it visible but rely on the
//     waveform for the primary scrubbing UX.
//   - The waveform is wrapped in a `role="slider"` element with
//     `aria-valuemin/max/now` so AT users can perceive position.
//   - Space toggles play/pause; arrow keys seek ±5 s; Home /
//     End jump to start / end. These conform to the WAI-ARIA
//     APG slider pattern.
//
// Decoding fallback:
//   If the runtime cannot decode Opus/WebM (e.g. older Safari
//   without Opus), we still surface the `<audio>` element under
//   the blob URL — the browser may still play it via its native
//   media pipeline even when WebAudio's decoder rejects. The
//   waveform falls back to a flat baseline in that case.

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
  type KeyboardEvent,
  type PointerEvent,
} from 'react';

import type { AttachmentRef } from '@konvo/protocol';

import {
  downloadAttachment as defaultDownload,
  type DownloadAttachmentOptions,
  type DownloadResult,
} from '../attachments/download.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface VoiceNotePlayerProps {
  readonly ref: AttachmentRef;
  /** Total recording length in milliseconds, taken from the
   *  envelope's `InnerType.VOICE_NOTE` payload. Used as the
   *  denominator for the seek bar BEFORE the audio metadata
   *  loads — the `<audio>` element's `duration` may not be
   *  populated for streamed Opus on first paint. */
  readonly durationMs: number;
  /** MIME type from the envelope. Drives the `<audio>` element's
   *  source MIME hint. */
  readonly mime: string;
  /** Override the download function for tests. Defaults to the
   *  real `downloadAttachment`. */
  readonly download?: (
    ref: AttachmentRef,
    options?: DownloadAttachmentOptions,
  ) => Promise<DownloadResult>;
  readonly downloadOptions?: DownloadAttachmentOptions;
  /** Override `AudioContext` for tests. jsdom doesn't ship one;
   *  the player tolerates its absence by rendering a flat
   *  waveform. */
  readonly audioContextCtor?: new (
    options?: AudioContextOptions,
  ) => AudioContext;
}

// ---------------------------------------------------------------------------
// Constants / strings
// ---------------------------------------------------------------------------

export const VOICE_NOTE_DECRYPT_FAILED_TEXT =
  "voice note couldn't be decrypted";
export const VOICE_NOTE_NOT_FOUND_TEXT = 'voice note unavailable';
const SEEK_STEP_MS = 5_000;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

type LoadState =
  | { kind: 'loading' }
  | { kind: 'tag_failed' }
  | { kind: 'not_found' }
  | { kind: 'error'; message: string }
  | {
      kind: 'ok';
      blobUrl: string;
      waveform: Float32Array | null;
    };

export function VoiceNotePlayer(
  props: VoiceNotePlayerProps,
): JSX.Element {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [currentMs, setCurrentMs] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  const audioElRef = useRef<HTMLAudioElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Fetch + decrypt + decode.
  useEffect(() => {
    let cancelled = false;
    let createdUrl: string | null = null;

    const run = async (): Promise<void> => {
      const downloader = props.download ?? defaultDownload;
      let result: DownloadResult;
      try {
        result = await downloader(props.ref, props.downloadOptions);
      } catch (err) {
        if (cancelled) return;
        const msg =
          err instanceof Error ? err.message : 'voice note download failed';
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

      // Build a blob URL the `<audio>` element can play
      // immediately while we decode the waveform in the
      // background.
      const blob = new Blob([result.plaintext as unknown as BlobPart], {
        type: props.mime,
      });
      const url = URL.createObjectURL(blob);
      createdUrl = url;

      // Try to decode PCM for the waveform. If the runtime
      // can't decode Opus/WebM (e.g. jsdom or Safari without
      // Opus support), fall through with `waveform: null` and
      // render a flat baseline.
      let waveform: Float32Array | null = null;
      try {
        const Ctor = pickAudioContext(props.audioContextCtor);
        if (Ctor !== null) {
          const ctx = new Ctor();
          // `decodeAudioData` consumes the buffer; copy first.
          const copy = result.plaintext.slice().buffer;
          const decoded = await ctx.decodeAudioData(copy);
          waveform = downsampleToWaveform(decoded);
          // Best-effort close — some implementations require it
          // for resource release. AudioContext.close returns a
          // Promise we don't have to await.
          if (typeof ctx.close === 'function') {
            void ctx.close();
          }
        }
      } catch {
        // Non-fatal: the audio element will still play; we just
        // can't render a waveform.
        waveform = null;
      }

      if (cancelled) {
        URL.revokeObjectURL(url);
        return;
      }
      setState({ kind: 'ok', blobUrl: url, waveform });
    };

    void run();
    return (): void => {
      cancelled = true;
      if (createdUrl !== null) {
        URL.revokeObjectURL(createdUrl);
      }
    };
  }, [
    props.ref.attachmentId,
    props.ref.key,
    props.ref.iv,
    props.ref.tag,
    props.mime,
    props.download,
    props.audioContextCtor,
  ]);

  // Render waveform whenever it (or the playhead) changes.
  useEffect(() => {
    if (state.kind !== 'ok') return;
    const canvas = canvasRef.current;
    if (canvas === null) return;
    const ctx2d = canvas.getContext('2d');
    if (ctx2d === null) return;
    drawWaveform(ctx2d, canvas, state.waveform, currentMs, props.durationMs);
  }, [state, currentMs, props.durationMs]);

  // ----- audio element event handlers -----------------------------------

  const onTimeUpdate = useCallback((): void => {
    const el = audioElRef.current;
    if (el === null) return;
    setCurrentMs(Math.floor(el.currentTime * 1000));
  }, []);

  const onPlay = useCallback((): void => setIsPlaying(true), []);
  const onPause = useCallback((): void => setIsPlaying(false), []);
  const onEnded = useCallback((): void => setIsPlaying(false), []);

  const togglePlay = useCallback((): void => {
    const el = audioElRef.current;
    if (el === null) return;
    if (el.paused) {
      void el.play().catch(() => {
        // Some browsers reject autoplay without a user gesture;
        // we already require a click/tap to reach here so this
        // is rare. Surface the error visibly without spamming
        // the console.
        setIsPlaying(false);
      });
    } else {
      el.pause();
    }
  }, []);

  const seekToMs = useCallback((ms: number): void => {
    const el = audioElRef.current;
    if (el === null) return;
    const clamped = Math.max(0, Math.min(ms, props.durationMs));
    el.currentTime = clamped / 1000;
    setCurrentMs(clamped);
  }, [props.durationMs]);

  const onCanvasPointerDown = useCallback(
    (ev: PointerEvent<HTMLCanvasElement>): void => {
      const canvas = canvasRef.current;
      if (canvas === null) return;
      const rect = canvas.getBoundingClientRect();
      const ratio = (ev.clientX - rect.left) / rect.width;
      seekToMs(Math.round(ratio * props.durationMs));
    },
    [seekToMs, props.durationMs],
  );

  const onCanvasKeyDown = useCallback(
    (ev: KeyboardEvent<HTMLDivElement>): void => {
      switch (ev.key) {
        case ' ':
        case 'k':
          ev.preventDefault();
          togglePlay();
          break;
        case 'ArrowLeft':
          ev.preventDefault();
          seekToMs(currentMs - SEEK_STEP_MS);
          break;
        case 'ArrowRight':
          ev.preventDefault();
          seekToMs(currentMs + SEEK_STEP_MS);
          break;
        case 'Home':
          ev.preventDefault();
          seekToMs(0);
          break;
        case 'End':
          ev.preventDefault();
          seekToMs(props.durationMs);
          break;
        default:
          break;
      }
    },
    [seekToMs, togglePlay, currentMs, props.durationMs],
  );

  const elapsedDisplay = useMemo(() => formatTime(currentMs), [currentMs]);
  const durationDisplay = useMemo(
    () => formatTime(props.durationMs),
    [props.durationMs],
  );

  // ----- render branches -------------------------------------------------

  if (state.kind === 'loading') {
    return (
      <div data-testid="voice-note-loading" aria-busy="true">
        loading voice note…
      </div>
    );
  }
  if (state.kind === 'tag_failed') {
    return (
      <div
        data-testid="voice-note-tag-failed"
        role="alert"
      >
        {VOICE_NOTE_DECRYPT_FAILED_TEXT}
      </div>
    );
  }
  if (state.kind === 'not_found') {
    return (
      <div
        data-testid="voice-note-not-found"
        role="alert"
      >
        {VOICE_NOTE_NOT_FOUND_TEXT}
      </div>
    );
  }
  if (state.kind === 'error') {
    return (
      <div data-testid="voice-note-error" role="alert">
        couldn't load voice note: {state.message}
      </div>
    );
  }

  return (
    <div data-testid="voice-note-player">
      <button
        type="button"
        data-testid="voice-note-play-pause"
        aria-label={isPlaying ? 'Pause voice note' : 'Play voice note'}
        onClick={togglePlay}
      >
        {isPlaying ? '⏸' : '▶'}
      </button>
      <div
        data-testid="voice-note-scrubber"
        role="slider"
        tabIndex={0}
        aria-label="Voice note position"
        aria-valuemin={0}
        aria-valuemax={Math.max(1, Math.round(props.durationMs / 1000))}
        aria-valuenow={Math.round(currentMs / 1000)}
        aria-valuetext={`${elapsedDisplay} of ${durationDisplay}`}
        onKeyDown={onCanvasKeyDown}
      >
        <canvas
          ref={canvasRef}
          data-testid="voice-note-waveform"
          width={300}
          height={48}
          onPointerDown={onCanvasPointerDown}
        />
      </div>
      <span data-testid="voice-note-elapsed">
        {elapsedDisplay} / {durationDisplay}
      </span>
      {/* The native <audio> element is mounted but visually
          unobtrusive — the canvas + slider drive playback. We
          keep it visible so a user who prefers native controls
          (or relies on AT that struggles with custom sliders)
          can still operate the player. */}
      <audio
        ref={audioElRef}
        data-testid="voice-note-audio"
        src={state.blobUrl}
        controls
        onTimeUpdate={onTimeUpdate}
        onPlay={onPlay}
        onPause={onPause}
        onEnded={onEnded}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pickAudioContext(
  override: VoiceNotePlayerProps['audioContextCtor'],
):
  | (new (options?: AudioContextOptions) => AudioContext)
  | null {
  if (override !== undefined) return override;
  const Ctor =
    (globalThis as unknown as {
      AudioContext?: new (options?: AudioContextOptions) => AudioContext;
      webkitAudioContext?: new (
        options?: AudioContextOptions,
      ) => AudioContext;
    }).AudioContext ??
    (globalThis as unknown as {
      webkitAudioContext?: new (
        options?: AudioContextOptions,
      ) => AudioContext;
    }).webkitAudioContext;
  return Ctor ?? null;
}

/**
 * Downsample the decoded PCM into a single Float32Array of
 * `WAVEFORM_BUCKETS` peak values in [0, 1]. Mixes channels by
 * absolute-max to preserve transient peaks (a stereo recording's
 * positive and negative peaks shouldn't average out to silence).
 */
const WAVEFORM_BUCKETS = 200;

function downsampleToWaveform(buffer: AudioBuffer): Float32Array {
  const channels: Float32Array[] = [];
  for (let c = 0; c < buffer.numberOfChannels; c += 1) {
    channels.push(buffer.getChannelData(c));
  }
  const totalSamples = buffer.length;
  const samplesPerBucket = Math.max(
    1,
    Math.floor(totalSamples / WAVEFORM_BUCKETS),
  );
  const out = new Float32Array(WAVEFORM_BUCKETS);
  for (let b = 0; b < WAVEFORM_BUCKETS; b += 1) {
    const start = b * samplesPerBucket;
    const end = Math.min(start + samplesPerBucket, totalSamples);
    let peak = 0;
    for (let i = start; i < end; i += 1) {
      let sample = 0;
      for (const ch of channels) {
        const v = Math.abs(ch[i] ?? 0);
        if (v > sample) sample = v;
      }
      if (sample > peak) peak = sample;
    }
    out[b] = Math.min(1, peak);
  }
  return out;
}

function drawWaveform(
  ctx: CanvasRenderingContext2D,
  canvas: HTMLCanvasElement,
  waveform: Float32Array | null,
  currentMs: number,
  durationMs: number,
): void {
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  // Background
  ctx.fillStyle = 'rgba(0,0,0,0.04)';
  ctx.fillRect(0, 0, w, h);

  // Waveform — vertical bars from the centre line.
  if (waveform === null || waveform.length === 0) {
    ctx.fillStyle = 'rgba(0,0,0,0.18)';
    ctx.fillRect(0, h / 2 - 1, w, 2);
  } else {
    const barCount = waveform.length;
    const barWidth = Math.max(1, Math.floor(w / barCount));
    for (let i = 0; i < barCount; i += 1) {
      const v = waveform[i] ?? 0;
      const x = Math.floor((i * w) / barCount);
      const barH = Math.max(1, v * (h - 4));
      const y = (h - barH) / 2;
      // Bars before the playhead are "played" (darker), after
      // are "unplayed" (lighter).
      const playheadX =
        durationMs > 0 ? (currentMs / durationMs) * w : 0;
      ctx.fillStyle =
        x < playheadX ? 'rgba(0,128,255,0.85)' : 'rgba(0,0,0,0.35)';
      ctx.fillRect(x, y, barWidth, barH);
    }
  }

  // Playhead
  if (durationMs > 0) {
    const playheadX = (currentMs / durationMs) * w;
    ctx.strokeStyle = 'rgba(0,128,255,1)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(playheadX, 0);
    ctx.lineTo(playheadX, h);
    ctx.stroke();
  }
}

function formatTime(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}:${s.toString().padStart(2, '0')}`;
}

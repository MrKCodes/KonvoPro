// apps/web/src/features/dm/VoiceNoteButton.tsx
//
// Hold-to-record button for the DM composer (task 5.4).
//
// Why a dedicated component:
//   The voice-note recorder is a state-machine that's painful to
//   wire correctly inside `Composer.tsx`'s text-send branch — it
//   needs pointerdown/pointerup, blur cancellation, keyboard
//   activation, and the "permission denied" branch surfaced
//   declaratively (req 5.7). Keeping it separate lets the text
//   composer stay simple and lets the voice-note seam be tested
//   in isolation.
//
// Accessibility (WCAG 2.5.7 / 2.1.1):
//   - The button is a real `<button>` so it picks up keyboard
//     activation, focus management, and the operating system's
//     hit-target sizing for free.
//   - Pointer-down + Space-down both start a recording; pointer-up,
//     pointer-cancel, blur, and Space-up + Enter-up all stop it.
//     The Space-down handler suppresses the default scroll, and
//     the Enter-up handler matches the WAI-ARIA "activate"
//     convention so screen-reader users can finalise a recording
//     after starting one.
//   - `aria-pressed` reflects the recording state for AT users.
//   - The "permission required" outcome renders inside the button's
//     adjacent live region so AT announces it.
//   - The `<audio>` self-playback exposes native controls (which
//     come with keyboard support).
//
// State flow:
//   idle ──pointerdown/Space-down──▶ recording
//   recording ──pointerup/Space-up──▶ finalizing or discarded
//   recording ──blur/pointercancel──▶ cancelled (treated as discard)
//   finalizing ──upload ok──▶ ok (caller handles)
//   finalizing ──upload fail──▶ failed (UI shows retry/dismiss)

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type JSX,
  type KeyboardEvent,
  type PointerEvent,
} from 'react';

import {
  VoiceNoteRecorder,
  type VoiceNoteOutcome,
  type VoiceNoteRecorderOptions,
  type VoiceNoteStatus,
} from './voice-note.js';

// ---------------------------------------------------------------------------
// User-facing strings
// ---------------------------------------------------------------------------

export const PERMISSION_REQUIRED_TEXT =
  'Microphone permission required to record voice notes';

export const VOICE_NOTE_FAILED_TEXT =
  'Voice note could not be sent. Please try again.';

export const RECORDING_LABEL = 'Hold to record voice note';
export const RECORDING_ACTIVE_LABEL = 'Recording — release to send';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface VoiceNoteButtonProps {
  /** Forwarded to `VoiceNoteRecorder`. The recipient device ids
   *  authorize the upload row. */
  readonly recorderOptions: VoiceNoteRecorderOptions;
  /** Fired with the produced `attachmentRef` + `durationMs` on a
   *  successful upload. The parent embeds them inside an
   *  `InnerType.VOICE_NOTE` payload. */
  readonly onSent: (outcome: Extract<VoiceNoteOutcome, { kind: 'ok' }>) => void;
  /** Optional override for the `VoiceNoteRecorder` instance. Tests
   *  inject a fake; production passes nothing and lets the
   *  component construct its own from `recorderOptions`. */
  readonly recorder?: VoiceNoteRecorder;
  /** Optional label override; defaults to `RECORDING_LABEL`. */
  readonly label?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

type ViewState =
  | { kind: 'idle' }
  | { kind: 'recording'; elapsedMs: number }
  | { kind: 'finalizing' }
  | { kind: 'permission_required' }
  | { kind: 'failed'; details: string };

export function VoiceNoteButton(props: VoiceNoteButtonProps): JSX.Element {
  // The recorder instance is held in a ref so it survives across
  // renders. We only construct it once, lazily, on the first
  // render — `useRef`'s initialiser runs once per component
  // lifetime.
  const recorderRef = useRef<VoiceNoteRecorder | null>(null);
  if (recorderRef.current === null) {
    recorderRef.current =
      props.recorder ?? new VoiceNoteRecorder(props.recorderOptions);
  }
  const recorder = recorderRef.current;

  const [view, setView] = useState<ViewState>({ kind: 'idle' });
  // Track whether a Space keypress is currently held so the
  // up-event finalises only the matching down-event (not e.g. a
  // Tab-into focus).
  const spaceHeldRef = useRef<boolean>(false);

  // Subscribe to recorder status updates so the elapsed time
  // ticks visibly while recording.
  useEffect(() => {
    const off = recorder.subscribe((status: VoiceNoteStatus): void => {
      if (status.kind === 'recording') {
        setView({ kind: 'recording', elapsedMs: status.elapsedMs });
      } else if (status.kind === 'finalizing' || status.kind === 'uploading') {
        setView({ kind: 'finalizing' });
      } else if (status.kind === 'idle') {
        // Don't drop a `failed` / `permission_required` view back
        // to idle here — the user must dismiss explicitly. Only
        // step back to idle from the `recording` / `finalizing`
        // branches.
        setView((prev) => {
          if (prev.kind === 'recording' || prev.kind === 'finalizing') {
            return { kind: 'idle' };
          }
          return prev;
        });
      }
    });
    return off;
  }, [recorder]);

  // Cleanup: cancel any in-flight recording on unmount.
  useEffect(() => {
    return (): void => {
      recorder.cancel();
    };
  }, [recorder]);

  const beginRecording = useCallback(async (): Promise<void> => {
    if (recorder.isRecording()) return;
    setView({ kind: 'recording', elapsedMs: 0 });
    const result = await recorder.start();
    if (result.kind === 'permission_denied') {
      // Req 5.7: surface the prompt and DO NOT begin recording.
      setView({ kind: 'permission_required' });
      return;
    }
    if (result.kind === 'unsupported') {
      setView({
        kind: 'failed',
        details: 'voice notes are not supported in this browser',
      });
      return;
    }
    // 'started' — the status subscription will keep `elapsedMs` updated.
  }, [recorder]);

  const finalize = useCallback(async (): Promise<void> => {
    if (!recorder.isRecording()) return;
    const outcome = await recorder.stop();
    if (outcome.kind === 'ok') {
      setView({ kind: 'idle' });
      props.onSent(outcome);
      return;
    }
    if (outcome.kind === 'discarded') {
      // Short release (req 5.8): silently return to idle.
      setView({ kind: 'idle' });
      return;
    }
    if (outcome.kind === 'permission_denied') {
      setView({ kind: 'permission_required' });
      return;
    }
    // 'failed': req 5.9 — caller must NOT send any envelope. We
    // surface the failure inside the button's own UI; the parent's
    // composer state machine is unaffected.
    setView({ kind: 'failed', details: outcome.details });
  }, [recorder, props]);

  const handlePointerDown = useCallback(
    (ev: PointerEvent<HTMLButtonElement>): void => {
      // Only react to primary button + capture the pointer so a
      // pointerup outside the button still finalises the recording.
      if (ev.button !== 0 && ev.pointerType !== 'touch' && ev.pointerType !== 'pen') {
        return;
      }
      try {
        ev.currentTarget.setPointerCapture(ev.pointerId);
      } catch {
        // setPointerCapture isn't critical — older browsers
        // ignore. The pointerup handler also listens on `window`
        // via `onPointerUp` below.
      }
      void beginRecording();
    },
    [beginRecording],
  );

  const handlePointerUp = useCallback(
    (ev: PointerEvent<HTMLButtonElement>): void => {
      try {
        ev.currentTarget.releasePointerCapture(ev.pointerId);
      } catch {
        // Same as above.
      }
      void finalize();
    },
    [finalize],
  );

  const handlePointerCancel = useCallback(
    (_ev: PointerEvent<HTMLButtonElement>): void => {
      // Treat a pointercancel (e.g. browser interrupted the
      // gesture) the same as a release — we want to finalise
      // gracefully rather than leaving the recorder in `recording`.
      void finalize();
    },
    [finalize],
  );

  const handleKeyDown = useCallback(
    (ev: KeyboardEvent<HTMLButtonElement>): void => {
      if (ev.repeat) return; // ignore key auto-repeat
      if (ev.key === ' ' || ev.key === 'Enter') {
        ev.preventDefault();
        spaceHeldRef.current = true;
        void beginRecording();
      }
    },
    [beginRecording],
  );

  const handleKeyUp = useCallback(
    (ev: KeyboardEvent<HTMLButtonElement>): void => {
      if (ev.key === ' ' || ev.key === 'Enter') {
        if (!spaceHeldRef.current) return;
        spaceHeldRef.current = false;
        ev.preventDefault();
        void finalize();
      }
    },
    [finalize],
  );

  const handleBlur = useCallback((): void => {
    if (recorder.isRecording()) {
      void finalize();
    }
  }, [recorder, finalize]);

  const dismissError = useCallback((): void => {
    setView({ kind: 'idle' });
  }, []);

  // Render the elapsed-seconds counter while recording.
  const elapsedSeconds =
    view.kind === 'recording' ? Math.floor(view.elapsedMs / 1000) : 0;

  const isRecording = view.kind === 'recording';
  const isFinalizing = view.kind === 'finalizing';
  const buttonLabel =
    isRecording ? RECORDING_ACTIVE_LABEL : (props.label ?? RECORDING_LABEL);

  return (
    <div data-testid="voice-note-button-wrap">
      <button
        type="button"
        data-testid="voice-note-button"
        aria-pressed={isRecording}
        aria-busy={isFinalizing}
        aria-label={buttonLabel}
        disabled={isFinalizing}
        onPointerDown={handlePointerDown}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerCancel}
        onKeyDown={handleKeyDown}
        onKeyUp={handleKeyUp}
        onBlur={handleBlur}
      >
        {isRecording ? (
          <span data-testid="voice-note-elapsed">
            ● {elapsedSeconds}s
          </span>
        ) : (
          <span aria-hidden="true">🎤</span>
        )}
      </button>
      {/* Live region for the recording status + permission /
          failure prompts. We use `role="status"` for the elapsed
          counter (polite) and `role="alert"` for permission /
          failure messages (assertive). */}
      <span
        data-testid="voice-note-status"
        role="status"
        aria-live="polite"
      >
        {isRecording
          ? `Recording: ${elapsedSeconds}s`
          : isFinalizing
            ? 'Sending voice note…'
            : ''}
      </span>
      {view.kind === 'permission_required' ? (
        <div
          data-testid="voice-note-permission-required"
          role="alert"
        >
          {PERMISSION_REQUIRED_TEXT}
          <button
            type="button"
            data-testid="voice-note-permission-dismiss"
            onClick={dismissError}
          >
            Dismiss
          </button>
        </div>
      ) : null}
      {view.kind === 'failed' ? (
        <div data-testid="voice-note-failed" role="alert">
          {VOICE_NOTE_FAILED_TEXT}
          <span data-testid="voice-note-failed-details">{view.details}</span>
          <button
            type="button"
            data-testid="voice-note-failed-dismiss"
            onClick={dismissError}
          >
            Dismiss
          </button>
        </div>
      ) : null}
    </div>
  );
}

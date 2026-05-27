// Public surface of the DM feature module (task 3.8 + 5.4).

export { Composer } from './Composer.js';
export type { ComposerProps } from './Composer.js';

export {
  VoiceNoteRecorder,
  MAX_RECORDING_MS,
  MIN_HOLD_MS,
  UPLOAD_MAX_RETRIES,
  UPLOAD_BACKOFF_BASE_MS,
  PREFERRED_MIME,
  type VoiceNoteOutcome,
  type VoiceNoteRecorderOptions,
  type VoiceNoteStatus,
  type VoiceNoteStatusListener,
} from './voice-note.js';

export {
  VoiceNoteButton,
  PERMISSION_REQUIRED_TEXT,
  VOICE_NOTE_FAILED_TEXT,
  RECORDING_LABEL,
  RECORDING_ACTIVE_LABEL,
  type VoiceNoteButtonProps,
} from './VoiceNoteButton.js';

export {
  VoiceNotePlayer,
  VOICE_NOTE_DECRYPT_FAILED_TEXT,
  VOICE_NOTE_NOT_FOUND_TEXT,
  type VoiceNotePlayerProps,
} from './VoiceNotePlayer.js';

export { ThreadList } from './ThreadList.js';
export type { ThreadListProps } from './ThreadList.js';

export { ThreadView } from './ThreadView.js';
export type { ThreadViewProps } from './ThreadView.js';

export {
  StateTicker,
  TICKER_GLYPH,
  TICKER_LABEL,
  TICKER_CLASS,
} from './StateTicker.js';
export type { StateTickerProps } from './StateTicker.js';

export { DmController } from './controller.js';
export type {
  DmChange,
  DmChangeListener,
  DmControllerOptions,
  RecipientDeviceIdsResolver,
  SenderUserIdResolver,
  SessionIdResolver,
} from './controller.js';

export {
  decodeWireCiphertext,
  encodeWireCiphertext,
  TAMPERED_PLACEHOLDER_TEXT,
} from './wire.js';

export { useDmThreads, useDmMessages } from './useDmStore.js';

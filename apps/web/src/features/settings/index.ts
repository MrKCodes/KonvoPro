// Public surface of the settings feature module.
//
// Re-exports the top-level Settings screen, the per-peer
// Safety_Number screen (mounted by the DM thread header per
// requirement 15.2), the theme-toggle widget (Requirement 15.4),
// and the key-backup primitives so callers
// `import { … } from '../features/settings'`.

export { Settings } from './Settings.js';
export type { SettingsProps } from './Settings.js';

export { SafetyNumberScreen } from './SafetyNumberScreen.js';
export type { SafetyNumberScreenProps } from './SafetyNumberScreen.js';

export {
  PushToggle,
  defaultPushSubscriber,
  TOGGLE_STORAGE_KEY as PUSH_TOGGLE_STORAGE_KEY,
  SUBSCRIPTION_ID_KEY as PUSH_SUBSCRIPTION_ID_KEY,
} from './PushToggle.js';
export type {
  PushToggleProps,
  PushSubscriber,
  PushApiClient,
  PushSubscriptionShape,
} from './PushToggle.js';

export { ThemeToggle } from './ThemeToggle.js';
export type { ThemeToggleProps } from './ThemeToggle.js';

export {
  exportEncryptedBackup,
  importEncryptedBackup,
  backupBlob,
  PassphraseValidationError,
  BackupFormatError,
  BackupDecryptError,
} from './key-backup.js';
export type {
  BackupOptions,
  PassphraseValidationCode,
  RestoredBackup,
  RestoredIdentity,
  RestoredPreKey,
  RestoredSession,
} from './key-backup.js';

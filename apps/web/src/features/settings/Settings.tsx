// apps/web/src/features/settings/Settings.tsx
//
// Settings landing screen (task 9.5 — UX wiring for requirements
// 15.1, 15.5, 15.6, 15.7).
//
// Sections rendered:
//
//   1. Devices — re-uses `DeviceList` from `../devices`. The
//      `DeviceList` component already realises requirement 15.1
//      (per-row `name`, `lastSeenTime` ISO-8601 UTC display,
//      revoke control with confirmation modal). We mount it
//      verbatim here so Settings is a single entry point per
//      requirement 15.1.
//
//   2. Key backup — exposes the "Export keys backup" affordance
//      from requirements 15.5 / 15.6 / 15.7. Clicking the button
//      opens a modal with a passphrase input. On submit we run
//      `exportEncryptedBackup` and surface a download link
//      pointing at a `Blob` URL. Validation errors (empty / < 8
//      / > 128 chars) render inline and the export does not run.
//
// What this screen explicitly does NOT do:
//   - Web-Push toggle (requirement 15.3) — lands in task 9.3 / 9.4
//     wiring.
//   - Per-peer Safety_Number list — requirement 15.2 places the
//     entry point on the DM thread header (task 4.8). The
//     `SafetyNumberScreen` component is exported from this
//     feature so the DM thread header can route into it.
//
// Theme toggle (requirement 15.4) is mounted as the "Appearance"
// section via {@link ThemeToggle} — see task 9.2.

import { useState } from 'react';

import { DeviceList } from '../devices/index.js';

import {
  backupBlob,
  exportEncryptedBackup,
  PassphraseValidationError,
  type PassphraseValidationCode,
} from './key-backup.js';
import { ThemeToggle } from './ThemeToggle.js';

export interface SettingsProps {
  /** Test override for the export function. Defaults to the
   *  production `exportEncryptedBackup` which reads from the
   *  shared Dexie singleton. */
  readonly exportFn?: typeof exportEncryptedBackup;
}

interface ExportPromptState {
  readonly kind: 'closed' | 'open' | 'busy' | 'error' | 'success';
  readonly errorCode?: PassphraseValidationCode;
  readonly errorMessage?: string;
  readonly downloadUrl?: string;
  readonly downloadName?: string;
}

const EXPORT_CLOSED: ExportPromptState = { kind: 'closed' };

export function Settings(props: SettingsProps): JSX.Element {
  const exportFn = props.exportFn ?? exportEncryptedBackup;

  const [exportState, setExportState] = useState<ExportPromptState>(EXPORT_CLOSED);
  const [passphrase, setPassphrase] = useState<string>('');
  const [confirmPassphrase, setConfirmPassphrase] = useState<string>('');

  function openExportPrompt(): void {
    setPassphrase('');
    setConfirmPassphrase('');
    setExportState({ kind: 'open' });
  }

  function closeExportPrompt(): void {
    // Revoke any existing object URL so the browser can free the
    // backing Blob. Object URLs leak by default until revoked.
    if (exportState.downloadUrl !== undefined) {
      try {
        URL.revokeObjectURL(exportState.downloadUrl);
      } catch {
        // Ignore — best effort cleanup.
      }
    }
    setExportState(EXPORT_CLOSED);
    setPassphrase('');
    setConfirmPassphrase('');
  }

  async function handleExportSubmit(): Promise<void> {
    if (passphrase !== confirmPassphrase) {
      setExportState({
        kind: 'error',
        errorMessage:
          'The two passphrases do not match. Please re-enter the same passphrase in both fields.',
      });
      return;
    }
    setExportState({ kind: 'busy' });
    try {
      const bytes = await exportFn(passphrase);
      const blob = backupBlob(bytes);
      const url = URL.createObjectURL(blob);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      setExportState({
        kind: 'success',
        downloadUrl: url,
        downloadName: `konvo-keys-${stamp}.bin`,
      });
    } catch (err) {
      if (err instanceof PassphraseValidationError) {
        setExportState({
          kind: 'error',
          errorCode: err.code,
          errorMessage: passphraseValidationMessage(err.code),
        });
        return;
      }
      setExportState({
        kind: 'error',
        errorMessage:
          err instanceof Error
            ? `Export failed: ${err.message}`
            : 'Export failed. Please try again.',
      });
    }
  }

  return (
    <main aria-labelledby="settings-heading" data-testid="settings-screen">
      <h1 id="settings-heading">Settings</h1>

      <section aria-labelledby="settings-devices-heading">
        <h2 id="settings-devices-heading">Devices</h2>
        <DeviceList />
      </section>

      <section aria-labelledby="settings-appearance-heading">
        <h2 id="settings-appearance-heading">Appearance</h2>
        <p>
          Choose between light and dark themes. Your choice is saved
          on this device and applied across browser sessions.
        </p>
        <ThemeToggle />
      </section>

      <section aria-labelledby="settings-backup-heading">
        <h2 id="settings-backup-heading">Key backup</h2>
        <p>
          Export an encrypted backup of your identity, prekeys, and
          ratchet sessions. Keep the backup file and your passphrase
          safe — together they let you recover your end-to-end
          encrypted history on a new browser.
        </p>
        <button
          type="button"
          onClick={openExportPrompt}
          data-testid="export-keys-button"
        >
          Export keys backup
        </button>
      </section>

      {exportState.kind !== 'closed' ? (
        <ExportPromptDialog
          state={exportState}
          passphrase={passphrase}
          confirmPassphrase={confirmPassphrase}
          onPassphraseChange={setPassphrase}
          onConfirmPassphraseChange={setConfirmPassphrase}
          onSubmit={() => void handleExportSubmit()}
          onClose={closeExportPrompt}
        />
      ) : null}
    </main>
  );
}

interface ExportPromptDialogProps {
  readonly state: ExportPromptState;
  readonly passphrase: string;
  readonly confirmPassphrase: string;
  readonly onPassphraseChange: (v: string) => void;
  readonly onConfirmPassphraseChange: (v: string) => void;
  readonly onSubmit: () => void;
  readonly onClose: () => void;
}

function ExportPromptDialog(props: ExportPromptDialogProps): JSX.Element {
  const busy = props.state.kind === 'busy';
  // Disable submit when either field is empty OR the lengths
  // are out of policy. The actual export call still runs full
  // validation, but the button-disabled UX prevents the user
  // from triggering an obvious-bad submission.
  const lengthOk =
    props.passphrase.length >= 8 && props.passphrase.length <= 128;
  const submitDisabled = busy || !lengthOk;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="export-prompt-heading"
      data-testid="export-prompt-dialog"
    >
      <h2 id="export-prompt-heading">Export keys backup</h2>

      {props.state.kind !== 'success' ? (
        <>
          <p>
            Choose a passphrase between 8 and 128 characters. This
            passphrase encrypts the backup; without it the backup
            cannot be decrypted.
          </p>

          <label>
            <span>Passphrase</span>
            <input
              type="password"
              autoComplete="new-password"
              value={props.passphrase}
              onChange={(e) => props.onPassphraseChange(e.currentTarget.value)}
              minLength={8}
              maxLength={128}
              data-testid="export-passphrase-input"
              disabled={busy}
            />
          </label>

          <label>
            <span>Confirm passphrase</span>
            <input
              type="password"
              autoComplete="new-password"
              value={props.confirmPassphrase}
              onChange={(e) =>
                props.onConfirmPassphraseChange(e.currentTarget.value)
              }
              minLength={8}
              maxLength={128}
              data-testid="export-passphrase-confirm-input"
              disabled={busy}
            />
          </label>

          {props.state.kind === 'error' && props.state.errorMessage !== undefined ? (
            <p role="alert" data-testid="export-error-message">
              {props.state.errorMessage}
            </p>
          ) : null}

          <button
            type="button"
            onClick={props.onSubmit}
            disabled={submitDisabled}
            data-testid="export-submit-button"
          >
            {busy ? 'Encrypting…' : 'Export'}
          </button>
          <button
            type="button"
            onClick={props.onClose}
            disabled={busy}
            data-testid="export-cancel-button"
          >
            Cancel
          </button>
        </>
      ) : null}

      {props.state.kind === 'success' &&
      props.state.downloadUrl !== undefined &&
      props.state.downloadName !== undefined ? (
        <>
          <p data-testid="export-success-message">
            Your backup is ready. Download the file and store it
            somewhere safe.
          </p>
          <a
            href={props.state.downloadUrl}
            download={props.state.downloadName}
            data-testid="export-download-link"
          >
            Download backup
          </a>
          <button
            type="button"
            onClick={props.onClose}
            data-testid="export-close-button"
          >
            Done
          </button>
        </>
      ) : null}
    </div>
  );
}

function passphraseValidationMessage(code: PassphraseValidationCode): string {
  switch (code) {
    case 'passphrase_empty':
      return 'Please enter a passphrase.';
    case 'passphrase_too_short':
      return 'Passphrase must be at least 8 characters.';
    case 'passphrase_too_long':
      return 'Passphrase must be 128 characters or fewer.';
  }
}

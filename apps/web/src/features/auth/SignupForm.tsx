// apps/web/src/features/auth/SignupForm.tsx
//
// Signup form (task 2.10).
//
// Realizes the UX contract for Requirement 16.1, 16.2, and the
// signup-side of Requirement 1.10:
//
//   - Always renders the recovery-loss notice + a confirm checkbox
//     (Requirement 16.1).
//   - The submit button stays disabled, AND a separate validation
//     message is shown, until the checkbox is checked (Requirement
//     16.2). We enforce the disabled-state AND the validation message
//     so a future refactor that loosens one still satisfies the
//     other.
//   - Handle / password validation mirrors the server-side regex
//     (Requirements 1.1, 1.13).
//   - On success, redirects to the login screen (the parent screen
//     handles routing via the `onSignupSuccess` prop). We
//     deliberately do NOT auto-login because the design's onboarding
//     copy expects the user to consciously log in once after signup.

import { useState, type FormEvent } from 'react';

import { authApi, AuthApiError, type AuthApiClient } from './api.js';
import { validateSignup, type ValidResult } from './validate.js';

/** Hard-coded notice copy from Requirement 1.10 / 16.1. The string is
 *  kept in source rather than i18n'd because the test asserts on a
 *  stable substring; once an i18n layer lands the tests assert on the
 *  message id instead. */
export const RECOVERY_LOSS_NOTICE =
  'There is no email recovery — losing all your devices means losing your end-to-end encrypted history.';

export interface SignupFormProps {
  /** Optional API client override; defaults to the singleton. Tests
   *  inject a stub. */
  readonly api?: AuthApiClient;
  /** Called with the new user id once the server confirms creation.
   *  Parent owns navigation; this component never calls
   *  `window.location` directly. */
  readonly onSignupSuccess?: (result: { userId: string; handle: string }) => void;
}

interface FormStatus {
  readonly kind: 'idle' | 'submitting' | 'success' | 'error';
  readonly message?: string;
}

const IDLE: FormStatus = { kind: 'idle' };

export function SignupForm(props: SignupFormProps): JSX.Element {
  const apiClient = props.api ?? authApi;
  const [handle, setHandle] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryLossConfirmed, setRecoveryLossConfirmed] = useState(false);
  const [validationError, setValidationError] = useState<ValidResult | null>(null);
  const [status, setStatus] = useState<FormStatus>(IDLE);

  // The button is disabled iff ANY of the validation predicates fails.
  // We re-run the aggregate validator inline (rather than memoising) so
  // re-typing keeps the disabled state in sync without extra wiring.
  const liveCheck: ValidResult = validateSignup({
    handle,
    password,
    recoveryLossConfirmed,
  });
  const submitDisabled =
    !liveCheck.valid || status.kind === 'submitting';

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const check = validateSignup({ handle, password, recoveryLossConfirmed });
    if (!check.valid) {
      // Defense in depth: the button SHOULD be disabled in this state,
      // but a manual `requestSubmit()` from devtools / a synthetic event
      // could bypass that. The validation message must surface either
      // way (Requirement 16.2).
      setValidationError(check);
      return;
    }
    setValidationError(null);
    setStatus({ kind: 'submitting' });
    try {
      const result = await apiClient.signup({ handle, password });
      setStatus({
        kind: 'success',
        message: 'Account created. You can now log in.',
      });
      props.onSignupSuccess?.({ userId: result.userId, handle });
    } catch (err) {
      setStatus({
        kind: 'error',
        message: errorToMessage(err),
      });
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      aria-labelledby="signup-form-heading"
      noValidate
    >
      <h1 id="signup-form-heading">Create your Konvo account</h1>

      <label>
        <span>Handle</span>
        <input
          type="text"
          name="handle"
          autoComplete="username"
          minLength={3}
          maxLength={32}
          value={handle}
          onChange={(e) => setHandle(e.currentTarget.value)}
          aria-describedby="signup-handle-help"
          required
        />
      </label>
      <p id="signup-handle-help">3–32 lowercase letters, digits, or underscores.</p>

      <label>
        <span>Password</span>
        <input
          type="password"
          name="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={128}
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          aria-describedby="signup-password-help"
          required
        />
      </label>
      <p id="signup-password-help">12–128 characters.</p>

      {/* Recovery-loss notice + checkbox (Requirements 16.1, 16.2). The
          notice text is rendered next to the checkbox so screen readers
          group them via the implicit label. */}
      <fieldset aria-labelledby="recovery-loss-legend">
        <legend id="recovery-loss-legend">Privacy notice</legend>
        <p>{RECOVERY_LOSS_NOTICE}</p>
        <label>
          <input
            type="checkbox"
            name="recoveryLossConfirmed"
            checked={recoveryLossConfirmed}
            onChange={(e) => setRecoveryLossConfirmed(e.currentTarget.checked)}
            data-testid="recovery-loss-checkbox"
          />
          <span>
            I understand that there is no email recovery and that losing
            all my devices means losing my E2EE history.
          </span>
        </label>
      </fieldset>

      <button type="submit" disabled={submitDisabled}>
        {status.kind === 'submitting' ? 'Creating account…' : 'Create account'}
      </button>

      {/* Validation / status messages — keep separate `role` regions so
          screen readers don't conflate "form invalid" with "server
          rejected". */}
      {validationError !== null && !validationError.valid ? (
        <p role="alert" data-testid="signup-validation-error">
          {validationError.message}
        </p>
      ) : null}
      {status.kind === 'error' && status.message !== undefined ? (
        <p role="alert" data-testid="signup-status-error">
          {status.message}
        </p>
      ) : null}
      {status.kind === 'success' && status.message !== undefined ? (
        <p role="status" data-testid="signup-status-success">
          {status.message}
        </p>
      ) : null}
    </form>
  );
}

function errorToMessage(err: unknown): string {
  if (err instanceof AuthApiError) {
    if (err.kind === 'http' && err.status === 409) {
      return 'That handle is already taken. Please choose another.';
    }
    if (err.kind === 'http' && err.status === 400) {
      return 'Please check your handle and password and try again.';
    }
    if (err.kind === 'http' && err.status === 429) {
      return 'Too many signup attempts. Please wait a minute and try again.';
    }
    if (err.kind === 'network') {
      return 'Could not reach the Konvo server. Please check your connection.';
    }
    return 'Signup failed. Please try again.';
  }
  return 'Signup failed. Please try again.';
}

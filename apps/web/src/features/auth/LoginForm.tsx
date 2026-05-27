// apps/web/src/features/auth/LoginForm.tsx
//
// Login form (task 2.10).
//
// Realizes Requirement 1.3 / 1.4 on the client side:
//   - Submits handle + password (and optional 6-digit TOTP) to
//     `/auth/login`.
//   - On success, the auth store now holds the access token in
//     memory only (Requirement 1.11). The cookie-borne refresh token
//     is set by the server with `Secure; HttpOnly; SameSite=Lax`.
//   - On failure, surfaces the server's non-disclosing
//     `invalid_credentials` body as a single message ("Invalid handle,
//     password, or TOTP code.") — we deliberately echo the
//     non-disclosing posture (Requirement 1.5).
//
// After login, the parent screen is responsible for routing into the
// device-enrollment flow (`enrollDeviceIfNeeded`) and then to the
// app's home view. We expose `onLoginSuccess` so the parent can
// orchestrate that without this component knowing about routing.

import { useState, type FormEvent } from 'react';

import {
  authApi,
  AuthApiError,
  type AuthApiClient,
} from './api.js';
import { validateLogin, type ValidResult } from './validate.js';
import { readStoredDeviceId } from '../devices/enrollment.js';

export interface LoginFormProps {
  readonly api?: AuthApiClient;
  /** Called once the access token is in memory. Receives the user id +
   *  handle so the parent can navigate or trigger enrollment. */
  readonly onLoginSuccess?: (result: { userId: string; handle: string }) => void;
}

interface FormStatus {
  readonly kind: 'idle' | 'submitting' | 'error';
  readonly message?: string;
}

const IDLE: FormStatus = { kind: 'idle' };

export function LoginForm(props: LoginFormProps): JSX.Element {
  const apiClient = props.api ?? authApi;
  const [handle, setHandle] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [validationError, setValidationError] = useState<ValidResult | null>(null);
  const [status, setStatus] = useState<FormStatus>(IDLE);

  const liveCheck: ValidResult = validateLogin({
    handle,
    password,
    ...(totp.length > 0 ? { totp } : {}),
  });
  const submitDisabled = !liveCheck.valid || status.kind === 'submitting';

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const check = validateLogin({
      handle,
      password,
      ...(totp.length > 0 ? { totp } : {}),
    });
    if (!check.valid) {
      setValidationError(check);
      return;
    }
    setValidationError(null);
    setStatus({ kind: 'submitting' });
    try {
      // If we already have a deviceId from a prior session, send it so
      // the access token's `did` claim is bound from the start
      // (otherwise the server signs with `did = ''` and the SPA refreshes
      // post-enrollment to upgrade the token; see `routes/auth.ts`
      // header for the Phase-1 caveat).
      const cachedDeviceId = readStoredDeviceId() ?? undefined;
      const res = await apiClient.login({
        handle,
        password,
        // Only include `totp` when present; the schema rejects empty
        // strings even though the regex would.
        ...(totp.length > 0 ? { totp } : {}),
        ...(cachedDeviceId !== undefined ? { deviceId: cachedDeviceId } : {}),
      });
      setStatus(IDLE);
      props.onLoginSuccess?.({ userId: res.user.id, handle: res.user.handle });
    } catch (err) {
      setStatus({ kind: 'error', message: errorToMessage(err) });
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      aria-labelledby="login-form-heading"
      noValidate
    >
      <h1 id="login-form-heading">Log in to Konvo</h1>

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
          required
        />
      </label>

      <label>
        <span>Password</span>
        <input
          type="password"
          name="password"
          autoComplete="current-password"
          minLength={12}
          maxLength={128}
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          required
        />
      </label>

      <label>
        <span>TOTP (if enabled)</span>
        <input
          type="text"
          name="totp"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          maxLength={6}
          value={totp}
          onChange={(e) => setTotp(e.currentTarget.value)}
        />
      </label>

      <button type="submit" disabled={submitDisabled}>
        {status.kind === 'submitting' ? 'Logging in…' : 'Log in'}
      </button>

      {validationError !== null && !validationError.valid ? (
        <p role="alert" data-testid="login-validation-error">
          {validationError.message}
        </p>
      ) : null}
      {status.kind === 'error' && status.message !== undefined ? (
        <p role="alert" data-testid="login-status-error">
          {status.message}
        </p>
      ) : null}
    </form>
  );
}

function errorToMessage(err: unknown): string {
  if (err instanceof AuthApiError) {
    if (err.kind === 'http' && (err.status === 401 || err.status === 400)) {
      // Mirror the server's non-disclosing posture (Requirement 1.5).
      return 'Invalid handle, password, or TOTP code.';
    }
    if (err.kind === 'http' && err.status === 429) {
      return 'Too many login attempts. Please wait a minute and try again.';
    }
    if (err.kind === 'network') {
      return 'Could not reach the Konvo server. Please check your connection.';
    }
    return 'Login failed. Please try again.';
  }
  return 'Login failed. Please try again.';
}

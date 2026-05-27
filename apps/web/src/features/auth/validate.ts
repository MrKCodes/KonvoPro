// apps/web/src/features/auth/validate.ts
//
// Pure validators for the signup / login forms. Mirrors the server-side
// regexes in `apps/api/src/routes/auth.ts` so the client can reject
// obviously bad input before round-tripping.
//
// Validators are pure functions returning a structured result rather
// than throwing — the form components map a `valid: false` result to
// inline error text, and the test suite asserts on the `reason` strings
// without parsing thrown messages.
//
// Realizes:
//   - Requirement 1.1: handle `^[a-z0-9_]{3,32}$`, password 12..128.
//   - Requirement 1.13: signup rejects passwords outside the 12..128
//     range with a validation message (mirrors server 400 path).
//   - Requirement 16.1, 16.2: signup blocked until the recovery-loss
//     checkbox is selected; missing checkbox surfaces a validation
//     message indicating the confirmation is required.

/** Successful validation. */
export interface ValidOk {
  readonly valid: true;
}

/** Failed validation with a stable machine-readable reason and a
 *  human-readable message suitable for inline error text. */
export interface ValidErr {
  readonly valid: false;
  readonly reason: ValidationReason;
  readonly message: string;
}

export type ValidResult = ValidOk | ValidErr;

export type ValidationReason =
  | 'handle_required'
  | 'handle_invalid'
  | 'password_required'
  | 'password_too_short'
  | 'password_too_long'
  | 'recovery_loss_unconfirmed'
  | 'totp_invalid';

const HANDLE_REGEX = /^[a-z0-9_]{3,32}$/;

const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;

const TOTP_REGEX = /^[0-9]{6}$/;

const ok: ValidOk = { valid: true };

/** Validate a handle. Mirrors the server-side regex in
 *  `apps/api/src/routes/auth.ts SignupBodySchema`. */
export function validateHandle(handle: string): ValidResult {
  if (handle.length === 0) {
    return {
      valid: false,
      reason: 'handle_required',
      message: 'Handle is required.',
    };
  }
  if (!HANDLE_REGEX.test(handle)) {
    return {
      valid: false,
      reason: 'handle_invalid',
      message:
        'Handle must be 3–32 lowercase letters, digits, or underscores.',
    };
  }
  return ok;
}

/** Validate a password against the server's 12..128 rule. */
export function validatePassword(password: string): ValidResult {
  if (password.length === 0) {
    return {
      valid: false,
      reason: 'password_required',
      message: 'Password is required.',
    };
  }
  if (password.length < PASSWORD_MIN) {
    return {
      valid: false,
      reason: 'password_too_short',
      message: `Password must be at least ${PASSWORD_MIN} characters.`,
    };
  }
  if (password.length > PASSWORD_MAX) {
    return {
      valid: false,
      reason: 'password_too_long',
      message: `Password must be at most ${PASSWORD_MAX} characters.`,
    };
  }
  return ok;
}

/** Validate the optional 6-digit TOTP code on login. Empty string is
 *  treated as "not supplied" (the server allows that when 2FA is not
 *  enabled). A non-empty value MUST match exactly 6 digits. */
export function validateTotp(totp: string): ValidResult {
  if (totp.length === 0) {
    return ok;
  }
  if (!TOTP_REGEX.test(totp)) {
    return {
      valid: false,
      reason: 'totp_invalid',
      message: 'TOTP must be exactly 6 digits.',
    };
  }
  return ok;
}

/** Aggregate signup validation. Returns the first failure encountered,
 *  in input order, so the form's primary error region only shows one
 *  message at a time.
 *
 *  Per Requirement 16.1 / 16.2 the recovery-loss checkbox MUST be
 *  selected before the form can submit. We surface that as the LAST
 *  failure so handle / password issues get reported first; that order
 *  matches the form's visual top-to-bottom flow. */
export function validateSignup(input: {
  readonly handle: string;
  readonly password: string;
  readonly recoveryLossConfirmed: boolean;
}): ValidResult {
  const h = validateHandle(input.handle);
  if (!h.valid) return h;
  const p = validatePassword(input.password);
  if (!p.valid) return p;
  if (!input.recoveryLossConfirmed) {
    return {
      valid: false,
      reason: 'recovery_loss_unconfirmed',
      message:
        'Please confirm you understand that losing all your devices means losing your encrypted history.',
    };
  }
  return ok;
}

/** Aggregate login validation. */
export function validateLogin(input: {
  readonly handle: string;
  readonly password: string;
  readonly totp?: string;
}): ValidResult {
  const h = validateHandle(input.handle);
  if (!h.valid) return h;
  const p = validatePassword(input.password);
  if (!p.valid) return p;
  if (input.totp !== undefined) {
    const t = validateTotp(input.totp);
    if (!t.valid) return t;
  }
  return ok;
}

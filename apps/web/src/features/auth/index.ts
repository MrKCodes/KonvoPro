// Public surface of the auth feature module.
//
// Re-exports the form components, the in-memory store, the REST
// client, and the validators so consumers `import { … } from
// '../features/auth'` rather than reaching into individual files.

export { SignupForm, RECOVERY_LOSS_NOTICE } from './SignupForm.js';
export type { SignupFormProps } from './SignupForm.js';

export { LoginForm } from './LoginForm.js';
export type { LoginFormProps } from './LoginForm.js';

export {
  authActions,
  getAuthState,
  subscribeAuth,
  useAuthStore,
  __resetAuthStoreForTests,
  installPersistenceTripwire,
} from './store.js';
export type { AuthActions, AuthState, AuthUser } from './store.js';

export {
  AuthApiClient,
  AuthApiError,
  authApi,
} from './api.js';
export type {
  AuthApiClientOptions,
  AuthApiErrorKind,
} from './api.js';

export {
  validateHandle,
  validateLogin,
  validatePassword,
  validateSignup,
  validateTotp,
} from './validate.js';
export type {
  ValidErr,
  ValidOk,
  ValidResult,
  ValidationReason,
} from './validate.js';

export {
  OPK_POLL_INTERVAL_MS,
  OPK_TARGET,
  OPK_THRESHOLD,
  SIGNED_PREKEY_MAX_AGE_MS,
  LAST_ROTATED_STORAGE_KEY,
  checkAndReplenishOpks,
  checkAndRotateSignedPreKey,
  readLastRotatedAt,
  startOpkReplenishment,
  startPreKeyMaintenance,
  startSignedPreKeyRotation,
} from './opkReplenishment.js';
export type {
  OpkReplenishmentOptions,
  SignedPreKeyRotationOptions,
  StopFn,
} from './opkReplenishment.js';

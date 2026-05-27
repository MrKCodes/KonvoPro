// apps/web/src/app/screens/AuthScreen.tsx
//
// Hosts the existing SignupForm + LoginForm inside a single auth
// card with a segmented Login/Signup tab switcher. The forms own
// their own validation, error states, and store-write side effects
// — this wrapper only handles tab state and post-success
// navigation.

import { useState } from 'react';

import { LoginForm, SignupForm, authApi } from '../../features/auth/index.js';
import { enrollDeviceIfNeeded } from '../../features/devices/enrollment.js';
import { navigate } from '../router.js';

type Tab = 'login' | 'signup';

export interface AuthScreenProps {
  readonly initialTab?: Tab;
}

export function AuthScreen({ initialTab = 'login' }: AuthScreenProps): JSX.Element {
  const [tab, setTab] = useState<Tab>(initialTab);

  return (
    <main className="auth">
      <section className="auth__card" aria-label="Authentication">
        <h1>{tab === 'login' ? 'Sign in to Konvo' : 'Create your Konvo account'}</h1>
        <div className="auth__tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'login'}
            className="auth__tab"
            onClick={() => {
              setTab('login');
              navigate('/login');
            }}
          >
            Log in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'signup'}
            className="auth__tab"
            onClick={() => {
              setTab('signup');
              navigate('/signup');
            }}
          >
            Create account
          </button>
        </div>

        <div className="auth__form">
          {tab === 'login' ? (
            <LoginForm
              onLoginSuccess={async () => {
                // Best-effort device enrollment after a fresh login —
                // the function is idempotent and silently no-ops if
                // a wrapped identity already exists. After
                // enrollment, refresh the access token so the new
                // `did` claim lands in memory; without this step the
                // bearer token still carries `did=""` and any state-
                // changing API call (e.g. POST /rooms) is rejected
                // by the server's auth posture.
                try {
                  const result = await enrollDeviceIfNeeded();
                  await authApi.refresh(result.deviceId);
                } catch (err) {
                  console.warn('device-enrollment:', err);
                }
                navigate('/dm');
              }}
            />
          ) : (
            <SignupForm
              onSignupSuccess={() => {
                // Don't auto-login — the spec brief calls for the user
                // to consciously sign in once after signup.
                setTab('login');
                navigate('/login');
              }}
            />
          )}
        </div>

        <p className="auth__hint">
          Konvo is self-hosted. There is no email recovery — keep your
          devices.
        </p>
      </section>
    </main>
  );
}

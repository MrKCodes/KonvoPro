// apps/web/src/app/screens/PublicRoomScreen.tsx
//
// Wraps the existing public-read `PublicRoomRoute` in a small
// header so unauthenticated viewers always see a clear "this room
// is public" affordance and a sign-in CTA. Reachable without auth
// at /r/:slug (matching the API gateway's public route surface).

import { useAuthStore } from '../../features/auth/store.js';
import { PublicRoomRoute } from '../../features/broadcast/index.js';
import { navigate } from '../router.js';

export interface PublicRoomScreenProps {
  readonly slug: string;
}

export function PublicRoomScreen({ slug }: PublicRoomScreenProps): JSX.Element {
  const authed = useAuthStore((s) => s.user !== null);

  return (
    <main
      style={{
        minHeight: '100dvh',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--color-bg)',
      }}
    >
      <header
        className="detail-header"
        style={{
          background: 'var(--color-bg-elevated)',
        }}
      >
        <h2 style={{ margin: 0 }}>#{slug}</h2>
        <span className="pill pill--warn" aria-label="Public room">
          PUBLIC
        </span>
        <div style={{ marginLeft: 'auto' }}>
          {authed ? (
            <button type="button" onClick={() => navigate('/dm')}>
              Back to app
            </button>
          ) : (
            <button
              type="button"
              onClick={() => navigate('/login')}
              style={{
                background: 'var(--color-accent)',
                color: 'var(--color-accent-fg)',
                borderColor: 'var(--color-accent)',
              }}
            >
              Sign in to post
            </button>
          )}
        </div>
      </header>
      <div style={{ padding: 'var(--space-4)', flex: 1, overflow: 'auto' }}>
        <p
          style={{
            margin: '0 0 var(--space-4) 0',
            color: 'var(--color-fg-muted)',
            fontSize: 'var(--type-14)',
          }}
        >
          🛈 Posts in this room are public. They're signed by the
          author so you can verify who wrote them, but the body is
          plaintext — anyone with the link can read.
        </p>
        <PublicRoomRoute slug={slug} />
      </div>
    </main>
  );
}

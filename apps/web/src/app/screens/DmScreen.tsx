// apps/web/src/app/screens/DmScreen.tsx
//
// DM list + thread layout. The list pane exposes a "Start a
// conversation" form that resolves a typed handle via the
// directory endpoint and routes to /dm/:peerUserId. The detail
// pane renders the live thread (`ThreadView`) plus a composer
// (`Composer`) bound to the in-session `PlaintextDmController`.
//
// The thread + composer are functional today on the Phase-2
// plaintext transport. The libsignal layering lands on top of
// this exact UI without any structural change — only the
// controller swap.

import { useState, type FormEvent } from 'react';

import {
  AuthApiError,
  type UserDirectoryResponse,
} from '../../features/auth/index.js';
import { useDmHost } from '../../features/dm/DmHost.js';
import {
  Composer,
  ThreadList,
  ThreadView,
} from '../../features/dm/index.js';
import { LockIcon, MessagesIcon, PlusIcon } from '../Icons.js';
import { navigate, type Route } from '../router.js';

const HANDLE_RE = /^[a-z0-9_]{3,32}$/;

export interface DmScreenProps {
  readonly route: Route;
}

export function DmScreen({ route }: DmScreenProps): { list: JSX.Element; detail: JSX.Element } {
  const peer = route.kind === 'dm-thread' ? route.peerUserId : null;

  return {
    list: <DmListPane selectedThreadId={peer} />,
    detail: <DmDetailPane peerUserId={peer} />,
  };
}

interface DmListPaneProps {
  readonly selectedThreadId: string | null;
}

function DmListPane({ selectedThreadId }: DmListPaneProps): JSX.Element {
  const [composerOpen, setComposerOpen] = useState(false);
  const host = useDmHost();
  const ready = host.controller !== null;

  return (
    <section aria-label="Direct messages">
      <header className="list-header">
        <h2>Messages</h2>
        <button
          type="button"
          className="rail__btn"
          aria-label="New conversation"
          title="New conversation"
          onClick={() => setComposerOpen((v) => !v)}
          aria-expanded={composerOpen}
          aria-pressed={composerOpen}
          disabled={!ready}
        >
          <PlusIcon label="New conversation" />
        </button>
      </header>

      {composerOpen ? (
        <NewConversationForm onClose={() => setComposerOpen(false)} />
      ) : null}

      {host.controller !== null ? (
        <ThreadList
          controller={host.controller}
          selectedThreadId={selectedThreadId}
          onSelectThread={(peer) => navigate(`/dm/${encodeURIComponent(peer)}`)}
        />
      ) : (
        <div className="empty">
          <MessagesIcon size={32} />
          <h3>Connecting…</h3>
          <p>Establishing the secure channel.</p>
        </div>
      )}
    </section>
  );
}

interface DmDetailPaneProps {
  readonly peerUserId: string | null;
}

function DmDetailPane({ peerUserId }: DmDetailPaneProps): JSX.Element {
  const host = useDmHost();

  if (peerUserId === null) {
    return (
      <div className="empty" style={{ flex: 1 }}>
        <LockIcon size={32} />
        <h3>Select a conversation</h3>
        <p>
          Choose a thread on the left, or start a new one to send a
          message. Messages travel over a TLS-encrypted WebSocket
          to the server (Phase-2 plaintext-on-server transitional
          mode; libsignal E2EE layering ships in a follow-up).
        </p>
      </div>
    );
  }

  if (host.controller === null || host.senderDeviceId === null) {
    return (
      <div className="empty" style={{ flex: 1 }}>
        <LockIcon size={32} />
        <h3>Connecting…</h3>
        <p>Establishing the secure channel.</p>
      </div>
    );
  }

  return (
    <div
      className="detail-body"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-3)',
      }}
    >
      <header
        className="detail-header"
        style={{ position: 'static', borderBottom: 'none', padding: 0 }}
      >
        <h2 style={{ margin: 0, fontSize: 'var(--type-18)' }}>
          @{peerUserId}
        </h2>
        <span className="pill pill--warn" style={{ marginLeft: 'auto' }}>
          PHASE 2
        </span>
      </header>
      <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
        <ThreadView
          controller={host.controller}
          threadId={peerUserId}
          senderDeviceId={host.senderDeviceId}
        />
      </div>
      <Composer
        controller={host.controller}
        peerUserId={peerUserId}
      />
    </div>
  );
}

interface NewConversationFormProps {
  readonly onClose: () => void;
}

function NewConversationForm({ onClose }: NewConversationFormProps): JSX.Element {
  const [handle, setHandle] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const host = useDmHost();

  const handleOk = HANDLE_RE.test(handle);

  async function handleSubmit(ev: FormEvent<HTMLFormElement>): Promise<void> {
    ev.preventDefault();
    if (!handleOk || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const dto = await host.resolvePeerByHandle(handle);
      if (dto === null) {
        setError(`No user found for @${handle}.`);
        return;
      }
      if (dto.deviceIds.length === 0) {
        setError(
          `@${dto.handle} exists but has no active devices yet. Ask them to sign in once before messaging.`,
        );
        return;
      }
      onClose();
      navigate(`/dm/${encodeURIComponent(dto.userId)}`);
    } catch (err) {
      if (err instanceof AuthApiError) {
        setError(err.serverError ?? `HTTP ${err.status ?? '?'}`);
      } else {
        setError((err as Error).message);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={(ev) => void handleSubmit(ev)}
      data-testid="dm-new-conversation-form"
      style={{
        padding: 'var(--space-3) var(--space-4)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-3)',
        borderBottom: '1px solid var(--color-border)',
        background: 'var(--color-bg-elevated)',
      }}
    >
      <h3 style={{ margin: 0, fontSize: 'var(--type-16)' }}>Start a conversation</h3>
      <label>
        <span
          style={{
            display: 'block',
            fontSize: 'var(--type-12)',
            color: 'var(--color-fg-muted)',
            marginBottom: 'var(--space-1)',
          }}
        >
          Recipient handle (3–32 chars; lowercase, digits, underscores)
        </span>
        <input
          type="text"
          value={handle}
          onChange={(e) => setHandle(e.currentTarget.value.toLowerCase())}
          autoComplete="off"
          spellCheck={false}
          required
          minLength={3}
          maxLength={32}
          pattern="[a-z0-9_]{3,32}"
          placeholder="alice_local"
          data-testid="dm-new-handle-input"
          style={{ width: '100%', boxSizing: 'border-box' }}
        />
      </label>
      {error !== null ? (
        <p role="alert" data-testid="dm-new-error" style={{ margin: 0 }}>
          {error}
        </p>
      ) : null}
      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <button
          type="submit"
          disabled={!handleOk || submitting}
          data-testid="dm-new-submit"
          style={{
            background: 'var(--color-accent)',
            color: 'var(--color-accent-fg)',
            borderColor: 'var(--color-accent)',
            flex: 1,
          }}
        >
          {submitting ? 'Looking up…' : 'Start'}
        </button>
        <button
          type="button"
          onClick={onClose}
          data-testid="dm-new-cancel"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

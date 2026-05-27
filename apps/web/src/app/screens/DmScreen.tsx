// apps/web/src/app/screens/DmScreen.tsx
//
// DM list + thread layout. Renders the list pane and a detail
// pane. The detail pane currently renders an empty state because
// wiring a `DmController` (libsignal session store, recipient
// resolver, ws client) is a larger integration outside the UI
// build. Once that lands, swap the empty state for `<ThreadView
// controller={...} peerUserId={...} />`.

import type { Route } from '../router.js';
import { LockIcon, MessagesIcon, PlusIcon } from '../Icons.js';

export interface DmScreenProps {
  readonly route: Route;
}

export function DmScreen({ route }: DmScreenProps): { list: JSX.Element; detail: JSX.Element } {
  const peer =
    route.kind === 'dm-thread' ? route.peerUserId : null;

  return {
    list: (
      <section aria-label="Direct messages">
        <header className="list-header">
          <h2>Messages</h2>
          <button
            type="button"
            className="rail__btn"
            aria-label="New conversation"
            title="New conversation (coming soon)"
            disabled
          >
            <PlusIcon label="New conversation" />
          </button>
        </header>
        <div className="empty">
          <MessagesIcon size={32} />
          <h3>No conversations yet</h3>
          <p>
            Direct messages are end-to-end encrypted with libsignal —
            text, voice notes, and attachments are readable only on
            your device and your peer's. Threads will appear here
            once you start one.
          </p>
        </div>
      </section>
    ),
    detail:
      peer === null ? (
        <div className="empty" style={{ flex: 1 }}>
          <LockIcon size={32} />
          <h3>Select a conversation</h3>
          <p>
            Choose a thread on the left, or start a new one to send
            an end-to-end encrypted message.
          </p>
        </div>
      ) : (
        <div className="empty" style={{ flex: 1 }}>
          <LockIcon size={32} />
          <h3>{peer}</h3>
          <p>
            This thread can't be opened in the current build — DM
            ratchet wiring lands in a follow-up. Use the public
            broadcast room flow to exercise the live data plane in
            the meantime.
          </p>
        </div>
      ),
  };
}

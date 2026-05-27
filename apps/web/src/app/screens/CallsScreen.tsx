// apps/web/src/app/screens/CallsScreen.tsx
//
// Calls index. The full-viewport CallScreen overlay is mounted by
// the call subsystem when a call goes active; this list is the
// landing surface for "show me my recent calls / start a call".
// Until the call provisioning side wires real session metadata in,
// the screen renders a calm empty state.

import { CallIcon } from '../Icons.js';

export function CallsScreen(): { list: JSX.Element; detail: JSX.Element } {
  return {
    list: (
      <section aria-label="Calls">
        <header className="list-header">
          <h2>Calls</h2>
        </header>
        <div className="empty">
          <CallIcon size={32} />
          <h3>No recent calls</h3>
          <p>
            Direct calls travel browser-to-browser via DTLS-SRTP and
            never touch the server as a media endpoint. coturn
            relays only encrypted media when NAT traversal needs
            help.
          </p>
        </div>
      </section>
    ),
    detail: (
      <div className="empty" style={{ flex: 1 }}>
        <CallIcon size={32} />
        <h3>Place an audio or video call</h3>
        <p>
          Open a thread and tap the call button to start. Active
          calls float in a full-viewport overlay so you don't lose
          the underlying thread.
        </p>
      </div>
    ),
  };
}

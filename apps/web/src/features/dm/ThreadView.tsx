// apps/web/src/features/dm/ThreadView.tsx
//
// DM thread view (task 3.8).
//
// Renders the messages of a single thread in chronological order
// (oldest at top, newest at bottom — the natural append order for
// a chat surface). Each message row shows:
//   - the body (decoded as UTF-8 for the Phase-2 plaintext slice),
//   - the 3-state ticker icon (`StateTicker`),
//   - a "Retry" button when the row is in `'failed'` state.
//
// Inbound vs outbound rendering: for the Phase-2 slice we render
// every row uniformly. Once the WS inbound path lands proper
// inbound rows (task 4.7) the component is the seam for "right-
// align outbound vs left-align inbound" styling.

import { useCallback, useState, type JSX } from 'react';

import type { Message } from '../../db/repositories/messages.js';
import type { DmController } from './controller.js';
import { StateTicker } from './StateTicker.js';
import { useDmMessages } from './useDmStore.js';

export interface ThreadViewProps {
  readonly controller: DmController;
  /** `peerUserId` of the thread to render. `null` means "no
   *  thread selected" — the view shows an empty placeholder. */
  readonly threadId: string | null;
  /** This client's `senderDeviceId`, used to classify a row as
   *  "outbound" (matches) vs "inbound" (doesn't). Phase-2 doesn't
   *  visually differentiate, but the data attribute is exposed
   *  for the test surface and future styling. */
  readonly senderDeviceId: string;
}

export function ThreadView(props: ThreadViewProps): JSX.Element {
  const messages = useDmMessages(props.controller, props.threadId);

  if (props.threadId === null) {
    return (
      <section
        aria-labelledby="dm-thread-view-heading"
        data-testid="dm-thread-view"
      >
        <h2 id="dm-thread-view-heading">No conversation selected</h2>
        <p>Pick a thread on the left to start chatting.</p>
      </section>
    );
  }

  if (messages === null) {
    return (
      <section
        aria-labelledby="dm-thread-view-heading"
        data-testid="dm-thread-view"
        data-thread-id={props.threadId}
      >
        <h2 id="dm-thread-view-heading">Loading…</h2>
        <p role="status">Loading messages…</p>
      </section>
    );
  }

  return (
    <section
      aria-labelledby="dm-thread-view-heading"
      data-testid="dm-thread-view"
      data-thread-id={props.threadId}
    >
      <h2 id="dm-thread-view-heading">Conversation</h2>
      {messages.length === 0 ? (
        <p data-testid="dm-thread-empty">
          No messages yet — send the first one below.
        </p>
      ) : (
        <ol data-testid="dm-message-list">
          {messages.map((msg) => (
            <MessageRow
              key={msg.id}
              controller={props.controller}
              message={msg}
              isOutbound={msg.senderDeviceId === props.senderDeviceId}
            />
          ))}
        </ol>
      )}
    </section>
  );
}

interface MessageRowProps {
  readonly controller: DmController;
  readonly message: Message;
  readonly isOutbound: boolean;
}

function MessageRow(props: MessageRowProps): JSX.Element {
  const { message } = props;
  const [retrying, setRetrying] = useState<boolean>(false);

  const handleRetry = useCallback((): void => {
    setRetrying(true);
    void props.controller
      .retry(message.id)
      .finally(() => setRetrying(false));
  }, [props.controller, message.id]);

  const body = decodeBody(message.body);

  return (
    <li
      data-testid={`dm-message-${message.id}`}
      data-message-state={message.state}
      data-outbound={props.isOutbound ? 'true' : 'false'}
    >
      <span data-testid={`dm-message-body-${message.id}`}>{body}</span>
      <StateTicker state={message.state} />
      {message.state === 'failed' ? (
        <button
          type="button"
          onClick={handleRetry}
          disabled={retrying}
          data-testid={`dm-message-retry-${message.id}`}
        >
          {retrying ? 'Retrying…' : 'Retry'}
        </button>
      ) : null}
    </li>
  );
}

function decodeBody(body: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(body);
  } catch {
    return '';
  }
}

// apps/web/src/features/dm/ThreadList.tsx
//
// DM thread-list panel (task 3.8).
//
// Renders the user's threads ordered by most-recent message first.
// Each row carries:
//   - the peer handle (or a fallback to the peer's user id),
//   - an unread badge when `unreadCount > 0`,
//   - a one-line preview of the most recent message in the thread.
//
// Clicking a row invokes `onSelectThread(peerUserId)` so the parent
// shell can switch the active thread view.
//
// The component reads through `useDmThreads`, which subscribes to
// the controller's change stream and re-fetches on every mutation.
// A separate `useThreadPreview` hook fetches the latest message in
// the thread; we don't bake the preview into the `ThreadRow` schema
// because the preview field would have to mirror the message body
// (subject to the same plaintext-vs-ciphertext deferral as the
// `messages.body` field — see schema.ts header).

import { useEffect, useState, type JSX, type KeyboardEvent } from 'react';

import type { Message } from '../../db/repositories/messages.js';
import type { Thread } from '../../db/repositories/threads.js';
import type { DmController } from './controller.js';
import { useDmThreads } from './useDmStore.js';

export interface ThreadListProps {
  readonly controller: DmController;
  /** Currently selected thread id (or `null`). Used to highlight
   *  the active row. */
  readonly selectedThreadId: string | null;
  /** Click handler. Receives the `peerUserId` of the clicked row. */
  readonly onSelectThread: (peerUserId: string) => void;
}

export function ThreadList(props: ThreadListProps): JSX.Element {
  const threads = useDmThreads(props.controller);

  if (threads === null) {
    return (
      <section
        aria-labelledby="dm-thread-list-heading"
        data-testid="dm-thread-list"
      >
        <h2 id="dm-thread-list-heading">Conversations</h2>
        <p role="status">Loading conversations…</p>
      </section>
    );
  }

  if (threads.length === 0) {
    return (
      <section
        aria-labelledby="dm-thread-list-heading"
        data-testid="dm-thread-list"
      >
        <h2 id="dm-thread-list-heading">Conversations</h2>
        <p>No conversations yet.</p>
      </section>
    );
  }

  return (
    <section
      aria-labelledby="dm-thread-list-heading"
      data-testid="dm-thread-list"
    >
      <h2 id="dm-thread-list-heading">Conversations</h2>
      <ul>
        {threads.map((thread) => (
          <ThreadRow
            key={thread.peerUserId}
            controller={props.controller}
            thread={thread}
            selected={props.selectedThreadId === thread.peerUserId}
            onSelect={props.onSelectThread}
          />
        ))}
      </ul>
    </section>
  );
}

interface ThreadRowProps {
  readonly controller: DmController;
  readonly thread: Thread;
  readonly selected: boolean;
  readonly onSelect: (peerUserId: string) => void;
}

function ThreadRow(props: ThreadRowProps): JSX.Element {
  const preview = useThreadPreview(props.controller, props.thread.peerUserId);
  const display = props.thread.peerHandle ?? props.thread.peerUserId;

  // Keyboard navigation: ArrowDown / ArrowUp move focus to the
  // next / previous selectable thread button. Tab + Enter / Space
  // already work natively via the underlying `<button>`; the
  // arrow-key handler is the small a11y improvement that lets
  // users browse the list without leaving the home row
  // (Requirement 14.7 — "navigate threads operable from
  // keyboard alone").
  const onKeyDown = (ev: KeyboardEvent<HTMLButtonElement>): void => {
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
    ev.preventDefault();
    const list = ev.currentTarget.closest('ul');
    if (list === null) return;
    const buttons = Array.from(
      list.querySelectorAll<HTMLButtonElement>('button[data-testid^="dm-thread-select-"]'),
    );
    const idx = buttons.indexOf(ev.currentTarget);
    if (idx === -1) return;
    const next =
      ev.key === 'ArrowDown' ? Math.min(idx + 1, buttons.length - 1) : Math.max(idx - 1, 0);
    buttons[next]?.focus();
  };

  return (
    <li
      data-testid={`dm-thread-row-${props.thread.peerUserId}`}
      data-selected={props.selected ? 'true' : 'false'}
    >
      <button
        type="button"
        onClick={(): void => props.onSelect(props.thread.peerUserId)}
        onKeyDown={onKeyDown}
        data-testid={`dm-thread-select-${props.thread.peerUserId}`}
        aria-pressed={props.selected}
        aria-label={`Open conversation with ${display}${
          props.thread.unreadCount > 0
            ? `, ${props.thread.unreadCount} unread`
            : ''
        }`}
      >
        <span data-testid={`dm-thread-handle-${props.thread.peerUserId}`}>
          {display}
        </span>
        {props.thread.unreadCount > 0 ? (
          <span
            aria-label={`${props.thread.unreadCount} unread`}
            data-testid={`dm-thread-unread-${props.thread.peerUserId}`}
          >
            {props.thread.unreadCount}
          </span>
        ) : null}
        <span
          data-testid={`dm-thread-preview-${props.thread.peerUserId}`}
        >
          {preview}
        </span>
      </button>
    </li>
  );
}

/** Latest message body, decoded as UTF-8 for display. Returns
 *  the empty string until the fetch resolves so the preview
 *  doesn't flash a placeholder before the real text lands. */
function useThreadPreview(controller: DmController, threadId: string): string {
  const [preview, setPreview] = useState<string>('');

  useEffect(() => {
    let cancelled = false;
    const refresh = (): void => {
      void controller
        .listMessagesForThread(threadId, 50)
        .then((messages: readonly Message[]) => {
          if (cancelled) return;
          if (messages.length === 0) {
            setPreview('');
            return;
          }
          const latest = messages[messages.length - 1]!;
          setPreview(decodeBody(latest.body));
        });
    };
    refresh();
    const off = controller.subscribe((change) => {
      if (
        change.threadId !== undefined &&
        change.threadId !== threadId
      ) {
        return;
      }
      refresh();
    });
    return (): void => {
      cancelled = true;
      off();
    };
  }, [controller, threadId]);

  return preview;
}

/** Decode a `Uint8Array` body as UTF-8 for display. The Phase-2
 *  envelope `ciphertext` carries plaintext bytes (see schema.ts
 *  header); once libsignal lands in task 4.7 the decoded
 *  plaintext is supplied by the decrypt path and this helper
 *  becomes a no-op pass-through. */
function decodeBody(body: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(body);
  } catch {
    return '';
  }
}

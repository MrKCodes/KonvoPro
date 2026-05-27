// apps/web/src/features/dm/Composer.tsx
//
// DM message composer (task 3.8).
//
// Realises the user-facing send seam: a textarea + send button
// that, on submit, hands the body bytes to the `DmController`
// which inserts a `'sending'` `MessageRow`, enqueues the
// envelope into the persisted outbox, and bumps the thread's
// `lastMessageAt`. The composer itself is intentionally
// stateless about the DM data layer — its only job is to
// translate keyboard events into a single `controller.send`
// call.

import {
  useCallback,
  useState,
  type FormEvent,
  type JSX,
  type KeyboardEvent,
} from 'react';

import type { DmController } from './controller.js';

export interface ComposerProps {
  readonly controller: DmController;
  /** `peerUserId` of the active thread. The composer is hidden
   *  by the parent when no thread is selected, so this is
   *  required. */
  readonly peerUserId: string;
  /** Optional handle for the peer; passed through to
   *  `controller.sendMessage` so the thread row can render the
   *  human-readable name. */
  readonly peerHandle?: string;
  /** Optional callback fired with the persisted message after
   *  every successful send. Tests use this to assert the
   *  send-side state machine without polling Dexie; the
   *  parent thread view doesn't need it (the controller's
   *  change stream already drives the re-render). */
  readonly onSent?: (info: {
    readonly messageId: number;
    readonly clientNonce: string;
  }) => void;
}

type SendState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'sending' }
  | { readonly kind: 'error'; readonly message: string };

const IDLE: SendState = { kind: 'idle' };

export function Composer(props: ComposerProps): JSX.Element {
  const [draft, setDraft] = useState<string>('');
  const [sendState, setSendState] = useState<SendState>(IDLE);

  const send = useCallback(async (): Promise<void> => {
    const trimmed = draft.trim();
    if (trimmed.length === 0) {
      // Empty drafts are a UX no-op rather than an error —
      // clicking "Send" with nothing in the box just resets
      // focus.
      return;
    }
    setSendState({ kind: 'sending' });
    try {
      const sendArgs: Parameters<DmController['sendMessage']>[0] = {
        peerUserId: props.peerUserId,
        body: new TextEncoder().encode(trimmed),
        ...(props.peerHandle !== undefined
          ? { peerHandle: props.peerHandle }
          : {}),
      };
      const message = await props.controller.sendMessage(sendArgs);
      setDraft('');
      setSendState(IDLE);
      props.onSent?.({
        messageId: message.id,
        clientNonce: message.clientNonce,
      });
    } catch (err) {
      setSendState({
        kind: 'error',
        message:
          err instanceof Error
            ? err.message
            : 'Failed to send. Please try again.',
      });
    }
  }, [draft, props]);

  const handleSubmit = useCallback(
    (ev: FormEvent<HTMLFormElement>): void => {
      ev.preventDefault();
      void send();
    },
    [send],
  );

  const handleKeyDown = useCallback(
    (ev: KeyboardEvent<HTMLTextAreaElement>): void => {
      // Enter sends; Shift+Enter / Cmd+Enter inserts a newline.
      // Mirrors the keyboard convention every messaging client
      // uses; tests also exercise the click path.
      if (ev.key === 'Enter' && !ev.shiftKey && !ev.metaKey && !ev.ctrlKey) {
        ev.preventDefault();
        void send();
      }
    },
    [send],
  );

  return (
    <form
      onSubmit={handleSubmit}
      data-testid="dm-composer"
      aria-label="Message composer"
    >
      <label
        htmlFor="dm-composer-input"
        style={{ position: 'absolute', left: -9999 }}
      >
        Message body
      </label>
      <textarea
        id="dm-composer-input"
        data-testid="dm-composer-input"
        value={draft}
        onChange={(ev): void => setDraft(ev.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Type a message…"
        rows={2}
        disabled={sendState.kind === 'sending'}
      />
      <button
        type="submit"
        data-testid="dm-composer-send"
        disabled={sendState.kind === 'sending' || draft.trim().length === 0}
      >
        {sendState.kind === 'sending' ? 'Sending…' : 'Send'}
      </button>
      {sendState.kind === 'error' ? (
        <p role="alert" data-testid="dm-composer-error">
          {sendState.message}
        </p>
      ) : null}
    </form>
  );
}

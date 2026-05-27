// apps/web/src/features/dm/StateTicker.tsx
//
// Small leaf component that renders the 3-state ticker icon for
// a DM message (task 3.8 — surface for requirement 4.6).
//
// Visual contract (mirrors design.md §15.2):
//   - `'sending'`   gray clock     (⏱)
//   - `'delivered'` single check   (✓)
//   - `'read'`      double check   (✓✓)
//   - `'failed'`    red cross      (❌) — paired with a retry
//                   button in the parent message row, not here.
//
// The component is a pure leaf: no state, no effects, no Dexie
// access. Tests and the message row both consume it directly.

import type { JSX } from 'react';

import type { MessageState } from '../../db/schema.js';

export interface StateTickerProps {
  readonly state: MessageState;
}

/** Stable text-content per state. Exported so unit tests can
 *  assert against it without duplicating glyphs. */
export const TICKER_GLYPH: Readonly<Record<MessageState, string>> = {
  sending: '⏱',
  delivered: '✓',
  read: '✓✓',
  failed: '❌',
  tampered: '⚠',
};

/** Stable per-state CSS class hooks. Exposed so the parent
 *  stylesheet can target each state independently without
 *  re-deriving the mapping. */
export const TICKER_CLASS: Readonly<Record<MessageState, string>> = {
  sending: 'dm-ticker dm-ticker--sending',
  delivered: 'dm-ticker dm-ticker--delivered',
  read: 'dm-ticker dm-ticker--read',
  failed: 'dm-ticker dm-ticker--failed',
  tampered: 'dm-ticker dm-ticker--tampered',
};

/** Stable per-state human-readable label, used as the
 *  `aria-label` on the rendered span so screen readers
 *  announce the delivery state alongside the message body. */
export const TICKER_LABEL: Readonly<Record<MessageState, string>> = {
  sending: 'Sending',
  delivered: 'Delivered',
  read: 'Read',
  failed: 'Failed to send',
  tampered: 'Message couldn’t be decrypted',
};

export function StateTicker(props: StateTickerProps): JSX.Element {
  const { state } = props;
  return (
    <span
      data-testid="dm-state-ticker"
      data-state={state}
      className={TICKER_CLASS[state]}
      aria-label={TICKER_LABEL[state]}
      title={TICKER_LABEL[state]}
    >
      {TICKER_GLYPH[state]}
    </span>
  );
}

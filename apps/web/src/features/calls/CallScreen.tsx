// apps/web/src/features/calls/CallScreen.tsx
//
// Host component for an active 1:1 call. Task 6.5 requires a
// "Verify Safety Number" affordance be reachable from the call UI;
// this is the smallest scaffold that exposes that affordance and
// owns the show/hide toggle for the {@link InCallSafetyNumber}
// overlay.
//
// What this component DOES (today):
//   - renders a minimal call header (peer label) + a "Verify
//     safety number" button (requirement 7.6),
//   - mounts {@link InCallSafetyNumber} as an overlay when the user
//     clicks the button, passing through the four crypto inputs +
//     the optional peer handle,
//   - hides the overlay when the user clicks its close affordance.
//
// What this component does NOT do (yet):
//   - bind to a real `CallPeer` instance,
//   - render local / remote video,
//   - expose mute / hangup / camera / audio-only controls.
//
// Those land alongside the rest of phase-5 UI work (tasks 6.2 / 6.3
// already produced `peer.ts` and the E2EE-envelope wrapping; the UI
// shell that consumes them is iterative and arrives over multiple
// phase-5 sub-tasks). Wiring task 6.5's safety-number surface here
// rather than waiting for the rest of the call UI keeps the
// requirement satisfied without forcing a big-bang screen rewrite
// later — the existing button + overlay can simply be lifted into a
// real call layout when one materialises.

import { useCallback, useEffect, useState, type JSX, type KeyboardEvent } from 'react';

import { InCallSafetyNumber } from './InCallSafetyNumber.js';

export interface CallScreenProps {
  readonly localIdentityPub: Uint8Array;
  readonly localUserId: string;
  readonly remoteIdentityPub: Uint8Array;
  readonly remoteUserId: string;
  /** Optional peer display label. Surfaced in the header and in
   *  the safety-number overlay heading. */
  readonly peerHandle?: string;
  /** Optional callback invoked when the user accepts an incoming
   *  call. When omitted, the accept affordance is hidden. The
   *  call host wires this to its peer-connection adapter. */
  readonly onAcceptCall?: () => void;
  /** Optional callback invoked when the user hangs up. When
   *  omitted, the hang-up affordance is hidden. */
  readonly onHangup?: () => void;
  /** When `true` the accept-call button is rendered (e.g. an
   *  incoming call is ringing). Defaults to `false`. */
  readonly canAccept?: boolean;
}

export function CallScreen(props: CallScreenProps): JSX.Element {
  const [safetyNumberOpen, setSafetyNumberOpen] = useState<boolean>(false);

  const peerLabel = props.peerHandle ?? 'peer';

  // Keyboard-operable accept / hangup. Requirement 14.7 demands
  // primary call flows be reachable from the keyboard alone. The
  // affordances are normal `<button>` elements so Tab / Enter /
  // Space work natively; we additionally bind window-level
  // Escape → hangup so a user can drop a call without first
  // tabbing to the button (matches the convention every native
  // dialer uses).
  const onHangup = useCallback((): void => {
    props.onHangup?.();
  }, [props]);

  const onAccept = useCallback((): void => {
    props.onAcceptCall?.();
  }, [props]);

  useEffect(() => {
    if (props.onHangup === undefined) return;
    const onKey = (ev: globalThis.KeyboardEvent): void => {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        props.onHangup?.();
      }
    };
    window.addEventListener('keydown', onKey);
    return (): void => window.removeEventListener('keydown', onKey);
  }, [props]);

  // When the safety-number overlay is open, Escape closes it
  // first (don't escalate to hangup). The component-local
  // handler is bound on the overlay container so it has higher
  // priority than the window-level handler above.
  const onContainerKeyDown = useCallback(
    (ev: KeyboardEvent<HTMLDivElement>): void => {
      if (ev.key === 'Escape' && safetyNumberOpen) {
        ev.stopPropagation();
        ev.preventDefault();
        setSafetyNumberOpen(false);
      }
    },
    [safetyNumberOpen],
  );

  return (
    <main aria-labelledby="call-screen-heading" data-testid="call-screen">
      <header>
        <h1 id="call-screen-heading">In call with {peerLabel}</h1>
        <button
          type="button"
          onClick={() => setSafetyNumberOpen(true)}
          aria-label={`Verify safety number with ${peerLabel}`}
          data-testid="verify-safety-number-button"
        >
          Verify safety number
        </button>
        {props.canAccept === true && props.onAcceptCall !== undefined ? (
          <button
            type="button"
            onClick={onAccept}
            aria-label={`Accept call from ${peerLabel}`}
            data-testid="call-accept-button"
          >
            Accept call
          </button>
        ) : null}
        {props.onHangup !== undefined ? (
          <button
            type="button"
            onClick={onHangup}
            aria-label={`Hang up call with ${peerLabel}`}
            data-testid="call-hangup-button"
          >
            Hang up
          </button>
        ) : null}
      </header>

      {safetyNumberOpen ? (
        <div onKeyDown={onContainerKeyDown}>
          <InCallSafetyNumber
            localIdentityPub={props.localIdentityPub}
            localUserId={props.localUserId}
            remoteIdentityPub={props.remoteIdentityPub}
            remoteUserId={props.remoteUserId}
            {...(props.peerHandle !== undefined
              ? { peerHandle: props.peerHandle }
              : {})}
            onClose={() => setSafetyNumberOpen(false)}
          />
        </div>
      ) : null}
    </main>
  );
}

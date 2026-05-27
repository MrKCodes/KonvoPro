// apps/web/src/features/settings/SafetyNumberScreen.tsx
//
// Per-peer Safety_Number screen (task 9.5 — UI half of requirement
// 15.2). The data layer (`@konvo/crypto`'s `computeSafetyNumber`)
// already produces the 60-digit string formatted as 12 groups of 5,
// plus the 60-byte raw QR payload (see
// `packages/crypto/src/safety-number.ts`). This component:
//
//   - takes the local + remote identity public keys and user ids,
//   - calls `computeSafetyNumber`,
//   - renders the digits in a `monospace` block grouped 12 × 5 (the
//     value already comes pre-formatted from the data layer),
//   - renders a base64 string of the raw QR payload — requirement
//     8.6 / 15.2 specifies a base64-encoded payload as the QR
//     content. We expose the base64 string and a `data-qr-payload`
//     attribute so a future QR-rendering integration (e.g. via the
//     `qrcode` npm package, which we haven't added yet) can pick
//     it up without changing this component.
//
// The component is intentionally framework-light: no router, no
// data fetch. The parent screen (Settings or a DM thread header)
// owns navigation and supplies the four inputs.
//
// Accessibility:
//   - The digits region uses `role="region"` + a labelled heading so
//     screen readers can navigate to it directly.
//   - The QR payload is rendered as plain text with a stable
//     `data-testid` so a sighted user (and the test harness) can
//     copy it for cross-device verification even when no QR canvas
//     is present.

import { useEffect, useState } from 'react';

import { computeSafetyNumber, type SafetyNumber } from '@konvo/crypto';

export interface SafetyNumberScreenProps {
  readonly localIdentityPub: Uint8Array;
  readonly localUserId: string;
  readonly remoteIdentityPub: Uint8Array;
  readonly remoteUserId: string;
  /** Optional peer display label. Surfaced in the heading; falls
   *  back to "this peer" when omitted so the heading stays
   *  meaningful for tests that don't supply one. */
  readonly peerHandle?: string;
}

/** Discriminated state machine. Mirrors the pattern used in
 *  `apps/web/src/features/calls/InCallSafetyNumber.tsx` so a
 *  reader of either component sees the same shape. */
type RenderState =
  | { readonly kind: 'computing' }
  | { readonly kind: 'ready'; readonly safetyNumber: SafetyNumber }
  | { readonly kind: 'error'; readonly message: string };

const COMPUTING: RenderState = { kind: 'computing' };

export function SafetyNumberScreen(
  props: SafetyNumberScreenProps,
): JSX.Element {
  const [state, setState] = useState<RenderState>(COMPUTING);

  // Recompute whenever any of the four inputs change. The
  // computation is ~10 ms on a modern desktop (5200 SHA-512 rounds
  // × 2 sides per `computeSafetyNumber`), so a fresh call on every
  // input change is fine — no memoisation needed.
  useEffect(() => {
    let cancelled = false;
    setState(COMPUTING);
    computeSafetyNumber(
      props.localIdentityPub,
      props.localUserId,
      props.remoteIdentityPub,
      props.remoteUserId,
    )
      .then((sn: SafetyNumber) => {
        if (!cancelled) {
          setState({ kind: 'ready', safetyNumber: sn });
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            kind: 'error',
            message:
              err instanceof Error ? err.message : 'Failed to compute safety number.',
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [
    props.localIdentityPub,
    props.localUserId,
    props.remoteIdentityPub,
    props.remoteUserId,
  ]);

  const peerLabel = props.peerHandle ?? 'this peer';

  return (
    <section aria-labelledby="safety-number-heading" data-testid="safety-number-screen">
      <h1 id="safety-number-heading">Verify safety number with {peerLabel}</h1>
      <p>
        Compare the digits below — or the QR payload — with what {peerLabel}
        sees on their device. They should match exactly.
      </p>

      {state.kind === 'computing' ? (
        <p role="status" data-testid="safety-number-loading">
          Computing safety number…
        </p>
      ) : null}

      {state.kind === 'error' ? (
        <p role="alert" data-testid="safety-number-error">
          {state.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? (
        <SafetyNumberDisplay safetyNumber={state.safetyNumber} />
      ) : null}
    </section>
  );
}

interface SafetyNumberDisplayProps {
  readonly safetyNumber: SafetyNumber;
}

/** Sub-component renders the digits + QR payload. Split out so a
 *  future variant (e.g. an embedded modal) can re-use the same
 *  layout without owning the compute path. */
function SafetyNumberDisplay(props: SafetyNumberDisplayProps): JSX.Element {
  const qrBase64 = bytesToBase64(props.safetyNumber.qrPayload);
  return (
    <>
      <div
        role="region"
        aria-labelledby="safety-number-digits-heading"
        data-testid="safety-number-digits"
      >
        <h2 id="safety-number-digits-heading">Safety number</h2>
        <pre style={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
          {props.safetyNumber.digits}
        </pre>
      </div>

      <div
        role="region"
        aria-labelledby="safety-number-qr-heading"
        data-testid="safety-number-qr"
        data-qr-payload={qrBase64}
      >
        <h2 id="safety-number-qr-heading">QR payload</h2>
        {/*
          Pre-rendered as text so the user (and the test harness)
          can copy the value without a QR-rendering library.
          A future task can mount a real QR canvas here and read
          the same `data-qr-payload` attribute as the input.
        */}
        <code data-testid="safety-number-qr-base64">{qrBase64}</code>
      </div>
    </>
  );
}

/** Standard-base64 encode a byte buffer using `btoa` over a
 *  Latin-1 string. Mirrors the helper in `auth/api.ts`. */
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

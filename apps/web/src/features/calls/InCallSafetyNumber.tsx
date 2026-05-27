// apps/web/src/features/calls/InCallSafetyNumber.tsx
//
// In-call Safety_Number overlay (task 6.5 — UI realisation of
// requirement 7.6).
//
// Surface contract:
//   - Inputs: the local + remote 32-byte Curve25519 identity public
//     keys, plus the local + remote stable user-id strings (the same
//     four inputs `computeSafetyNumber` already requires; the data
//     layer canonicalises which side is "A" vs "B" so the digits and
//     QR payload match what the peer sees).
//   - Output: a 60-digit string formatted as 12 groups of 5 in a
//     monospace block (requirement 7.6 verbatim) plus a base64
//     `data-qr-payload` and an inline SVG QR code rendered from
//     the `qrcode` package.
//   - Lifecycle: a single "X" close button forwards to the parent
//     via `onClose`. The component is intentionally controlled so
//     the parent (CallScreen) can present it as either an in-call
//     overlay or a side-panel without owning safety-number compute
//     state itself.
//
// Why a separate component (rather than re-using
// `apps/web/src/features/settings/SafetyNumberScreen.tsx`):
//   - the in-call surface needs a close affordance and a tighter
//     layout — the settings screen is a full page,
//   - it needs an actual QR (the settings screen renders the base64
//     payload as text pending a QR-rendering library); task 6.5
//     requires the QR be visible in-call so users can scan it
//     out-of-band while the call is connecting,
//   - keeping the components separate avoids coupling the call UI
//     to any future Settings-screen restructuring.
//
// Both components delegate the actual derivation to
// `@konvo/crypto`'s `computeSafetyNumber`, so the digits + qrPayload
// match across the two surfaces by construction (requirement 8.4 /
// P8: determinism + symmetry).
//
// Accessibility:
//   - The overlay is rendered with `role="dialog"` + `aria-modal`
//     so screen readers treat it as a modal surface.
//   - Headings carry stable `id`s referenced by `aria-labelledby`
//     on the regions they describe.
//   - The close button has an explicit `aria-label="Close"` and a
//     visible "×" character.

import { useEffect, useState } from 'react';

import { computeSafetyNumber, type SafetyNumber } from '@konvo/crypto';

// `qrcode` ships as CommonJS without bundled type declarations. We
// import the SVG-string entry-point from the browser-side bundle
// (`qrcode/lib/browser.js`) so we don't drag the server entry's
// `pngjs` / `fs` requirements into the bundle. The browser entry
// exports `toString` which renders SVG markup as a string; that's
// the only QR rendering primitive we need.
//
// `toString({ type: 'svg' })` renders an SVG document as a string
// (see `apps/web/node_modules/qrcode/lib/browser.js`). We use it
// because it sidesteps `<canvas>` (jsdom's canvas is non-rendering
// and would break the test path) and because inlining SVG keeps
// the component dependency-light at runtime.
//
// The cast is local to this import statement so callers see a
// fully-typed `qrToString`.
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import * as qrcode from 'qrcode/lib/browser.js';

type QrToStringOpts = {
  readonly type?: 'svg';
  readonly errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
  readonly margin?: number;
  readonly width?: number;
};
type QrToString = (text: string, opts?: QrToStringOpts) => Promise<string>;
const qrToString = (qrcode as unknown as { toString: QrToString }).toString;

/** Props accepted by the in-call Safety_Number overlay.
 *
 *  The four crypto inputs map 1:1 onto `computeSafetyNumber`'s
 *  signature; passing them through unmodified keeps the canonical-
 *  ordering logic in the data layer (per design.md §13.4). */
export interface InCallSafetyNumberProps {
  readonly localIdentityPub: Uint8Array;
  readonly localUserId: string;
  readonly remoteIdentityPub: Uint8Array;
  readonly remoteUserId: string;
  /** Optional peer label rendered in the heading. Falls back to
   *  "this peer" when absent so headings stay meaningful in tests. */
  readonly peerHandle?: string;
  /** Called when the user clicks the close affordance. The parent
   *  is responsible for unmounting / hiding this component. */
  readonly onClose: () => void;
}

/** Rendering-state machine. We always start in `computing` and
 *  transition to either `ready` or `error` once both the safety
 *  number and the QR SVG resolve. */
type RenderState =
  | { readonly kind: 'computing' }
  | {
      readonly kind: 'ready';
      readonly safetyNumber: SafetyNumber;
      readonly qrSvg: string;
      readonly qrBase64: string;
    }
  | { readonly kind: 'error'; readonly message: string };

const COMPUTING: RenderState = { kind: 'computing' };

export function InCallSafetyNumber(
  props: InCallSafetyNumberProps,
): JSX.Element {
  const [state, setState] = useState<RenderState>(COMPUTING);

  // Recompute whenever any of the four inputs change. Both
  // `computeSafetyNumber` and `qrToString` are async; we run them
  // in sequence (compute → encode QR) to avoid a race between two
  // setState calls.
  useEffect(() => {
    let cancelled = false;
    setState(COMPUTING);

    (async (): Promise<void> => {
      try {
        const sn = await computeSafetyNumber(
          props.localIdentityPub,
          props.localUserId,
          props.remoteIdentityPub,
          props.remoteUserId,
        );
        const qrBase64 = bytesToBase64(sn.qrPayload);
        // SVG keeps the dependency rendering-free in jsdom. Margin
        // 1 keeps the QR compact on a small in-call overlay; the
        // default of 4 is overkill at the size we display.
        const qrSvg = await qrToString(qrBase64, {
          type: 'svg',
          errorCorrectionLevel: 'M',
          margin: 1,
          width: 192,
        });
        if (cancelled) return;
        setState({ kind: 'ready', safetyNumber: sn, qrSvg, qrBase64 });
      } catch (err) {
        if (cancelled) return;
        setState({
          kind: 'error',
          message:
            err instanceof Error
              ? err.message
              : 'Failed to compute safety number.',
        });
      }
    })();

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
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="in-call-safety-number-heading"
      data-testid="in-call-safety-number"
    >
      <header>
        <h1 id="in-call-safety-number-heading">
          Safety number with {peerLabel}
        </h1>
        <button
          type="button"
          aria-label="Close"
          onClick={props.onClose}
          data-testid="in-call-safety-number-close"
        >
          ×
        </button>
      </header>

      <p>
        Compare the digits — or scan the QR — with what {peerLabel} sees.
        Matching values mean nobody is intercepting your call.
      </p>

      {state.kind === 'computing' ? (
        <p role="status" data-testid="in-call-safety-number-loading">
          Computing safety number…
        </p>
      ) : null}

      {state.kind === 'error' ? (
        <p role="alert" data-testid="in-call-safety-number-error">
          {state.message}
        </p>
      ) : null}

      {state.kind === 'ready' ? (
        <SafetyNumberBody
          digits={state.safetyNumber.digits}
          qrSvg={state.qrSvg}
          qrBase64={state.qrBase64}
        />
      ) : null}
    </div>
  );
}

interface SafetyNumberBodyProps {
  readonly digits: string;
  readonly qrSvg: string;
  readonly qrBase64: string;
}

/** Renders the digits + QR. Split out so the loading / error paths
 *  in `InCallSafetyNumber` stay flat. */
function SafetyNumberBody(props: SafetyNumberBodyProps): JSX.Element {
  return (
    <>
      <section
        aria-labelledby="in-call-safety-number-digits-heading"
        data-testid="in-call-safety-number-digits"
      >
        <h2 id="in-call-safety-number-digits-heading">Digits</h2>
        <pre style={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
          {props.digits}
        </pre>
      </section>

      <section
        aria-labelledby="in-call-safety-number-qr-heading"
        data-testid="in-call-safety-number-qr"
        data-qr-payload={props.qrBase64}
      >
        <h2 id="in-call-safety-number-qr-heading">QR code</h2>
        {/*
          The SVG comes from the `qrcode` library and is plain
          structural markup (no scripts, no event handlers). Inlining
          via `dangerouslySetInnerHTML` is the standard way to embed
          a third-party SVG string in React; the input is from a
          pinned npm dep and is not user-supplied.
        */}
        <div
          aria-label="Safety number QR code"
          role="img"
          dangerouslySetInnerHTML={{ __html: props.qrSvg }}
        />
      </section>
    </>
  );
}

/** Standard-base64 encode a byte buffer. Mirrors the helper in
 *  `auth/api.ts` and `settings/SafetyNumberScreen.tsx`. The QR
 *  payload format (base64 of the 60-byte concatenation) matches
 *  requirement 8.6 / 15.2 so the in-call QR scans to the same
 *  payload as the per-peer screen. */
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

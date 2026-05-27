// P22 — Validates Requirements 7.5, 21.22
//
// apps/web/test/fingerprint-binding.property.test.ts
//
// Property test for task 6.7 — P22: Fingerprint binding.
//
// Property under test (orchestrator-specified P22 wording, also
// design.md §14.5 / requirements.md §21.22):
//
//   For any call where the SDP fingerprint inside the E2EE
//   envelope does not match the fingerprint advertised in the SDP,
//   the call is terminated before any RTP/SRTP media packet is
//   processed, on both offer and answer paths.
//
// **Validates: Requirements 7.5, 21.22**
//
// Strategy
// --------
// We exercise `dispatchInner` (apps/web/src/features/calls/signaling.ts)
// because that is the single point where the binding check sits in
// the inbound call path; both `handleInboundCallEnvelope` (post-
// ratchet decrypt) and the test harness here flow through the same
// switch. The kind-level unit tests in `dtls-fingerprint.test.ts`
// cover the helper + a handful of hand-picked counterexamples; this
// file uses fast-check to randomise across the whole space of
// distinct (envelope, sdp) fingerprint pairs and asserts the same
// observable outcome holds for every input.
//
// For each (envelopeFp, sdpFp) where `envelopeFp` and `sdpFp` are
// not equal under canonicalisation (case-insensitive, whitespace-
// collapsed) we drive `dispatchInner` for BOTH `CALL_OFFER` and
// `CALL_ANSWER` (the property explicitly demands the symmetry) and
// assert that:
//
//   1. The result discriminator is `'fingerprint_mismatch'` with
//      the matching `which` field.
//   2. `peerConnection.setRemoteDescription` is NEVER called. This
//      is the single WebRTC method on the inbound path that would
//      let libwebrtc start the DTLS handshake against the SDP and
//      consequently process RTP/SRTP packets, so its absence is the
//      structural witness that "no media packet was processed"
//      (Requirement 7.5).
//   3. `peerConnection.addIceCandidate` is NEVER called either —
//      defense-in-depth: if the rejection ever started accepting
//      ICE candidates the connection could still progress to a
//      DTLS handshake on the next setRemoteDescription.
//   4. `peerConnection.close()` is called exactly once, synchronously,
//      so the underlying `RTCPeerConnection` is torn down before
//      the dispatcher returns and any re-entrant inbound envelope
//      can slip in.
//   5. `onFingerprintMismatch` is called exactly once with the
//      structured args (callId, which, cause, envelopeFingerprint,
//      sdpFingerprint).
//   6. `onOffer` / `onAnswer` are NEVER called — the caller learns
//      of the rejected envelope only via `onFingerprintMismatch`.
//
// Symmetric sanity anchor: when the envelope's fingerprint matches
// the SDP's fingerprint, the dispatcher proceeds normally — close
// is NOT called and setRemoteDescription IS. This is included so a
// regression that always rejected (and thus trivially satisfied
// items 2–6) would still be caught.
//
// Generators
// ----------
// `arbAlgo`            : RFC 8122 algorithm tokens libwebrtc emits.
// `arbHexBytes(n)`     : `n` colon-separated upper-case hex bytes.
// `arbFingerprint`     : `<algo> <hex:hex:...>` matched to the
//                        algo's expected length (16 / 20 / 32 / 48 /
//                        64 bytes for md5 / sha-1 / sha-256 / sha-384
//                        / sha-512 respectively).
// `arbDistinctPair`    : two `arbFingerprint`s filtered so they are
//                        not equal under canonicalisation. The filter
//                        rejects fewer than 1 in 10^30 candidates in
//                        practice (different random hex bytes), so
//                        fast-check never times out trying to find a
//                        valid input. We also generate "tampered"
//                        siblings (single-bit flips, single-byte
//                        substitutions, length truncations) so the
//                        property catches a regression that only
//                        fired on grossly different inputs.
// `arbWhich`           : `'offer'` | `'answer'` for the symmetric
//                        coverage demanded by P22.

import { InnerType } from '@konvo/protocol';
import * as fc from 'fast-check';
import { describe, it, vi } from 'vitest';

import {
  dispatchInner,
  type CallPeerConnectionLike,
  type CallSignalingHandlers,
} from '../src/features/calls/signaling.js';

// ---------------------------------------------------------------------------
// SDP fixtures
// ---------------------------------------------------------------------------

/** Build a synthetic SDP that advertises the given fingerprint
 *  string. The exact preamble doesn't matter for the binding check
 *  — `extractDtlsFingerprint` is a single regex on `^a=fingerprint:`
 *  — so we use a minimal but RFC-shaped SDP so any future addition
 *  of structural validation in the helper would still see a parsable
 *  blob. */
function makeSdp(fp: string): string {
  return (
    'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
    'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
    `a=fingerprint:${fp}\r\n` +
    'a=setup:actpass\r\n'
  );
}

// ---------------------------------------------------------------------------
// Fingerprint generators
// ---------------------------------------------------------------------------

/** RFC 8122 §5 algorithm tokens. libwebrtc emits sha-256 by default
 *  for fresh DTLS certificates, but a peer is permitted to advertise
 *  any of these and the binding check must distinguish them. */
const FP_ALGOS = ['sha-256', 'sha-1', 'sha-384', 'sha-512', 'md5'] as const;
type FpAlgo = (typeof FP_ALGOS)[number];

/** Expected hex byte count per algorithm. */
const ALGO_BYTES: Readonly<Record<FpAlgo, number>> = {
  'md5': 16,
  'sha-1': 20,
  'sha-256': 32,
  'sha-384': 48,
  'sha-512': 64,
};

const arbAlgo: fc.Arbitrary<FpAlgo> = fc.constantFrom(...FP_ALGOS);

/** `n` colon-separated upper-case hex bytes (e.g. `"AB:CD:EF"`). */
function arbHexBytes(n: number): fc.Arbitrary<string> {
  return fc
    .uint8Array({ minLength: n, maxLength: n })
    .map((bytes) =>
      Array.from(bytes, (b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(':'),
    );
}

/** A complete fingerprint string `"<algo> <hex:hex:...>"`. */
const arbFingerprint: fc.Arbitrary<{ readonly algo: FpAlgo; readonly fp: string }> =
  arbAlgo.chain((algo) =>
    arbHexBytes(ALGO_BYTES[algo]).map((hex) => ({ algo, fp: `${algo} ${hex}` })),
  );

/** Canonicalise per `verifyDtlsFingerprintBinding`'s rules so the
 *  "distinct under canonicalisation" filter on `arbDistinctPair`
 *  matches the production comparison exactly. RFC 8122 makes
 *  fingerprint strings case-insensitive; whitespace runs collapse
 *  to a single space. */
function canonicalise(fp: string): string {
  return fp.trim().replace(/\s+/g, ' ').toLowerCase();
}

/** A pair `(envFp, sdpFp)` guaranteed to canonicalise to different
 *  strings — i.e. a guaranteed mismatch. We generate three classes
 *  of distinct pairs and pick uniformly so the property covers:
 *    - bulk-different (independently sampled bytes + algo),
 *    - same-algo / different-bytes (the common attacker model:
 *      keep the algo, swap the cert),
 *    - same-bytes / different-algo (attacker substitutes a stronger
 *      / weaker hash to confuse a naive comparator),
 *    - single-bit flip (the smallest possible mutation; catches a
 *      regression where the helper compared by hash digest length
 *      or by some other coarse property),
 *    - length truncation (catches a regression that compared only
 *      a prefix). */
const arbDistinctPair: fc.Arbitrary<{
  readonly envFp: string;
  readonly sdpFp: string;
  readonly mode:
    | 'bulk-different'
    | 'same-algo-diff-bytes'
    | 'same-bytes-diff-algo'
    | 'single-bit-flip'
    | 'truncation';
}> = fc.oneof(
  // 1. Bulk-different: two independently-sampled fingerprints,
  //    filtered so they differ under canonicalisation. Filter
  //    rejection rate is negligible.
  fc
    .tuple(arbFingerprint, arbFingerprint)
    .filter(([a, b]) => canonicalise(a.fp) !== canonicalise(b.fp))
    .map(([a, b]) => ({
      envFp: a.fp,
      sdpFp: b.fp,
      mode: 'bulk-different' as const,
    })),
  // 2. Same-algo, different bytes: the common MITM-cert-swap.
  arbAlgo.chain((algo) =>
    fc
      .tuple(arbHexBytes(ALGO_BYTES[algo]), arbHexBytes(ALGO_BYTES[algo]))
      .filter(([a, b]) => a !== b)
      .map(([a, b]) => ({
        envFp: `${algo} ${a}`,
        sdpFp: `${algo} ${b}`,
        mode: 'same-algo-diff-bytes' as const,
      })),
  ),
  // 3. Same hex bytes, different algorithm: an attacker substituting
  //    a different hash to evade a naive comparator. We deliberately
  //    pad/truncate the byte string to fit the second algo's length
  //    so the resulting string is structurally well-formed (different
  //    algos require different hex byte counts, so a same-bytes-
  //    same-length pair is only achievable for sha-384/sha-512 or by
  //    constructing a sha-256 hex string and presenting it under
  //    `sha-1` truncated to 20 bytes — both impossible with raw
  //    same-bytes generation). We instead generate a fingerprint A,
  //    pick a DIFFERENT algo B, and regenerate the byte run for B
  //    based on the same uint8 stream taken modulo B's length. The
  //    resulting "same hex prefix, different algo" pair canonicalises
  //    to a different string because the algo token differs.
  fc
    .tuple(
      arbAlgo,
      arbAlgo,
      fc.uint8Array({ minLength: 64, maxLength: 64 }),
    )
    .filter(([a, b]) => a !== b)
    .map(([algoA, algoB, src]) => {
      const hexA = Array.from(src.subarray(0, ALGO_BYTES[algoA]))
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(':');
      const hexB = Array.from(src.subarray(0, ALGO_BYTES[algoB]))
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(':');
      return {
        envFp: `${algoA} ${hexA}`,
        sdpFp: `${algoB} ${hexB}`,
        mode: 'same-bytes-diff-algo' as const,
      };
    }),
  // 4. Single-bit flip: take a fingerprint and flip exactly one bit
  //    in one of its hex bytes. Catches a regression whose
  //    comparison used a coarse digest (e.g. SHA-256 of the FP
  //    string) and could collide on small mutations.
  arbFingerprint.chain(({ algo, fp }) =>
    fc
      .integer({ min: 0, max: ALGO_BYTES[algo] - 1 })
      .chain((byteIdx) =>
        fc.integer({ min: 0, max: 7 }).map((bitIdx) => {
          const hexParts = fp.split(' ')[1]!.split(':');
          const original = Number.parseInt(hexParts[byteIdx]!, 16);
          const flipped = (original ^ (1 << bitIdx)) & 0xff;
          hexParts[byteIdx] = flipped
            .toString(16)
            .padStart(2, '0')
            .toUpperCase();
          const mutated = `${algo} ${hexParts.join(':')}`;
          return {
            envFp: fp,
            sdpFp: mutated,
            mode: 'single-bit-flip' as const,
          };
        }),
      ),
  ),
  // 5. Truncation: drop the last hex byte from one side. Catches a
  //    regression whose comparison compared the algo + a prefix.
  arbFingerprint.map(({ algo, fp }) => {
    const hexParts = fp.split(' ')[1]!.split(':');
    hexParts.pop();
    return {
      envFp: fp,
      sdpFp: `${algo} ${hexParts.join(':')}`,
      mode: 'truncation' as const,
    };
  }),
);

const arbWhich: fc.Arbitrary<'offer' | 'answer'> = fc.constantFrom(
  'offer',
  'answer',
);

const CALL_ID = 'pbt-fp-binding';

// ---------------------------------------------------------------------------
// Peer connection + handlers harness
// ---------------------------------------------------------------------------

interface FakePeer
  extends Required<Pick<CallPeerConnectionLike, 'setRemoteDescription' | 'addIceCandidate'>>,
    Pick<CallPeerConnectionLike, 'close'> {
  setRemoteDescription: ReturnType<typeof vi.fn>;
  addIceCandidate: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
}

/** Build a fresh peer-connection fake per iteration. We construct
 *  inside the fast-check property so cross-iteration state in the
 *  vi.fn call counters can't pollute the per-iteration assertions. */
function makeFakePeer(): FakePeer {
  return {
    setRemoteDescription: vi.fn(async () => {}),
    addIceCandidate: vi.fn(async () => {}),
    close: vi.fn(() => {}),
  };
}

interface MismatchArgs {
  callId: string;
  which: 'offer' | 'answer';
  cause: 'mismatch' | 'sdp_missing' | 'envelope_missing';
  envelopeFingerprint: string;
  sdpFingerprint: string | null;
}

/** Build a handlers bag whose `vi.fn`s we can introspect. */
function makeHandlers(peer: FakePeer): {
  handlers: CallSignalingHandlers;
  onOffer: ReturnType<typeof vi.fn>;
  onAnswer: ReturnType<typeof vi.fn>;
  onFingerprintMismatch: ReturnType<typeof vi.fn>;
  onHangup: ReturnType<typeof vi.fn>;
} {
  const onOffer = vi.fn();
  const onAnswer = vi.fn();
  const onFingerprintMismatch = vi.fn();
  const onHangup = vi.fn();
  return {
    handlers: {
      peerConnection: peer,
      onOffer,
      onAnswer,
      onFingerprintMismatch,
      onHangup,
    },
    onOffer,
    onAnswer,
    onFingerprintMismatch,
    onHangup,
  };
}

// ---------------------------------------------------------------------------
// Property: P22 — fingerprint binding (mismatch path)
// ---------------------------------------------------------------------------

describe('P22: fingerprint binding (Requirements 7.5, 21.22)', () => {
  it('mismatched envelope/SDP fingerprint terminates the call before any RTP/SRTP processing on both offer and answer paths', () => {
    fc.assert(
      fc.property(arbDistinctPair, arbWhich, ({ envFp, sdpFp }, which) => {
        const sdp = makeSdp(sdpFp);
        const peer = makeFakePeer();
        const { handlers, onOffer, onAnswer, onFingerprintMismatch, onHangup } =
          makeHandlers(peer);

        const innerKind =
          which === 'offer' ? InnerType.CALL_OFFER : InnerType.CALL_ANSWER;
        const result = dispatchInner(
          {
            kind: innerKind,
            callId: CALL_ID,
            sdp,
            dtlsFingerprint: envFp,
          },
          handlers,
        );

        // (1) Result is the structured fingerprint_mismatch outcome
        //     with the right `which`. We assert structurally rather
        //     than with `expect(...).toEqual(...)` so a fast-check
        //     shrink reports the offending field directly.
        if (result.kind !== 'fingerprint_mismatch') return false;
        if (result.callId !== CALL_ID) return false;
        if (result.which !== which) return false;
        // The cause is one of three values; for these mismatch-pair
        // generators it must be `'mismatch'` (both sides non-empty,
        // SDP has a fingerprint line).
        if (result.cause !== 'mismatch') return false;
        if (result.envelopeFingerprint !== envFp) return false;
        // sdpFingerprint is the helper's extracted form, which uses
        // the algo token verbatim and the upper-case hex from the
        // SDP. Our `makeSdp` interpolates `sdpFp` as-is, so the
        // extractor returns the same `sdpFp` we generated.
        if (result.sdpFingerprint !== sdpFp) return false;

        // (2) The single WebRTC method that would let libwebrtc
        //     start the DTLS handshake against this SDP must NEVER
        //     have been called. This is the structural witness for
        //     "no RTP/SRTP packet processed" (Requirement 7.5).
        if (peer.setRemoteDescription.mock.calls.length !== 0) return false;

        // (3) Defense-in-depth: addIceCandidate must not have been
        //     called either — accepting candidates would prime the
        //     connection for a subsequent setRemoteDescription.
        if (peer.addIceCandidate.mock.calls.length !== 0) return false;

        // (4) The underlying RTCPeerConnection is torn down before
        //     the dispatcher returns. Synchronous + exactly one call.
        if (peer.close.mock.calls.length !== 1) return false;

        // (5) onFingerprintMismatch fires exactly once with the
        //     structured args.
        if (onFingerprintMismatch.mock.calls.length !== 1) return false;
        const cb = onFingerprintMismatch.mock.calls[0]?.[0] as
          | MismatchArgs
          | undefined;
        if (cb === undefined) return false;
        if (cb.callId !== CALL_ID) return false;
        if (cb.which !== which) return false;
        if (cb.cause !== 'mismatch') return false;
        if (cb.envelopeFingerprint !== envFp) return false;
        if (cb.sdpFingerprint !== sdpFp) return false;

        // (6) The accept-handlers are NEVER fired. The caller must
        //     learn of the rejected envelope only via the mismatch
        //     callback, so it cannot accidentally send back an
        //     answer / set the SDP / open the audio track.
        if (onOffer.mock.calls.length !== 0) return false;
        if (onAnswer.mock.calls.length !== 0) return false;
        // Mismatch is not a hangup envelope, so onHangup is unused.
        if (onHangup.mock.calls.length !== 0) return false;

        return true;
      }),
    );
  });

  // -------------------------------------------------------------------------
  // Sanity anchor: matching pair → dispatcher proceeds normally
  // -------------------------------------------------------------------------
  //
  // Without this anchor a regression that *always* rejected (and
  // thus trivially satisfied items 2–6 of the mismatch property)
  // would not be caught. Asserting the matching path uses the same
  // fingerprint generator so the symmetry is visible: the only
  // difference between this property and the mismatch property is
  // whether the two strings canonicalise to the same value.

  it('matching envelope/SDP fingerprint dispatches normally on both offer and answer paths', () => {
    fc.assert(
      fc.property(arbFingerprint, arbWhich, ({ fp }, which) => {
        const sdp = makeSdp(fp);
        const peer = makeFakePeer();
        const { handlers, onOffer, onAnswer, onFingerprintMismatch } =
          makeHandlers(peer);

        const innerKind =
          which === 'offer' ? InnerType.CALL_OFFER : InnerType.CALL_ANSWER;
        const result = dispatchInner(
          {
            kind: innerKind,
            callId: CALL_ID,
            sdp,
            dtlsFingerprint: fp,
          },
          handlers,
        );

        // Result is the kind-discriminator for the matched path.
        if (result.kind !== which) return false;
        if (result.callId !== CALL_ID) return false;

        // setRemoteDescription was called exactly once with the
        // peer's SDP and the right type discriminator.
        if (peer.setRemoteDescription.mock.calls.length !== 1) return false;
        const desc = peer.setRemoteDescription.mock.calls[0]?.[0] as
          | RTCSessionDescriptionInit
          | undefined;
        if (desc === undefined) return false;
        if (desc.type !== which) return false;
        if (desc.sdp !== sdp) return false;

        // close was NOT called — the dispatcher's sole `close()`
        // call site is the binding-rejection branch.
        if (peer.close.mock.calls.length !== 0) return false;

        // The mismatch callback was NOT fired.
        if (onFingerprintMismatch.mock.calls.length !== 0) return false;

        // Exactly one accept-handler fired, matching the kind. The
        // other handler was NOT fired.
        const offerCalls = onOffer.mock.calls.length;
        const answerCalls = onAnswer.mock.calls.length;
        if (which === 'offer') {
          if (offerCalls !== 1) return false;
          if (answerCalls !== 0) return false;
        } else {
          if (answerCalls !== 1) return false;
          if (offerCalls !== 0) return false;
        }

        return true;
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Symmetry property — the offer and answer paths reject identically
// ---------------------------------------------------------------------------
//
// P22 explicitly demands the property hold on *both* offer and
// answer paths. The first property above randomises across `which`,
// so each iteration covers one path; this property pairs the two
// paths on the SAME mismatch input and asserts byte-for-byte
// identical observable behaviour up to the `which` discriminator.
// A regression that rejected only one direction (e.g. a typo where
// the answer branch in `dispatchInner` skipped the helper call) is
// caught here even if the iteration count happens to land on
// `which: 'offer'` for every input that would have shrunk it.

describe('P22: fingerprint binding symmetry across offer and answer (Requirements 7.5, 21.22)', () => {
  it('offer and answer paths produce structurally identical rejections (modulo which)', () => {
    fc.assert(
      fc.property(arbDistinctPair, ({ envFp, sdpFp }) => {
        const sdp = makeSdp(sdpFp);

        const peerOffer = makeFakePeer();
        const peerAnswer = makeFakePeer();
        const offerBag = makeHandlers(peerOffer);
        const answerBag = makeHandlers(peerAnswer);

        const offerResult = dispatchInner(
          {
            kind: InnerType.CALL_OFFER,
            callId: CALL_ID,
            sdp,
            dtlsFingerprint: envFp,
          },
          offerBag.handlers,
        );
        const answerResult = dispatchInner(
          {
            kind: InnerType.CALL_ANSWER,
            callId: CALL_ID,
            sdp,
            dtlsFingerprint: envFp,
          },
          answerBag.handlers,
        );

        if (offerResult.kind !== 'fingerprint_mismatch') return false;
        if (answerResult.kind !== 'fingerprint_mismatch') return false;
        if (offerResult.which !== 'offer') return false;
        if (answerResult.which !== 'answer') return false;

        // Cause / envelope FP / SDP FP are byte-identical.
        if (offerResult.cause !== answerResult.cause) return false;
        if (
          offerResult.envelopeFingerprint !== answerResult.envelopeFingerprint
        ) {
          return false;
        }
        if (offerResult.sdpFingerprint !== answerResult.sdpFingerprint) {
          return false;
        }

        // Both peer connections were torn down identically.
        if (peerOffer.close.mock.calls.length !== 1) return false;
        if (peerAnswer.close.mock.calls.length !== 1) return false;
        if (peerOffer.setRemoteDescription.mock.calls.length !== 0) return false;
        if (peerAnswer.setRemoteDescription.mock.calls.length !== 0) {
          return false;
        }

        // Each side's own mismatch callback fired exactly once;
        // each side's accept-handlers stayed silent.
        if (offerBag.onFingerprintMismatch.mock.calls.length !== 1) return false;
        if (answerBag.onFingerprintMismatch.mock.calls.length !== 1) {
          return false;
        }
        if (offerBag.onOffer.mock.calls.length !== 0) return false;
        if (answerBag.onAnswer.mock.calls.length !== 0) return false;

        return true;
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// End — see dtls-fingerprint.test.ts for the unit-test coverage that
// complements this property suite (hand-picked counterexamples for
// the `sdp_missing` / `envelope_missing` causes, plus the full end-
// to-end `handleInboundCallEnvelope` ratchet round-trip).
// ---------------------------------------------------------------------------

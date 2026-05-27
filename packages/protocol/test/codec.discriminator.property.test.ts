// packages/protocol/test/codec.discriminator.property.test.ts
//
// P12: Discriminator robustness — for any byte buffer whose discriminator
// is outside the known enum range, `decode*` throws
// `CodecError('unknown_type')`.
//
// Validates: Requirements 12.8, 21.12.
//
// Strategy:
//   - Construct a msgpack frame whose top-level shape is otherwise
//     well-typed but whose discriminator field is a value outside the
//     enum range documented in `src/ws-messages.ts` and
//     `src/envelopes.ts`.
//   - Decode the frame and assert it throws `CodecError` with
//     `reason === 'unknown_type'`.
//
// Known discriminators (`src/ws-messages.ts` / `src/envelopes.ts`):
//   - C2S `t`:                    1, 2, 3, 4, 5, 6
//   - S2C `t`:                    101, 102, 103, 104, 199
//   - Envelope `type`:            1, 2, 3
//
// `validateEnvelopeShape` checks `type` *before* any other field
// (`src/codec.ts`), so a minimal-shape envelope with just an out-of-range
// `type` already exercises the discriminator branch — but we still send a
// fully-shaped envelope so the test would survive a future reordering of
// validation steps.

import { encode as mpEncode } from '@msgpack/msgpack';
import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  CodecError,
  decodeC2S,
  decodeEnvelope,
  decodeS2C,
} from '../src/codec.js';

describe('P12: discriminator robustness', () => {
  const KNOWN_C2S_TAGS = new Set<number>([1, 2, 3, 4, 5, 6]);
  const KNOWN_S2C_TAGS = new Set<number>([101, 102, 103, 104, 199]);
  const KNOWN_ENVELOPE_TYPES = new Set<number>([1, 2, 3]);

  const arbBadC2STag = fc
    .integer({ min: 0, max: 255 })
    .filter((n) => !KNOWN_C2S_TAGS.has(n));
  const arbBadS2CTag = fc
    .integer({ min: 0, max: 255 })
    .filter((n) => !KNOWN_S2C_TAGS.has(n));
  const arbBadEnvelopeType = fc
    .integer({ min: 0, max: 255 })
    .filter((n) => !KNOWN_ENVELOPE_TYPES.has(n));

  /** Returns `true` iff `e` is `CodecError('unknown_type')`. */
  function isUnknownType(e: unknown): boolean {
    return e instanceof CodecError && e.reason === 'unknown_type';
  }

  it('decodeC2S throws CodecError(unknown_type) on out-of-range t', () => {
    fc.assert(
      fc.property(arbBadC2STag, (t) => {
        const buf = new Uint8Array(mpEncode({ t }, { useBigInt64: true }));
        try {
          decodeC2S(buf);
          return false;
        } catch (e) {
          return isUnknownType(e);
        }
      }),
    );
  });

  it('decodeS2C throws CodecError(unknown_type) on out-of-range t', () => {
    fc.assert(
      fc.property(arbBadS2CTag, (t) => {
        const buf = new Uint8Array(mpEncode({ t }, { useBigInt64: true }));
        try {
          decodeS2C(buf);
          return false;
        } catch (e) {
          return isUnknownType(e);
        }
      }),
    );
  });

  it('decodeEnvelope throws CodecError(unknown_type) on out-of-range type', () => {
    // Static, fully-typed remainder so the only deviation from a valid
    // envelope is the out-of-range `type` discriminator.
    const sessionId = '00000000-0000-0000-0000-000000000000';
    const senderDeviceId = '11111111-1111-1111-1111-111111111111';
    const recipientDeviceId = '22222222-2222-2222-2222-222222222222';
    const ciphertext = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

    fc.assert(
      fc.property(arbBadEnvelopeType, (type) => {
        const buf = new Uint8Array(
          mpEncode(
            {
              type,
              sessionId,
              senderDeviceId,
              recipientDeviceId,
              ciphertext,
            },
            { useBigInt64: true },
          ),
        );
        try {
          decodeEnvelope(buf);
          return false;
        } catch (e) {
          return isUnknownType(e);
        }
      }),
    );
  });
});

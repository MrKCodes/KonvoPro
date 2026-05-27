// Property test P11 — frame size enforcement.
//
// Per Requirements 12.7 and 21.11 (see `.kiro/specs/konvo-platform/requirements.md`),
// the codec MUST reject any byte buffer larger than `MAX_FRAME_BYTES` (1 MiB)
// up front with `CodecError('malformed')`, *before* any msgpack parse work.
// This applies uniformly to `decodeC2S`, `decodeS2C`, and `decodeEnvelope`.
//
// **Validates: Requirements 12.7, 21.11**
//
// Generator strategy notes:
//   We deliberately avoid `fc.uint8Array({ minLength: MAX_FRAME_BYTES + 1, … })`
//   because that allocates and randomises a fresh ~1 MiB buffer on every
//   iteration, which dominates the runtime of the property suite. Instead we
//   pick a small `extra` byte count from `[1, 1024]` and allocate a single
//   zero-filled `Uint8Array` of length `MAX_FRAME_BYTES + extra`. The actual
//   byte contents are irrelevant to the property under test — the size check
//   short-circuits *before* msgpack ever sees the buffer (see `decodeMsgpack`
//   in `src/codec.ts`), so any buffer of the right length is sufficient.

import * as fc from 'fast-check';
import { describe, it } from 'vitest';

import {
  CodecError,
  MAX_FRAME_BYTES,
  decodeC2S,
  decodeEnvelope,
  decodeS2C,
} from '../src/codec.js';

describe('P11: frame size enforcement', () => {
  // Sparse arbitrary: a `Uint8Array` whose length is in
  // (MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1024]. Contents are all zeros — we
  // only care about the length triggering the size guard.
  const oversizeBuffer = fc
    .integer({ min: 1, max: 1024 })
    .map((extra) => new Uint8Array(MAX_FRAME_BYTES + extra));

  it('decodeC2S throws CodecError(malformed) on > 1 MiB buffers', () => {
    fc.assert(
      fc.property(oversizeBuffer, (buf) => {
        try {
          decodeC2S(buf);
          return false;
        } catch (e) {
          return e instanceof CodecError && e.reason === 'malformed';
        }
      }),
    );
  });

  it('decodeS2C throws CodecError(malformed) on > 1 MiB buffers', () => {
    fc.assert(
      fc.property(oversizeBuffer, (buf) => {
        try {
          decodeS2C(buf);
          return false;
        } catch (e) {
          return e instanceof CodecError && e.reason === 'malformed';
        }
      }),
    );
  });

  it('decodeEnvelope throws CodecError(malformed) on > 1 MiB buffers', () => {
    fc.assert(
      fc.property(oversizeBuffer, (buf) => {
        try {
          decodeEnvelope(buf);
          return false;
        } catch (e) {
          return e instanceof CodecError && e.reason === 'malformed';
        }
      }),
    );
  });
});

// packages/protocol/test/codec.property.test.ts
//
// P10: msgpack codec round-trip — for any well-typed `ClientToServer`,
// `ServerToClient`, or `CiphertextEnvelope` value `v`,
// `decode(encode(v))` deep-equals `v`.
//
// **Validates: Requirements 12.6, 21.10**
//
// Library: `fast-check`; ≥ 100 iterations (the global default seeded by
// `test/setup.ts` from `FAST_CHECK_RUNS`, default 100).
//
// Notes:
//   - `expect(...).toEqual(...)` performs structural deep equality and
//     compares `Uint8Array` contents byte-by-byte and `bigint` values by
//     value, so it correctly verifies the msgpack `bin` ↔ `Uint8Array`
//     and `int64` ↔ `bigint` round-trips that the codec relies on.
//   - The arbitraries in `./arbitraries.ts` mirror the wire-format
//     generators from `packages/crypto/test/arbitraries.ts`; see that
//     file's header for the rationale on inlining a copy here.

import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  decodeC2S,
  decodeEnvelope,
  decodeS2C,
  encodeC2S,
  encodeEnvelope,
  encodeS2C,
} from '../src/codec.js';

import {
  arbClientToServer,
  arbEnvelope,
  arbServerToClient,
} from './arbitraries.js';

describe('P10: msgpack codec round-trip', () => {
  it('decodeC2S(encodeC2S(v)) deep-equals v', () => {
    fc.assert(
      fc.property(arbClientToServer, (v) => {
        const decoded = decodeC2S(encodeC2S(v));
        expect(decoded).toEqual(v);
      }),
    );
  });

  it('decodeS2C(encodeS2C(v)) deep-equals v', () => {
    fc.assert(
      fc.property(arbServerToClient, (v) => {
        const decoded = decodeS2C(encodeS2C(v));
        expect(decoded).toEqual(v);
      }),
    );
  });

  it('decodeEnvelope(encodeEnvelope(v)) deep-equals v', () => {
    fc.assert(
      fc.property(arbEnvelope, (v) => {
        const decoded = decodeEnvelope(encodeEnvelope(v));
        expect(decoded).toEqual(v);
      }),
    );
  });
});

// packages/protocol/src/codec.ts
//
// msgpack wire-format codec for Konvo per design.md §7 and Requirements
// 12.5 – 12.8.
//
// Encoding rules (design.md §7):
//   - `bigint` values are encoded as msgpack `int64` (`useBigInt64: true`).
//   - `Uint8Array` values are encoded as the msgpack `bin` family.
//   - Discriminator fields (`t`, `kind`, `type`) are small positive integers
//     and are natively packed by msgpack as a single byte.
//
// Decode-side guarantees (Requirements 12.7 / 12.8):
//   - Any frame whose byte length exceeds `MAX_FRAME_BYTES` (1 MiB) is
//     rejected up front with `CodecError('malformed')` *before* the buffer
//     is handed to msgpack. The check applies to encoded output too as a
//     defense-in-depth measure.
//   - Any frame whose discriminator (`t` for WS messages, `type` for
//     envelopes, `code` for errors) is outside the documented enum range
//     is rejected with `CodecError('unknown_type')`.
//   - Every other shape mismatch (wrong field type, missing required field,
//     msgpack parse failure) is rejected with `CodecError('malformed')`.
//
// The validators are deliberately exhaustive: a `decode*` call either
// returns a value that satisfies the static type *exactly* or it throws.
//
// Library: `@msgpack/msgpack` v3.x (uses `useBigInt64: true` for native
// int64 ↔ bigint round-tripping).

import { decode as mpDecode, encode as mpEncode } from '@msgpack/msgpack';

import { EnvelopeRouterType, type CiphertextEnvelope } from './envelopes.js';
import {
  C2S,
  ErrorCode,
  S2C,
  type BroadcastPost,
  type ClientToServer,
  type ServerToClient,
} from './ws-messages.js';

/**
 * Maximum frame size accepted on encode or decode. Per Requirement 12.7 /
 * design.md §7: 1 MiB (1 * 1024 * 1024 bytes).
 */
export const MAX_FRAME_BYTES = 1 * 1024 * 1024;

/** Reasons a codec operation can fail. */
export type CodecErrorReason = 'malformed' | 'unknown_type' | 'version_mismatch';

/**
 * Sole error type thrown by every encode/decode path in this module. The
 * `reason` discriminates between size/shape failures (`malformed`),
 * unknown enum discriminators (`unknown_type`), and protocol version
 * mismatches (`version_mismatch`, reserved for future use by the WS
 * gateway HELLO handshake — see design.md §10).
 */
export class CodecError extends Error {
  public readonly reason: CodecErrorReason;
  public override readonly name = 'CodecError';

  constructor(reason: CodecErrorReason) {
    super(`codec: ${reason}`);
    this.reason = reason;
  }
}

// Shared msgpack options applied to every encode/decode (design.md §7).
// `useBigInt64: true` makes `bigint` values round-trip through msgpack
// `int64` natively, which is the wire format mandated for envelope ids.
const ENCODE_OPTIONS = { useBigInt64: true } as const;
const DECODE_OPTIONS = { useBigInt64: true } as const;

// ---------------------------------------------------------------------------
// Validation helpers — small, explicit type guards used by every decoder.
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function assertRecord(v: unknown): asserts v is Record<string, unknown> {
  if (!isRecord(v)) throw new CodecError('malformed');
}

function assertString(v: unknown): asserts v is string {
  if (typeof v !== 'string') throw new CodecError('malformed');
}

function assertInteger(v: unknown): asserts v is number {
  if (typeof v !== 'number' || !Number.isInteger(v)) throw new CodecError('malformed');
}

function assertBigInt(v: unknown): asserts v is bigint {
  if (typeof v !== 'bigint') throw new CodecError('malformed');
}

function assertBytes(v: unknown): asserts v is Uint8Array {
  if (!(v instanceof Uint8Array)) throw new CodecError('malformed');
}

function assertLiteral<T extends number>(v: unknown, expected: T): asserts v is T {
  if (v !== expected) throw new CodecError('malformed');
}

// ---------------------------------------------------------------------------
// msgpack wrappers
// ---------------------------------------------------------------------------

function encodeMsgpack(value: unknown): Uint8Array {
  // `mpEncode` returns a `Uint8Array<ArrayBuffer>`; widen to plain
  // `Uint8Array` for the public API.
  const buf: Uint8Array = mpEncode(value, ENCODE_OPTIONS);
  if (buf.byteLength > MAX_FRAME_BYTES) throw new CodecError('malformed');
  return buf;
}

function decodeMsgpack(buf: Uint8Array): unknown {
  // Per Requirement 12.7 the size check runs *before* any parsing.
  if (buf.byteLength > MAX_FRAME_BYTES) throw new CodecError('malformed');
  try {
    return mpDecode(buf, DECODE_OPTIONS);
  } catch (_err) {
    // Any parse-time failure (RangeError on truncation, DecodeError on
    // invalid msgpack bytes, etc.) collapses to `malformed`.
    throw new CodecError('malformed');
  }
}

// ---------------------------------------------------------------------------
// CiphertextEnvelope
// ---------------------------------------------------------------------------

function isEnvelopeRouterType(v: unknown): v is EnvelopeRouterType {
  return (
    v === EnvelopeRouterType.MESSAGE ||
    v === EnvelopeRouterType.ACK ||
    v === EnvelopeRouterType.CALL
  );
}

function validateEnvelopeShape(v: unknown): asserts v is CiphertextEnvelope {
  assertRecord(v);

  // `type` is the only enum-discriminator on the envelope; an out-of-range
  // value is the canonical `unknown_type` failure (Requirement 12.8).
  if (!isEnvelopeRouterType(v['type'])) throw new CodecError('unknown_type');

  assertString(v['sessionId']);
  assertString(v['senderDeviceId']);
  assertString(v['recipientDeviceId']);
  assertBytes(v['ciphertext']);

  // Server-assigned fields are optional on the C→S path.
  if (v['id'] !== undefined) assertBigInt(v['id']);
  if (v['createdAt'] !== undefined) assertInteger(v['createdAt']);
}

/** Encode a `CiphertextEnvelope` to a msgpack frame. */
export function encodeEnvelope(env: CiphertextEnvelope): Uint8Array {
  return encodeMsgpack(env);
}

/**
 * Decode a msgpack frame into a `CiphertextEnvelope`. Throws `CodecError`
 * on size, parse, or shape failure.
 */
export function decodeEnvelope(buf: Uint8Array): CiphertextEnvelope {
  const v = decodeMsgpack(buf);
  validateEnvelopeShape(v);
  return v;
}

// ---------------------------------------------------------------------------
// ClientToServer
// ---------------------------------------------------------------------------

function isC2SDiscriminator(t: unknown): t is C2S {
  return (
    t === C2S.HELLO ||
    t === C2S.SEND_ENVELOPE ||
    t === C2S.ENVELOPE_RECEIVED ||
    t === C2S.PRESENCE_PING ||
    t === C2S.SUBSCRIBE_ROOM ||
    t === C2S.UNSUBSCRIBE_ROOM
  );
}

function validateC2SShape(v: unknown): asserts v is ClientToServer {
  assertRecord(v);
  const t = v['t'];
  if (!isC2SDiscriminator(t)) throw new CodecError('unknown_type');

  switch (t) {
    case C2S.HELLO: {
      assertString(v['deviceId']);
      assertLiteral(v['protoVersion'], 1);
      return;
    }
    case C2S.SEND_ENVELOPE: {
      assertString(v['clientNonce']);
      validateEnvelopeShape(v['envelope']);
      return;
    }
    case C2S.ENVELOPE_RECEIVED: {
      assertBigInt(v['envelopeId']);
      return;
    }
    case C2S.PRESENCE_PING: {
      // No additional fields beyond the discriminator.
      return;
    }
    case C2S.SUBSCRIBE_ROOM:
    case C2S.UNSUBSCRIBE_ROOM: {
      assertString(v['slug']);
      return;
    }
  }
}

/** Encode a `ClientToServer` message to a msgpack frame. */
export function encodeC2S(msg: ClientToServer): Uint8Array {
  return encodeMsgpack(msg);
}

/**
 * Decode a msgpack frame into a `ClientToServer` message. Throws
 * `CodecError('unknown_type')` for unknown discriminators and
 * `CodecError('malformed')` for any other failure.
 */
export function decodeC2S(buf: Uint8Array): ClientToServer {
  const v = decodeMsgpack(buf);
  validateC2SShape(v);
  return v;
}

// ---------------------------------------------------------------------------
// ServerToClient
// ---------------------------------------------------------------------------

function isS2CDiscriminator(t: unknown): t is S2C {
  return (
    t === S2C.HELLO_OK ||
    t === S2C.ENVELOPE ||
    t === S2C.ENVELOPE_QUEUED ||
    t === S2C.ROOM_POST ||
    t === S2C.ERROR
  );
}

function isErrorCode(v: unknown): v is ErrorCode {
  return (
    v === ErrorCode.AUTH_REQUIRED ||
    v === ErrorCode.RATE_LIMITED ||
    v === ErrorCode.INVALID_PAYLOAD ||
    v === ErrorCode.RECIPIENT_UNKNOWN ||
    v === ErrorCode.INTERNAL
  );
}

function validateBroadcastPostShape(v: unknown): asserts v is BroadcastPost {
  assertRecord(v);
  assertBigInt(v['id']);
  assertString(v['roomId']);
  assertString(v['authorUserId']);
  assertString(v['authorHandle']);
  assertBytes(v['authorIdentityPub']);
  assertString(v['body']);
  assertBytes(v['authorSignature']);
  assertInteger(v['createdAt']);
}

function validateS2CShape(v: unknown): asserts v is ServerToClient {
  assertRecord(v);
  const t = v['t'];
  if (!isS2CDiscriminator(t)) throw new CodecError('unknown_type');

  switch (t) {
    case S2C.HELLO_OK: {
      assertInteger(v['serverTimeMs']);
      assertInteger(v['queuedCount']);
      return;
    }
    case S2C.ENVELOPE: {
      validateEnvelopeShape(v['envelope']);
      return;
    }
    case S2C.ENVELOPE_QUEUED: {
      assertString(v['clientNonce']);
      assertBigInt(v['envelopeId']);
      assertInteger(v['serverTimeMs']);
      return;
    }
    case S2C.ROOM_POST: {
      validateBroadcastPostShape(v['post']);
      return;
    }
    case S2C.ERROR: {
      // An unknown error code is structurally a malformed S→C frame: the
      // protocol enumerates a closed set of codes, so the `unknown_type`
      // verdict applies to the inner discriminator just as it does to `t`.
      if (!isErrorCode(v['code'])) throw new CodecError('unknown_type');
      assertString(v['message']);
      return;
    }
  }
}

/** Encode a `ServerToClient` message to a msgpack frame. */
export function encodeS2C(msg: ServerToClient): Uint8Array {
  return encodeMsgpack(msg);
}

/**
 * Decode a msgpack frame into a `ServerToClient` message. Throws
 * `CodecError('unknown_type')` for unknown discriminators and
 * `CodecError('malformed')` for any other failure.
 */
export function decodeS2C(buf: Uint8Array): ServerToClient {
  const v = decodeMsgpack(buf);
  validateS2CShape(v);
  return v;
}

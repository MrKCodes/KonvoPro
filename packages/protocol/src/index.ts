// @konvo/protocol — shared wire-format types and msgpack codecs.
//
// This package is the single source of truth for any byte that crosses the
// WebSocket or REST boundary between `apps/web` and `apps/api`.
//
// Layout (per design.md §2):
//   - src/envelopes.ts    — CiphertextEnvelope, InnerType, AttachmentRef, …
//   - src/ws-messages.ts  — ClientToServer, ServerToClient, BroadcastPost, …
//   - src/rest-dto.ts     — REST request / response DTOs
//   - src/codec.ts        — msgpack encode/decode (task 3.2)

export const PROTOCOL_VERSION = 1 as const;

export * from './envelopes.js';
export * from './ws-messages.js';
export * from './rest-dto.js';
export * from './codec.js';

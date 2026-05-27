// packages/protocol/src/envelopes.ts
//
// Shared wire-format envelope types per design.md §6.1.
//
// These types are the single source of truth for any byte that crosses the
// WSS or REST boundary. The server only ever sees CiphertextEnvelope; the
// inner payload (InnerPayload) is decrypted client-side and never touches
// the API_Gateway.
//
// Note on enum representation: design.md §6.1 specifies `const enum`, but
// the monorepo enables `verbatimModuleSyntax: true` (see tsconfig.base.json),
// which forbids `const enum` from crossing module boundaries. We use plain
// `enum` so the discriminator literal values (e.g. `InnerType.TEXT === 1`)
// are preserved at runtime for both encode and decode paths.

/** Discriminator for the inner plaintext payload after decryption.
 *  The server NEVER sees these values; it only sees the encrypted byte blob. */
export enum InnerType {
  TEXT = 1,
  VOICE_NOTE = 2,
  ATTACHMENT = 3,
  ACK_DELIVERED = 10,
  ACK_READ = 11,
  TYPING = 12,
  CALL_OFFER = 20,
  CALL_ANSWER = 21,
  CALL_ICE_CANDIDATE = 22,
  CALL_HANGUP = 23,
}

/** Coarse routing types — server-visible only. */
export enum EnvelopeRouterType {
  MESSAGE = 1, // any DM payload (text, voice, attachment, typing)
  ACK = 2, // delivered/read receipts
  CALL = 3, // signaling (offer/answer/ICE/hangup)
}

/** Outer envelope visible to the server (opaque ciphertext only). */
export interface CiphertextEnvelope {
  /** Server-assigned monotonic id; absent on client→server sends. */
  readonly id?: bigint;
  readonly sessionId: string; // UUID
  readonly senderDeviceId: string; // UUID
  readonly recipientDeviceId: string; // UUID
  /** A coarse type hint so the server can route ACKs vs. messages without
   *  decrypting. Does NOT reveal payload content. */
  readonly type: EnvelopeRouterType;
  /** Serialized libsignal ciphertext (PreKeySignalMessage or SignalMessage). */
  readonly ciphertext: Uint8Array;
  readonly createdAt?: number; // server-assigned ms epoch
}

/** Reference to a ciphertext blob in MinIO with the AES-GCM key material
 *  that lives ONLY inside an E2EE envelope. */
export interface AttachmentRef {
  readonly attachmentId: string; // UUID
  readonly key: Uint8Array; // 32 bytes
  readonly iv: Uint8Array; // 12 bytes
  readonly tag: Uint8Array; // 16 bytes (AES-GCM tag, if not appended)
  readonly sizeBytes: number;
}

/** Local mirror of the WebRTC `RTCIceCandidateInit` shape (lib.dom.d.ts).
 *
 *  We define this structurally rather than importing the global DOM type so
 *  the protocol package stays consumable from Node-only environments
 *  (apps/api), which do not pull in the DOM lib. The fields match the
 *  WebRTC 1.0 spec exactly so values produced by `RTCPeerConnection` in the
 *  browser can be assigned to this type without conversion. */
export interface IceCandidateInit {
  readonly candidate?: string;
  readonly sdpMid?: string | null;
  readonly sdpMLineIndex?: number | null;
  readonly usernameFragment?: string | null;
}

/** Plaintext payload (decrypted client-side, never seen by server). */
export type InnerPayload =
  | { kind: InnerType.TEXT; body: string; clientMsgId: string; sentAt: number }
  | {
      kind: InnerType.VOICE_NOTE;
      attachmentRef: AttachmentRef;
      durationMs: number;
      clientMsgId: string;
    }
  | {
      kind: InnerType.ATTACHMENT;
      attachmentRef: AttachmentRef;
      mime: string;
      name: string;
      clientMsgId: string;
    }
  | { kind: InnerType.ACK_DELIVERED; refClientMsgId: string }
  | { kind: InnerType.ACK_READ; refClientMsgId: string }
  | { kind: InnerType.TYPING; isTyping: boolean }
  | { kind: InnerType.CALL_OFFER; callId: string; sdp: string; dtlsFingerprint: string }
  | { kind: InnerType.CALL_ANSWER; callId: string; sdp: string; dtlsFingerprint: string }
  | { kind: InnerType.CALL_ICE_CANDIDATE; callId: string; candidate: IceCandidateInit }
  | {
      kind: InnerType.CALL_HANGUP;
      callId: string;
      reason: 'normal' | 'busy' | 'declined' | 'failed';
    };

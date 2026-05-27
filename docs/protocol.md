# Protocol

This doc describes the wire format Konvo uses on WSS and REST. Wire types are
the contract between the Web_Client (`apps/web`) and the API gateway
(`apps/api`); both sides import them from
[`@konvo/protocol`](../packages/protocol/src/).

## 1. Discriminator enums

### 1.1 `InnerType`

Inner-payload kind (decrypted client-side ; **never seen by the server**).
Source: [`packages/protocol/src/envelopes.ts`](../packages/protocol/src/envelopes.ts).

| Value | Name | Carries |
| --- | --- | --- |
| `1` | `TEXT` | `body: string`, `clientMsgId`, `sentAt` |
| `2` | `VOICE_NOTE` | `attachmentRef`, `durationMs`, `clientMsgId` |
| `3` | `ATTACHMENT` | `attachmentRef`, `mime`, `name`, `clientMsgId` |
| `10` | `ACK_DELIVERED` | `refClientMsgId` |
| `11` | `ACK_READ` | `refClientMsgId` |
| `12` | `TYPING` | `isTyping` |
| `20` | `CALL_OFFER` | `callId`, `sdp`, `dtlsFingerprint` |
| `21` | `CALL_ANSWER` | `callId`, `sdp`, `dtlsFingerprint` |
| `22` | `CALL_ICE_CANDIDATE` | `callId`, `candidate: IceCandidateInit` |
| `23` | `CALL_HANGUP` | `callId`, `reason: 'normal' \| 'busy' \| 'declined' \| 'failed'` |

Note on TypeScript representation: the implementation uses plain `enum` (not
`const enum`) so the discriminator literal values are preserved at runtime
across module boundaries. The monorepo enables `verbatimModuleSyntax: true`,
which forbids `const enum` exports.

### 1.2 `EnvelopeRouterType` (server-visible)

The single discriminator the API gateway is allowed to inspect on a routed
envelope. Coarse enough to route ACKs vs. messages without decrypting,
narrow enough to reveal nothing about the inner payload.

| Value | Name | Used for |
| --- | --- | --- |
| `1` | `MESSAGE` | any DM payload (text, voice, attachment, typing) |
| `2` | `ACK` | delivered/read receipts |
| `3` | `CALL` | signaling (offer/answer/ICE/hangup) |

### 1.3 `C2S` (client → server WS frames)

Source: [`packages/protocol/src/ws-messages.ts`](../packages/protocol/src/ws-messages.ts).

| Value | Name |
| --- | --- |
| `1` | `HELLO` |
| `2` | `SEND_ENVELOPE` |
| `3` | `ENVELOPE_RECEIVED` |
| `4` | `PRESENCE_PING` |
| `5` | `SUBSCRIBE_ROOM` |
| `6` | `UNSUBSCRIBE_ROOM` |

### 1.4 `S2C` (server → client WS frames)

| Value | Name |
| --- | --- |
| `101` | `HELLO_OK` |
| `102` | `ENVELOPE` |
| `103` | `ENVELOPE_QUEUED` |
| `104` | `ROOM_POST` |
| `199` | `ERROR` |

### 1.5 `ErrorCode`

| Value | Name | When |
| --- | --- | --- |
| `1` | `AUTH_REQUIRED` | missing/expired token, HELLO mismatch |
| `2` | `RATE_LIMITED` | per-device SEND_ENVELOPE token bucket exhausted |
| `3` | `INVALID_PAYLOAD` | codec error, oversize frame, sender mismatch |
| `4` | `RECIPIENT_UNKNOWN` | `recipientDeviceId` not found |
| `99` | `INTERNAL` | unexpected server-side failure |

## 2. Envelope shapes

### 2.1 `CiphertextEnvelope` (the only shape the server sees)

```ts
interface CiphertextEnvelope {
  readonly id?: bigint;                  // server-assigned monotonic id
  readonly sessionId: string;            // UUID
  readonly senderDeviceId: string;       // UUID — MUST match the connection's deviceId
  readonly recipientDeviceId: string;    // UUID
  readonly type: EnvelopeRouterType;     // MESSAGE | ACK | CALL
  readonly ciphertext: Uint8Array;       // libsignal PreKeySignalMessage or SignalMessage
  readonly createdAt?: number;           // server-assigned ms epoch
}
```

Invariants enforced by the gateway
([`apps/api/src/ws/gateway.ts`](../apps/api/src/ws/gateway.ts)):

- `senderDeviceId === ctx.deviceId` (failure → `INVALID_PAYLOAD`).
- `type ∈ EnvelopeRouterType` (failure → `INVALID_PAYLOAD`).
- `ciphertext` is **opaque** — never logged, never persisted in plaintext,
  never inspected.

### 2.2 `InnerPayload` (decrypted client-side)

`InnerPayload` is the discriminated union of plaintext payloads carried
inside `ciphertext`. The full type lives in
[`envelopes.ts`](../packages/protocol/src/envelopes.ts) ; see §1.1 above
for the discriminator values.

The server NEVER reconstructs an `InnerPayload`. It only ever sees the
opaque `Uint8Array` produced by libsignal.

### 2.3 `AttachmentRef`

Reference to a ciphertext blob in MinIO with the AES-GCM key material that
lives ONLY inside an E2EE envelope.

```ts
interface AttachmentRef {
  readonly attachmentId: string;   // UUID
  readonly key: Uint8Array;        // 32 bytes — never sent to the server in plaintext
  readonly iv: Uint8Array;         // 12 bytes
  readonly tag: Uint8Array;        // 16 bytes (AES-GCM tag)
  readonly sizeBytes: number;
}
```

The MinIO blob carries the ciphertext only ; `key` and `iv` and `tag` ride
inside another libsignal-encrypted envelope.

### 2.4 `IceCandidateInit`

Structural mirror of the WebRTC `RTCIceCandidateInit` shape — defined here
so `@konvo/protocol` stays consumable from Node-only environments
(`apps/api`) without pulling in the DOM lib.

```ts
interface IceCandidateInit {
  readonly candidate?: string;
  readonly sdpMid?: string | null;
  readonly sdpMLineIndex?: number | null;
  readonly usernameFragment?: string | null;
}
```

Every ICE candidate is wrapped inside an E2EE
`InnerType.CALL_ICE_CANDIDATE` payload before transmission.

### 2.5 `BroadcastPost` (server → client fan-out)

```ts
interface BroadcastPost {
  readonly id: bigint;
  readonly roomId: string;
  readonly authorUserId: string;
  readonly authorHandle: string;
  readonly authorIdentityPub: Uint8Array;   // for client-side signature verification
  readonly body: string;                    // plaintext (broadcast rooms are public)
  readonly authorSignature: Uint8Array;     // 64 bytes Ed25519 over (body || roomId || createdAt)
  readonly createdAt: number;
}
```

Viewers run `verifyBroadcastPost` against `authorIdentityPub` and render a
verified or red-unverified badge based on the result.

## 3. msgpack codec

Implementation:
[`packages/protocol/src/codec.ts`](../packages/protocol/src/codec.ts).

```ts
export function encodeC2S(msg: ClientToServer): Uint8Array;
export function decodeC2S(buf: Uint8Array): ClientToServer;
export function encodeS2C(msg: ServerToClient): Uint8Array;
export function decodeS2C(buf: Uint8Array): ServerToClient;

export function encodeEnvelope(env: CiphertextEnvelope): Uint8Array;
export function decodeEnvelope(buf: Uint8Array): CiphertextEnvelope;

export class CodecError extends Error {
  constructor(
    public readonly reason: 'malformed' | 'unknown_type' | 'version_mismatch',
  );
}
```

### 3.1 Encoding rules

- `bigint` → msgpack `int64` (extType where needed). Used for envelope `id`
  and `BroadcastPost.id`.
- `Uint8Array` → msgpack `bin` family.
- Discriminated unions encode the discriminator (`t` for WS frames, `kind`
  for `InnerPayload`) as a `uint8` field for compactness.
- Object keys are stable across encode/decode round trips. Property order is
  not significant.

### 3.2 Frame size limit

Maximum frame size: **1 MiB**. Anything larger is rejected at the codec
layer with `CodecError('malformed')` ; the WS gateway maps this onto
`S2C.ERROR { code: INVALID_PAYLOAD }`.

For attachments the wire path is the multipart `POST /attachments`
endpoint, NOT a WS frame ; the multipart limit is 25 MiB.

### 3.3 Discriminator robustness

A buffer whose discriminator value is outside the known enum range is
rejected with `CodecError('unknown_type')`. This prevents a malicious peer
from smuggling unrecognised envelope types through future-version
mismatches.

## 4. Cryptographic header layout (Phase-3 ratchet)

Konvo's Phase-3 ratchet ships a structured header alongside the
libsignal-style ciphertext. The header is exactly 40 bytes, big-endian:

```
+---------+---------+---------+---------+---------+---------+---------+---------+
|        DH public key (32 bytes, Curve25519)                                  |
+---------+---------+---------+---------+---------+---------+---------+---------+
| prevChainLength (uint32)            | messageNumber (uint32)                |
+-------------------------------------+---------------------------------------+
```

Field semantics:

- **DH public key (32 bytes)** — the sender's current ratchet DH public key.
  A change in this field signals a DH ratchet step on the receiver.
- **`prevChainLength`** — number of messages sent in the previous sending
  chain, used to compute skipped-key ranges.
- **`messageNumber`** — counter within the current sending chain ; drives
  per-message key derivation.

The encrypted ciphertext follows the header. Tamper rejection is enforced
by libsignal's authenticated encryption tag — single-byte mutation anywhere
in the header or ciphertext yields
`DecryptError { kind: 'invalid_message' }`.

When libsignal-client is wired in a later phase the structured header is
replaced by libsignal's opaque `SignalMessage` byte buffer ; the wire shape
of the outer `CiphertextEnvelope.ciphertext` does not change.

## 5. Property invariants the protocol must satisfy

The properties below are exercised on every CI run via fast-check ; the
catalogue with test file paths lives in [`testing.md`](./testing.md) and the
attacker-class mapping in [`security.md`](./security.md).

| ID | Property | Test file |
| --- | --- | --- |
| P10 | msgpack codec round-trip | `packages/protocol/test/codec.property.test.ts` |
| P11 | frame size enforcement (>1 MiB rejected) | `packages/protocol/test/codec.frame-size.property.test.ts` |
| P12 | discriminator robustness (unknown type rejected) | `packages/protocol/test/codec.discriminator.property.test.ts` |

## 6. Versioning

`HELLO` carries `protoVersion: 1`. The gateway rejects any other value with
`S2C.ERROR { code: INVALID_PAYLOAD }`. Future protocol versions will bump
the constant and gate behaviour from the HELLO_OK reply.

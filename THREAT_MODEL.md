# Konvo Threat Model

This document describes the assets Konvo protects, the trust boundaries it
operates across, the attacker classes it defends against, and what is
explicitly out of scope. It is the human-readable canonical security model
for the project.

The complete property → attacker-class map (P1–P23) lives in
[`docs/security.md`](./docs/security.md) §5. Architecture context lives in
[`docs/architecture.md`](./docs/architecture.md).

## 1. Scope

Konvo is a self-hosted, web-first PWA with two distinct conversation modes:

- **End-to-end encrypted 1:1 direct messages.** Text, voice notes, file/image
  attachments, and audio + video calls. All cryptography uses libsignal
  (X3DH for session establishment, Double Ratchet for per-message
  encryption). The server is engineered as a **blind router**: it stores
  opaque `ciphertext_envelopes` rows and AES-GCM ciphertext blobs, and
  never holds plaintext DM content, plaintext attachment bytes, or DM call
  media.
- **Public broadcast rooms.** Plaintext posts cryptographically signed by
  the author's Ed25519 identity key, plus optional live A/V via LiveKit
  SFU. Broadcast content is intentionally not E2EE — the security property
  here is **author authenticity**, not confidentiality.

What Konvo **claims**:

- **Confidentiality of DM content** against the server, the database
  operator, the network, and any third party. Verified by P1 (round-trip),
  P3 (tamper rejection), P18 (plaintext non-leakage).
- **Forward secrecy and post-compromise security** for DMs (P4, P5).
- **Authenticity of broadcast posts** (P19, P20).
- **Authenticated, tamper-evident DM call setup** with DTLS-fingerprint
  binding (P22, P23).
- **Per-device key isolation** — losing one device does not compromise
  other devices' future messages.

What Konvo **does not** claim:

- **Metadata privacy.** The server learns who talks to whom and when
  (sender device, recipient device, sizes, timestamps).
- **Endpoint security.** A compromised browser sandbox is treated as a
  compromised account.
- **Account recovery.** There is no email recovery; losing all devices
  means losing E2EE history.

## 2. Assets

| Asset | Where it lives | Protection |
| --- | --- | --- |
| Identity Curve25519 keypair (X25519) | Wrapped in IndexedDB on the device only | AES-KW under a non-extractable WebCrypto key; never serialized to JSON or logs |
| Ed25519 signing key (broadcast post / SPK signature) | Wrapped in IndexedDB on the device only | Same wrapping as identity keypair |
| libsignal Double Ratchet sessions (root key, chain keys, DH privkeys, skipped keys) | IndexedDB via the `SignalProtocolStore` adapter | Consumed message keys are deleted after each ratchet step |
| Signed prekey + one-time prekeys (private halves) | IndexedDB on the device | Public halves uploaded; private halves never leave the device |
| Per-attachment AES-GCM 256-bit key + 96-bit IV | Inside the E2EE inner payload of a `CiphertextEnvelope` | Never sent to the server in cleartext |
| DM ciphertext envelopes (`ciphertext_envelopes.ciphertext`) | Postgres | Opaque to the server; never decrypted, logged, or echoed in error responses |
| DM attachment ciphertext blobs | MinIO (private bucket, no presigned URLs) | Server has ciphertext only; AES-GCM key material is in a different envelope |
| Refresh token | httpOnly, Secure, SameSite=Lax cookie client-side; hashed server-side | Rotated on every use; reuse triggers full revocation |
| Access token (JWT, 15 min) | In-memory in the Web_Client only | Never persisted to localStorage/sessionStorage |
| Web Push subscription (endpoint + p256dh + auth) | Postgres | Push payloads carry only `{type, senderHandle, conversationId}` — never plaintext or ciphertext |
| Argon2id password hash | Postgres | `m=64 MiB, t=3, p=4`; hash never logged |
| TOTP secret | Postgres, encrypted at rest | Validated server-side; never echoed in errors |
| LiveKit publisher / viewer JWTs | Issued per request, TTL 3600 s | Scoped to `{room, role}`; not reusable cross-room |
| coturn TURN credentials | Issued per device, TTL 3600 s | Ephemeral REST-issued username/password |
| Key-export backup file | User-downloaded blob | Encrypted with passphrase-derived key via Argon2id |

## 3. Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TB1 — Browser / device (TRUSTED for content confidentiality)            │
│   • Crypto module (libsignal wrapper)                                   │
│   • IndexedDB (Dexie): identity privkey (wrapped), ratchet state,       │
│                        prekeys, outbox, cached plaintext                │
│   • Service Worker (Workbox): offline shell, push handler               │
│   • WebRTC PeerConnection (DM calls; SRTP keyed via DTLS)               │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ TLS 1.2+ / WSS  (TB3: network)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TB2 — Server (HONEST-BUT-CURIOUS for DMs, TRUSTED for availability      │
│        and broadcast room state)                                        │
│   • Caddy (auto-TLS, HSTS, CSP)                                         │
│   • Fastify API gateway + WS gateway (blind router for DM envelopes)    │
│   • Postgres 16 (metadata, ciphertext_envelopes, broadcast posts)       │
│   • Redis 7 (pub/sub fan-out, presence, rate-limit token buckets)       │
│   • MinIO (private bucket, E2EE attachment ciphertext only)             │
│   • coturn (STUN/TURN relay; relays SRTP, cannot decrypt)               │
│   • LiveKit SFU (broadcast rooms only — never DMs)                      │
└─────────────────────────────────────────────────────────────────────────┘
```

The server is treated as **honest-but-curious** for DMs (it follows the
protocol but its operator may inspect anything it persists) and **untrusted
for content confidentiality** but **trusted for availability, ordering
hints, and broadcast-room state**.

External boundaries:

- **Browser sandbox.** Trusted for confidentiality only as far as the
  browser's same-origin policy and IndexedDB isolation hold. A compromised
  origin equals a compromised account.
- **Web Push provider** (FCM, APNs-relay, Mozilla autopush). Untrusted ;
  sees only `{type, senderHandle, conversationId}`.
- **Operator of self-hosted infrastructure.** Has the same powers as a
  malicious server (see §4.1) — by design.

## 4. Attacker models

### 4.1 Malicious server / hosting provider

**Powers.** Read all Postgres rows, all MinIO blobs, all log lines, all
routed envelopes, and all in-transit WSS frames after TLS termination at
Caddy. Can drop, delay, or reorder envelopes. Can modify ciphertext bytes
in transit or at rest.

**What they get.**

- Public keys for every device (`devices.identity_pub`, signed prekeys, OPK
  public halves).
- DM **metadata**: sender device, recipient device, timing, envelope sizes,
  router type (`MESSAGE` / `ACK` / `CALL`).
- All public broadcast room content.
- Encrypted attachment blobs (ciphertext only).
- Argon2id password hashes (offline cracking subject to Argon2id
  parameters).

**What they don't get.**

- **Plaintext DM bodies.** Verified by P1 (round-trip soundness), P3
  (tamper rejection without leak), P18 (no plaintext bytes in any
  log/metric/error), and the integration-level
  greppable-plaintext check across DB and MinIO that returns zero matches.
- **Plaintext attachment bytes.** AES-GCM key material lives only inside
  another E2EE envelope ; MinIO holds only ciphertext.
- **DM call media.** WebRTC media is DTLS-SRTP between browsers ; coturn
  relays only encrypted SRTP. The server is never a media endpoint for
  DMs.
- **Identity privkeys / ratchet state.** These never leave the browser.
- **Forged broadcast posts.** Posts are Ed25519-signed by the author's
  identity key ; viewers verify with `verifyBroadcastPost` (P19, P20).

**Mitigations.**

- Blind-router architecture and discriminated `EnvelopeRouterType`
  (`MESSAGE | ACK | CALL`) — coarse enough to route, narrow enough to
  reveal nothing about payload content.
- Logger redaction layer recursively strips `ciphertext`, `body`,
  `password`, `token`, `key`, `privateKey`, `identityPriv`, `secret`,
  `argon2Hash` at any depth before write.
- Postgres connection enforces TLS with no non-TLS fallback in production.

### 4.2 Malicious peer (Mallory in a DM)

**Powers.** Holds a valid X3DH session with the victim. Can send arbitrary
ciphertexts, replay old ciphertexts, attempt single-byte mutations, send
out-of-order messages, attempt to exhaust the skipped-message store.

**What they get.** Whatever the victim sends to them inside the active
session.

**What they don't get.**

- **Tampered messages accepted as valid.** libsignal AEAD authenticates
  every ciphertext ; mutations produce
  `DecryptError { kind: 'invalid_message' }` with no plaintext leak (P3).
- **Replays accepted twice.** The Crypto module returns
  `DecryptError { kind: 'duplicate' }` on second attempt and advances
  ratchet state exactly once (P6).
- **The ability to forge messages from a third party.** Each ciphertext is
  bound to the sender's ratchet, which is bound to the X3DH handshake,
  which is bound to the sender's identity key.
- **Past messages after re-compromise.** Forward secrecy : consumed
  message keys and superseded chain keys are deleted (P4).
- **Future messages after a brief past compromise.** Post-compromise
  security : a fresh DH ratchet step rederives chain keys from a new
  shared secret combined with the existing root key (P5).

**Mitigations.**

- libsignal Double Ratchet authenticated encryption (P3).
- Idempotent decryption with state advance-exactly-once (P6).
- Out-of-order delivery within K ≤ 1000 (P7) plus FIFO eviction beyond
  that with a user-visible "messages were lost" notice.
- TOFU first-contact and Safety_Number verification. On identity change,
  outbound sends pause until the user explicitly accepts or rejects.

### 4.3 Lost or stolen device

**Powers.** Holds the full IndexedDB of a single device — the wrapped
identity privkey, all ratchet sessions, prekey state, outbox, and any
cached plaintext.

**What they get.**

- All cached plaintext on that device.
- The ability to impersonate that device until its identity is revoked.

**What they don't get.**

- **Other devices' future or past messages.** Per-device sessions: each
  browser has its own identity keypair, signed prekey, and OPK set ;
  revoking one device does not affect the others.
- **Plaintext of an exported backup without the passphrase.** Backups are
  encrypted with a passphrase-derived key via Argon2id `m=64 MiB, t=3,
  p=4` ; cleartext export is forbidden.
- **Future messages from peers after the victim performs a DH ratchet
  step.** Post-compromise security (P5) means once peers exchange one
  more round, the stolen ratchet state stops being useful for new
  messages on that chain.

**Mitigations.**

- Per-device identity revocation via `DELETE /devices/:id`, which revokes
  the session, deletes remaining OPKs, and surfaces a Safety_Number
  change to peers.
- Optional TOTP at login as a second factor. A stolen device that has
  been logged out still requires both password and TOTP (where enabled)
  to obtain new tokens.
- Wrapped identity privkey at rest (AES-KW under non-extractable
  WebCrypto key) raises the bar for forensic extraction from a casually
  compromised device — but is not a defence against a determined attacker
  with the device.

**Explicit acceptance:** there is no email recovery. Losing all devices
means losing E2EE history. Surfaced as a confirm-checkbox during signup.

### 4.4 Network attacker (passive and active)

**Powers.**

- *Passive:* observe all bytes between browser and Caddy, between browser
  and coturn, and between browser and LiveKit.
- *Active:* drop, delay, reorder, inject, or attempt MITM on any of those
  flows.

**What they get.**

- TLS-encrypted WSS / HTTPS frames. Sizes and timings are visible (traffic
  analysis).
- DTLS-encrypted SRTP for DM calls. Packet sizes and timings are visible.

**What they don't get.**

- **Plaintext at any layer.** Two encryption layers stack for DMs :
  libsignal ciphertext is itself wrapped in TLS ; even if TLS were broken,
  the inner libsignal layer remains.
- **Successful MITM.** TLS handshakes are validated against the
  Caddy-served certificate ; HSTS `max-age=63072000; includeSubDomains;
  preload` prevents downgrade ; CSP `connect-src 'self' wss: turns:
  <livekit-host>` prevents script-injected exfiltration.
- **A `ws://` connection.** Caddy refuses it.
- **Cross-site request forgery on state-changing endpoints.** Double-submit
  CSRF token required for POST / PUT / PATCH / DELETE.
- **Plaintext ICE candidates.** Each DM ICE candidate travels inside an
  E2EE envelope ; routed CALL envelopes contain zero candidate strings in
  plaintext (P23).
- **Successful DTLS MITM on a DM call.** The DTLS fingerprint is bound to
  the E2EE-signed offer/answer ; mismatch terminates the call before any
  RTP/SRTP packet is processed (P22).

**Mitigations.**

- Caddy auto-TLS via Let's Encrypt ; HTTP→HTTPS redirect.
- HSTS preload.
- Strict CSP.
- DTLS-fingerprint binding on every CALL_OFFER / CALL_ANSWER (P22).
- Per-device, per-socket rate limits prevent active attackers from
  amplifying through Konvo (P16).

## 5. Out of scope (explicit non-goals)

These are accepted by the design and surfaced to users where relevant. They
are **not** bugs.

1. **Metadata privacy.** The server sees who talks to whom and when. There
   is no onion routing, no sealed-sender, and no traffic-shape padding in
   the MVP.
2. **Endpoint security.** A compromised browser process, malicious browser
   extension, OS keylogger, or screen recorder is equivalent to a
   compromised account. Konvo cannot defend the device against itself.
3. **TOFU is best-effort, not blocking.** The Web_Client accepts a peer
   device's identity key on first contact and only warns on later change.
   Until a Safety_Number is verified out-of-band, a sufficiently
   positioned active attacker present at the moment of first contact
   could mount a MITM. The UI surfaces this — it does not silently hide
   it.
4. **No email-based account recovery.** Losing all devices = losing E2EE
   history.
5. **Group DMs are not supported in MVP.** Only 1:1 DMs and public
   broadcast rooms.
6. **Broadcast rooms are public, not E2EE.** Posts are signed plaintext
   stored in Postgres. Live A/V is via LiveKit SFU ; LiveKit sees the
   stream. Broadcast guarantees authenticity, not confidentiality.
7. **No call recording.** DM calls are never recorded server-side.
8. **No third-party analytics or telemetry SDKs.** First-party Prometheus
   metrics only.
9. **Password-hash offline cracking is bounded only by Argon2id
   parameters** (`m=64 MiB, t=3, p=4`). A weak user password remains a
   weak user password.
10. **Subpoena / legal compulsion against the operator** can yield
    everything in §4.1's "what they get" column, and nothing in its "what
    they don't get" column. This is the same as a malicious server.

## 6. Property test mapping

The full property → attacker-class map (P1–P23) lives in
[`docs/security.md` §5](./docs/security.md). Each property is a fast-check
suite that runs on every CI build (default ≥100 iterations ; nightly ≥500
for tamper / forward-secrecy properties).

## 7. References

- [`docs/architecture.md`](./docs/architecture.md) — system topology, trust
  boundaries, end-to-end data flows.
- [`docs/security.md`](./docs/security.md) — full security map, hardening
  posture, P1–P23 catalogue with attacker-class mappings.
- [`docs/data-model.md`](./docs/data-model.md) — what is and is not stored
  in Postgres / MinIO / IndexedDB.
- [`docs/protocol.md`](./docs/protocol.md) — wire format, msgpack codec
  rules, ratchet header layout.
- [`docs/api-reference.md`](./docs/api-reference.md) — REST endpoints + WSS
  frame types with auth posture and error codes.

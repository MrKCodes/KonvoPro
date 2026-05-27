# Security

This document is the canonical security model for Konvo: the assets it
protects, the trust boundaries it operates across, the attacker classes it
defends against, and the property tests that back each guarantee.

## 1. What Konvo claims and does not claim

### 1.1 Claims (each verified by a property test ; see §5)

- **Confidentiality of DM content** against the server, the database
  operator, the network, and any third party.
- **Forward secrecy** — past messages remain unreadable if the device is
  later compromised.
- **Post-compromise security** — future messages become unreadable to an
  attacker who briefly compromised an old chain key, after both peers
  perform one DH ratchet step.
- **Authenticity of broadcast posts** — Ed25519 signatures by the author's
  identity key, verified client-side.
- **Authenticated, tamper-evident DM call setup** — DTLS-fingerprint binding
  on every call ; mismatch terminates the call before any RTP/SRTP packet.
- **Per-device key isolation** — losing one device does not compromise other
  devices' future messages.

### 1.2 Does NOT claim

- **Metadata privacy.** The server learns who talks to whom and when
  (sender device, recipient device, sizes, timestamps).
- **Endpoint security.** A compromised browser sandbox is treated as a
  compromised account.
- **Account recovery.** There is no email recovery — losing all devices
  means losing E2EE history.

## 2. Trust boundaries

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
protocol but its operator may inspect anything it persists) and
**untrusted for content confidentiality** but **trusted for availability,
ordering hints, and broadcast-room state**.

External boundaries:

- **Browser sandbox.** Trusted only as far as same-origin policy and
  IndexedDB isolation hold. A compromised origin equals a compromised
  account.
- **Web Push provider** (FCM, APNs-relay, Mozilla autopush). Untrusted ;
  sees only `{type, senderHandle, conversationId}`.
- **Operator of self-hosted infrastructure.** Has the same powers as a
  malicious server (see §3.1) — by design.

## 3. Attacker models

### 3.1 Malicious server / hosting provider

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
- Argon2id password hashes (offline cracking subject to Argon2id parameters).

**What they don't get.**

- **Plaintext DM bodies.** Verified by P1 (round-trip), P3 (tamper rejection
  with no leak), P18 (no plaintext bytes in any log/metric/error).
- **Plaintext attachment bytes.** AES-GCM key material lives only inside
  another E2EE envelope ; MinIO holds ciphertext only.
- **DM call media.** WebRTC media is DTLS-SRTP between browsers ; coturn
  relays only encrypted SRTP. The server is never a media endpoint for DMs.
- **Identity privkeys / ratchet state.** Never leave the browser.
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

### 3.2 Malicious peer (Mallory in a DM)

**Powers.** Holds a valid X3DH session with the victim. Can send arbitrary
ciphertexts, replay old ciphertexts, attempt single-byte mutations, send
out-of-order messages, attempt to exhaust the skipped-message store.

**What they get.** Whatever the victim sends to them inside the active
session.

**What they don't get.**

- **Tampered messages accepted as valid** — libsignal AEAD authenticates
  every ciphertext ; mutations produce `DecryptError { kind:
  'invalid_message' }` with no plaintext leak (P3).
- **Replays accepted twice** — the Crypto module returns
  `DecryptError { kind: 'duplicate' }` on second attempt and advances
  ratchet state exactly once (P6).
- **Forge messages from a third party** — each ciphertext is bound to the
  sender's ratchet, which is bound to the X3DH handshake, which is bound
  to the sender's identity key.
- **Past messages after re-compromise** — forward secrecy ; consumed
  message keys and superseded chain keys are deleted (P4).
- **Future messages after a brief past compromise** — post-compromise
  security ; a fresh DH ratchet step rederives chain keys (P5).

**Mitigations.**

- libsignal Double Ratchet authenticated encryption (P3).
- Idempotent decryption with state advance-exactly-once (P6).
- Out-of-order delivery within K ≤ 1000 (P7) plus FIFO eviction beyond that
  with a user-visible "messages were lost" notice.
- TOFU first-contact and Safety_Number verification. On identity change,
  outbound sends pause until the user explicitly accepts or rejects the
  new safety number.

### 3.3 Lost or stolen device

**Powers.** Holds the full IndexedDB of a single device — the wrapped
identity privkey, all ratchet sessions, prekey state, outbox, and any
cached plaintext.

**What they get.**

- All cached plaintext on that device.
- The ability to impersonate that device until its identity is revoked.

**What they don't get.**

- **Other devices' future or past messages** — per-device sessions ; each
  browser has its own identity keypair, signed prekey, and OPK set.
- **Plaintext of an exported backup without the passphrase** — backups are
  encrypted with a passphrase-derived key via Argon2id `m=64 MiB t=3 p=4`.
- **Future messages from peers after the victim performs a DH ratchet
  step** — post-compromise security (P5).

**Mitigations.**

- Per-device identity revocation via `DELETE /devices/:id`, which revokes
  the session, deletes remaining OPKs, and surfaces a Safety_Number change
  to peers.
- Optional TOTP at login as a second factor.
- Wrapped identity privkey at rest (AES-KW under non-extractable WebCrypto
  key) — raises the bar for forensic extraction but is not a defence
  against a determined attacker with the device.

**Explicit acceptance:** there is no email recovery. Losing all devices
means losing E2EE history. Surfaced as a confirm-checkbox during signup.

### 3.4 Network attacker (passive and active)

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

- **Plaintext at any layer.** Two encryption layers stack for DMs:
  libsignal ciphertext is itself wrapped in TLS.
- **Successful MITM.** TLS validated against Caddy's cert ; HSTS preload
  prevents downgrade ; CSP `connect-src 'self' wss: turns: <livekit>`
  prevents script-injected exfiltration.
- **A `ws://` connection.** Caddy refuses it.
- **Cross-site request forgery on state-changing endpoints** — double-submit
  CSRF token required for POST / PUT / PATCH / DELETE.
- **Plaintext ICE candidates** — every DM ICE candidate travels inside an
  E2EE envelope ; routed CALL envelopes contain zero candidate strings in
  plaintext (P23).
- **Successful DTLS MITM on a DM call** — DTLS fingerprint bound to the
  E2EE-signed offer/answer ; mismatch terminates the call before any
  RTP/SRTP packet is processed (P22).

**Mitigations.**

- Caddy auto-TLS via Let's Encrypt ; HTTP→HTTPS redirect.
- HSTS preload (`max-age=63072000; includeSubDomains; preload`).
- Strict CSP.
- DTLS-fingerprint binding on every CALL_OFFER / CALL_ANSWER.
- Per-device, per-socket rate limits prevent active attackers from
  amplifying through Konvo.

## 4. Out of scope (explicit non-goals)

These are accepted by the design and surfaced to users where relevant. They
are NOT bugs.

1. **Metadata privacy.** No onion routing, no sealed-sender, no
   traffic-shape padding in the MVP.
2. **Endpoint security.** A compromised browser process, malicious
   extension, OS keylogger, or screen recorder is equivalent to a
   compromised account.
3. **TOFU is best-effort, not blocking.** The Web_Client accepts a peer
   device's identity key on first contact and only warns on later change.
   A sufficiently positioned active attacker present at the moment of
   first contact could mount a MITM. The UI surfaces this — it does not
   silently hide it.
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
9. **Password-hash offline cracking is bounded only by Argon2id parameters**
   (`m=64 MiB, t=3, p=4`). A weak user password remains a weak user
   password.
10. **Subpoena / legal compulsion against the operator** can yield
    everything in §3.1's "what they get" column, and nothing in its "what
    they don't get" column. This is the same as a malicious server.

## 5. Property → attacker class map

Each property is a fast-check suite that runs on every CI build (default
≥100 iterations ; nightly ≥500 for tamper / forward-secrecy properties).

| # | Property | Test file | Defends against |
| --- | --- | --- | --- |
| P1 | E2EE round-trip (text) | `packages/crypto/test/p1-e2ee-roundtrip.property.test.ts` | Malicious server (3.1) — plaintext never traverses the server intact |
| P2 | E2EE round-trip (attachments) | `packages/crypto/test/p2-attachment-roundtrip.property.test.ts` | Malicious server (3.1) — plaintext never enters MinIO |
| P3 | Tamper rejection | `packages/crypto/test/p3-tamper-rejection.property.test.ts` | Malicious server (3.1), malicious peer (3.2), network attacker (3.4) |
| P4 | Forward secrecy | `packages/crypto/test/p4-forward-secrecy.property.test.ts` | Lost/stolen device (3.3), malicious peer (3.2) |
| P5 | Post-compromise security | `packages/crypto/test/p5-post-compromise.property.test.ts` | Lost/stolen device (3.3), malicious peer (3.2) |
| P6 | Idempotent decryption | `packages/crypto/test/p6-idempotent-decryption.property.test.ts` | Malicious peer replay ; malicious server re-injection |
| P7 | Out-of-order delivery | `packages/crypto/test/p7-out-of-order.property.test.ts` | Malicious peer reorder ; network attacker reorder |
| P8 | Safety-number determinism + symmetry | `packages/crypto/test/safety-number.test.ts` | Network attacker MITM — both peers compute the same digits |
| P9 | Safety-number sensitivity | `packages/crypto/test/safety-number.test.ts` | Network attacker MITM — single-bit identity-key change ⇒ different digits |
| P10 | msgpack codec round-trip | `packages/protocol/test/codec.property.test.ts` | Defensive depth — rules out codec confusion bugs that could break P3/P18 |
| P11 | Frame-size enforcement | `packages/protocol/test/codec.frame-size.property.test.ts` | Malicious peer ; network attacker — DoS resistance |
| P12 | Discriminator robustness | `packages/protocol/test/codec.discriminator.property.test.ts` | Malicious server / peer cannot smuggle unknown frame types |
| P13 | Idempotent envelope delivery | `apps/api/test/idempotent-envelope.property.test.ts` | Network attacker replay ; malicious server re-injection |
| P14 | Recipient isolation | `apps/api/test/recipient-isolation.property.test.ts` | Malicious server cross-delivery ; cross-thread eavesdrop |
| P15 | Offline queue completeness | `apps/api/test/offline-queue-completeness.property.test.ts` | Malicious server drop/reorder ; network attacker drop |
| P16 | Rate limit conservation | `apps/api/test/rate-limit-conservation.property.test.ts` | Malicious peer ; network attacker — amplification / DoS resistance |
| P17 | Sender authentication | `apps/api/test/sender-authentication.property.test.ts` | Malicious peer cannot spoof the sender device id |
| P18 | Plaintext non-leakage | `apps/api/test/plaintext-non-leakage.property.test.ts` | Malicious server ; subpoena scenario — no plaintext in any log/metric/error |
| P19 | Broadcast signature soundness | `packages/crypto/test/broadcast.property.test.ts` | Malicious server cannot forge a verified post |
| P20 | Broadcast signature completeness | `packages/crypto/test/broadcast.completeness.property.test.ts` | Malicious server / network attacker cannot mutate posts undetected |
| P21 | Admin-only post enforcement | `apps/api/test/broadcast-admin-only.property.test.ts` | Malicious peer cannot impersonate admin posting privilege |
| P22 | DTLS fingerprint binding | `apps/web/test/fingerprint-binding.property.test.ts` | Network attacker cannot DTLS-MITM a DM call |
| P23 | ICE candidate confidentiality | `apps/api/test/ice-candidate-confidentiality.property.test.ts` | Malicious server cannot enumerate peer endpoints |

## 6. Hardening posture

| Layer | Enforcement | Where |
| --- | --- | --- |
| TLS 1.2+ ; HTTP→HTTPS redirect | Caddy auto-TLS via Let's Encrypt | `infra/caddy/Caddyfile` |
| HSTS `max-age=63072000; includeSubDomains; preload` | Caddy + helmet (defence in depth) | `apps/api/src/server.ts` |
| Strict CSP | helmet-managed in `apps/api/src/server.ts` | `apps/api/src/server.ts` |
| `ws://` refused at edge | Caddyfile | `infra/caddy/Caddyfile` |
| CSRF double-submit on every state-changing route | `services/auth/csrf.ts` | `apps/api/src/services/auth/csrf.ts` |
| Per-IP rate limits (`/auth/*`, `/auth/refresh`) | `@fastify/rate-limit` per route config | `apps/api/src/routes/auth.ts` |
| Per-device WS rate limit (50 burst / 10 sustained per second) | token bucket | `apps/api/src/ws/rate-limit.ts` |
| Argon2id `m=64 MiB t=3 p=4` ; boot benchmark alert | `services/auth/argon2.ts` | `apps/api/src/services/auth/argon2.ts` |
| Refresh-token rotation + reuse-revoke-all | `services/auth/tokens.ts` | `apps/api/src/services/auth/tokens.ts` |
| Logger redaction (recursive) | `obs/logger.ts` | `apps/api/src/obs/logger.ts` |
| Postgres TLS-only in production | zod schema | `apps/api/src/config.ts` |
| MinIO private bucket ; no presigned URLs for E2EE blobs | S3 client | `apps/api/src/storage/minio.ts` |
| `: any` ban in production source | CI gate 1 (eslint + grep) | `.github/workflows/ci.yml` |

## 7. Privacy acceptances surfaced to users

These are design choices, not bugs. The user-facing surfaces that
acknowledge them:

- **Recovery-loss notice on signup** — explicit checkbox-confirmed; signup
  cannot complete without the user accepting that losing all devices means
  losing E2EE history.
- **TOFU first-contact notice** — surfaced in DM-thread UI on first contact
  with a peer device.
- **Identity-changed banner** — outbound sends pause until the user
  explicitly accepts or rejects the new safety number.
- **No third-party analytics or telemetry SDKs** — first-party Prometheus
  metrics only.

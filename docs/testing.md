# Testing Strategy

Konvo's tests are arranged in four layers : unit, property-based, integration,
and end-to-end. Each layer answers a distinct question.

## 1. Layers

| Layer | Library | Question it answers |
| --- | --- | --- |
| Unit | vitest | Does this function compute the right value for the typical case? |
| Property-based | fast-check | Does this function obey its specified invariant for ALL inputs in the generator's domain? |
| Integration | vitest + fastify-light + ephemeral docker stack | Does the wiring across services hold under realistic data flow? |
| End-to-end | Playwright (headless Chromium) | Does the user-visible behaviour hold across two real browser contexts? |

## 2. Per-workspace coverage

| Workspace | Files | Tests | Notes |
| --- | --- | --- | --- |
| `@konvo/crypto` | 16 | 92 | properties P1, P2, P3, P4, P5, P6, P7, P8, P9, P19, P20 |
| `@konvo/protocol` | 3 | 9 | properties P10, P11, P12 |
| `@konvo/api` | 35 | 319 | properties P13–P18, P21, P23 |
| `@konvo/web` | 28 | 263 | property P22 |
| `@konvo/e2e` | 14 specs / 21 tests | live-gated | runs under `KONVO_E2E_LIVE=1` against the docker-compose stack |

## 3. Property-based tests (P1–P23)

fast-check is the property library. Every property runs ≥100 iterations on
each CI build (gate 6) and ≥500 iterations on the nightly cron job. When a
generator is finite, fast-check exhausts it and exits ; when it's
unbounded, fast-check shrinks any failure to the smallest counterexample.

Generators :

- `arbCurve25519KeyPair` — fresh keypair via libsignal.
- `arbPlaintext(min, max)` — random `Uint8Array`.
- `arbSession(arbA, arbB)` — pair of stores with completed X3DH.
- `arbEnvelope` — well-formed `CiphertextEnvelope` with arbitrary
  ciphertext bytes.
- `arbWSMessage` — discriminated-union generator for `ClientToServer` /
  `ServerToClient`.

### 3.1 Catalogue

#### Cryptography (`@konvo/crypto`)

| ID | Property | Validates |
| --- | --- | --- |
| **P1** | E2EE round-trip (text) — for all `m` of length 1..16384, `decrypt_B(encrypt_A→B(m)) === m` | DM text confidentiality |
| **P2** | E2EE round-trip (attachments) — `decryptAttachment(encryptAttachment(b)) === b` for `b` ∈ [1, 25 MiB] | DM attachment confidentiality |
| **P3** | Tamper rejection — single-byte mutation of a valid ciphertext yields `invalid_message`; no plaintext leaks | DM authenticity |
| **P4** | Forward secrecy — compromise of ratchet state at message N cannot derive keys for messages 1..N-1 | Forward secrecy |
| **P5** | Post-compromise security — after one fresh DH ratchet step, an old chain key cannot decrypt new messages | Post-compromise security |
| **P6** | Idempotent decryption — exactly one `ok: true` per ciphertext ; subsequent attempts return `duplicate` | Replay protection |
| **P7** | Out-of-order delivery — any permutation of K ≤ 1000 ciphertexts decrypts each to its plaintext exactly once | Reordering robustness |
| **P8** | Safety-number determinism + symmetry — `compute(A,B) === compute(B,A)` ; result is stable across calls | Safety-number contract |
| **P9** | Safety-number sensitivity — single-bit identity-key change ⇒ different digits | MITM detection |
| **P19** | Broadcast signature soundness — a valid signature verifies | Broadcast authenticity |
| **P20** | Broadcast signature completeness — any tamper of body/roomId/createdAt/signature/key ⇒ verification fails | Broadcast tamper detection |

#### Protocol (`@konvo/protocol`)

| ID | Property | Validates |
| --- | --- | --- |
| **P10** | msgpack codec round-trip — `decodeC2S(encodeC2S(v))` deep-equals `v` ; same for S2C | Codec correctness |
| **P11** | Frame size enforcement — buffers > 1 MiB throw `CodecError('malformed')` | DoS resistance |
| **P12** | Discriminator robustness — out-of-range discriminators throw `CodecError('unknown_type')` | Future-version safety |

#### Server behaviour (`@konvo/api`)

| ID | Property | Validates |
| --- | --- | --- |
| **P13** | Idempotent envelope delivery — `(senderDeviceId, clientNonce)` deduplicates ; exactly one row, exactly one fan-out publish | Replay protection |
| **P14** | Recipient isolation — fan-out only to `recipientDeviceId` ; never cross-delivered | Routing safety |
| **P15** | Offline queue completeness — N envelopes sent while offline ⇒ exactly N replayed in `created_at` order, no losses, no duplicates | Offline reliability |
| **P16** | Rate limit conservation — at most 50 SEND_ENVELOPE accepted per device per second ; excess rejected with `RATE_LIMITED` | DoS resistance |
| **P17** | Sender authentication — `envelope.senderDeviceId` MUST equal connection `deviceId` ; mismatch ⇒ `INVALID_PAYLOAD`, no row | Spoof resistance |
| **P18** | Plaintext non-leakage — no log line, metric label, or error response contains envelope ciphertext bytes | Subpoena-safe logging |
| **P21** | Admin-only post enforcement — non-admin POSTs to `/rooms/:slug/messages` return 403 | Authorization |
| **P23** | ICE candidate confidentiality — every candidate inside an E2EE envelope ; zero plaintext candidates in CALL logs | Endpoint privacy |

#### Calls (`@konvo/web`)

| ID | Property | Validates |
| --- | --- | --- |
| **P22** | DTLS fingerprint binding — fingerprint mismatch terminates the call before any RTP/SRTP packet | DTLS MITM resistance |

The attacker-class mapping for each property lives in
[`security.md` §5](./security.md).

## 4. Integration tests

Integration specs sit under `e2e/*.integration.spec.ts`. They exercise the
full wiring against the docker-compose data plane and self-skip when
`KONVO_E2E_LIVE` is unset (so a developer can run the full Playwright
suite without docker-compose, getting unit + property + e2e-only-ish
coverage). CI gate 7 sets the env to `1` and runs them live :

- `db-redaction.integration.spec.ts` — plaintext canaries sent over E2EE
  DMs do not appear in Postgres or MinIO ; one-byte tamper of an inbound
  envelope yields the inert UI placeholder within 2 s.
- `offline-queue.integration.spec.ts` — ≥10 envelopes are delivered exactly
  once within 30 s of reconnect.
- `attachments-no-leak.integration.spec.ts` — plaintext canaries inside an
  image attachment and a voice note never appear in Postgres or MinIO.
- `broadcast-live.integration.spec.ts` — audio-only and audio+video paths ;
  both viewers receive the admin stream.

## 5. End-to-end tests (Playwright)

The full e2e suite (gate 8) runs 14 spec files / 21 tests across two
browser contexts. The gate enforces zero failed AND zero skipped — the
JSON reporter output is parsed by `jq` to enforce the zero-skipped clause.

Notable specs :

- `signup-and-login.spec.ts` — auth flow soup-to-nuts.
- `dm-send.spec.ts` — Alice → Bob and Bob → Alice E2EE messages render as
  plaintext on the recipient and never leak to Postgres.
- `voice-note.spec.ts` — Alice records a voice note, Bob plays it back,
  MinIO blob is encrypted.
- `attachment.spec.ts` — Alice uploads an image, Bob decrypts and renders
  it.
- `video-call.spec.ts` — Alice ↔ Bob video call connects, holds for 60 s,
  safety numbers match, hangup tears down.
- `tamper.e2e.spec.ts` — one-byte mutation of an inbound envelope yields
  the inert "decryption-failed" placeholder within 2 s ; remains
  responsive ; no crash.
- `broadcast-post.spec.ts` — admin posts ; viewer renders signed post with
  verified badge.
- `broadcast-live.spec.ts` — admin goes live (A+V) ; viewer receives both
  streams.
- `pwa-install.spec.ts` — install prompt, SW registration, offline reload
  < 3 s, push opens correct thread, Lighthouse PWA ≥ 90.
- `push-offline-delivery.spec.ts` — offline Bob receives a metadata-only
  notification on Alice→Bob DM ; tap opens correct thread.

## 6. How to run them

```bash
# Unit + property only (fast feedback loop ; no docker required).
pnpm test

# Just the property suites at the daytime cadence (≥100 iterations).
pnpm -r run test:property

# Property suites at the nightly cadence (≥500 iterations).
FAST_CHECK_RUNS=500 pnpm -r run test:property

# Integration + e2e (needs the dev stack running).
docker compose -f infra/docker-compose.yml up -d
KONVO_E2E_LIVE=1 pnpm -F @konvo/e2e test
```

## 7. Tamper / rotation tests

Two tests are MUST-HAVE :

- **Tamper test** — encrypt → flip one byte of ciphertext → decrypt MUST
  fail with `invalid_message`, MUST NOT produce garbage plaintext, MUST
  NOT crash. Implemented as the P3 property suite plus
  `e2e/tamper.e2e.spec.ts`.
- **Key rotation test** — complete N messages → simulate compromise (export
  ratchet state) → A and B each ratchet → attacker with old state cannot
  decrypt new messages. Implemented as the P5 property suite.

## 8. Why property-based testing matters here

E2EE correctness is hard to argue for case-by-case. The property
formulation flips the proof obligation : instead of writing test cases the
developer believes are representative, you state the invariant ("for any
plaintext `m` of length 1..16384, round-trip preserves `m`") and let
fast-check search for a counterexample. A failure in P3 reduces to a
single-byte mutation index ; a failure in P7 reduces to a permutation that
breaks out-of-order delivery. The reduced counterexample is then committed
as a regression test.

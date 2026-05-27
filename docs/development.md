# Development

This doc covers the local dev loop, the test cadences, the CI gates, and the
contribution conventions Konvo enforces.

## 1. Prerequisites

- **Node.js ≥ 20.10**
- **pnpm ≥ 9**
- **Docker** with the Compose plugin (for the data plane)
- A free port set : `80`, `443`, `3000`, `5173`, `3478/udp`, `7880`–`7882`

## 2. Local dev loop

```bash
# 1. Install every workspace.
pnpm install

# 2. Configure API secrets.
cp apps/api/.env.example apps/api/.env

# 3. Bring up postgres / redis / minio / livekit / coturn / caddy / observability.
docker compose -f infra/docker-compose.yml up -d

# 4. Run the API gateway (auto-migrates).
pnpm -F @konvo/api dev          # http://localhost:3000

# 5. In a second terminal, run the PWA.
pnpm -F @konvo/web dev          # http://localhost:5173
```

Open http://localhost:5173, sign up two profiles in two browser windows,
exchange a message. The first thread surfaces a TOFU first-contact notice
— that is by design (see [`security.md` §7](./security.md)).

For deployment-side concerns (env vars, TLS, backup) see
[`deployment.md`](./deployment.md).

## 3. Workspace commands

Run from the repo root.

```bash
pnpm typecheck                          # tsc --noEmit across every workspace
pnpm lint                               # eslint --max-warnings=0 across every workspace
pnpm format                             # prettier --check
pnpm test                               # unit + property suites across every workspace

# Per workspace:
pnpm -F @konvo/crypto test
pnpm -F @konvo/protocol test
pnpm -F @konvo/api test
pnpm -F @konvo/web test

# Property suites only :
pnpm -r run test:property               # default ≥100 fast-check iterations
FAST_CHECK_RUNS=500 pnpm -r run test:property   # nightly cadence

# Playwright e2e (needs the dev stack running) :
pnpm -F @konvo/e2e test:list
pnpm -F @konvo/e2e test
```

The `test:property` script in each workspace points fast-check at a
`setup.ts` that reads `FAST_CHECK_RUNS` and configures the iteration count
globally.

## 4. CI gates

The pipeline lives in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
Eight sequential gates run on every push, every PR against `main`, and on
manual dispatches from the Actions tab. Each is wired via `needs:` so any
failure fails the build immediately :

| # | Gate | Enforces |
| --- | --- | --- |
| 1 | typecheck | `tsc --noEmit` across every workspace + grep guard forbidding `: any` annotations in production source |
| 2 | lint | `eslint --max-warnings=0` across every workspace |
| 3 | format | `pnpm -r exec prettier --check .` |
| 4 | audit | `pnpm audit --prod --audit-level=high` and `osv-scanner -r .` ; build fails on any `high` finding |
| 5 | unit | `pnpm -r run test:unit` |
| 6 | property | `pnpm -r run test:property` with `FAST_CHECK_RUNS=100` |
| 7 | integration | docker-compose stack + `*.integration.spec.ts` Playwright specs under `KONVO_E2E_LIVE=1` |
| 8 | e2e | docker-compose stack + full Playwright suite ; **zero failed AND zero skipped** required |

Triggers:

- `push` to any branch.
- `pull_request` against `main`.
- `schedule` at 04:00 UTC daily — runs only the nightly ≥500-iteration
  property job.
- `workflow_dispatch` (manual via the Actions tab) — runs gates 1–8 by
  default. Toggling the `run_nightly` boolean input also fires the
  ≥500-iteration property job alongside.

Concurrency: in-flight runs for the same branch / PR are cancelled on
re-push so re-pushing doesn't queue redundant pipelines.

## 5. Conventions

### 5.1 Strict TypeScript

- `"strict": true` ; `verbatimModuleSyntax: true` ; no implicit `any`.
- The `: any` annotation is BANNED in production source under `apps/*/src`
  and `packages/*/src`. Both eslint
  (`@typescript-eslint/no-explicit-any`) and a CI grep guard enforce this ;
  fixtures and shims under `test/` are exempt.
- All async functions return `Promise<T>` with explicit `T`. Errors are
  typed discriminated unions when failure modes matter for the caller (e.g.
  `DecryptError`) ; otherwise thrown.

### 5.2 Identifiers

- `camelCase` for variables / functions
- `PascalCase` for types / classes
- `SCREAMING_SNAKE_CASE` for env vars

### 5.3 Module boundaries

See [`code-structure.md` §9](./code-structure.md). The boundaries are not
suggestions — `packages/protocol` cannot import `@konvo/crypto`,
`@konvo/api` cannot import `@konvo/web`, and so on.

### 5.4 Crypto rules

- libsignal is the SOLE provider of session/ratchet primitives. No custom
  crypto.
- WebCrypto `subtle` for AES-GCM attachment encryption.
- Identity privkeys are AES-KW-wrapped via a non-extractable WebCrypto KEK.
- Cleartext keys MUST NEVER be serialized through `JSON.stringify` or
  `console.log`. The logger redaction layer
  ([`obs/logger.ts`](../apps/api/src/obs/logger.ts)) is the safety net ;
  the `: any` ban is the type-system net.

### 5.5 Logging rules

The redaction layer recursively strips these field names at any depth
BEFORE write : `ciphertext`, `body`, `password`, `token`, `key`,
`privateKey`, `identityPriv`, `secret`, `argon2Hash`.

The plaintext-non-leakage property test
([`apps/api/test/plaintext-non-leakage.property.test.ts`](../apps/api/test/plaintext-non-leakage.property.test.ts))
verifies that no log line, metric label, or error response contains the
bytes of `envelope.ciphertext`.

### 5.6 Env validation

All env-loaded secrets validated at boot via a zod schema in
[`apps/api/src/config.ts`](../apps/api/src/config.ts). Missing or empty
values fail fast — the API exits with status 1 BEFORE the listener opens.

`.env` is gitignored ; `apps/api/.env.example` is committed and updated
whenever a new env var lands.

## 6. Adding a dependency

Konvo's audit gate fails on any `high` severity finding. Before adding a
dependency :

- Prefer well-known, actively-maintained packages.
- Pin exact versions (or at minimum a `^x.y.z` minor range) ; never use
  open ranges.
- Run `pnpm audit --prod --audit-level=high` locally before committing.
- If the dependency is in `apps/*` it must work under the strict CSP
  (`script-src 'self' 'wasm-unsafe-eval'`). No remote-fetched code at
  runtime.

## 7. Where to read more

- [`testing.md`](./testing.md) — testing strategy, per-PBT description,
  what each property validates.
- [`api-reference.md`](./api-reference.md) — REST + WSS endpoint catalogue.
- [`protocol.md`](./protocol.md) — wire format details.
- [`security.md`](./security.md) — security map (P1–P23 ↔ attacker classes).
- [`deployment.md`](./deployment.md) — docker-compose stack and operational
  checklist.

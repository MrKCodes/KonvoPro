# Konvo — Documentation Set

This is the canonical documentation for the Konvo platform. Every doc here is
self-contained — together they describe the architecture, data model, wire
format, security posture, deployment, dev loop, and testing strategy without
depending on any other source.

If you're reading this for the first time, start with
[`architecture.md`](./architecture.md). Then dive into whichever doc matches
the task you're working on.

## Table of contents

| Doc | What you'll learn |
| --- | --- |
| [`architecture.md`](./architecture.md) | System topology, trust boundaries, blind-router invariant, end-to-end data flows for DM send, broadcast post, voice/image attachments, 1:1 calls, and broadcast live A/V. |
| [`code-structure.md`](./code-structure.md) | Monorepo layout, per-workspace responsibilities, public API surfaces, module-boundary rules, build/test commands. |
| [`data-model.md`](./data-model.md) | Postgres schema (every table, column, index, retention rule), MinIO bucket posture, and the Dexie/IndexedDB client schema. |
| [`api-reference.md`](./api-reference.md) | REST endpoints + WSS frame types with request/response shapes, auth posture, error codes. |
| [`protocol.md`](./protocol.md) | Wire format details: envelope types, msgpack codec rules, frame size limits, ratchet header layout. |
| [`security.md`](./security.md) | Threat model, attacker classes, asset catalogue, and the property-test → attacker-class map (P1–P23). |
| [`deployment.md`](./deployment.md) | docker-compose stack, environment variables, TLS posture, observability, backup/restore. |
| [`development.md`](./development.md) | Local dev setup, test execution, CI gates, contribution conventions. |
| [`testing.md`](./testing.md) | Testing strategy: unit, property-based (P1–P23 catalogued), integration, e2e. |

## Conventions used in these docs

- Cross-references between docs use **relative paths** so the docs work in a
  GitHub render, in a local clone, and in any rendered docs site.
- Mermaid diagrams are used for architecture, sequence flows, and state
  machines.
- "Server" means the Fastify API gateway (`apps/api`) and the data plane it
  fronts (Postgres, Redis, MinIO, coturn, LiveKit). "Client" means the React
  PWA (`apps/web`) running in a single browser profile, which is also a
  "device" in libsignal terms.
- "DM" means a 1:1 end-to-end encrypted direct message. "Broadcast" means a
  Telegram-style public room with Ed25519-signed plaintext posts and
  optional live A/V via LiveKit SFU.
- Property invariants (P1–P23) are catalogued in
  [`testing.md`](./testing.md). Each property is exercised by a fast-check
  suite that runs on every CI build.

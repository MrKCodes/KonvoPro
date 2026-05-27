# Legacy

Archived Django prototype, replaced by greenfield TypeScript monorepo per `design.md`.

This directory holds the original Django skeleton (`manage.py`, the `Konvo/` settings
module, and the `chat/` app) that predates the current Konvo platform design. It is
retained as a historical reference only.

- Not part of any build, lint, or test pipeline.
- Not deployed by `infra/docker-compose.yml`.
- Not imported by `apps/web`, `apps/api`, `packages/protocol`, or `packages/crypto`.

For the active implementation, see `apps/` and `packages/`. Developer-facing
documentation lives in [`../docs/`](../docs/).

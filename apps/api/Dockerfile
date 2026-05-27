# apps/api/Dockerfile
#
# Multi-stage build for the Konvo Fastify API. Builds the workspace
# packages (`@konvo/protocol`, `@konvo/crypto`) and `@konvo/api`,
# then uses `pnpm deploy --prod` to materialise a self-contained
# tree (with all transitive workspace deps copied in, not symlinked
# into the pnpm virtual store) for the runtime image.
#
# Build context MUST be the repo root, not apps/api — this image
# needs pnpm-workspace.yaml and the workspace package sources.
# The compose file passes `context: ..` for that reason.

# -----------------------------------------------------------------------------
# Stage 1 — install + build
# -----------------------------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

# Native build deps for argon2's C++ addon.
RUN apk add --no-cache python3 make g++ linux-headers

# Pin pnpm to the version declared in package.json packageManager.
RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

# Copy workspace manifests first so install can be cached when only
# sources change.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/protocol/package.json packages/protocol/
COPY packages/crypto/package.json packages/crypto/
COPY e2e/package.json e2e/

# Install everything; needed because we still have to TypeScript-compile
# the workspace packages, which need their devDependencies.
RUN pnpm install --frozen-lockfile --ignore-scripts

# Bring in sources for the packages we actually compile.
COPY packages/protocol packages/protocol
COPY packages/crypto packages/crypto
COPY apps/api apps/api

# Build the workspace packages the api depends on, then the api.
RUN pnpm -F @konvo/protocol build \
 && pnpm -F @konvo/crypto build \
 && pnpm -F @konvo/api build

# `pnpm deploy --prod` flattens the api into /deploy with every
# transitive workspace dep COPIED (not symlinked) into the local
# node_modules. The result is self-contained and works with plain
# `node`.
RUN pnpm deploy --filter=@konvo/api --prod /deploy

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM node:20-alpine AS runtime
WORKDIR /app

# wget for the compose healthcheck; tini for clean signal handling.
RUN apk add --no-cache wget tini

# Copy only the deployed app — already includes dist/ + node_modules/
# with every workspace dep flattened in.
COPY --from=build /deploy ./

ENV NODE_ENV=production
EXPOSE 3000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]

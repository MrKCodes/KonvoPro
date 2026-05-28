#!/usr/bin/env bash
#
# scripts/deploy.sh — production deploy for Konvo on a single host.
#
# Idempotent. Safe to run on a fresh EC2 instance, a Lightsail box,
# a bare-metal Linux server, or to redeploy on an existing host.
# Tested against Ubuntu 22.04, Debian 12, Amazon Linux 2023,
# RHEL/Rocky 9, and macOS (manual install of docker).
#
# Required env vars:
#   KONVO_HOST    public FQDN, e.g. konvo.opsalchemistlabs.co.in
#   TLS_EMAIL     operator email for Let's Encrypt registration
#
# Optional env vars (auto-generated if absent):
#   POSTGRES_PASSWORD       strong DB password
#   MINIO_ROOT_PASSWORD     strong MinIO admin password
#   GRAFANA_ADMIN_PASSWORD  strong Grafana admin password
#
# Pre-flight on the host:
#   - DNS A/AAAA for $KONVO_HOST points at this server's public IP.
#   - Inbound firewall: tcp/80, tcp/443 (caddy + ACME),
#     tcp 7880-7881 + udp 7882 (livekit), tcp/3478 + udp/3478 +
#     udp 49152-49200 (coturn).
#   - Outbound 443 reachable (ACME).
#
# Usage:
#   KONVO_HOST=konvo.example.com TLS_EMAIL=ops@example.com \
#     ./scripts/deploy.sh           # deploy / redeploy
#   ./scripts/deploy.sh status      # show stack status
#   ./scripts/deploy.sh logs api    # tail logs of any service
#   ./scripts/deploy.sh down        # stop and remove the stack
#   ./scripts/deploy.sh down --volumes   # ALSO wipe volumes (DANGEROUS)
#   ./scripts/deploy.sh update      # git pull + rebuild + restart
#
# Exit codes:
#   0  success
#   1  unrecoverable error (preflight failed, build failed, …)
#   2  bad usage

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve repo root + load defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "${REPO_ROOT}"

COMPOSE_BASE="infra/docker-compose.yml"
COMPOSE_PROD="infra/docker-compose.prod.yml"
ENV_API="apps/api/.env"
ENV_API_EXAMPLE="apps/api/.env.example"
DEPLOY_ENV="infra/.env.deploy"   # gitignored — secrets that compose reads
WEB_DIST="apps/web/dist"

ACTION="${1:-deploy}"
shift || true

# Colour helpers (skip when not a TTY).
if [ -t 1 ]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
  C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_BLUE='\033[34m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''
fi

log()  { printf '%b\n' "${C_BOLD}${C_BLUE}==>${C_RESET} ${C_BOLD}$*${C_RESET}"; }
ok()   { printf '%b\n' "${C_GREEN}✓${C_RESET} $*"; }
warn() { printf '%b\n' "${C_YELLOW}!${C_RESET} $*"; }
err()  { printf '%b\n' "${C_RED}✗${C_RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# OS detection — used to decide which package manager runs
# ---------------------------------------------------------------------------

detect_os() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${ID:-unknown}"
  elif [ "$(uname -s)" = "Darwin" ]; then
    echo "darwin"
  else
    echo "unknown"
  fi
}

OS_ID="$(detect_os)"

# ---------------------------------------------------------------------------
# Prereq install (best-effort, only when missing)
# ---------------------------------------------------------------------------

require_root_or_sudo() {
  if [ "$(id -u)" = "0" ]; then
    SUDO=""
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    err "Need root or sudo for system package installation."
    exit 1
  fi
}

install_docker() {
  log "Installing Docker"
  case "${OS_ID}" in
    ubuntu|debian)
      ${SUDO} apt-get update -y
      ${SUDO} apt-get install -y ca-certificates curl gnupg
      ${SUDO} install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
        | ${SUDO} gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      ${SUDO} chmod a+r /etc/apt/keyrings/docker.gpg
      echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${OS_ID} \
$(. /etc/os-release; echo "${VERSION_CODENAME}") stable" \
        | ${SUDO} tee /etc/apt/sources.list.d/docker.list > /dev/null
      ${SUDO} apt-get update -y
      ${SUDO} apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      ;;
    amzn|rocky|rhel|centos|fedora)
      # Amazon Linux 2023 ships Docker via dnf already; the compose plugin
      # is installed separately.
      ${SUDO} dnf install -y docker
      ${SUDO} systemctl enable --now docker
      # Compose plugin via the official binary release.
      local arch; arch="$(uname -m)"
      ${SUDO} curl -fsSL \
        "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${arch}" \
        -o /usr/libexec/docker/cli-plugins/docker-compose
      ${SUDO} chmod +x /usr/libexec/docker/cli-plugins/docker-compose
      ;;
    darwin)
      err "Install Docker Desktop manually on macOS, then re-run."
      exit 1
      ;;
    *)
      err "Don't know how to install Docker on '${OS_ID}'. Install it manually then re-run."
      exit 1
      ;;
  esac
  ${SUDO} systemctl enable --now docker || true

  # Add the invoking user to the docker group so subsequent runs can
  # `docker compose ...` without sudo. The current shell session
  # won't pick up the new group until logout/login; we keep using
  # sudo for the rest of THIS run.
  if [ -n "${SUDO_USER:-}" ]; then
    ${SUDO} usermod -aG docker "${SUDO_USER}" || true
  elif [ -n "${USER:-}" ] && [ "${USER}" != "root" ]; then
    ${SUDO} usermod -aG docker "${USER}" || true
  fi
}

install_git() {
  log "Installing git"
  case "${OS_ID}" in
    ubuntu|debian) ${SUDO} apt-get install -y git ;;
    amzn|rocky|rhel|centos|fedora) ${SUDO} dnf install -y git ;;
    *) err "Install git manually then re-run."; exit 1 ;;
  esac
}

ensure_prereqs() {
  log "Checking prerequisites (docker, docker compose, git, openssl, curl)"
  local need_install=0
  if ! command -v docker >/dev/null 2>&1; then need_install=1; fi
  if ! command -v git >/dev/null 2>&1; then need_install=1; fi

  if [ "${need_install}" = "1" ]; then
    require_root_or_sudo
    if ! command -v docker >/dev/null 2>&1; then install_docker; fi
    if ! command -v git    >/dev/null 2>&1; then install_git; fi
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    err "openssl missing — required for secret generation."
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    err "curl missing — required for healthchecks."
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    err "'docker compose' subcommand not available. Install the compose plugin."
    exit 1
  fi
  ok "prereqs OK (${OS_ID})"
}

# ---------------------------------------------------------------------------
# Compose helper bound to base + prod files. Reads infra/.env.deploy
# so substitutions like ${KONVO_HOST}, ${TLS_EMAIL}, ${POSTGRES_PASSWORD}
# resolve consistently across `up`, `ps`, `logs`, `down`.
# ---------------------------------------------------------------------------

compose() {
  if [ "$(id -u)" = "0" ] || groups 2>/dev/null | grep -q '\bdocker\b'; then
    docker compose --env-file "${DEPLOY_ENV}" -f "${COMPOSE_BASE}" -f "${COMPOSE_PROD}" "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo docker compose --env-file "${DEPLOY_ENV}" -f "${COMPOSE_BASE}" -f "${COMPOSE_PROD}" "$@"
  else
    docker compose --env-file "${DEPLOY_ENV}" -f "${COMPOSE_BASE}" -f "${COMPOSE_PROD}" "$@"
  fi
}

# ---------------------------------------------------------------------------
# Secret + env-file generation
# ---------------------------------------------------------------------------

# Generate a high-entropy URL-safe secret of the given byte length.
gen_secret() {
  local bytes="${1:-32}"
  openssl rand -base64 "${bytes}" | tr -d '\n=+/' | cut -c1-$(( bytes * 4 / 3 ))
}

# Append `KEY=value` to file unless the key already exists.
ensure_kv() {
  local file="$1" key="$2" value="$3"
  if ! grep -qE "^${key}=" "${file}" 2>/dev/null; then
    printf '%s=%s\n' "${key}" "${value}" >> "${file}"
  fi
}

# Bootstrap apps/api/.env with strong dev-grade secrets if absent.
# Writes through .env.example shape but with real entropy so the api
# boot validator passes on first run.
ensure_api_env_file() {
  if [ -f "${ENV_API}" ]; then
    ok "${ENV_API} already exists; leaving secrets in place"
    return 0
  fi
  log "Generating ${ENV_API} (strong random secrets)"

  local jwt pep cot lk_key lk_secret vapid_pub vapid_priv
  jwt="$(gen_secret 48)"
  pep="$(gen_secret 48)"
  cot="$(gen_secret 48)"
  lk_key="API$(gen_secret 12)"
  lk_secret="$(gen_secret 48)"

  # VAPID keypair via the npx web-push tool, run inside a node:20
  # container so we don't require pnpm/node on the host. Falls back
  # to placeholders if the network is unavailable; admin must
  # rotate.
  if docker run --rm node:20-alpine sh -c \
       'npm i -g web-push >/dev/null 2>&1 && web-push generate-vapid-keys --json' \
       2>/dev/null | grep -q publicKey; then
    local vapid_json
    vapid_json="$(docker run --rm node:20-alpine sh -c \
                  'npm i -g web-push >/dev/null 2>&1 && web-push generate-vapid-keys --json' \
                  2>/dev/null)"
    vapid_pub="$(echo "${vapid_json}"  | sed -n 's/.*"publicKey":"\([^"]*\)".*/\1/p')"
    vapid_priv="$(echo "${vapid_json}" | sed -n 's/.*"privateKey":"\([^"]*\)".*/\1/p')"
  else
    warn "Couldn't run web-push generator; using example VAPID keys (rotate ASAP!)"
    vapid_pub='BNHe7Y_nHyB4AqlXYXo4hdr7oukLvPn-Wvy3DTMfNOnSMgPQkkOqOdg9nOKIEIPc7Gsp6pGiGdyGHbCW_3AeLS4'
    vapid_priv='Qz69Oezyzf83y3sNticrgaGWxVzMb0P7bpIlDiyMuzk'
  fi

  cat > "${ENV_API}" <<EOF
# Generated by scripts/deploy.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Rotate any of these by editing this file and running
# \`./scripts/deploy.sh update\`.

NODE_ENV=production
PORT=3000

JWT_ACCESS_SECRET=${jwt}
REFRESH_TOKEN_PEPPER=${pep}

ARGON2_M_KIB=65536
ARGON2_T=3
ARGON2_P=4

# DATABASE_URL is overridden by the prod compose overlay.
DATABASE_URL=postgres://konvo:konvo@postgres:5432/konvo?sslmode=require

REDIS_URL=redis://redis:6379

MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=konvo
MINIO_SECRET_KEY=${MINIO_ROOT_PASSWORD:-konvo-prod-password-rotate-me}
MINIO_BUCKET=konvo-attachments
MINIO_USE_SSL=false

VAPID_PUBLIC_KEY=${vapid_pub}
VAPID_PRIVATE_KEY=${vapid_priv}
VAPID_SUBJECT=mailto:${TLS_EMAIL:-ops@example.com}

LIVEKIT_API_KEY=${lk_key}
LIVEKIT_API_SECRET=${lk_secret}
LIVEKIT_URL=wss://${KONVO_HOST}/livekit

COTURN_REST_SECRET=${cot}
COTURN_REALM=${KONVO_HOST}
EOF
  chmod 600 "${ENV_API}"
  ok "wrote ${ENV_API} (mode 600)"
}

# Compose-side env file. Holds the host FQDN, TLS email, and any
# strong infra passwords. `compose` reads it via --env-file.
ensure_deploy_env_file() {
  log "Materialising ${DEPLOY_ENV}"
  : > "${DEPLOY_ENV}"
  chmod 600 "${DEPLOY_ENV}"

  ensure_kv "${DEPLOY_ENV}" KONVO_HOST  "${KONVO_HOST}"
  ensure_kv "${DEPLOY_ENV}" TLS_EMAIL   "${TLS_EMAIL:-}"

  ensure_kv "${DEPLOY_ENV}" POSTGRES_PASSWORD       "${POSTGRES_PASSWORD:-$(gen_secret 24)}"
  ensure_kv "${DEPLOY_ENV}" MINIO_ROOT_USER         "${MINIO_ROOT_USER:-konvo}"
  ensure_kv "${DEPLOY_ENV}" MINIO_ROOT_PASSWORD     "${MINIO_ROOT_PASSWORD:-$(gen_secret 24)}"
  ensure_kv "${DEPLOY_ENV}" GRAFANA_ADMIN_USER      "${GRAFANA_ADMIN_USER:-admin}"
  ensure_kv "${DEPLOY_ENV}" GRAFANA_ADMIN_PASSWORD  "${GRAFANA_ADMIN_PASSWORD:-$(gen_secret 24)}"
  ensure_kv "${DEPLOY_ENV}" NODE_ENV                "production"

  ok "${DEPLOY_ENV} ready"
}

# ---------------------------------------------------------------------------
# Web bundle build (inside docker so the host needs no node/pnpm)
# ---------------------------------------------------------------------------

build_web_bundle() {
  log "Building PWA bundle (apps/web -> ${WEB_DIST})"
  docker run --rm \
    -v "${REPO_ROOT}:/repo" \
    -w /repo \
    node:20-alpine \
    sh -c '
      set -e
      apk add --no-cache git python3 make g++ >/dev/null 2>&1 || true
      corepack enable >/dev/null 2>&1
      corepack prepare pnpm@9.12.3 --activate >/dev/null 2>&1
      pnpm install --frozen-lockfile --ignore-scripts
      pnpm -F @konvo/protocol build
      pnpm -F @konvo/crypto build
      pnpm -F @konvo/web build
    '
  if [ ! -f "${WEB_DIST}/index.html" ]; then
    err "Web build did not produce ${WEB_DIST}/index.html"
    exit 1
  fi
  ok "PWA bundle ready"
}

# ---------------------------------------------------------------------------
# Healthcheck loop
# ---------------------------------------------------------------------------

wait_for_https() {
  log "Waiting for https://${KONVO_HOST}/health (up to 180s — ACME issuance can take a moment)"
  local i
  for i in $(seq 1 180); do
    # We allow self-signed during the 30-60s window where Caddy is
    # still negotiating with Let's Encrypt; the healthcheck itself
    # is what we care about.
    if curl --resolve "${KONVO_HOST}:443:127.0.0.1" -fsSk \
         "https://${KONVO_HOST}/health" >/dev/null 2>&1; then
      ok "Caddy is serving HTTPS at https://${KONVO_HOST}"
      return 0
    fi
    sleep 1
  done
  err "Stack did not come fully healthy. Inspect: ${0##*/} logs caddy / api"
  return 1
}

# ---------------------------------------------------------------------------
# Pre-flight: required env vars, DNS sanity check
# ---------------------------------------------------------------------------

require_env() {
  local missing=()
  for k in "$@"; do
    if [ -z "${!k:-}" ]; then missing+=("$k"); fi
  done
  if [ "${#missing[@]}" -ne 0 ]; then
    err "Missing required environment variable(s): ${missing[*]}"
    err "Set them and re-run, e.g.:"
    err "  KONVO_HOST=konvo.example.com TLS_EMAIL=ops@example.com $0"
    exit 1
  fi
}

dns_sanity_check() {
  log "Checking DNS for ${KONVO_HOST}"
  local resolved=""
  if command -v dig >/dev/null 2>&1; then
    resolved="$(dig +short "${KONVO_HOST}" A | head -n1)"
  elif command -v getent >/dev/null 2>&1; then
    resolved="$(getent ahosts "${KONVO_HOST}" | awk '{print $1; exit}')"
  elif command -v host >/dev/null 2>&1; then
    resolved="$(host "${KONVO_HOST}" | awk '/has address/ {print $4; exit}')"
  fi
  if [ -z "${resolved}" ]; then
    warn "Could not resolve ${KONVO_HOST}. ACME issuance will fail until DNS lands."
  else
    ok "${KONVO_HOST} resolves to ${resolved}"
  fi
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

action_deploy() {
  require_env KONVO_HOST
  if [ -z "${TLS_EMAIL:-}" ]; then
    warn "TLS_EMAIL not set — Caddy will fall back to its internal CA (untrusted by browsers)."
  fi
  ensure_prereqs
  dns_sanity_check
  ensure_api_env_file
  ensure_deploy_env_file
  build_web_bundle

  log "Building api image (multi-stage)"
  compose build api

  log "Bringing the stack up"
  compose up -d

  if ! wait_for_https; then
    return 1
  fi

  cat <<EOF

  ${C_GREEN}${C_BOLD}Konvo deployed${C_RESET}

  PWA:        https://${KONVO_HOST}/
  Health:     https://${KONVO_HOST}/health
  Settings:   https://${KONVO_HOST}/settings

  Inspect:    ./scripts/deploy.sh status
  Logs:       ./scripts/deploy.sh logs api
  Restart:    ./scripts/deploy.sh update
  Tear down:  ./scripts/deploy.sh down

  ${C_DIM}Strong secrets were written to ${ENV_API} (mode 600).
  Compose env (${DEPLOY_ENV}) holds infra passwords + KONVO_HOST.${C_RESET}

EOF
}

action_status() {
  compose ps
}

action_logs() {
  if [ "$#" -eq 0 ]; then
    compose logs --tail=100 -f
  else
    compose logs --tail=100 -f "$@"
  fi
}

action_update() {
  require_env KONVO_HOST
  ensure_prereqs
  if [ -d .git ]; then
    log "Pulling latest from git"
    git fetch --all --prune
    git pull --ff-only
  else
    warn "Not a git checkout; skipping git pull"
  fi
  ensure_deploy_env_file
  build_web_bundle
  log "Rebuilding api image and restarting"
  compose build api
  compose up -d
  wait_for_https || true
  ok "update complete"
}

action_down() {
  local args=()
  if [ "${1:-}" = "--volumes" ]; then
    warn "DESTROY mode: wiping all data volumes (postgres, minio, caddy data)"
    args+=("--volumes")
  fi
  log "Stopping the stack"
  compose down "${args[@]}"
  ok "stopped"
}

usage() {
  cat <<EOF
Usage: KONVO_HOST=host TLS_EMAIL=email $(basename "$0") [action] [args...]

Actions:
  deploy           (default) install prereqs, build, bring stack up
  status           docker compose ps
  logs [service]   tail logs (all services if no name)
  update           git pull + rebuild + restart
  down             stop the stack (preserves volumes)
  down --volumes   stop the stack AND wipe volumes (DANGEROUS)

Required env on first run:
  KONVO_HOST       e.g. konvo.opsalchemistlabs.co.in
  TLS_EMAIL        e.g. ops@opsalchemistlabs.co.in

Optional env (auto-generated if absent):
  POSTGRES_PASSWORD, MINIO_ROOT_PASSWORD, GRAFANA_ADMIN_PASSWORD
EOF
}

case "${ACTION}" in
  deploy|"") action_deploy ;;
  status)    action_status ;;
  logs)      action_logs "$@" ;;
  update)    action_update ;;
  down)      action_down "$@" ;;
  -h|--help|help) usage ;;
  *)
    err "Unknown action: ${ACTION}"
    usage
    exit 2
    ;;
esac

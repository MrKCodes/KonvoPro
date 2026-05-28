#!/usr/bin/env bash
#
# scripts/dev.sh
#
# One-shot local-dev launcher for Konvo. Works on macOS, Linux, and
# WSL. Brings the full stack up, then runs the PWA dev server in the
# foreground so Ctrl+C tears everything down cleanly.
#
# Usage (from anywhere — the script chdir's to the repo root):
#
#   ./scripts/dev.sh             # full stack: docker api + web on host (default)
#   ./scripts/dev.sh host        # data plane in docker, api + web on host
#   ./scripts/dev.sh down        # tear everything down
#
# Behaviour:
#   - Default mode runs api inside docker; web runs on host so HMR
#     works while you edit apps/web sources. The web dev server
#     proxies /auth, /rooms, /ws, … to localhost:3000 (the api
#     container).
#   - `host` mode runs only the data plane (postgres, redis, minio,
#     livekit, coturn, prometheus, grafana, loki) inside docker and
#     leaves you free to run `pnpm -F @konvo/api dev` on the host
#     for tsx hot-reload while editing apps/api.
#   - `down` stops every container and exits.
#
# Anything funny happens? Run with `bash -x scripts/dev.sh` to trace.

set -euo pipefail

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "${REPO_ROOT}"

COMPOSE_FILE="infra/docker-compose.yml"
OVERRIDE_FILE="infra/docker-compose.override.yml"
ENV_FILE="apps/api/.env"
ENV_EXAMPLE="apps/api/.env.example"

API_PORT=3000
WEB_PORT=5173

MODE="${1:-docker}"

# Colours: only emit when stdout is a TTY so logs piped to files
# stay clean.
if [ -t 1 ]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_DIM='\033[2m'
  C_RED='\033[31m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_BLUE='\033[34m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''
fi

log()  { printf '%b\n' "${C_BOLD}${C_BLUE}==>${C_RESET} ${C_BOLD}$*${C_RESET}"; }
ok()   { printf '%b\n' "${C_GREEN}✓${C_RESET} $*"; }
warn() { printf '%b\n' "${C_YELLOW}!${C_RESET} $*"; }
err()  { printf '%b\n' "${C_RED}✗${C_RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Prereqs
# ---------------------------------------------------------------------------

require_cmd() {
  local cmd="$1"; local hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    err "${cmd} not found on PATH. ${hint}"
    exit 1
  fi
}

check_prereqs() {
  log "Checking prerequisites"
  require_cmd docker  "Install Docker Desktop or the docker engine + compose plugin."
  require_cmd pnpm    "Install pnpm: https://pnpm.io/installation"
  require_cmd node    "Install Node.js >= 20.10: https://nodejs.org/"
  # Recent docker has compose built in as a subcommand. Older systems
  # ship it as docker-compose v1 — we don't support that.
  if ! docker compose version >/dev/null 2>&1; then
    err "'docker compose' subcommand not available. Update Docker or install the Compose plugin."
    exit 1
  fi
  ok "docker, pnpm, node, docker compose available"
}

# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

# Print PIDs of host processes listening on the given TCP port. Cross-
# platform: prefers `lsof` (macOS / most Linux), falls back to `ss`
# (modern Linux without lsof) and finally `fuser` (very old Linux).
port_listeners() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null || true
  elif command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null \
      | awk -v p=":${port}" '$4 ~ p { for (i=1;i<=NF;i++) if ($i ~ /pid=/) { gsub(/.*pid=/,"",$i); gsub(/,.*/,"",$i); print $i } }'
  elif command -v fuser >/dev/null 2>&1; then
    fuser -n tcp "${port}" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' || true
  else
    return 0
  fi
}

# Free a host port by killing any orphan host process holding it.
# Skips PIDs owned by the docker daemon (those are the docker-proxy
# bridges that LEGITIMATELY hold the port).
free_port() {
  local port="$1"; local label="$2"
  local pids; pids="$(port_listeners "${port}" || true)"
  if [ -z "${pids}" ]; then
    return 0
  fi
  for pid in ${pids}; do
    # Inspect the binary path; skip docker-proxy and friends.
    local cmd
    if command -v ps >/dev/null 2>&1; then
      cmd="$(ps -o command= -p "${pid}" 2>/dev/null || true)"
    else
      cmd=""
    fi
    case "${cmd}" in
      *docker-proxy*|*com.docker*|*Docker.app*)
        # Docker holds the port itself; nothing to free.
        ;;
      "")
        # PID gone already; nothing to do.
        ;;
      *)
        warn "${label} :${port} held by host PID ${pid} (${cmd})"
        warn "  killing it so docker can bind the port…"
        kill "${pid}" 2>/dev/null || true
        ;;
    esac
  done
  # Wait briefly for the port to clear; fall through whether or not
  # it does — the actual bind error (if any) will be louder than ours.
  for _ in 1 2 3 4 5; do
    sleep 0.5
    if [ -z "$(port_listeners "${port}" || true)" ]; then
      return 0
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Env file
# ---------------------------------------------------------------------------

ensure_env_file() {
  if [ -f "${ENV_FILE}" ]; then
    return 0
  fi
  if [ ! -f "${ENV_EXAMPLE}" ]; then
    err "${ENV_EXAMPLE} missing — cannot bootstrap ${ENV_FILE}"
    exit 1
  fi
  log "Creating ${ENV_FILE} from ${ENV_EXAMPLE}"
  cp "${ENV_EXAMPLE}" "${ENV_FILE}"
  ok "${ENV_FILE} ready (rotate the secrets before any non-local use)"
}

# ---------------------------------------------------------------------------
# Compose helpers
# ---------------------------------------------------------------------------

compose() {
  docker compose -f "${COMPOSE_FILE}" -f "${OVERRIDE_FILE}" "$@"
}

stack_down() {
  log "Stopping the docker stack"
  compose down --remove-orphans
  ok "Stack stopped"
}

stack_up_full() {
  log "Building & starting the full stack (postgres, redis, minio, api, …)"
  compose up -d --build
  ok "Stack up. api is on http://localhost:${API_PORT}"
}

stack_up_data_plane() {
  log "Starting data plane only (api will run on host)"
  compose up -d \
    postgres redis minio livekit coturn prometheus grafana loki
  ok "Data plane up. Run \`pnpm -F @konvo/api dev\` in another terminal."
}

# Wait until /health returns 200, or fail with a clear message.
wait_for_api() {
  log "Waiting for api on http://localhost:${API_PORT}/health"
  local i
  for i in $(seq 1 60); do
    if curl -fsS "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
      ok "api is healthy"
      return 0
    fi
    sleep 1
  done
  err "api did not become healthy after 60s. Inspect: docker logs konvo-api-1"
  exit 1
}

# ---------------------------------------------------------------------------
# Web dev server (foreground)
# ---------------------------------------------------------------------------

run_web() {
  log "Starting PWA dev server on http://localhost:${WEB_PORT}"
  free_port "${WEB_PORT}" "web"
  printf '\n%b\n' "${C_DIM}Press Ctrl+C to stop the web server. The docker stack will keep running."
  printf '%b\n\n' "Run \`./scripts/dev.sh down\` when you're done.${C_RESET}"
  # Exec so signals (SIGINT/SIGTERM) propagate naturally to the
  # child process and the shell exits with its status code.
  exec pnpm -F @konvo/web dev
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

mode_docker() {
  check_prereqs
  ensure_env_file
  free_port "${API_PORT}" "api"
  stack_up_full
  wait_for_api
  run_web
}

mode_host() {
  check_prereqs
  ensure_env_file
  stack_up_data_plane
  warn "api is NOT running — open another terminal and run:"
  printf '\n  ${C_BOLD}pnpm -F @konvo/api dev${C_RESET}\n\n'
  warn "Then come back here and re-run \`./scripts/dev.sh\` (default mode) for the PWA, or:"
  printf '\n  ${C_BOLD}pnpm -F @konvo/web dev${C_RESET}\n\n'
}

mode_down() {
  stack_down
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [docker|host|down]

  docker  (default) start full stack (api in docker) + web on host
  host    start data plane only; you run api + web on the host yourself
  down    stop & remove every container

Environment variables:
  API_PORT  (default ${API_PORT})  host port the api binds
  WEB_PORT  (default ${WEB_PORT})  host port the PWA dev server binds
EOF
}

case "${MODE}" in
  docker|"") mode_docker ;;
  host)      mode_host ;;
  down)      mode_down ;;
  -h|--help|help) usage ;;
  *)
    err "Unknown mode: ${MODE}"
    usage
    exit 2
    ;;
esac

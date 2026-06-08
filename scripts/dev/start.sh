#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_DIR="$ROOT_DIR/.logs"
API_LOG="$LOG_DIR/api.log"
WEB_LOG="$LOG_DIR/web.log"
API_PID_FILE="$LOG_DIR/api.pid"
WEB_PID_FILE="$LOG_DIR/web.pid"
LAUNCHER_URL="http://127.0.0.1:3000/launch"

# ── colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  PURPLE=$'\033[0;35m'; CYAN=$'\033[0;36m'; GREEN=$'\033[0;32m'
  GRAY=$'\033[0;90m';   RESET=$'\033[0m';   BOLD=$'\033[1m'
else
  PURPLE=''; CYAN=''; GREEN=''; GRAY=''; RESET=''; BOLD=''
fi

fail() { printf '\n%serror:%s %s\n' "$PURPLE" "$RESET" "$1" >&2; exit 1; }

# ── spinner ───────────────────────────────────────────────────────────────────
SPINNER_PID=""
_spin_frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

spinner_start() {
  local msg="$1"
  ( i=0
    while true; do
      printf '\r  %s%s%s  %s' "$PURPLE" "${_spin_frames[$i]}" "$RESET" "$msg"
      i=$(( (i + 1) % ${#_spin_frames[@]} ))
      sleep 0.1
    done ) &
  SPINNER_PID=$!
}

spinner_stop() {
  if [ -n "$SPINNER_PID" ]; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
    printf '\r\033[2K'
  fi
}

# ── helpers ───────────────────────────────────────────────────────────────────
is_port_open() { nc -z 127.0.0.1 "$1" >/dev/null 2>&1; }

wait_for_http() {
  local url="$1" retries="${2:-90}" i=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "$retries" ] && return 1
    sleep 1
  done
}

stop_pid_file() {
  local pid_file="$1" pid=""
  [ -f "$pid_file" ] || return 0
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  rm -f "$pid_file"
}

open_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1;     then open "$url" &
  fi
}

ensure_log_dir() {
  [ -e "$LOG_DIR" ] && [ ! -w "$LOG_DIR" ] && rm -rf "$LOG_DIR"
  mkdir -p "$LOG_DIR"
}

ensure_node_deps() {
  [ -x "$ROOT_DIR/node_modules/.bin/next" ] && return 0
  spinner_stop
  printf '  %s→%s  Installing Node dependencies…\n' "$CYAN" "$RESET"
  spinner_start "Installing Node dependencies"
  if [ -f "$ROOT_DIR/package-lock.json" ]; then
    (cd "$ROOT_DIR" && npm ci --silent)
  else
    (cd "$ROOT_DIR" && npm install --silent)
  fi
  spinner_stop
}

# ── preflight ─────────────────────────────────────────────────────────────────
printf '\n'

ensure_log_dir
stop_pid_file "$API_PID_FILE"
stop_pid_file "$WEB_PID_FILE"

if is_port_open 8000; then
  printf '  %s→%s  Port 8000 in use — force-stopping…\n' "$CYAN" "$RESET"
  sudo fuser -k 8000/tcp >/dev/null 2>&1 || true; sleep 1
  is_port_open 8000 && fail "Port 8000 still in use after kill — check manually"
fi
if is_port_open 3000; then
  printf '  %s→%s  Port 3000 in use — force-stopping…\n' "$CYAN" "$RESET"
  sudo fuser -k 3000/tcp >/dev/null 2>&1 || true; sleep 1
  is_port_open 3000 && fail "Port 3000 still in use after kill — check manually"
fi

ensure_node_deps

# ── start API ─────────────────────────────────────────────────────────────────
spinner_start "Starting API"
nohup env DEBUG=true ENVIRONMENT=development \
  "$ROOT_DIR/scripts/dev/run-api.sh" >"$API_LOG" 2>&1 &
echo "$!" > "$API_PID_FILE"

wait_for_http "http://127.0.0.1:8000/api/health" 90 || {
  spinner_stop
  fail "API did not start. Check: $API_LOG"
}
spinner_stop
printf '  %s✓%s  API ready\n' "$GREEN" "$RESET"

# ── start Web ─────────────────────────────────────────────────────────────────
spinner_start "Starting Web"
(
  cd "$ROOT_DIR/apps/web"
  nohup env NEXT_TELEMETRY_DISABLED=1 npm run dev >"$WEB_LOG" 2>&1 &
  echo "$!" > "$WEB_PID_FILE"
)

wait_for_http "http://127.0.0.1:3000/health" 90 || {
  spinner_stop
  fail "Web did not start. Check: $WEB_LOG"
}

# Pre-compile /launch so the browser doesn't open to a stale page.
# Next.js lazily compiles each route on first request; the browser opening
# immediately would land mid-compilation and the page JS would timeout before
# useEffect can fetch /setup/status. One curl warm-up request here forces
# compilation to finish before the user's browser tab opens.
spinner_stop
spinner_start "Compiling launcher page"
wait_for_http "http://127.0.0.1:3000/launch" 120 || true
spinner_stop

printf '  %s✓%s  Web ready\n' "$GREEN" "$RESET"

# ── done ─────────────────────────────────────────────────────────────────────
printf '\n  %s→%s  %s\n\n' "$CYAN" "$RESET" "$LAUNCHER_URL"
open_browser "$LAUNCHER_URL"

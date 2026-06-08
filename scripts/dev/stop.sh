#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$ROOT_DIR/.logs"
PORTS=("${WEB_PORT:-3000}" "${API_PORT:-8000}")

usage() {
  cat <<'EOF'
Usage: ./stop.sh [--port PORT]...

Stops AdByG0d local services started from this checkout. By default it stops
the configured web/API ports and any matching local Next/Uvicorn processes.

Database, user credentials, and sessions are NOT touched — run ./clean.sh
to wipe all persisted data.

Options:
  --port PORT   Also stop processes listening on PORT.
  --help, -h    Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)
      [ "${2:-}" ] || { echo "error: --port requires a value" >&2; exit 1; }
      PORTS+=("$2")
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

stop_pid_file() {
  local pid_file="$1" name="$2" pid=""
  if [ ! -f "$pid_file" ]; then
    echo "$name: no pid file"
    return 0
  fi
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    echo "$name: stopped process $pid"
  else
    echo "$name: process already stopped"
  fi
  if ! rm -f "$pid_file" 2>/dev/null; then
    echo "$name: could not remove root-owned pid file $pid_file" >&2
  fi
}

stop_port() {
  local port="$1" name="$2" pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  fi
  if [ -z "$pids" ] && command -v fuser >/dev/null 2>&1; then
    pids="$(fuser "$port/tcp" 2>/dev/null || true)"
  fi
  if [ -n "$pids" ]; then
    echo "$pids" | tr ' ' '\n' | sort -u | xargs kill >/dev/null 2>&1 || true
    echo "$name: stopped remaining process on :$port"
  else
    echo "$name: no process listening on :$port"
  fi
}

stop_project_processes() {
  local pids="" pid="" args="" cwd=""
  while read -r pid args; do
    [ -n "$pid" ] || continue
    cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
    case "$cwd:$args" in
      "$ROOT_DIR":*uvicorn*|"$ROOT_DIR"/*:*uvicorn*|*"$ROOT_DIR"*uvicorn*|\
      "$ROOT_DIR":*"next dev"*|"$ROOT_DIR"/*:*"next dev"*|*"$ROOT_DIR"*"next dev"*|\
      "$ROOT_DIR":*"next start"*|"$ROOT_DIR"/*:*"next start"*|*"$ROOT_DIR"*"next start"*|\
      "$ROOT_DIR":*"npm run dev"*|"$ROOT_DIR"/*:*"npm run dev"*|*"$ROOT_DIR"*"npm run dev"*)
        pids="${pids}${pid}"$'\n'
        ;;
    esac
  done < <(ps -eo pid=,args=)

  if [ -n "$pids" ]; then
    echo "$pids" | sort -u | xargs kill >/dev/null 2>&1 || true
    sleep 1
    echo "$pids" | sort -u | while read -r pid; do
      [ -n "$pid" ] || continue
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    done
    echo "Project: stopped matching local dev processes"
  else
    echo "Project: no matching local dev processes"
  fi
}

stop_pid_file "$LOG_DIR/web.pid" "Web"
stop_pid_file "$LOG_DIR/api.pid" "API"
for port in "${PORTS[@]}"; do
  stop_port "$port" "Port"
done
stop_project_processes

echo "Local services stopped. (Assessments, credentials and sessions preserved — run ./clean.sh to wipe data.)"

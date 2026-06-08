#!/usr/bin/env bash
# Stops API + Web services only — does NOT wipe the database.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$ROOT_DIR/.logs"
PORTS=("${WEB_PORT:-3000}" "${API_PORT:-8000}")

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
  rm -f "$pid_file" 2>/dev/null || true
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
    # try as current user first, then escalate for root-owned processes
    echo "$pids" | tr ' ' '\n' | sort -u | xargs kill -9 >/dev/null 2>&1 || \
      sudo kill -9 $(echo "$pids" | tr '\n' ' ') >/dev/null 2>&1 || true
    echo "$name: stopped process(es) on :$port"
  else
    # last-resort: sudo fuser -k in case lsof missed root-owned sockets
    if sudo fuser -k "$port/tcp" >/dev/null 2>&1; then
      echo "$name: force-killed process on :$port (needed sudo)"
    else
      echo "$name: no process listening on :$port"
    fi
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
      kill -0 "$pid" >/dev/null 2>&1 && kill -9 "$pid" >/dev/null 2>&1 || true
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

echo ""
echo "AdByG0d services stopped."
read -rp "Press Enter to close..."

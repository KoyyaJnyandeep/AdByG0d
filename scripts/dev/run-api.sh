#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
API_DIR="$ROOT_DIR/apps/api"
VENV_DIR="$API_DIR/.venv"
RUNTIME_DIR="$ROOT_DIR/.dev-runtime"
DEV_SECRET_FILE="$RUNTIME_DIR/api_secret_key"

cd "$API_DIR"

USER_TOOL_PATHS=(
  "/usr/local/sbin"
  "/usr/sbin"
  "/sbin"
  "/usr/local/games"
  "/usr/games"
  "$HOME/.local/bin"
  "$HOME/go/bin"
  "$HOME/.cargo/bin"
  "$HOME/.nimble/bin"
)

if [ -d /home ]; then
  for home_dir in /home/*; do
    [ -d "$home_dir" ] || continue
    USER_TOOL_PATHS+=(
      "$home_dir/.local/bin"
      "$home_dir/go/bin"
      "$home_dir/.cargo/bin"
      "$home_dir/.nimble/bin"
    )
  done
fi

for tool_dir in "${USER_TOOL_PATHS[@]}"; do
  if [ -d "$tool_dir" ]; then
    case ":$PATH:" in
      *":$tool_dir:"*) ;;
      *) export PATH="$tool_dir:$PATH" ;;
    esac
  fi
done

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
fi

if [ ! -x "$VENV_DIR/bin/uvicorn" ]; then
  "$VENV_DIR/bin/pip" install -r requirements.txt
fi

generate_secret() {
  "$VENV_DIR/bin/python" - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
}

load_or_create_dev_secret() {
  if [ -n "${SECRET_KEY:-}" ]; then
    printf '%s' "$SECRET_KEY"
    return 0
  fi

  mkdir -p "$RUNTIME_DIR"
  chmod 700 "$RUNTIME_DIR" 2>/dev/null || true

  if [ ! -s "$DEV_SECRET_FILE" ]; then
    generate_secret >"$DEV_SECRET_FILE"
    chmod 600 "$DEV_SECRET_FILE" 2>/dev/null || true
  fi

  tr -d '\n\r' <"$DEV_SECRET_FILE"
}

export PYTHONPATH="$API_DIR/src"
export DEBUG=true
export ENVIRONMENT=development
export SECRET_KEY="$(load_or_create_dev_secret)"
export DATABASE_URL="${DATABASE_URL:-sqlite+aiosqlite:///$API_DIR/adbygod.db}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export ALLOW_DEV_BOOTSTRAP="${ALLOW_DEV_BOOTSTRAP:-true}"
export AUTH_COOKIE_SECURE="${AUTH_COOKIE_SECURE:-false}"

ensure_sqlite_writable() {
  local db_path=""
  case "$DATABASE_URL" in
    sqlite+aiosqlite:///*)
      db_path="${DATABASE_URL#sqlite+aiosqlite:///}"
      ;;
    sqlite:///*)
      db_path="${DATABASE_URL#sqlite:///}"
      ;;
    *)
      return 0
      ;;
  esac
  if [[ "$db_path" != /* ]]; then
    db_path="$API_DIR/$db_path"
  fi

  local db_dir
  db_dir="$(dirname "$db_path")"
  if [ -e "$db_path" ] && [ ! -w "$db_path" ]; then
    printf 'error: SQLite database is not writable: %s\n' "$db_path" >&2
    printf '       Fix ownership/permissions or remove the local dev DB, then restart.\n' >&2
    exit 1
  fi
  if [ ! -e "$db_path" ] && [ ! -w "$db_dir" ]; then
    printf 'error: SQLite database directory is not writable: %s\n' "$db_dir" >&2
    exit 1
  fi
}

ensure_sqlite_writable

if [ "${ADBYGOD_BOOTSTRAP_ADMIN:-false}" = "true" ]; then
  export ALLOW_DEV_BOOTSTRAP=true
  export DEFAULT_ADMIN_USERNAME="${DEFAULT_ADMIN_USERNAME:-admin}"
  export DEFAULT_ADMIN_EMAIL="${DEFAULT_ADMIN_EMAIL:-admin@example.invalid}"
  export DEFAULT_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:-password}"
  export DEFAULT_ADMIN_FULL_NAME="${DEFAULT_ADMIN_FULL_NAME:-Development Administrator}"
fi

exec "$VENV_DIR/bin/uvicorn" adbygod_api.main:app --host 127.0.0.1 --port "${API_PORT:-8000}" --reload "$@"

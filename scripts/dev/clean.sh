#!/usr/bin/env bash
# AdByG0d – project clean script
# Removes generated artefacts; target < 30 MB after deps are stripped.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRY=0 KEEP_DEPS=0 SUDO=0 VERBOSE=0 TARGET_MB=30 FREED=0

# ── colour ────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  R=$'\033[0;31m' Y=$'\033[1;33m' G=$'\033[0;32m' C=$'\033[0;36m'
  B=$'\033[1m' X=$'\033[0m'
else
  R='' Y='' G='' C='' B='' X=''
fi

usage() { cat <<EOF
${B}Usage:${X} ./clean.sh [options]

${B}Options:${X}
  --dry-run     Print what would be removed without deleting
  --keep-deps   Keep node_modules and apps/api/.venv
  --sudo        Retry failed removals with sudo
  --target MB   Size budget after cleaning (default: 30)
  --verbose     Print every matched path
  --help        Show this message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY=1 ;;
    --keep-deps) KEEP_DEPS=1 ;;
    --deps)      KEEP_DEPS=0 ;;
    --sudo)      SUDO=1 ;;
    --verbose)   VERBOSE=1 ;;
    --target)    shift; TARGET_MB="${1:?--target requires an integer}"; ;;
    --help|-h)   usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

# ── helpers ───────────────────────────────────────────────────────────────────
du_bytes() {
  [ -e "$1" ] || [ -L "$1" ] || { echo 0; return; }
  local v; v="$(du -sb "$1" 2>/dev/null | awk '{print $1}')"
  [[ "${v:-}" =~ ^[0-9]+$ ]] && echo "$v" || echo 0
}

human() {
  local b="${1:-0}"
  [[ "$b" =~ ^[0-9]+$ ]] || b=0
  if   (( b >= 1073741824 )); then printf '%d.%dG' $(( b/1073741824 )) $(( (b%1073741824)*10/1073741824 ))
  elif (( b >= 1048576 ));    then printf '%d.%dM' $(( b/1048576 ))    $(( (b%1048576)*10/1048576 ))
  elif (( b >= 1024 ));       then printf '%d.%dK' $(( b/1024 ))       $(( (b%1024)*10/1024 ))
  else printf '%dB' "$b"; fi
}

# do_rm PATH — remove one path; returns 0 on success
do_rm() {
  rm -rf "$1" 2>/dev/null && return 0
  [ "$SUDO" -eq 1 ] && sudo rm -rf "$1" 2>/dev/null && return 0
  return 1
}

# rm_path PATH LABEL — remove a known path; prints only if it exists or fails
rm_path() {
  local path="$1" label="${2:-$1}" sz
  [ -e "$path" ] || [ -L "$path" ] || return 0
  sz="$(du_bytes "$path")"
  if [ "$DRY" -eq 1 ]; then
    printf '  %swould rm%s  %-52s %s\n' "$Y" "$X" "$label" "$(human "$sz")"
    return 0
  fi
  if do_rm "$path"; then
    printf '  %srm%s        %-52s %s\n' "$G" "$X" "$label" "$(human "$sz")"
    FREED=$(( FREED + sz ))
  else
    printf '  %sFAIL%s      %s  (try --sudo)\n' "$R" "$X" "$label" >&2
  fi
}

# rm_find BASE LABEL [find-args…] — find-and-remove; silent when nothing matches
rm_find() {
  local base="$1" label="$2"; shift 2
  local -a hits=(); local total=0 freed=0 ok=0 fail=0 sz p

  while IFS= read -r -d '' p; do hits+=("$p"); done < <(
    find "$base" \
      \( -path "$ROOT/.git" \
         -o -path "$ROOT/node_modules" \
         -o -path "$ROOT/apps/api/.venv" \) -prune \
      -o \( "$@" -print0 \) 2>/dev/null
  ) || true

  [ "${#hits[@]}" -gt 0 ] || return 0

  for p in "${hits[@]}"; do
    sz="$(du_bytes "$p")"; total=$(( total + sz ))
    if [ "$DRY" -eq 0 ]; then
      if do_rm "$p"; then
        freed=$(( freed + sz )); (( ok++ ))
        [ "$VERBOSE" -eq 1 ] && printf '      %s\n' "$p"
      else
        (( fail++ ))
      fi
    else
      [ "$VERBOSE" -eq 1 ] && printf '      %s\n' "$p"
    fi
  done

  if [ "$DRY" -eq 1 ]; then
    printf '  %swould rm%s  %-52s %s  (%d entries)\n' \
      "$Y" "$X" "$label" "$(human "$total")" "${#hits[@]}"
  else
    printf '  %srm%s        %-52s %s  (%d/%d)\n' \
      "$G" "$X" "$label" "$(human "$freed")" "$ok" "${#hits[@]}"
    FREED=$(( FREED + freed ))
    [ "$fail" -gt 0 ] && printf '  %s%d entries failed%s  (try --sudo)\n' "$Y" "$fail" "$X" >&2
  fi
}

# section TITLE body_fn — run body_fn; print TITLE only if it produced output
section() {
  local title="$1"; shift
  local tmp; tmp="$(mktemp)"
  "$@" >"$tmp" 2>&1
  if [ -s "$tmp" ]; then
    printf '\n%s%s%s\n' "$B" "$title" "$X"
    cat "$tmp"
  fi
  rm -f "$tmp"
}

# ── sections ──────────────────────────────────────────────────────────────────
_crash_dumps() {
  rm_find "$ROOT" 'core dump files' -maxdepth 1 \( -name 'core' -o -name 'core.*' \)
}

_deps() {
  if [ "$KEEP_DEPS" -eq 1 ]; then
    printf '  %skept%s  node_modules / apps/api/.venv  (--keep-deps)\n' "$Y" "$X"
    return
  fi
  rm_path "$ROOT/node_modules"          'node_modules'
  rm_path "$ROOT/apps/api/.venv"        'apps/api/.venv'
  rm_path "$ROOT/apps/web/node_modules" 'apps/web/node_modules'
}

_frontend() {
  rm_path "$ROOT/apps/web/.next"                  'apps/web/.next'
  rm_path "$ROOT/apps/web/.turbo"                 'apps/web/.turbo'
  rm_path "$ROOT/apps/web/tsconfig.tsbuildinfo"   'apps/web/tsconfig.tsbuildinfo'
  rm_find "$ROOT/apps/web" 'Next.js backup dirs' -type d \( -name '.next.unwritable.*' -o -name '.next-*' \)
  rm_find "$ROOT/apps/web" 'Next.js out dirs'    -type d -name 'out'
}

_runtime() {
  rm_path "$ROOT/.logs"                    '.logs'
  rm_path "$ROOT/.dev-runtime"             '.dev-runtime'
  rm_path "$ROOT/.adbygod-runtime"         '.adbygod-runtime'
  rm_path "$ROOT/graphify-out"             'graphify-out'
  rm_path "$ROOT/dump.rdb"                 'dump.rdb'
  rm_path "$ROOT/apps/api/dump.rdb"        'apps/api/dump.rdb'
  rm_path "$ROOT/apps/api/adbygod.db"      'apps/api/adbygod.db'
  rm_path "$ROOT/apps/api/adbygod.db-shm"  'apps/api/adbygod.db-shm'
  rm_path "$ROOT/apps/api/adbygod.db-wal"  'apps/api/adbygod.db-wal'
}

_py_caches() {
  rm_path "$ROOT/.pytest_cache"           '.pytest_cache'
  rm_path "$ROOT/apps/api/.pytest_cache"  'apps/api/.pytest_cache'
  rm_path "$ROOT/.mypy_cache"             '.mypy_cache'
  rm_path "$ROOT/.ruff_cache"             '.ruff_cache'
  rm_find "$ROOT" '__pycache__'   -type d -name '__pycache__'
  rm_find "$ROOT" '.pyc / .pyo'   \( -name '*.pyc' -o -name '*.pyo' \)
  rm_find "$ROOT" 'build/test cache dirs' \
    -type d \( -name '.cache' -o -name 'htmlcov' -o -name '*.egg-info' \)
  rm_find "$ROOT" 'coverage artefacts' \( -name '.coverage' -o -name 'coverage.xml' \)
  rm_find "$ROOT" 'log / pid / tmp / editor junk' \
    \( -name '*.log' -o -name '*.pid' -o -name '*.tmp' \
       -o -name '*.swp' -o -name '*.swo' -o -name '*~' \
       -o -name '*.bak' -o -name '*.bak-*' -o -name '.DS_Store' -o -name 'Thumbs.db' \)
}

_planning() {
  rm_path "$ROOT/task_plan.md"  'task_plan.md'
  rm_path "$ROOT/findings.md"   'findings.md'
  rm_path "$ROOT/progress.md"   'progress.md'
}

_sensitive() {
  rm_find "$ROOT" 'credential / key / ticket files' \
    \( -name '*.ccache' -o -name 'krb5cc*' -o -name '*.kirbi' \
       -o -name '*.key'  -o -name '*.pem'  -o -name '*.pfx' -o -name '*.p12' \)
}

# ── run ───────────────────────────────────────────────────────────────────────
BEFORE="$(du_bytes "$ROOT")"
printf '\n%s%sAdByG0d clean%s\n' "$C" "$B" "$X"
printf '%sRoot:%s %s  |  %sBefore:%s %s\n' \
  "$C" "$X" "$ROOT" "$C" "$X" "$(human "$BEFORE")"

section 'Crash dumps'           _crash_dumps
section 'Dependency installs'   _deps
section 'Frontend build/cache'  _frontend
section 'Runtime state'         _runtime
section 'Python/test caches'    _py_caches
section 'Planning artefacts'    _planning
section 'Sensitive artefacts'   _sensitive

# ── summary ───────────────────────────────────────────────────────────────────
AFTER="$(du_bytes "$ROOT")"
TARGET_BYTES=$(( TARGET_MB * 1024 * 1024 ))

printf '\n'
if [ "$DRY" -eq 1 ]; then
  printf '%sDry-run complete.%s  Current size: %s\n' "$Y" "$X" "$(human "$BEFORE")"
  exit 0
fi

if [ "$FREED" -eq 0 ]; then
  printf '%sNothing to clean.%s  Repo: %s\n' "$G" "$X" "$(human "$AFTER")"
  exit 0
fi

printf '%s%sClean complete.%s  Freed %s  (%s → %s)\n' \
  "$G" "$B" "$X" "$(human "$FREED")" "$(human "$BEFORE")" "$(human "$AFTER")"

# Only warn about size if deps were removed (they're what pushes past 30 MB).
if [ "$KEEP_DEPS" -eq 0 ] && (( AFTER > TARGET_BYTES )); then
  printf '%s⚠  Still above %d MB after dep removal.%s\n' "$Y" "$TARGET_MB" "$X" >&2
  printf '   Largest non-git paths:\n' >&2
  find "$ROOT" -mindepth 1 -maxdepth 3 \
    \( -path "$ROOT/.git" -o -path "$ROOT/node_modules" -o -path "$ROOT/apps/api/.venv" \) -prune \
    -o -print0 2>/dev/null \
  | while IFS= read -r -d '' p; do printf '%s\t%s\n' "$(du_bytes "$p")" "${p#$ROOT/}"; done \
  | sort -nr | head -10 \
  | while IFS=$'\t' read -r b p; do printf '   %-54s %s\n' "$p" "$(human "$b")"; done >&2
fi

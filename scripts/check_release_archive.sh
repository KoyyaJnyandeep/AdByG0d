#!/usr/bin/env bash
# AdByG0d — Release Archive Safety Checker
#
# Inspects a release archive for sensitive files and secret patterns.
#
# Usage:
#   bash scripts/check_release_archive.sh <archive.tar.gz|archive.tgz|archive.tar|archive.zip>
#
# Exit 0 if all checks pass, exit 1 if any check fails.

set -euo pipefail

ARCHIVE="${1:-}"
if [[ -z "$ARCHIVE" ]]; then
  echo "Usage: $0 <archive.tar.gz>"
  exit 1
fi

if [[ ! -f "$ARCHIVE" ]]; then
  echo "Archive not found: $ARCHIVE"
  exit 1
fi

PASS=0
FAIL=0

ok()   { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

echo "============================================================"
echo "  AdByG0d — Archive Safety Check"
echo "  Archive : $ARCHIVE"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

# ── List archive contents ─────────────────────────────────────────
case "$ARCHIVE" in
  *.tar.gz|*.tgz)
    CONTENTS="$(tar tzf "$ARCHIVE")"
    ;;
  *.tar)
    CONTENTS="$(tar tf "$ARCHIVE")"
    ;;
  *.zip)
    # unzip -l: skip 3-line header; awk picks the filename column (NF>=4);
    # grep -v drops the trailing summary line that looks like "N files"
    CONTENTS="$(unzip -l "$ARCHIVE" | awk 'NR>3 && NF>=4 {print $NF}' | grep -vE '^-+$|^[0-9]+ file' || true)"
    ;;
  *)
    echo "Unsupported archive format: $ARCHIVE (expected .tar.gz, .tgz, .tar, or .zip)"
    exit 1
    ;;
esac

# ── Print first 40 lines of contents — safe: sed never causes SIGPIPE ───
echo "[ contents ] Archive file listing:"
printf '%s\n' "$CONTENTS" | sed -n '1,40p'
TOTAL_LINES="$(printf '%s\n' "$CONTENTS" | wc -l)"
if [[ "$TOTAL_LINES" -gt 40 ]]; then
  echo "  ... ($TOTAL_LINES total entries)"
fi
echo ""

# ── Check: no .git ────────────────────────────────────────────────
echo "[ check ] .git directory or files"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.git(/|$)'; then
  fail ".git present in archive"
else
  ok "No .git in archive"
fi

# ── Check: no .env (exact, not .env.example) ─────────────────────
echo "[ check ] .env file (exact match)"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.env$'; then
  fail ".env file present in archive"
else
  ok "No .env in archive"
fi

# ── Check: no .env.* prefix files (excluding .env.example and .env.docker.example) ───────
echo "[ check ] .env.* prefix files (excluding .env.example and .env.docker.example)"
ENV_PREFIX_HITS="$(printf '%s\n' "$CONTENTS" | grep -E '(^|/)\.env\.' | grep -vE '\.env\.(docker\.)?example' || true)"
if [[ -n "$ENV_PREFIX_HITS" ]]; then
  fail ".env.* prefix files found: $ENV_PREFIX_HITS"
else
  ok "No unwanted .env.* prefix files in archive"
fi

# ── Check: no .claude/ ────────────────────────────────────────────
echo "[ check ] .claude/ directory"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.claude/'; then
  fail ".claude/ present in archive"
else
  ok "No .claude/ in archive"
fi

# ── Check: no .codex/ ────────────────────────────────────────────
echo "[ check ] .codex/ directory"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.codex/'; then
  fail ".codex/ present in archive"
else
  ok "No .codex/ in archive"
fi

# ── Check: no *.local.json ────────────────────────────────────────
echo "[ check ] *.local.json files"
if printf '%s\n' "$CONTENTS" | grep -qE '\.local\.json$'; then
  fail "*.local.json files found in archive"
else
  ok "No *.local.json in archive"
fi

# ── Check: no __pycache__/ ───────────────────────────────────────
echo "[ check ] __pycache__/ directories"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)__pycache__/'; then
  fail "__pycache__/ present in archive"
else
  ok "No __pycache__/ in archive"
fi

# ── Check: no .pytest_cache/ ─────────────────────────────────────
echo "[ check ] .pytest_cache/ directory"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.pytest_cache/'; then
  fail ".pytest_cache/ present in archive"
else
  ok "No .pytest_cache/ in archive"
fi

# ── Check: no .ruff_cache/ ───────────────────────────────────────
echo "[ check ] .ruff_cache/ directory"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.ruff_cache/'; then
  fail ".ruff_cache/ present in archive"
else
  ok "No .ruff_cache/ in archive"
fi

# ── Check: no node_modules/ ──────────────────────────────────────
echo "[ check ] node_modules/ directory"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)node_modules/'; then
  fail "node_modules/ present in archive"
else
  ok "No node_modules/ in archive"
fi

# ── Check: no .next/ ─────────────────────────────────────────────
echo "[ check ] .next/ build directory"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)\.next/'; then
  fail ".next/ present in archive"
else
  ok "No .next/ in archive"
fi

# ── Check: no editor/patch backup files ─────────────────────────
echo "[ check ] backup files (*.bak, *.bak_*)"
if printf '%s\n' "$CONTENTS" | grep -qE '\.bak(_.*)?$'; then
  fail "backup files found in archive"
else
  ok "No backup files in archive"
fi

# ── Check: no *.log ──────────────────────────────────────────────
echo "[ check ] *.log files"
if printf '%s\n' "$CONTENTS" | grep -qE '\.log$'; then
  fail "*.log files found in archive"
else
  ok "No *.log files in archive"
fi

# ── Check: no *.pid ──────────────────────────────────────────────
echo "[ check ] *.pid files"
if printf '%s\n' "$CONTENTS" | grep -qE '\.pid$'; then
  fail "*.pid files found in archive"
else
  ok "No *.pid files in archive"
fi

# ── Check: no database files (exclude docs/ and examples/ paths) ─
echo "[ check ] database files (*.sqlite, *.sqlite3, *.db) outside docs/examples"
DB_HITS="$(printf '%s\n' "$CONTENTS" \
  | grep -E '(\.sqlite$|\.sqlite3$|\.db$)' \
  | grep -vE '(^|/)docs/' \
  | grep -vE '(^|/)examples/' \
  || true)"
if [[ -n "$DB_HITS" ]]; then
  fail "Database files found in archive: $DB_HITS"
else
  ok "No database files in archive"
fi

# ── Check: no ligolo config files ────────────────────────────────
echo "[ check ] ligolo config files (ligolo-ng.yaml, ligolo-*.yaml)"
if printf '%s\n' "$CONTENTS" | grep -qE '(^|/)ligolo-(ng|[^/]*)\.yaml$'; then
  fail "ligolo config files found in archive"
else
  ok "No ligolo config files in archive"
fi

# ── Check: no API key patterns in file contents ───────────────────
echo "[ check ] API key patterns in archive contents (sk-proj-*, AKIA*)"

TMPDIR_EXTRACT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_EXTRACT"' EXIT

case "$ARCHIVE" in
  *.tar.gz|*.tgz)
    tar xzf "$ARCHIVE" -C "$TMPDIR_EXTRACT" 2>/dev/null
    ;;
  *.tar)
    tar xf "$ARCHIVE" -C "$TMPDIR_EXTRACT" 2>/dev/null
    ;;
  *.zip)
    unzip -q "$ARCHIVE" -d "$TMPDIR_EXTRACT" 2>/dev/null
    ;;
esac

SECRET_FILES="$(grep -rlE 'sk-proj-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16,}' "$TMPDIR_EXTRACT" 2>/dev/null \
  | grep -v '\.example$' \
  || true)"

if [[ -n "$SECRET_FILES" ]]; then
  RELATIVE_HITS="$(printf '%s\n' "$SECRET_FILES" | sed "s|$TMPDIR_EXTRACT/||g")"
  fail "secret pattern found in: $RELATIVE_HITS"
else
  ok "No API key patterns found in archive contents"
fi

# ── Final verdict ─────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Archive check: PASS ($PASS) / FAIL ($FAIL)"
echo "============================================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0

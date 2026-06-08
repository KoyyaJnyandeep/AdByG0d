#!/usr/bin/env bash
# AdByG0d — Release Readiness Gate
# Run this before tagging a release.
# Fails fast on any blocker.
#
# Usage:
#   bash scripts/release_check.sh [archive.tar.gz]
#   ALLOW_DIRTY=1 bash scripts/release_check.sh   # skip git-dirty check

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
WARN=0

ok()   { echo "  [OK]   $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $*"; WARN=$((WARN + 1)); }

echo "============================================================"
echo "  AdByG0d — Release Readiness Gate"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

# ── 1. Git working tree status ─────────────────────────────────
echo "[ 1 ] Git working tree status"
if [[ -n "${ALLOW_DIRTY:-}" ]]; then
  warn "ALLOW_DIRTY set — skipping git-dirty check"
else
  DIRTY="$(git status --short 2>/dev/null)"
  if [[ -n "$DIRTY" ]]; then
    fail "Working tree is dirty — commit or stash changes before releasing"
  else
    ok "Working tree is clean"
  fi
fi

# ── 2. No tracked secret/generated files ───────────────────────
echo "[ 2 ] Checking for tracked secret/generated files"
SECRET_FILES="$(git ls-files | grep -E '(^|/)\.env$|(^|/)\.env\.(local|production|prod|dev|development)$|settings\.local\.json$|\.pem$|\.key$|\.p12$|\.pfx$|\.ccache$|\.kirbi$|\.ticket$|krb5cc|(^|/)node_modules/|(^|/)\.next/|(^|/)__pycache__/|(^|/)\.pytest_cache/|(^|/)\.ruff_cache/' || true)"
if [[ -n "$SECRET_FILES" ]]; then
  fail "Secret/generated files are tracked in git: $SECRET_FILES"
else
  ok "No secret/generated files tracked"
fi

# ── 3. No local agent/tooling docs tracked ─────────────────────
echo "[ 3 ] Checking for tracked local agent/tooling artifacts"
CLAUDE_FILES="$(git ls-files | grep -E '^\.claude/|^\.codex/|^\.superpowers/|^docs/superpowers/' || true)"
if [[ -n "$CLAUDE_FILES" ]]; then
  fail "Local agent/tooling artifacts are tracked in git: $CLAUDE_FILES"
else
  ok "No local agent/tooling artifacts tracked"
fi

# ── 4. No forbidden local files in working tree ────────────────
echo "[ 4 ] Checking for forbidden local files (gitignored but unsafe)"
# These files won't enter the archive (they're gitignored) but warn if present
# to keep the environment clean and avoid false confidence.
FOUND_FORBIDDEN=0

if [[ -f "$ROOT/apps/api/.env" ]]; then
  warn "apps/api/.env exists in working tree (gitignored — won't be in archive, but clean up before release)"
  FOUND_FORBIDDEN=1
fi

if [[ -f "$ROOT/ligolo-ng.yaml" ]]; then
  warn "ligolo-ng.yaml exists in working tree — remove before release"
  FOUND_FORBIDDEN=1
fi

for local_path in \
  "$ROOT/.dev-runtime" \
  "$ROOT/.logs" \
  "$ROOT/node_modules" \
  "$ROOT/apps/web/node_modules" \
  "$ROOT/apps/web/.next" \
  "$ROOT/apps/api/.venv"; do
  if [[ -e "$local_path" ]]; then
    warn "Local generated/private path exists (ignored, but remove before release): $local_path"
    FOUND_FORBIDDEN=1
  fi
done

DB_FILES="$(find "$ROOT/apps/api" -maxdepth 4 \( -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' \) 2>/dev/null || true)"
if [[ -n "$DB_FILES" ]]; then
  warn "Local database file(s) found in apps/api/ (gitignored — won't be in archive): $DB_FILES"
  FOUND_FORBIDDEN=1
fi

if [[ "$FOUND_FORBIDDEN" -eq 0 ]]; then
  ok "No forbidden local files found"
fi

# ── 5. Important files tracked in git ─────────────────────────
echo "[ 5 ] Verifying important files are tracked in git"

TRACKED_LIST="$(git ls-files)"

check_tracked() {
  local f="$1"
  if echo "$TRACKED_LIST" | grep -qxF "$f"; then
    ok "Tracked: $f"
  elif [[ ! -f "$ROOT/$f" ]]; then
    warn "Not on disk (not yet created): $f"
  else
    fail "Exists on disk but NOT tracked in git: $f"
  fi
}

check_tracked "README.md"
check_tracked "LICENSE"
check_tracked "CONTRIBUTING.md"
check_tracked "SECURITY.md"
check_tracked "CODE_OF_CONDUCT.md"
check_tracked "CHANGELOG.md"
check_tracked "docs/DANGEROUS_FEATURES.md"
check_tracked "docs/SECURITY_MODEL.md"
check_tracked "docs/INSTALLATION.md"
check_tracked "docs/CONFIGURATION.md"
check_tracked "docs/TESTING.md"
check_tracked "docs/SECURITY_SECRET_HANDLING.md"
check_tracked "docs/THREAT_MODEL.md"
check_tracked "docs/RELEASE_CHECKLIST.md"
check_tracked "docker-compose.yml"
check_tracked "docker-compose.prod.yml"
check_tracked ".dockerignore"
check_tracked ".gitignore"
check_tracked ".env.docker.example"
check_tracked "apps/api/.env.example"
check_tracked "apps/web/.env.example"
check_tracked "apps/api/Dockerfile"
check_tracked "apps/web/Dockerfile"
check_tracked "scripts/release_check.sh"
check_tracked "scripts/check_release_archive.sh"
check_tracked "scripts/release.sh"
check_tracked "apps/api/src/adbygod_api/core/dangerous_actions.py"
check_tracked "apps/api/src/adbygod_api/routes/security.py"

# .github/workflows/ci.yml — only required if the directory exists
if [[ -d "$ROOT/.github" ]]; then
  check_tracked ".github/workflows/ci.yml"
  check_tracked ".github/pull_request_template.md"
fi

# ── 6. Python compile ──────────────────────────────────────────
echo "[ 6 ] Python compile check"
COMPILE_OUT="$(PYTHONPATH="$ROOT/apps/api/src" python -m compileall -q "$ROOT/apps/api/src" "$ROOT/collectors/linux_remote/src" 2>&1 || true)"
if [[ -n "$COMPILE_OUT" ]]; then
  fail "Python compile errors: $COMPILE_OUT"
else
  ok "Python sources compile without errors"
fi

# ── 7. Backend key tests ───────────────────────────────────────
echo "[ 7 ] Backend key security tests"
if (
  cd "$ROOT/apps/api" && \
  SECRET_KEY=release-check-not-real-secret-1234567890abcdef \
  DEBUG=true \
  PYTHONPATH=src \
  python -m pytest \
    tests/test_auth_and_authorization.py \
    tests/test_zip_bomb_limits.py \
    tests/test_api_root.py \
    -q --tb=short > /tmp/rcheck_pytest.txt 2>&1
); then
  ok "Key security tests pass"
else
  fail "Key security tests FAILED — $(grep -E 'FAILED|ERROR|assert' /tmp/rcheck_pytest.txt | head -5)"
fi

# ── 8. Frontend type-check ─────────────────────────────────────
echo "[ 8 ] Frontend TypeScript type-check"
TSC_BIN="$ROOT/node_modules/typescript/bin/tsc"
if [[ ! -f "$TSC_BIN" ]]; then
  warn "TypeScript not found at $TSC_BIN — skipping (run npm ci first)"
else
  TSC_OUT="$(cd "$ROOT/apps/web" && node "$TSC_BIN" --noEmit 2>&1 | grep -v "^$" || true)"
  if echo "$TSC_OUT" | grep -q "error TS"; then
    fail "TypeScript errors: $(echo "$TSC_OUT" | grep "error TS" | head -3)"
  else
    ok "Frontend type-check passes"
  fi
fi

# ── 9. Secret pattern scan ─────────────────────────────────────
echo "[ 9 ] Scanning committed source for secret patterns"
SECRET_HITS="$(git grep -Il -e '-----BEGIN .*PRIVATE KEY-----' -e 'AKIA[0-9A-Z]\{16\}' -e 'AIza[0-9A-Za-z_-]\{30,\}' -e 'gh[pousr]_[0-9A-Za-z_]\{20,\}' -e 'xox[baprs]-[0-9A-Za-z-]\{10,\}' -e 'sk-proj-[A-Za-z0-9_-]\{20,\}' -- . ':!*.example' ':!*.md' ':!package-lock.json' ':!.github/workflows/ci.yml' ':!scripts/release_check.sh' ':!scripts/check_release_archive.sh' || true)"
if [[ -n "$SECRET_HITS" ]]; then
  fail "Possible real secrets found in tracked source: $SECRET_HITS"
else
  ok "No real secret patterns found in tracked source"
fi

# ── 10. Docker Compose config ──────────────────────────────────
echo "[ 10 ] Docker Compose config validation"
if [[ -f "$ROOT/docker-compose.yml" ]]; then
  DOCKER_OUT="$(cd "$ROOT" && docker compose config -q 2>&1 || true)"
  if [[ -z "$DOCKER_OUT" ]]; then
    ok "docker compose config is valid"
  else
    fail "docker compose config errors: $DOCKER_OUT"
  fi
else
  warn "No docker-compose.yml found — skipping docker check"
fi

# ── 11. Archive safety check ───────────────────────────────────
echo "[ 11 ] Release archive safety check"
ARCHIVE_ARG="${1:-}"
if [[ -n "$ARCHIVE_ARG" ]]; then
  # Explicit archive path supplied as argument
  if bash "$ROOT/scripts/check_release_archive.sh" "$ARCHIVE_ARG" > /tmp/arch_check.txt 2>&1; then
    ok "Archive $ARCHIVE_ARG passed safety checks"
  else
    fail "Archive $ARCHIVE_ARG FAILED safety checks:"
    tail -10 /tmp/arch_check.txt | sed 's/^/    /'
    FAIL=$((FAIL + 0))  # already counted in the fail() call above
  fi
else
  # No argument: look for recently-built archives in the repo root
  ARCHIVES=$(find "$ROOT" -maxdepth 1 -name "adbygod-*.tar.gz" 2>/dev/null || true)
  if [[ -n "$ARCHIVES" ]]; then
    for arch in $ARCHIVES; do
      if bash "$ROOT/scripts/check_release_archive.sh" "$arch" > /tmp/arch_check.txt 2>&1; then
        ok "Archive $arch passed safety checks"
      else
        fail "Archive $arch FAILED safety checks:"
        tail -10 /tmp/arch_check.txt | sed 's/^/    /'
      fi
    done
  else
    warn "No release archive supplied or found — skipping archive gate (run scripts/release.sh first, or pass archive path as argument)"
  fi
fi

# ── Final verdict ──────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Results: PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
echo "  Release verdict: $([ "$FAIL" -eq 0 ] && echo 'READY' || echo 'NOT READY')"
echo "============================================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0

#!/usr/bin/env bash
# AdByG0d — Fast local dev check (subset of release_check.sh)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0; FAIL=0
ok()   { echo "  [OK]   $*"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

echo "=== AdByG0d Dev Check ==="

# Backend compile
COMPILE="$(cd apps/api && PYTHONPATH=src python -m compileall -q src/ 2>&1 || true)"
[[ -z "$COMPILE" ]] && ok "Backend compiles" || fail "Compile errors: $COMPILE"

# Quick test subset
if (cd apps/api && SECRET_KEY=dev-check-secret-1234567890abcdef DEBUG=true PYTHONPATH=src \
    python -m pytest tests/test_auth_and_authorization.py tests/test_api_root.py -q --tb=short > /tmp/dev_pytest.txt 2>&1); then
  ok "Auth tests pass"
else
  fail "Auth tests failed — $(grep FAILED /tmp/dev_pytest.txt | head -3)"
fi

# Secret file check
SECRETS="$(git ls-files | grep -E '\.env$|settings\.local\.json$|\.pem$' || true)"
[[ -z "$SECRETS" ]] && ok "No secret files tracked" || fail "Secret files tracked: $SECRETS"

echo ""
echo "Dev check: $PASS pass / $FAIL fail"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1

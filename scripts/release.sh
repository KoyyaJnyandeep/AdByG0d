#!/usr/bin/env bash
# AdByG0d — clean release archive builder
#
# Produces a reproducible, vendor-free archive suitable for distribution.
# Uses `git archive` so only committed, tracked files are included.
#
# Usage:
#   ./scripts/release.sh [version]
#
# Examples:
#   ./scripts/release.sh              # uses version from package.json
#   ./scripts/release.sh 4.1.0       # explicit version tag

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Determine version.
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(node -e "process.stdout.write(require('./package.json').version)")"
fi

OUTPUT="adbygod-${VERSION}.tar.gz"

echo "Building release archive: ${OUTPUT}"
echo "  version : ${VERSION}"
echo "  ref     : $(git rev-parse --short HEAD 2>/dev/null || echo 'untracked')"

# git archive only includes committed, tracked content.
# It never includes:
#   .git/              (excluded by git itself)
#   .env               (listed in .gitignore — git archive skips gitignored files
#                       only if they were never committed; see note below)
#   .venv/ node_modules/ (gitignored — never committed)
#   .logs/ *.db *.pid  (gitignored)
#
# Safety check: warn if any sensitive file was accidentally committed.
SENSITIVE_PATTERNS=('.env$' 'adbygod\.db$' '\.venv/' 'node_modules/')
for pat in "${SENSITIVE_PATTERNS[@]}"; do
  if git ls-files | grep -qE "$pat"; then
    echo "WARNING: tracked file matches sensitive pattern '${pat}'. Review before distributing."
  fi
done

git archive \
  --format=tar.gz \
  --prefix="adbygod-${VERSION}/" \
  HEAD \
  --output="${OUTPUT}"

echo "Archive: $(pwd)/${OUTPUT}"
echo ""
echo "Verify contents with:"
echo "  tar tzf ${OUTPUT} | grep -E '(\.env|\.db|\.venv|node_modules)' && echo PROBLEM || echo OK"

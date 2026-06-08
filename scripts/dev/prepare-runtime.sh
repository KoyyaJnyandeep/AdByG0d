#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

mkdir -p "$ROOT_DIR/.logs"
mkdir -p "$ROOT_DIR/apps/web/.next"

echo "Prepared local runtime directories:"
echo "  $ROOT_DIR/.logs"
echo "  $ROOT_DIR/apps/web/.next"

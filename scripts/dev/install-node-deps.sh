#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ -f "$ROOT_DIR/package-lock.json" ] || [ -f "$ROOT_DIR/npm-shrinkwrap.json" ]; then
  npm ci
else
  npm install
fi

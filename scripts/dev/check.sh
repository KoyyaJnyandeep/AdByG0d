#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$ROOT_DIR"

echo "== Shell syntax =="
bash -n start.sh stop.sh clean.sh scripts/dev/*.sh

echo "== API tests =="
if [[ -x apps/api/.venv/bin/python ]]; then
  PYTHONPATH=apps/api/src apps/api/.venv/bin/python -m pytest apps/api/tests
else
  PYTHONPATH=apps/api/src python -m pytest apps/api/tests
fi

echo "== Web lint =="
npm --prefix apps/web run lint

echo "== Web type-check =="
npm --prefix apps/web run type-check -- --pretty false

echo "== Web production build =="
NEXT_DIST_DIR=.next-types npm --prefix apps/web run build
rm -rf apps/web/.next-types

echo "== Dependency audit =="
npm run audit

echo "All checks passed."

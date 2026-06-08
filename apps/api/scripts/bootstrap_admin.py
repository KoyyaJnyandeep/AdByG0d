from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _import_bootstrap_deps():
    try:
        from adbygod_api.config import settings
        from adbygod_api.routes.auth import bootstrap_admin_user
        return settings, bootstrap_admin_user
    except SyntaxError as exc:
        if "jose" in str(exc.filename or ""):
            raise SystemExit(
                "Wrong Python environment: a legacy 'jose' package was imported from the system interpreter.\n"
                "Use the repo virtualenv instead:\n"
                "  .venv/bin/python scripts/bootstrap_admin.py --username admin --email admin@example.invalid --password 'password'\n"
                "If .venv does not exist yet, create it first:\n"
                "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
            ) from exc
        raise
    except ModuleNotFoundError as exc:
        if exc.name in {"jose", "fastapi", "sqlalchemy", "passlib"}:
            raise SystemExit(
                f"Missing dependency '{exc.name}'. Use the repo virtualenv:\n"
                "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n"
                "  .venv/bin/python scripts/bootstrap_admin.py --username admin --email admin@example.invalid --password 'password'"
            ) from exc
        raise


async def _main() -> None:
    settings, bootstrap_admin_user = _import_bootstrap_deps()
    parser = argparse.ArgumentParser(description="Explicitly create a development bootstrap admin account")
    parser.add_argument("--username", default=settings.DEFAULT_ADMIN_USERNAME or "admin")
    parser.add_argument("--email", default=settings.DEFAULT_ADMIN_EMAIL or "admin@example.invalid")
    parser.add_argument("--password", required=not bool(settings.DEFAULT_ADMIN_PASSWORD), default=settings.DEFAULT_ADMIN_PASSWORD or None)
    parser.add_argument("--full-name", default=settings.DEFAULT_ADMIN_FULL_NAME or "Development Administrator")
    args = parser.parse_args()

    user = await bootstrap_admin_user(
        username=args.username,
        email=args.email,
        password=args.password,
        full_name=args.full_name,
    )
    print(f"Created bootstrap admin: {user.username} ({user.email})")


if __name__ == "__main__":
    asyncio.run(_main())

from __future__ import annotations

import argparse
import asyncio
import copy
import sys
from pathlib import Path

from sqlalchemy import inspect, select, update

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _import_deps():
    try:
        from adbygod_api.database import AsyncSessionLocal
        from adbygod_api.models import (
            Assessment,
            AttackChain,
            ConnectivityProfile,
            JobOutput,
            OffensiveJob,
        )
        return AsyncSessionLocal, Assessment, AttackChain, ConnectivityProfile, JobOutput, OffensiveJob
    except ModuleNotFoundError as exc:
        raise SystemExit(
            f"Missing dependency '{exc.name}'. Run this with the API virtualenv, for example:\n"
            "  cd apps/api && .venv/bin/python scripts/reprotect_sensitive_storage.py"
        ) from exc


async def _table_exists(session, model) -> bool:
    """Return False for older databases that predate a later migration."""
    connection = await session.connection()
    return await connection.run_sync(
        lambda sync_connection: inspect(sync_connection).has_table(model.__tablename__)
    )


async def _rewrite_rows(
    session,
    model,
    fields: tuple[str, ...],
    *,
    dry_run: bool,
) -> tuple[int, bool]:
    if not await _table_exists(session, model):
        return 0, False

    rows = (await session.execute(select(model))).scalars().all()
    if dry_run:
        return len(rows), True
    for row in rows:
        payload = {field: copy.deepcopy(getattr(row, field)) for field in fields}
        await session.execute(update(model).where(model.id == row.id).values(**payload))
    return len(rows), True


async def _main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Rewrite legacy plaintext sensitive rows so the EncryptedJSON/EncryptedText "
            "SQLAlchemy types persist them encrypted at rest."
        )
    )
    parser.add_argument("--dry-run", action="store_true", help="Print row counts without writing anything")
    args = parser.parse_args()

    AsyncSessionLocal, Assessment, AttackChain, ConnectivityProfile, JobOutput, OffensiveJob = _import_deps()

    async with AsyncSessionLocal() as session:
        counts = {
            "connectivity_profiles": await _rewrite_rows(session, ConnectivityProfile, ("config",), dry_run=args.dry_run),
            "assessments": await _rewrite_rows(session, Assessment, ("collection_config",), dry_run=args.dry_run),
            "attack_chains": await _rewrite_rows(session, AttackChain, ("steps", "loot", "params"), dry_run=args.dry_run),
            "offensive_jobs": await _rewrite_rows(session, OffensiveJob, ("params",), dry_run=args.dry_run),
            "job_outputs": await _rewrite_rows(session, JobOutput, ("line",), dry_run=args.dry_run),
        }
        if not args.dry_run:
            await session.commit()

    mode = "would rewrite" if args.dry_run else "rewrote"
    missing_tables: list[str] = []
    for table, (count, table_exists) in counts.items():
        if table_exists:
            print(f"{mode:>13} {count:>6} rows in {table}")
            continue
        missing_tables.append(table)
        print(f"{'skipped':>13} {'-':>6} rows in {table} (table is not present in this database)")

    if missing_tables:
        print(
            "\nNote: this database predates one or more schema migrations. "
            "That is safe for tables that do not exist yet, but run `alembic upgrade head` "
            "before starting the API so the database schema matches the code."
        )


if __name__ == "__main__":
    asyncio.run(_main())

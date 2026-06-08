from __future__ import annotations
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


def ev(x) -> str:
    """Return .value for enums, str() otherwise."""
    return x.value if hasattr(x, "value") else str(x)


def parse_enum(cls, val: str, field: str = "value"):
    try:
        return cls(val.strip().upper())
    except ValueError as exc:
        raise HTTPException(400, f"Invalid {field}: {val}") from exc


async def q_count(db: AsyncSession, q) -> int:
    r = await db.execute(select(func.count()).select_from(q.subquery()))
    return r.scalar_one() or 0

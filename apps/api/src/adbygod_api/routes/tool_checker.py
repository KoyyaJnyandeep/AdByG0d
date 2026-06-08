from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.tool_checker.probe import probe_all_tools, TOOL_CATALOG
from adbygod_api.database import AsyncSessionLocal, get_db
from adbygod_api.models import PlatformUser, ToolCheckResult
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tool-checker", tags=["tool-checker"])


class ToolResultOut(BaseModel):
    tool_name: str
    available: bool
    version: str | None
    install_cmd: str
    phases: list[int]
    checked_at: str | None


async def _run_scan(user_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        try:
            results = await probe_all_tools()
            await db.execute(delete(ToolCheckResult).where(ToolCheckResult.checked_by == user_id))
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            for r in results:
                db.add(ToolCheckResult(
                    id=uuid.uuid4(),
                    tool_name=r.name,
                    available=r.available,
                    version=r.version,
                    install_cmd=r.install_cmd,
                    phases=json.dumps(r.phases),
                    checked_at=now,
                    checked_by=user_id,
                ))
            await db.commit()
        except Exception:
            log.exception("Tool scan failed for user %s", user_id)


@router.post("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    current_user: PlatformUser = Depends(get_current_user),
):
    if not current_user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin access required")
    background_tasks.add_task(_run_scan, current_user.id)
    return {"status": "queued", "message": f"Scanning {len(TOOL_CATALOG)} tools in background"}


@router.get("/results", response_model=list[ToolResultOut])
async def get_results(
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin access required")
    rows = (await db.execute(
        select(ToolCheckResult)
        .where(ToolCheckResult.checked_by == current_user.id)
        .order_by(ToolCheckResult.tool_name)
    )).scalars().all()
    return [
        ToolResultOut(
            tool_name=r.tool_name,
            available=r.available,
            version=r.version,
            install_cmd=r.install_cmd or "",
            phases=json.loads(r.phases) if r.phases else [],
            checked_at=r.checked_at.isoformat() if r.checked_at else None,
        )
        for r in rows
    ]

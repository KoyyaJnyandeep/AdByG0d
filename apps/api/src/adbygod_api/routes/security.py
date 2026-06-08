from __future__ import annotations
from fastapi import APIRouter, Depends
from adbygod_api.models import PlatformUser
from adbygod_api.routes.auth import get_current_user
from adbygod_api.core.privileged_operations import get_capabilities_summary

router = APIRouter(prefix="/security", tags=["security"])

@router.get("/capabilities")
async def security_capabilities(current_user: PlatformUser = Depends(get_current_user)):
    """Return safe boolean flags for which dangerous features are enabled."""
    return get_capabilities_summary()

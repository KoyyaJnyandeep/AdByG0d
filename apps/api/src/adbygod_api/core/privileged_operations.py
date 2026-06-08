from __future__ import annotations
from enum import Enum
from fastapi import HTTPException, status
from adbygod_api.config import settings


class DangerousAction(str, Enum):
    COMMAND_EXECUTION = "command_execution"
    AI_OPERATOR_EXECUTION = "ai_operator_execution"
    AI_ARBITRARY_SHELL = "ai_arbitrary_shell"
    REMOTE_COLLECTION = "remote_collection"
    TUNNEL_MANAGEMENT = "tunnel_management"
    CREDENTIAL_HANDLING = "credential_handling"
    FILE_IMPORT = "file_import"
    CHAIN_BUILDER = "chain_builder"


_ACTION_FLAGS = {
    DangerousAction.COMMAND_EXECUTION: lambda s: s.ENABLE_COMMAND_EXECUTION,
    DangerousAction.AI_OPERATOR_EXECUTION: lambda s: s.ENABLE_COMMAND_EXECUTION,
    DangerousAction.AI_ARBITRARY_SHELL: lambda s: getattr(s, 'ENABLE_AI_ARBITRARY_SHELL', False),
    DangerousAction.REMOTE_COLLECTION: lambda _: True,  # Always allowed when authenticated
    DangerousAction.TUNNEL_MANAGEMENT: lambda s: s.ENABLE_TUNNEL_MANAGEMENT,
    DangerousAction.CREDENTIAL_HANDLING: lambda s: s.ENABLE_COMMAND_EXECUTION,
    DangerousAction.FILE_IMPORT: lambda _: True,  # Import is always available
    DangerousAction.CHAIN_BUILDER: lambda s: s.ENABLE_CHAIN_BUILDER,
}

_ACTION_REQUIRES_SUPERADMIN = {
    DangerousAction.COMMAND_EXECUTION,
    DangerousAction.AI_OPERATOR_EXECUTION,
    DangerousAction.AI_ARBITRARY_SHELL,
    DangerousAction.TUNNEL_MANAGEMENT,
    DangerousAction.CREDENTIAL_HANDLING,
    DangerousAction.CHAIN_BUILDER,
}


def is_action_enabled(action: DangerousAction) -> bool:
    flag_fn = _ACTION_FLAGS.get(action)
    return bool(flag_fn(settings)) if flag_fn else False


async def require_dangerous_action_allowed(action: DangerousAction, current_user) -> None:
    """Raise HTTP 403 if action is not allowed for this user/config."""
    if not is_action_enabled(action):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action '{action.value}' is disabled. Enable the corresponding feature flag in server config.",
        )
    if action in _ACTION_REQUIRES_SUPERADMIN and not getattr(current_user, 'is_superadmin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action '{action.value}' requires superadmin privileges.",
        )


def get_capabilities_summary() -> dict:
    """Safe boolean summary for frontend — no secrets exposed."""
    return {
        "command_execution_enabled": is_action_enabled(DangerousAction.COMMAND_EXECUTION),
        "ai_operator_enabled": True,  # AI chat always available; execution requires flag
        "ai_execution_enabled": is_action_enabled(DangerousAction.AI_OPERATOR_EXECUTION),
        "ai_arbitrary_shell_enabled": is_action_enabled(DangerousAction.AI_ARBITRARY_SHELL),
        "remote_collection_enabled": is_action_enabled(DangerousAction.REMOTE_COLLECTION),
        "tunnel_management_enabled": is_action_enabled(DangerousAction.TUNNEL_MANAGEMENT),
        "chain_builder_enabled": is_action_enabled(DangerousAction.CHAIN_BUILDER),
        "file_import_enabled": is_action_enabled(DangerousAction.FILE_IMPORT),
        "environment": settings.ENVIRONMENT,
    }

from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from adbygod_api.models import Assessment, Entity, Finding, PlatformUser, Workspace, WorkspaceUser

LEGACY_WORKSPACE_FORBIDDEN_DETAIL = (
    "This object is not assigned to a workspace. Legacy unscoped data is only accessible to superadmin users."
)


async def get_accessible_workspace_ids(db: AsyncSession, current_user: PlatformUser) -> set[UUID]:
    if current_user.is_superadmin:
        return set()

    result = await db.execute(
        select(WorkspaceUser.workspace_id).where(WorkspaceUser.user_id == current_user.id)
    )
    return {workspace_id for workspace_id in result.scalars().all() if workspace_id is not None}


async def require_workspace_membership(
    workspace_id: UUID | None,
    db: AsyncSession,
    current_user: PlatformUser,
) -> UUID | None:
    if current_user.is_superadmin:
        return workspace_id

    if workspace_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=LEGACY_WORKSPACE_FORBIDDEN_DETAIL)

    membership = await db.execute(
        select(WorkspaceUser.id).where(
            WorkspaceUser.workspace_id == workspace_id,
            WorkspaceUser.user_id == current_user.id,
        )
    )
    if membership.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Workspace access denied")

    return workspace_id


async def require_superadmin(current_user: PlatformUser) -> PlatformUser:
    if not current_user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin access required")
    return current_user


async def require_workspace_write_access(
    workspace_id: UUID | None,
    db: AsyncSession,
    current_user: PlatformUser,
) -> UUID | None:
    if workspace_id is None and not current_user.is_superadmin:
        workspace_ids = await get_accessible_workspace_ids(db, current_user)
        if len(workspace_ids) == 0:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No accessible workspace available for this user",
            )
        # The launch UI intentionally stays workspace-free. When a user can
        # write to multiple workspaces, choose a stable default instead of
        # blocking assessment creation behind an internal scoping detail.
        workspace_id = sorted(workspace_ids, key=str)[0]

    if workspace_id is not None:
        workspace_result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
        if workspace_result.scalars().first() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")

    if current_user.is_superadmin:
        return workspace_id

    membership = await db.execute(
        select(WorkspaceUser.role).where(
            WorkspaceUser.workspace_id == workspace_id,
            WorkspaceUser.user_id == current_user.id,
        )
    )
    role = membership.scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Workspace access denied")
    if str(role).lower() == "viewer":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Workspace write access denied")

    return workspace_id


async def require_assessment_access(
    assessment_id: UUID,
    db: AsyncSession,
    current_user: PlatformUser,
    *,
    include_collection_config: bool = False,
) -> Assessment:
    statement = select(Assessment).where(Assessment.id == assessment_id)
    if not include_collection_config:
        statement = statement.options(defer(Assessment.collection_config))
    result = await db.execute(statement)
    assessment = result.scalars().first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    await require_workspace_membership(assessment.workspace_id, db, current_user)
    return assessment


async def require_assessment_write_access(
    assessment_id: UUID,
    db: AsyncSession,
    current_user: PlatformUser,
    *,
    include_collection_config: bool = False,
) -> Assessment:
    assessment = await require_assessment_access(
        assessment_id,
        db,
        current_user,
        include_collection_config=include_collection_config,
    )
    await require_workspace_write_access(assessment.workspace_id, db, current_user)
    return assessment


async def require_finding_access(
    finding_id: UUID,
    db: AsyncSession,
    current_user: PlatformUser,
) -> Finding:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    await require_assessment_access(finding.assessment_id, db, current_user)
    return finding


async def require_entity_access(
    entity_id: UUID,
    db: AsyncSession,
    current_user: PlatformUser,
) -> Entity:
    result = await db.execute(select(Entity).where(Entity.id == entity_id))
    entity = result.scalars().first()
    if not entity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entity not found")

    await require_assessment_access(entity.assessment_id, db, current_user)
    return entity


async def scope_assessment_query(
    statement: Select,
    db: AsyncSession,
    current_user: PlatformUser,
) -> Select:
    if current_user.is_superadmin:
        return statement

    workspace_ids = await get_accessible_workspace_ids(db, current_user)
    if not workspace_ids:
        return statement.where(False)

    return statement.where(Assessment.workspace_id.in_(workspace_ids))


async def scope_assessment_child_query(
    statement: Select,
    assessment_id_column,
    db: AsyncSession,
    current_user: PlatformUser,
) -> Select:
    if current_user.is_superadmin:
        return statement

    workspace_ids = await get_accessible_workspace_ids(db, current_user)
    if not workspace_ids:
        return statement.where(False)

    # add distinct() to prevent duplicate rows when the caller's
    # base statement already involves a join that touches the Assessment table
    return statement.join(Assessment, assessment_id_column == Assessment.id).where(
        Assessment.workspace_id.in_(workspace_ids)
    ).distinct()

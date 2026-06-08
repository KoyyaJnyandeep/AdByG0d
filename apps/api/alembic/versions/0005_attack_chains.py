"""attack_chains table

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def uuid_type():
    return postgresql.UUID(as_uuid=True) if _is_postgres() else sa.String(36)


def upgrade() -> None:
    op.create_table(
        "attack_chains",
        sa.Column("id", uuid_type(), primary_key=True),
        sa.Column("assessment_id", uuid_type(), sa.ForeignKey("assessments.id"), nullable=True),
        sa.Column("owner_user_id", uuid_type(), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, server_default="Path to DA"),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("target_label", sa.String(255), nullable=True),
        sa.Column("path_nodes", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("steps", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("current_step", sa.Integer, nullable=False, server_default="0"),
        sa.Column("loot", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("job_ids", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("target", sa.String(255), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("params", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_attack_chains_owner", "attack_chains", ["owner_user_id"])
    op.create_index("ix_attack_chains_assessment", "attack_chains", ["assessment_id"])


def downgrade() -> None:
    op.drop_table("attack_chains")

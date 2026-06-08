"""add connectivity_profiles table and assessment FK

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def uuid_type():
    return postgresql.UUID(as_uuid=True) if _is_postgres() else sa.String(36)


def upgrade() -> None:
    op.create_table(
        "connectivity_profiles",
        sa.Column("id", uuid_type(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("mode", sa.String(50), nullable=False),
        sa.Column("config", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("is_default", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="UNKNOWN"),
        sa.Column("last_tested_at", sa.DateTime, nullable=True),
        sa.Column("last_latency_ms", sa.Integer, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("created_by", uuid_type(), sa.ForeignKey("platform_users.id"), nullable=True),
    )
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.add_column(sa.Column("connectivity_profile_id", uuid_type(), nullable=True))
        batch_op.create_foreign_key(
            "fk_assessments_connectivity_profile_id",
            "connectivity_profiles",
            ["connectivity_profile_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.drop_constraint("fk_assessments_connectivity_profile_id", type_="foreignkey")
        batch_op.drop_column("connectivity_profile_id")
    op.drop_table("connectivity_profiles")

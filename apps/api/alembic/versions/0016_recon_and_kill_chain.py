"""Add recon_scans and kill_chain_progress tables

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-29
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


def _is_postgres():
    from alembic import op as _op
    return _op.get_bind().dialect.name == "postgresql"


def now_default():
    return sa.text("NOW()") if _is_postgres() else sa.text("CURRENT_TIMESTAMP")

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recon_scans",
        sa.Column("id", sa.CHAR(36), primary_key=True),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("target_dc_ip", sa.String(50), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("findings", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("summary", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=now_default()),
    )
    op.create_table(
        "kill_chain_progress",
        sa.Column("id", sa.CHAR(36), primary_key=True),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("phase_id", sa.Integer, nullable=False),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="not_started"),
        sa.Column("techniques_run", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=now_default()),
    )


def downgrade() -> None:
    op.drop_table("kill_chain_progress")
    op.drop_table("recon_scans")

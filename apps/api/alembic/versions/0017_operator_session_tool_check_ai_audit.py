"""Add operator_sessions, tool_check_results, ai_operator_actions tables

Revision ID: 0017
Revises: 0016
Create Date: 2026-05-29
"""
from alembic import op
import sqlalchemy as sa


def _is_postgres():
    from alembic import op as _op
    return _op.get_bind().dialect.name == "postgresql"


def now_default():
    return sa.text("NOW()") if _is_postgres() else sa.text("CURRENT_TIMESTAMP")


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operator_sessions",
        sa.Column("id", sa.CHAR(36), primary_key=True),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_ip", sa.String(100), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("auth_level", sa.String(50), nullable=False, server_default="anon"),
        sa.Column("commands_run", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("machines_owned", sa.Integer, nullable=False, server_default="0"),
        sa.Column("users_owned", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_by", sa.CHAR(36), sa.ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=False, server_default=now_default()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=now_default()),
    )

    op.create_table(
        "tool_check_results",
        sa.Column("id", sa.CHAR(36), primary_key=True),
        sa.Column("tool_name", sa.String(100), nullable=False, index=True),
        sa.Column("available", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("install_cmd", sa.Text, nullable=True),
        sa.Column("phases", sa.String(100), nullable=False, server_default=""),
        sa.Column("checked_at", sa.DateTime, nullable=False, server_default=now_default()),
        sa.Column("checked_by", sa.CHAR(36), sa.ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True),
    )

    op.create_table(
        "ai_operator_actions",
        sa.Column("id", sa.CHAR(36), primary_key=True),
        sa.Column("session_id", sa.CHAR(36), sa.ForeignKey("operator_sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("technique_id", sa.String(100), nullable=True),
        sa.Column("command_executed", sa.Text, nullable=True),
        sa.Column("output_snippet", sa.Text, nullable=True),
        sa.Column("reasoning", sa.Text, nullable=True),
        sa.Column("phase_id", sa.Integer, nullable=True),
        sa.Column("worker_id", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=now_default()),
    )


def downgrade() -> None:
    op.drop_table("ai_operator_actions")
    op.drop_table("tool_check_results")
    op.drop_table("operator_sessions")

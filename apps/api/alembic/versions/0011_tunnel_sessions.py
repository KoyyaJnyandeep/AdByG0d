"""add tunnel_sessions table

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def uuid_type():
    return postgresql.UUID(as_uuid=True) if _is_postgres() else sa.String(36)


def upgrade() -> None:
    op.create_table(
        "tunnel_sessions",
        sa.Column("id", uuid_type(), primary_key=True),
        sa.Column("profile_id", uuid_type(), sa.ForeignKey("connectivity_profiles.id"), nullable=False),
        sa.Column("mode", sa.String(50), nullable=False),
        sa.Column("jumpbox_host", sa.String(255), nullable=False),
        sa.Column("jumpbox_port", sa.Integer, nullable=False),
        sa.Column("jumpbox_username", sa.String(255), nullable=False),
        sa.Column("local_host", sa.String(50), nullable=False, server_default="127.0.0.1"),
        sa.Column("local_port", sa.Integer, nullable=False),
        sa.Column("process_pid", sa.Integer, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="starting"),
        sa.Column("started_by", uuid_type(), sa.ForeignKey("platform_users.id"), nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("stopped_at", sa.DateTime, nullable=True),
        sa.Column("last_healthcheck_at", sa.DateTime, nullable=True),
        sa.Column("error_summary", sa.Text, nullable=True),
        sa.Column("sanitized_command_preview", sa.Text, nullable=False, server_default=""),
        sa.Column("metadata_json", sa.JSON, nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_table("tunnel_sessions")

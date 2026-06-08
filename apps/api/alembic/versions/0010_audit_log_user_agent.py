"""add audit log user agent

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-10
"""

from alembic import op
import sqlalchemy as sa


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("audit_logs")}
    if "user_agent" not in columns:
        op.add_column("audit_logs", sa.Column("user_agent", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("audit_logs")}
    if "user_agent" in columns:
        op.drop_column("audit_logs", "user_agent")

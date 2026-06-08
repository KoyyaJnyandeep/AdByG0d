"""add assessment progress columns

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assessments", sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("assessments", sa.Column("last_message", sa.String(500), nullable=True))


def downgrade() -> None:
    op.drop_column("assessments", "last_message")
    op.drop_column("assessments", "progress_pct")

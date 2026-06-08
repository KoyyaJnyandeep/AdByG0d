"""add extra columns to attack_chains

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-04
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("attack_chains", sa.Column("starting_position", sa.String(30), nullable=True))
    op.add_column("attack_chains", sa.Column("all_paths", sa.JSON, nullable=False, server_default="[]"))
    op.add_column("attack_chains", sa.Column("selected_path", sa.Integer, nullable=False, server_default="0"))
    op.add_column("attack_chains", sa.Column("failed_steps", sa.JSON, nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("attack_chains", "failed_steps")
    op.drop_column("attack_chains", "selected_path")
    op.drop_column("attack_chains", "all_paths")
    op.drop_column("attack_chains", "starting_position")

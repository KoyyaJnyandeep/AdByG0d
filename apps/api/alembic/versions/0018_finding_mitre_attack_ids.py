"""add finding mitre attack ids

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-30
"""
from alembic import op
import sqlalchemy as sa


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("mitre_attack_ids", sa.JSON(), nullable=True))
    op.execute("UPDATE findings SET mitre_attack_ids = '[]' WHERE mitre_attack_ids IS NULL")


def downgrade() -> None:
    op.drop_column("findings", "mitre_attack_ids")

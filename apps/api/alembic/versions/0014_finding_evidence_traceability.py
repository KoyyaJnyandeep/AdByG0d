"""Add traceability metadata to finding evidence links

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-19
"""
from alembic import op
import sqlalchemy as sa


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "finding_evidence",
        sa.Column("relation_type", sa.String(50), nullable=False, server_default="supports"),
    )
    op.add_column("finding_evidence", sa.Column("source_ref", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("finding_evidence", "source_ref")
    op.drop_column("finding_evidence", "relation_type")

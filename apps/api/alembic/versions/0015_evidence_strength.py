"""Add evidence_strength to finding_evidence for quality classification

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-19
"""
from alembic import op
import sqlalchemy as sa


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "finding_evidence",
        sa.Column(
            "evidence_strength",
            sa.String(50),
            nullable=False,
            server_default="payload_level_fallback",
        ),
    )


def downgrade() -> None:
    op.drop_column("finding_evidence", "evidence_strength")

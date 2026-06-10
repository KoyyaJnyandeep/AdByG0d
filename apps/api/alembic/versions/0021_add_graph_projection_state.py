"""add graph_projection_state

Revision ID: 0021
Revises: 0020
Create Date: 2026-06-10
"""
from alembic import op
import sqlalchemy as sa

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "graph_projection_state",
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id"), primary_key=True),
        sa.Column("last_projected_at", sa.DateTime(), nullable=True),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
    )


def downgrade() -> None:
    op.drop_table("graph_projection_state")

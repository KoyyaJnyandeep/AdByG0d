"""add provenance columns for findings and evidence

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-23
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    origin_enum = sa.Enum('COLLECTED', 'IMPORTED', 'INFERRED', 'SIMULATED', name='dataorigin')
    origin_enum.create(op.get_bind(), checkfirst=True)

    op.add_column(
        'evidence_records',
        sa.Column('origin', origin_enum, nullable=False, server_default='COLLECTED'),
    )
    op.add_column(
        'findings',
        sa.Column('origin', origin_enum, nullable=False, server_default='INFERRED'),
    )


def downgrade() -> None:
    op.drop_column('findings', 'origin')
    op.drop_column('evidence_records', 'origin')
    sa.Enum(name='dataorigin').drop(op.get_bind(), checkfirst=True)

"""workspace and evidence unique constraints

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-12
"""
from alembic import op


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        'uq_workspace_users_workspace_user',
        'workspace_users',
        ['workspace_id', 'user_id'],
        unique=True,
    )
    op.create_index(
        'uq_finding_evidence_pair',
        'finding_evidence',
        ['finding_id', 'evidence_id'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index('uq_finding_evidence_pair', table_name='finding_evidence')
    op.drop_index('uq_workspace_users_workspace_user', table_name='workspace_users')

"""add offensive_jobs and job_outputs tables

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def uuid_type():
    return postgresql.UUID(as_uuid=True) if _is_postgres() else sa.String(36)


def upgrade() -> None:
    op.create_table(
        'offensive_jobs',
        sa.Column('id', uuid_type(), primary_key=True),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=True),
        sa.Column('technique_id', sa.String(100), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('params', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('executor', sa.String(50), nullable=False, server_default='impacket'),
        sa.Column('opsec_profile', sa.String(20), nullable=False, server_default='BALANCED'),
        sa.Column('status', sa.String(20), nullable=False, server_default='PENDING'),
        sa.Column('owner_user_id', uuid_type(), sa.ForeignKey('platform_users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
    )

    op.create_table(
        'job_outputs',
        sa.Column('id', uuid_type(), primary_key=True),
        sa.Column('job_id', uuid_type(), sa.ForeignKey('offensive_jobs.id'), nullable=False),
        sa.Column('stream', sa.String(10), nullable=False, server_default='stdout'),
        sa.Column('line', sa.Text(), nullable=False),
        sa.Column('ts', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_job_outputs_job_id', 'job_outputs', ['job_id'])


def downgrade() -> None:
    op.drop_index('ix_job_outputs_job_id', 'job_outputs')
    op.drop_table('job_outputs')
    op.drop_table('offensive_jobs')

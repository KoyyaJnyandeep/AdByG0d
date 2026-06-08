"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def uuid_type():
    return postgresql.UUID(as_uuid=True) if _is_postgres() else sa.String(36)


def uuid_default():
    return sa.text("uuid_generate_v4()") if _is_postgres() else None


def json_type():
    return postgresql.JSONB() if _is_postgres() else sa.JSON()


def now_default():
    return sa.text("NOW()") if _is_postgres() else sa.text("CURRENT_TIMESTAMP")


def upgrade() -> None:
    # Extensions
    if _is_postgres():
        op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')

    # platform_users
    op.create_table(
        'platform_users',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('username', sa.String(255), nullable=False, unique=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('is_superadmin', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
        sa.Column('last_login', sa.DateTime()),
        sa.Column('preferences', json_type(), server_default='{}'),
    )

    # workspaces
    op.create_table(
        'workspaces',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
        sa.Column('updated_at', sa.DateTime(), server_default=now_default()),
        sa.Column('settings', json_type(), server_default='{}'),
    )

    # workspace_users
    op.create_table(
        'workspace_users',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('workspace_id', uuid_type(), sa.ForeignKey('workspaces.id'), nullable=False),
        sa.Column('user_id', uuid_type(), sa.ForeignKey('platform_users.id'), nullable=False),
        sa.Column('role', sa.String(50), server_default='analyst'),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
    )

    # assessments
    op.create_table(
        'assessments',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('workspace_id', uuid_type(), sa.ForeignKey('workspaces.id')),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('dc_ip', sa.String(50)),
        sa.Column('status', sa.String(50), server_default='PENDING'),
        sa.Column('collection_mode', sa.String(50)),
        sa.Column('started_at', sa.DateTime()),
        sa.Column('completed_at', sa.DateTime()),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
        sa.Column('created_by', uuid_type(), sa.ForeignKey('platform_users.id')),
        sa.Column('modules_run', json_type(), server_default='[]'),
        sa.Column('collection_config', json_type(), server_default='{}'),
        sa.Column('error_message', sa.Text()),
        sa.Column('stats', json_type(), server_default='{}'),
        sa.Column('exposure_score', sa.Float(), server_default='0'),
        sa.Column('previous_assessment_id', uuid_type(), sa.ForeignKey('assessments.id')),
    )
    op.create_index('ix_assessments_workspace_status', 'assessments', ['workspace_id', 'status'])
    op.create_index('ix_assessments_domain', 'assessments', ['domain'])

    # entities
    op.create_table(
        'entities',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('entity_type', sa.String(50), nullable=False),
        sa.Column('distinguished_name', sa.Text()),
        sa.Column('object_sid', sa.String(100)),
        sa.Column('sam_account_name', sa.String(255)),
        sa.Column('display_name', sa.String(255)),
        sa.Column('dns_hostname', sa.String(255)),
        sa.Column('domain', sa.String(255)),
        sa.Column('is_enabled', sa.Boolean(), server_default='true'),
        sa.Column('is_admin_count', sa.Boolean(), server_default='false'),
        sa.Column('is_sensitive', sa.Boolean(), server_default='false'),
        sa.Column('is_protected_user', sa.Boolean(), server_default='false'),
        sa.Column('tier', sa.Integer()),
        sa.Column('is_crown_jewel', sa.Boolean(), server_default='false'),
        sa.Column('business_tags', json_type(), server_default='[]'),
        sa.Column('owner_team', sa.String(255)),
        sa.Column('attributes', json_type(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
        sa.Column('object_created', sa.DateTime()),
        sa.Column('object_modified', sa.DateTime()),
        sa.Column('last_logon', sa.DateTime()),
        sa.Column('password_last_set', sa.DateTime()),
    )
    op.create_index('ix_entities_assessment_type', 'entities', ['assessment_id', 'entity_type'])
    op.create_index('ix_entities_sid', 'entities', ['object_sid'])
    op.create_index('ix_entities_samaccountname', 'entities', ['sam_account_name'])

    # evidence_records
    op.create_table(
        'evidence_records',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('source_type', sa.String(50)),
        sa.Column('source_host', sa.String(255)),
        sa.Column('source_port', sa.Integer()),
        sa.Column('collection_method', sa.String(100)),
        sa.Column('raw_data', json_type()),
        sa.Column('collected_at', sa.DateTime(), server_default=now_default()),
        sa.Column('is_corroborated', sa.Boolean(), server_default='false'),
        sa.Column('confidence', sa.Float(), server_default='1.0'),
    )

    # graph_edges
    op.create_table(
        'graph_edges',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('source_id', uuid_type(), sa.ForeignKey('entities.id'), nullable=False),
        sa.Column('target_id', uuid_type(), sa.ForeignKey('entities.id'), nullable=False),
        sa.Column('edge_type', sa.String(100), nullable=False),
        sa.Column('provenance', sa.Text()),
        sa.Column('inheritance_root', sa.Text()),
        sa.Column('risk_weight', sa.Float(), server_default='1.0'),
        sa.Column('evidence_id', uuid_type(), sa.ForeignKey('evidence_records.id')),
        sa.Column('attributes', json_type(), server_default='{}'),
    )
    op.create_index('ix_edges_assessment_type', 'graph_edges', ['assessment_id', 'edge_type'])
    op.create_index('ix_edges_source', 'graph_edges', ['source_id'])
    op.create_index('ix_edges_target', 'graph_edges', ['target_id'])

    # findings
    op.create_table(
        'findings',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('finding_type', sa.String(100), nullable=False),
        sa.Column('module', sa.String(100), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('technical_severity', sa.Float()),
        sa.Column('reachability_score', sa.Float()),
        sa.Column('confidence', sa.Float(), server_default='1.0'),
        sa.Column('asset_criticality', sa.Float()),
        sa.Column('breadth_score', sa.Float()),
        sa.Column('remediation_complexity', sa.Float()),
        sa.Column('composite_score', sa.Float()),
        sa.Column('affected_count', sa.Integer(), server_default='0'),
        sa.Column('affected_objects', json_type(), server_default='[]'),
        sa.Column('root_cause', sa.Text()),
        sa.Column('causal_chain', json_type(), server_default='[]'),
        sa.Column('attack_path', json_type(), server_default='[]'),
        sa.Column('status', sa.String(50), server_default='OPEN'),
        sa.Column('assigned_to', uuid_type(), sa.ForeignKey('platform_users.id')),
        sa.Column('remediation', sa.Text()),
        sa.Column('remediation_steps', json_type(), server_default='[]'),
        sa.Column('fix_complexity', sa.String(50)),
        sa.Column('estimated_effort', sa.String(100)),
        sa.Column('references', json_type(), server_default='[]'),
        sa.Column('cve_ids', json_type(), server_default='[]'),
        sa.Column('first_seen', sa.DateTime(), server_default=now_default()),
        sa.Column('last_seen', sa.DateTime(), server_default=now_default()),
        sa.Column('drift_status', sa.String(50)),
        sa.Column('previous_finding_id', uuid_type(), sa.ForeignKey('findings.id')),
        sa.Column('waiver_reason', sa.Text()),
        sa.Column('waiver_expiry', sa.DateTime()),
        sa.Column('waiver_owner', sa.String(255)),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
        sa.Column('updated_at', sa.DateTime(), server_default=now_default()),
    )
    op.create_index('ix_findings_assessment_severity', 'findings', ['assessment_id', 'severity'])
    op.create_index('ix_findings_type', 'findings', ['finding_type'])
    op.create_index('ix_findings_status', 'findings', ['status'])
    op.create_index('ix_findings_score', 'findings', ['composite_score'])

    # finding_evidence
    op.create_table(
        'finding_evidence',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('finding_id', uuid_type(), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('evidence_id', uuid_type(), sa.ForeignKey('evidence_records.id'), nullable=False),
        sa.Column('relevance', sa.Text()),
    )

    # exposure_paths
    op.create_table(
        'exposure_paths',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('source_entity_id', uuid_type(), sa.ForeignKey('entities.id')),
        sa.Column('target_entity_id', uuid_type(), sa.ForeignKey('entities.id')),
        sa.Column('path_steps', json_type()),
        sa.Column('hop_count', sa.Integer()),
        sa.Column('path_score', sa.Float()),
        sa.Column('target_tier', sa.Integer()),
        sa.Column('path_type', sa.String(100)),
        sa.Column('explanation', sa.Text()),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
    )

    # assessment_diffs
    op.create_table(
        'assessment_diffs',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('baseline_assessment_id', uuid_type(), sa.ForeignKey('assessments.id')),
        sa.Column('current_assessment_id', uuid_type(), sa.ForeignKey('assessments.id')),
        sa.Column('new_findings', json_type(), server_default='[]'),
        sa.Column('resolved_findings', json_type(), server_default='[]'),
        sa.Column('regressed_findings', json_type(), server_default='[]'),
        sa.Column('new_entities', json_type(), server_default='[]'),
        sa.Column('removed_entities', json_type(), server_default='[]'),
        sa.Column('score_delta', sa.Float()),
        sa.Column('severity_deltas', json_type(), server_default='{}'),
        sa.Column('computed_at', sa.DateTime(), server_default=now_default()),
    )

    # cert_templates
    op.create_table(
        'cert_templates',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('assessment_id', uuid_type(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('name', sa.String(255)),
        sa.Column('distinguished_name', sa.Text()),
        sa.Column('ca_name', sa.String(255)),
        sa.Column('enrollee_supplies_subject', sa.Boolean(), server_default='false'),
        sa.Column('requires_manager_approval', sa.Boolean(), server_default='false'),
        sa.Column('authorized_signatures_required', sa.Integer(), server_default='0'),
        sa.Column('validity_period', sa.String(50)),
        sa.Column('renewal_period', sa.String(50)),
        sa.Column('ekus', json_type(), server_default='[]'),
        sa.Column('enrollment_rights', json_type(), server_default='[]'),
        sa.Column('write_rights', json_type(), server_default='[]'),
        sa.Column('esc1_vulnerable', sa.Boolean(), server_default='false'),
        sa.Column('esc2_vulnerable', sa.Boolean(), server_default='false'),
        sa.Column('esc3_vulnerable', sa.Boolean(), server_default='false'),
        sa.Column('esc4_vulnerable', sa.Boolean(), server_default='false'),
        sa.Column('raw_attributes', json_type(), server_default='{}'),
    )

    # audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', uuid_type(), primary_key=True, server_default=uuid_default()),
        sa.Column('user_id', uuid_type(), sa.ForeignKey('platform_users.id')),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(100)),
        sa.Column('resource_id', sa.String(100)),
        sa.Column('details', json_type(), server_default='{}'),
        sa.Column('ip_address', sa.String(50)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('created_at', sa.DateTime(), server_default=now_default()),
    )
    op.create_index('ix_audit_user_time', 'audit_logs', ['user_id', 'created_at'])


def downgrade() -> None:
    for table in [
        'audit_logs', 'cert_templates', 'assessment_diffs', 'exposure_paths',
        'finding_evidence', 'findings', 'graph_edges', 'evidence_records',
        'entities', 'assessments', 'workspace_users', 'workspaces', 'platform_users',
    ]:
        op.drop_table(table)

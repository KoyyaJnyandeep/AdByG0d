"""add validation_runs and validation_expert_decisions tables

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def uuid_type():
    return postgresql.UUID(as_uuid=True) if _is_postgres() else sa.String(36)


def upgrade() -> None:
    op.create_table(
        "validation_runs",
        sa.Column("id", uuid_type(), primary_key=True),
        sa.Column("assessment_id", uuid_type(), sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("module_id", sa.String(100), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("requested_mode", sa.String(50), nullable=False),
        sa.Column("execution_mode", sa.String(50), nullable=False, server_default="SIMULATION_CONSENSUS"),
        sa.Column("status", sa.String(50), nullable=False, server_default="RUNNING"),
        sa.Column("final_verdict", sa.String(100), nullable=True),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("confidence", sa.Integer, nullable=True),
        sa.Column("consensus_score", sa.Integer, nullable=True),
        sa.Column("evidence_quality_score", sa.Integer, nullable=True),
        sa.Column("severity_projection", sa.String(50), nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("reasoning_json", sa.JSON, nullable=True),
        sa.Column("telemetry_json", sa.JSON, nullable=True),
        sa.Column("created_by", uuid_type(), sa.ForeignKey("platform_users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("simulated", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("origin", sa.String(50), nullable=False, server_default="SIMULATED"),
    )
    op.create_index("ix_validation_runs_assessment_id", "validation_runs", ["assessment_id"])

    op.create_table(
        "validation_expert_decisions",
        sa.Column("id", uuid_type(), primary_key=True),
        sa.Column("validation_run_id", uuid_type(), sa.ForeignKey("validation_runs.id"), nullable=False),
        sa.Column("expert_id", sa.String(100), nullable=False),
        sa.Column("expert_name", sa.String(255), nullable=False),
        sa.Column("verdict", sa.String(50), nullable=False),
        sa.Column("score_delta", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("severity_hint", sa.String(50), nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("reasoning_json", sa.JSON, nullable=True),
        sa.Column("supporting_signals_json", sa.JSON, nullable=True),
        sa.Column("contradicting_signals_json", sa.JSON, nullable=True),
        sa.Column("missing_signals_json", sa.JSON, nullable=True),
        sa.Column("evidence_refs_json", sa.JSON, nullable=True),
        sa.Column("related_finding_ids_json", sa.JSON, nullable=True),
        sa.Column("related_entity_ids_json", sa.JSON, nullable=True),
        sa.Column("related_edge_ids_json", sa.JSON, nullable=True),
        sa.Column("telemetry_json", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_validation_expert_decisions_run_id", "validation_expert_decisions", ["validation_run_id"])


def downgrade() -> None:
    op.drop_table("validation_expert_decisions")
    op.drop_table("validation_runs")

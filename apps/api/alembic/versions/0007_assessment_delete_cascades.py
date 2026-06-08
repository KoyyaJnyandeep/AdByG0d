"""add assessment delete cascades

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-01
"""
from alembic import op


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def _is_sqlite() -> bool:
    return op.get_bind().dialect.name == "sqlite"


def _replace_fk(table: str, name: str, columns: list[str], ref_table: str, ref_columns: list[str], *, ondelete: str) -> None:
    op.drop_constraint(name, table, type_="foreignkey")
    op.create_foreign_key(name, table, ref_table, columns, ref_columns, ondelete=ondelete)


def upgrade() -> None:
    if _is_sqlite():
        return

    _replace_fk("entities", "entities_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("evidence_records", "evidence_records_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("graph_edges", "graph_edges_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("findings", "findings_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("exposure_paths", "exposure_paths_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("cert_templates", "cert_templates_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("attack_chains", "attack_chains_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")
    _replace_fk("offensive_jobs", "offensive_jobs_assessment_id_fkey", ["assessment_id"], "assessments", ["id"], ondelete="CASCADE")

    _replace_fk("assessment_diffs", "assessment_diffs_baseline_assessment_id_fkey", ["baseline_assessment_id"], "assessments", ["id"], ondelete="SET NULL")
    _replace_fk("assessment_diffs", "assessment_diffs_current_assessment_id_fkey", ["current_assessment_id"], "assessments", ["id"], ondelete="SET NULL")
    _replace_fk("assessments", "assessments_previous_assessment_id_fkey", ["previous_assessment_id"], "assessments", ["id"], ondelete="SET NULL")

    _replace_fk("finding_evidence", "finding_evidence_finding_id_fkey", ["finding_id"], "findings", ["id"], ondelete="CASCADE")
    _replace_fk("finding_evidence", "finding_evidence_evidence_id_fkey", ["evidence_id"], "evidence_records", ["id"], ondelete="CASCADE")
    _replace_fk("graph_edges", "graph_edges_source_id_fkey", ["source_id"], "entities", ["id"], ondelete="CASCADE")
    _replace_fk("graph_edges", "graph_edges_target_id_fkey", ["target_id"], "entities", ["id"], ondelete="CASCADE")
    _replace_fk("graph_edges", "graph_edges_evidence_id_fkey", ["evidence_id"], "evidence_records", ["id"], ondelete="SET NULL")
    _replace_fk("exposure_paths", "exposure_paths_source_entity_id_fkey", ["source_entity_id"], "entities", ["id"], ondelete="SET NULL")
    _replace_fk("exposure_paths", "exposure_paths_target_entity_id_fkey", ["target_entity_id"], "entities", ["id"], ondelete="SET NULL")
    _replace_fk("job_outputs", "job_outputs_job_id_fkey", ["job_id"], "offensive_jobs", ["id"], ondelete="CASCADE")


def downgrade() -> None:
    if _is_sqlite():
        return

    for table, name, columns, ref_table, ref_columns in [
        ("entities", "entities_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("evidence_records", "evidence_records_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("graph_edges", "graph_edges_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("findings", "findings_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("exposure_paths", "exposure_paths_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("cert_templates", "cert_templates_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("attack_chains", "attack_chains_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("offensive_jobs", "offensive_jobs_assessment_id_fkey", ["assessment_id"], "assessments", ["id"]),
        ("assessment_diffs", "assessment_diffs_baseline_assessment_id_fkey", ["baseline_assessment_id"], "assessments", ["id"]),
        ("assessment_diffs", "assessment_diffs_current_assessment_id_fkey", ["current_assessment_id"], "assessments", ["id"]),
        ("assessments", "assessments_previous_assessment_id_fkey", ["previous_assessment_id"], "assessments", ["id"]),
        ("finding_evidence", "finding_evidence_finding_id_fkey", ["finding_id"], "findings", ["id"]),
        ("finding_evidence", "finding_evidence_evidence_id_fkey", ["evidence_id"], "evidence_records", ["id"]),
        ("graph_edges", "graph_edges_source_id_fkey", ["source_id"], "entities", ["id"]),
        ("graph_edges", "graph_edges_target_id_fkey", ["target_id"], "entities", ["id"]),
        ("graph_edges", "graph_edges_evidence_id_fkey", ["evidence_id"], "evidence_records", ["id"]),
        ("exposure_paths", "exposure_paths_source_entity_id_fkey", ["source_entity_id"], "entities", ["id"]),
        ("exposure_paths", "exposure_paths_target_entity_id_fkey", ["target_entity_id"], "entities", ["id"]),
        ("job_outputs", "job_outputs_job_id_fkey", ["job_id"], "offensive_jobs", ["id"]),
    ]:
        _replace_fk(table, name, columns, ref_table, ref_columns, ondelete="NO ACTION")

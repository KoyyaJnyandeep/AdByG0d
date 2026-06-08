"""graph enhancement tables and graph_edges columns

Revision ID: 0019
Revises: 0018
Create Date: 2026-06-02
"""
from alembic import op
import sqlalchemy as sa


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # New tables
    op.create_table(
        "graph_centrality",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", sa.CHAR(36), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("betweenness", sa.Float(), nullable=False, server_default="0"),
        sa.Column("degree_centrality", sa.Float(), nullable=False, server_default="0"),
        sa.Column("eigenvector", sa.Float(), nullable=False, server_default="0"),
        sa.Column("pagerank", sa.Float(), nullable=False, server_default="0"),
        sa.Column("computed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("assessment_id", "entity_id", name="uq_graph_centrality"),
    )
    op.create_table(
        "graph_layout",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.CHAR(36), sa.ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("layout_name", sa.String(128), nullable=False),
        sa.Column("node_positions", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("assessment_id", "user_id", "layout_name", name="uq_graph_layout"),
    )
    op.create_table(
        "graph_snapshot",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.CHAR(36), sa.ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("label", sa.String(256), nullable=True),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("snapshot_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "graph_markings",
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.CHAR(36), sa.ForeignKey("platform_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("owned_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("high_value_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("pinned_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("assessment_id", "user_id"),
    )
    op.create_table(
        "graph_view",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("assessment_id", sa.CHAR(36), sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.CHAR(36), sa.ForeignKey("platform_users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    # New columns on graph_edges
    op.add_column("graph_edges", sa.Column("edge_confidence", sa.Float(), nullable=False, server_default="1.0"))
    op.add_column("graph_edges", sa.Column("edge_provenance_type", sa.String(20), nullable=False, server_default="collected"))
    op.add_column("graph_edges", sa.Column("edge_key", sa.String(64), nullable=True))
    op.add_column("graph_edges", sa.Column("first_seen_at", sa.DateTime(), nullable=True))
    op.add_column("graph_edges", sa.Column("last_seen_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("graph_edges", "last_seen_at")
    op.drop_column("graph_edges", "first_seen_at")
    op.drop_column("graph_edges", "edge_key")
    op.drop_column("graph_edges", "edge_provenance_type")
    op.drop_column("graph_edges", "edge_confidence")
    op.drop_table("graph_view")
    op.drop_table("graph_markings")
    op.drop_table("graph_snapshot")
    op.drop_table("graph_layout")
    op.drop_table("graph_centrality")

"""Add ON DELETE CASCADE to tunnel_sessions.profile_id FK

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-19
"""
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.drop_constraint("tunnel_sessions_profile_id_fkey", "tunnel_sessions", type_="foreignkey")
        op.create_foreign_key(
            "tunnel_sessions_profile_id_fkey",
            "tunnel_sessions",
            "connectivity_profiles",
            ["profile_id"],
            ["id"],
            ondelete="CASCADE",
        )
    else:
        # SQLite does not support ALTER COLUMN FK; recreate table with cascade.
        op.execute("PRAGMA foreign_keys=OFF")
        op.execute("""
            CREATE TABLE IF NOT EXISTS tunnel_sessions_new (
                id TEXT NOT NULL PRIMARY KEY,
                profile_id TEXT NOT NULL REFERENCES connectivity_profiles(id) ON DELETE CASCADE,
                mode VARCHAR(50) NOT NULL,
                jumpbox_host VARCHAR(255) NOT NULL,
                jumpbox_port INTEGER NOT NULL,
                jumpbox_username VARCHAR(255) NOT NULL,
                local_host VARCHAR(50) NOT NULL DEFAULT '127.0.0.1',
                local_port INTEGER NOT NULL,
                process_pid INTEGER,
                status VARCHAR(20) NOT NULL DEFAULT 'starting',
                started_by TEXT NOT NULL,
                started_at DATETIME,
                stopped_at DATETIME,
                last_healthcheck_at DATETIME,
                error_summary TEXT,
                sanitized_command_preview TEXT NOT NULL DEFAULT '',
                metadata_json JSON
            )
        """)
        op.execute("INSERT INTO tunnel_sessions_new SELECT * FROM tunnel_sessions")
        op.execute("DROP TABLE tunnel_sessions")
        op.execute("ALTER TABLE tunnel_sessions_new RENAME TO tunnel_sessions")
        op.execute("PRAGMA foreign_keys=ON")


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.drop_constraint("tunnel_sessions_profile_id_fkey", "tunnel_sessions", type_="foreignkey")
        op.create_foreign_key(
            "tunnel_sessions_profile_id_fkey",
            "tunnel_sessions",
            "connectivity_profiles",
            ["profile_id"],
            ["id"],
        )

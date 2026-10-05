"""baseline schema

Revision ID: 0001
Revises:
Create Date: 2026-10-05 03:33:12.354509
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Databases created before migrations existed already have some or all of these
    # tables, so each one is created only if it is missing.
    existing = set(sa.inspect(op.get_bind()).get_table_names())

    if "file_intel" not in existing:
        op.create_table(
            "file_intel",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("found", sa.Boolean(), nullable=False),
            sa.Column("malicious", sa.Integer(), nullable=True),
            sa.Column("suspicious", sa.Integer(), nullable=True),
            sa.Column("engines", sa.Integer(), nullable=True),
            sa.Column("label", sa.String(length=255), nullable=True),
            sa.Column("payload", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("sha256", "provider", name="uq_file_intel_provider"),
        )
        with op.batch_alter_table("file_intel", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_file_intel_fetched_at"), ["fetched_at"], unique=False
            )
            batch_op.create_index(batch_op.f("ix_file_intel_sha256"), ["sha256"], unique=False)

    if "ip_geo" not in existing:
        op.create_table(
            "ip_geo",
            sa.Column("ip", sa.String(length=45), nullable=False),
            sa.Column("country_code", sa.String(length=2), nullable=True),
            sa.Column("country_name", sa.String(length=128), nullable=True),
            sa.Column("city", sa.String(length=128), nullable=True),
            sa.Column("latitude", sa.Float(), nullable=True),
            sa.Column("longitude", sa.Float(), nullable=True),
            sa.Column("accuracy_radius_km", sa.Integer(), nullable=True),
            sa.Column("asn", sa.Integer(), nullable=True),
            sa.Column("as_org", sa.String(length=255), nullable=True),
            sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("ip"),
        )
        with op.batch_alter_table("ip_geo", schema=None) as batch_op:
            batch_op.create_index(batch_op.f("ix_ip_geo_asn"), ["asn"], unique=False)
            batch_op.create_index(
                batch_op.f("ix_ip_geo_country_code"), ["country_code"], unique=False
            )

    if "ip_intel" not in existing:
        op.create_table(
            "ip_intel",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("ip", sa.String(length=45), nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("score", sa.Integer(), nullable=True),
            sa.Column("flagged", sa.Boolean(), nullable=True),
            sa.Column("payload", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("ip", "provider", name="uq_ip_intel_provider"),
        )
        with op.batch_alter_table("ip_intel", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_ip_intel_fetched_at"), ["fetched_at"], unique=False
            )
            batch_op.create_index(batch_op.f("ix_ip_intel_ip"), ["ip"], unique=False)

    if "sessions" not in existing:
        op.create_table(
            "sessions",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("src_ip", sa.String(length=45), nullable=True),
            sa.Column("start_time", sa.DateTime(timezone=True), nullable=True),
            sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("client_version", sa.Text(), nullable=True),
            sa.Column("hassh", sa.String(length=32), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        with op.batch_alter_table("sessions", schema=None) as batch_op:
            batch_op.create_index(batch_op.f("ix_sessions_hassh"), ["hassh"], unique=False)
            batch_op.create_index(batch_op.f("ix_sessions_src_ip"), ["src_ip"], unique=False)
            batch_op.create_index(
                batch_op.f("ix_sessions_start_time"), ["start_time"], unique=False
            )

    if "commands" not in existing:
        op.create_table(
            "commands",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("command", sa.Text(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("session_id", "timestamp", "command", name="uq_command_event"),
        )
        with op.batch_alter_table("commands", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_commands_session_id"), ["session_id"], unique=False
            )

    if "downloads" not in existing:
        op.create_table(
            "downloads",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("url", sa.Text(), nullable=True),
            sa.Column("sha256", sa.String(length=64), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "session_id", "timestamp", "url", "sha256", name="uq_download_event"
            ),
        )
        with op.batch_alter_table("downloads", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_downloads_session_id"), ["session_id"], unique=False
            )
            batch_op.create_index("ix_downloads_sha256", ["sha256"], unique=False)

    if "logins" not in existing:
        op.create_table(
            "logins",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("username", sa.Text(), nullable=True),
            sa.Column("password", sa.Text(), nullable=True),
            sa.Column("success", sa.Boolean(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "session_id", "timestamp", "username", "password", "success", name="uq_login_event"
            ),
        )
        with op.batch_alter_table("logins", schema=None) as batch_op:
            batch_op.create_index(batch_op.f("ix_logins_session_id"), ["session_id"], unique=False)

    if "session_mappings" not in existing:
        op.create_table(
            "session_mappings",
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("ruleset_version", sa.String(length=16), nullable=False),
            sa.Column("attack_version", sa.String(length=16), nullable=False),
            sa.Column("command_count", sa.Integer(), nullable=False),
            sa.Column("login_count", sa.Integer(), nullable=False),
            sa.Column("mapped_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("session_id"),
        )

    if "technique_matches" not in existing:
        op.create_table(
            "technique_matches",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("command_id", sa.Integer(), nullable=True),
            sa.Column("technique_id", sa.String(length=12), nullable=False),
            sa.Column("tactics", sa.String(length=255), nullable=False),
            sa.Column("rule_id", sa.String(length=64), nullable=False),
            sa.Column("confidence", sa.String(length=8), nullable=False),
            sa.Column("evidence", sa.String(length=300), nullable=False),
            sa.ForeignKeyConstraint(["command_id"], ["commands.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        with op.batch_alter_table("technique_matches", schema=None) as batch_op:
            batch_op.create_index(
                batch_op.f("ix_technique_matches_session_id"), ["session_id"], unique=False
            )
            batch_op.create_index(
                batch_op.f("ix_technique_matches_technique_id"), ["technique_id"], unique=False
            )


def downgrade() -> None:
    with op.batch_alter_table("technique_matches", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_technique_matches_technique_id"))
        batch_op.drop_index(batch_op.f("ix_technique_matches_session_id"))

    op.drop_table("technique_matches")
    op.drop_table("session_mappings")
    with op.batch_alter_table("logins", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_logins_session_id"))

    op.drop_table("logins")
    with op.batch_alter_table("downloads", schema=None) as batch_op:
        batch_op.drop_index("ix_downloads_sha256")
        batch_op.drop_index(batch_op.f("ix_downloads_session_id"))

    op.drop_table("downloads")
    with op.batch_alter_table("commands", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_commands_session_id"))

    op.drop_table("commands")
    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sessions_start_time"))
        batch_op.drop_index(batch_op.f("ix_sessions_src_ip"))
        batch_op.drop_index(batch_op.f("ix_sessions_hassh"))

    op.drop_table("sessions")
    with op.batch_alter_table("ip_intel", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ip_intel_ip"))
        batch_op.drop_index(batch_op.f("ix_ip_intel_fetched_at"))

    op.drop_table("ip_intel")
    with op.batch_alter_table("ip_geo", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ip_geo_country_code"))
        batch_op.drop_index(batch_op.f("ix_ip_geo_asn"))

    op.drop_table("ip_geo")
    with op.batch_alter_table("file_intel", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_file_intel_sha256"))
        batch_op.drop_index(batch_op.f("ix_file_intel_fetched_at"))

    op.drop_table("file_intel")

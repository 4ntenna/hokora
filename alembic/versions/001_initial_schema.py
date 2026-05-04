# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Initial schema for v0.1.0 — squashed baseline.

Revision ID: 001_initial
Revises: None
Create Date: 2026-04-30

Squashed from the dev migration chain (001-015 pre-release). Replicates
the schema produced by ``Base.metadata.create_all()`` against the
v0.1.0 ORM models. FTS5 virtual table + triggers are NOT created here —
``hokora.db.fts.FTSManager.init_fts()`` owns FTS lifecycle at daemon
startup. Existing pre-v0.1.0 deployments at the legacy
``015_pending_sealed_distributions`` revision should ``alembic stamp
001_initial`` on first upgrade — the schema shape is byte-equivalent.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "categories",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("position", sa.Integer),
        sa.Column("collapsed_default", sa.Boolean),
        sa.Column("created_at", sa.Float),
    )

    op.create_table(
        "identities",
        sa.Column("hash", sa.String(64), primary_key=True),
        sa.Column("display_name", sa.String(64)),
        sa.Column("public_key", sa.LargeBinary),
        sa.Column("avatar", sa.LargeBinary),
        sa.Column("status_text", sa.String(256)),
        sa.Column("bio", sa.String(1024)),
        sa.Column("first_seen", sa.Float),
        sa.Column("last_seen", sa.Float),
        sa.Column("blocked", sa.Boolean),
        sa.Column("blocked_at", sa.Float),
        sa.Column("blocked_by", sa.String(64)),
        sa.Column("announce_data", sa.LargeBinary),
    )

    op.create_table(
        "roles",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("permissions", sa.Integer),
        sa.Column("position", sa.Integer),
        sa.Column("colour", sa.String(7)),
        sa.Column("mentionable", sa.Boolean),
        sa.Column("is_builtin", sa.Boolean),
        sa.Column("created_at", sa.Float),
    )

    op.create_table(
        "peers",
        sa.Column("identity_hash", sa.String(64), primary_key=True),
        sa.Column("node_name", sa.String(128)),
        sa.Column("last_announce", sa.Float),
        sa.Column("last_seen", sa.Float),
        sa.Column("channels_mirrored", sa.JSON),
        sa.Column("sync_cursor", sa.JSON),
        sa.Column("federation_trusted", sa.Boolean),
        sa.Column("last_handshake", sa.Float),
        sa.Column("public_key", sa.LargeBinary),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("target", sa.String(64)),
        sa.Column("channel_id", sa.String(64)),
        sa.Column("timestamp", sa.Float),
        sa.Column("details", sa.JSON),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])

    op.create_table(
        "sessions",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("identity_hash", sa.String(64)),
        sa.Column("sync_profile", sa.Integer),
        sa.Column("cdsp_version", sa.Integer),
        sa.Column("state", sa.String(32)),
        sa.Column("resume_token", sa.LargeBinary),
        sa.Column("deferred_count", sa.Integer),
        sa.Column("created_at", sa.Float),
        sa.Column("last_activity", sa.Float),
        sa.Column("expires_at", sa.Float),
    )
    op.create_index("ix_sessions_identity_hash", "sessions", ["identity_hash"])

    op.create_table(
        "federation_epoch_state",
        sa.Column("peer_identity_hash", sa.String(64), primary_key=True),
        sa.Column("current_epoch_id", sa.Integer),
        sa.Column("epoch_duration", sa.Integer),
        sa.Column("is_initiator", sa.Boolean),
        sa.Column("epoch_start_time", sa.Float),
        sa.Column("current_key_send", sa.LargeBinary),
        sa.Column("current_key_recv", sa.LargeBinary),
        sa.Column("nonce_prefix", sa.LargeBinary),
        sa.Column("message_counter", sa.Integer),
        sa.Column("last_chain_hash", sa.LargeBinary),
        sa.Column("updated_at", sa.Float),
    )

    op.create_table(
        "channels",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(512)),
        sa.Column("category_id", sa.String(64), sa.ForeignKey("categories.id")),
        sa.Column("position", sa.Integer),
        sa.Column("access_mode", sa.String(20)),
        sa.Column("slowmode", sa.Integer),
        sa.Column("max_retention", sa.Integer),
        sa.Column("latest_seq", sa.Integer),
        sa.Column("identity_hash", sa.String(64)),
        sa.Column("destination_hash", sa.String(32)),
        sa.Column("created_at", sa.Float),
        sa.Column("sealed", sa.Boolean),
        sa.Column("rotation_old_hash", sa.String(64)),
        sa.Column("rotation_grace_end", sa.Float),
    )
    op.create_index("ix_channels_category_id", "channels", ["category_id"])

    op.create_table(
        "deferred_sync_items",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.String(64),
            sa.ForeignKey("sessions.session_id", ondelete="CASCADE"),
        ),
        sa.Column("channel_id", sa.String(64)),
        sa.Column("sync_action", sa.Integer),
        sa.Column("payload", sa.JSON),
        sa.Column("priority", sa.Integer),
        sa.Column("created_at", sa.Float),
        sa.Column("expires_at", sa.Float),
    )
    op.create_index("ix_deferred_sync_items_session_id", "deferred_sync_items", ["session_id"])

    op.create_table(
        "messages",
        sa.Column("msg_hash", sa.String(64), primary_key=True),
        sa.Column("channel_id", sa.String(64), sa.ForeignKey("channels.id"), nullable=False),
        sa.Column("sender_hash", sa.String(64)),
        sa.Column("seq", sa.Integer),
        sa.Column("timestamp", sa.Float, nullable=False),
        sa.Column("type", sa.Integer, nullable=False),
        sa.Column("body", sa.Text),
        sa.Column("media_path", sa.String(512)),
        sa.Column("media_meta", sa.JSON),
        sa.Column("reply_to", sa.String(64)),
        sa.Column("thread_seq", sa.Integer),
        sa.Column("ttl", sa.Integer),
        sa.Column("received_at", sa.Float),
        sa.Column("deleted", sa.Boolean),
        sa.Column("deleted_by", sa.String(64)),
        sa.Column("pinned", sa.Boolean),
        sa.Column("pinned_at", sa.Float),
        sa.Column("edit_chain", sa.JSON),
        sa.Column("reactions", sa.JSON),
        sa.Column("lxmf_signature", sa.LargeBinary),
        sa.Column("lxmf_signed_part", sa.LargeBinary),
        sa.Column("display_name", sa.String(64)),
        sa.Column("mentions", sa.JSON),
        sa.Column("origin_node", sa.String(64)),
        sa.Column("encrypted_body", sa.LargeBinary),
        sa.Column("encryption_nonce", sa.LargeBinary),
        sa.Column("encryption_epoch", sa.Integer),
    )
    op.create_index("ix_messages_timestamp", "messages", ["timestamp"])
    op.create_index("ix_channel_seq", "messages", ["channel_id", "seq"])
    op.create_index("ix_messages_reply_to", "messages", ["reply_to"])
    op.create_index("ix_messages_channel_id", "messages", ["channel_id"])
    op.create_index("ix_messages_sender_hash", "messages", ["sender_hash"])

    op.create_table(
        "role_assignments",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("role_id", sa.String(64), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column(
            "identity_hash",
            sa.String(64),
            sa.ForeignKey("identities.hash"),
            nullable=False,
        ),
        sa.Column("channel_id", sa.String(64), sa.ForeignKey("channels.id")),
        sa.Column("assigned_at", sa.Float),
        sa.Column("assigned_by", sa.String(64)),
        sa.UniqueConstraint(
            "role_id",
            "identity_hash",
            "channel_id",
            name="uq_role_identity_channel",
        ),
    )
    op.create_index(
        "ix_role_identity_channel",
        "role_assignments",
        ["identity_hash", "channel_id"],
    )
    op.create_index("ix_role_assignments_role_id", "role_assignments", ["role_id"])

    op.create_table(
        "channel_overrides",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("channel_id", sa.String(64), sa.ForeignKey("channels.id"), nullable=False),
        sa.Column("role_id", sa.String(64), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("allow", sa.Integer),
        sa.Column("deny", sa.Integer),
    )
    op.create_index(
        "ix_override_channel_role",
        "channel_overrides",
        ["channel_id", "role_id"],
        unique=True,
    )

    op.create_table(
        "invites",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("channel_id", sa.String(64), sa.ForeignKey("channels.id")),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("max_uses", sa.Integer),
        sa.Column("uses", sa.Integer),
        sa.Column("used_by", sa.JSON),
        sa.Column("used_at", sa.JSON),
        sa.Column("expires_at", sa.Float),
        sa.Column("created_at", sa.Float),
        sa.Column("revoked", sa.Boolean),
    )

    op.create_table(
        "sealed_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("channel_id", sa.String(64), sa.ForeignKey("channels.id"), nullable=False),
        sa.Column("epoch", sa.Integer, nullable=False),
        sa.Column("encrypted_key_blob", sa.LargeBinary, nullable=False),
        sa.Column("identity_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float),
    )
    op.create_index("ix_sealed_channel_epoch", "sealed_keys", ["channel_id", "epoch"])

    op.create_table(
        "pending_sealed_distributions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "channel_id",
            sa.String(64),
            sa.ForeignKey("channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("identity_hash", sa.String(64), nullable=False),
        sa.Column(
            "role_id",
            sa.String(64),
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("queued_at", sa.Float, nullable=False),
        sa.Column("last_attempt_at", sa.Float),
        sa.Column("retry_count", sa.Integer, nullable=False),
        sa.Column("last_error", sa.String),
        sa.UniqueConstraint(
            "channel_id",
            "identity_hash",
            "role_id",
            name="uq_pending_sealed_distributions_triple",
        ),
    )
    op.create_index(
        "ix_pending_sealed_distributions_identity_hash",
        "pending_sealed_distributions",
        ["identity_hash"],
    )

    op.create_table(
        "threads",
        sa.Column(
            "root_msg_hash",
            sa.String(64),
            sa.ForeignKey("messages.msg_hash"),
            primary_key=True,
        ),
        sa.Column("channel_id", sa.String(64), sa.ForeignKey("channels.id"), nullable=False),
        sa.Column("reply_count", sa.Integer),
        sa.Column("latest_thread_seq", sa.Integer),
        sa.Column("last_activity", sa.Float),
        sa.Column("participant_hashes", sa.JSON),
    )


def downgrade() -> None:
    op.drop_table("threads")
    op.drop_table("pending_sealed_distributions")
    op.drop_table("sealed_keys")
    op.drop_table("invites")
    op.drop_table("channel_overrides")
    op.drop_table("role_assignments")
    op.drop_table("messages")
    op.drop_table("deferred_sync_items")
    op.drop_table("channels")
    op.drop_table("federation_epoch_state")
    op.drop_table("sessions")
    op.drop_table("audit_log")
    op.drop_table("peers")
    op.drop_table("roles")
    op.drop_table("identities")
    op.drop_table("categories")

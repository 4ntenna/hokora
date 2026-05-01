# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ORM models for Hokora."""

import time

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Channel(Base):
    __tablename__ = "channels"

    id = Column(String(64), primary_key=True)
    name = Column(String(64), nullable=False)
    description = Column(String(512), default="")
    category_id = Column(String(64), ForeignKey("categories.id"), nullable=True, index=True)
    position = Column(Integer, default=0)
    access_mode = Column(String(20), default="public")
    slowmode = Column(Integer, default=0)  # seconds between messages per identity
    max_retention = Column(Integer, default=10000)  # per-channel message retention limit
    latest_seq = Column(Integer, default=0)
    identity_hash = Column(String(64), nullable=True)
    destination_hash = Column(String(32), nullable=True)
    created_at = Column(Float, default=time.time)
    sealed = Column(Boolean, default=False)
    # RNS identity key rotation state.
    # NULL on channels that have never been rotated. When a rotation fires,
    # ``rotation_old_hash`` captures the pre-rotation ``identity_hash`` and
    # ``rotation_grace_end`` stores the UNIX timestamp after which federation
    # stops accepting pushes signed under the old identity.
    rotation_old_hash = Column(String(64), nullable=True)
    rotation_grace_end = Column(Float, nullable=True)

    messages = relationship(
        "Message", back_populates="channel", lazy="dynamic", cascade="all, delete-orphan"
    )
    category = relationship("Category", back_populates="channels")


class Category(Base):
    __tablename__ = "categories"

    id = Column(String(64), primary_key=True)
    name = Column(String(64), nullable=False)
    position = Column(Integer, default=0)
    collapsed_default = Column(Boolean, default=False)
    created_at = Column(Float, default=time.time)

    channels = relationship("Channel", back_populates="category")


class Message(Base):
    # NOTE: JSON columns use default=list/dict (mutable). All access sites use `or []`/`or {}`
    # to copy before mutation, so shared-default is safe. Do not change to default_factory.
    __tablename__ = "messages"

    msg_hash = Column(String(64), primary_key=True)
    channel_id = Column(String(64), ForeignKey("channels.id"), nullable=False, index=True)
    sender_hash = Column(String(64), nullable=True)
    seq = Column(Integer, nullable=True)  # None for thread replies
    timestamp = Column(Float, nullable=False)
    type = Column(Integer, nullable=False)
    body = Column(Text, nullable=True)
    media_path = Column(String(512), nullable=True)
    media_meta = Column(JSON, nullable=True)  # {mime, filename, size, thumb_path}
    reply_to = Column(String(64), nullable=True)
    thread_seq = Column(Integer, nullable=True)  # sequence within thread
    ttl = Column(Integer, nullable=True)
    received_at = Column(Float, default=time.time)
    deleted = Column(Boolean, default=False)
    deleted_by = Column(String(64), nullable=True)
    pinned = Column(Boolean, default=False)
    pinned_at = Column(Float, nullable=True)
    edit_chain = Column(JSON, default=list)
    reactions = Column(JSON, default=dict)
    lxmf_signature = Column(LargeBinary, nullable=True)
    lxmf_signed_part = Column(LargeBinary, nullable=True)
    display_name = Column(String(64), nullable=True)
    mentions = Column(JSON, default=list)
    origin_node = Column(String(64), nullable=True)  # Federation loop prevention
    encrypted_body = Column(LargeBinary, nullable=True)  # AES-256-GCM ciphertext
    encryption_nonce = Column(LargeBinary, nullable=True)  # 12-byte GCM nonce
    encryption_epoch = Column(Integer, nullable=True)  # Sealed key epoch used

    channel = relationship("Channel", back_populates="messages")

    __table_args__ = (
        Index("ix_channel_seq", "channel_id", "seq"),
        Index("ix_messages_sender_hash", "sender_hash"),
        Index("ix_messages_reply_to", "reply_to"),
        Index("ix_messages_timestamp", "timestamp"),
    )


class Identity(Base):
    __tablename__ = "identities"

    hash = Column(String(64), primary_key=True)
    display_name = Column(String(64), nullable=True)
    public_key = Column(LargeBinary, nullable=True)
    avatar = Column(LargeBinary, nullable=True)
    status_text = Column(String(256), nullable=True)
    bio = Column(String(1024), nullable=True)
    first_seen = Column(Float, default=time.time)
    last_seen = Column(Float, default=time.time)
    blocked = Column(Boolean, default=False)
    blocked_at = Column(Float, nullable=True)
    blocked_by = Column(String(64), nullable=True)
    announce_data = Column(LargeBinary, nullable=True)


class Role(Base):
    __tablename__ = "roles"

    id = Column(String(64), primary_key=True)
    name = Column(String(64), nullable=False, unique=True)
    permissions = Column(Integer, default=0)
    position = Column(Integer, default=0)
    colour = Column(String(7), default="#FFFFFF")
    mentionable = Column(Boolean, default=False)
    is_builtin = Column(Boolean, default=False)
    created_at = Column(Float, default=time.time)

    assignments = relationship("RoleAssignment", back_populates="role")


class RoleAssignment(Base):
    __tablename__ = "role_assignments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    role_id = Column(String(64), ForeignKey("roles.id"), nullable=False, index=True)
    identity_hash = Column(String(64), ForeignKey("identities.hash"), nullable=False)
    channel_id = Column(String(64), ForeignKey("channels.id"), nullable=True)
    assigned_at = Column(Float, default=time.time)
    assigned_by = Column(String(64), nullable=True)

    role = relationship("Role", back_populates="assignments")

    __table_args__ = (
        Index("ix_role_identity_channel", "identity_hash", "channel_id"),
        UniqueConstraint("role_id", "identity_hash", "channel_id", name="uq_role_identity_channel"),
    )


class ChannelOverride(Base):
    __tablename__ = "channel_overrides"

    id = Column(Integer, primary_key=True, autoincrement=True)
    channel_id = Column(String(64), ForeignKey("channels.id"), nullable=False)
    role_id = Column(String(64), ForeignKey("roles.id"), nullable=False)
    allow = Column(Integer, default=0)
    deny = Column(Integer, default=0)

    __table_args__ = (Index("ix_override_channel_role", "channel_id", "role_id", unique=True),)


class Invite(Base):
    __tablename__ = "invites"

    token_hash = Column(String(64), primary_key=True)
    channel_id = Column(String(64), ForeignKey("channels.id"), nullable=True)
    created_by = Column(String(64), nullable=False)
    max_uses = Column(Integer, default=1)
    uses = Column(Integer, default=0)
    used_by = Column(JSON, default=list)
    used_at = Column(JSON, default=list)
    expires_at = Column(Float, nullable=True)
    created_at = Column(Float, default=time.time)
    revoked = Column(Boolean, default=False)


class Thread(Base):
    __tablename__ = "threads"

    root_msg_hash = Column(String(64), ForeignKey("messages.msg_hash"), primary_key=True)
    channel_id = Column(String(64), ForeignKey("channels.id"), nullable=False)
    reply_count = Column(Integer, default=0)
    latest_thread_seq = Column(Integer, default=0)
    last_activity = Column(Float, default=time.time)
    participant_hashes = Column(JSON, default=list)


class Peer(Base):
    __tablename__ = "peers"

    identity_hash = Column(String(64), primary_key=True)
    node_name = Column(String(128), nullable=True)
    last_announce = Column(Float, nullable=True)
    last_seen = Column(Float, nullable=True)
    channels_mirrored = Column(JSON, default=list)
    sync_cursor = Column(JSON, default=dict)  # {channel_id: last_seq}
    federation_trusted = Column(Boolean, default=False)
    last_handshake = Column(Float, nullable=True)
    public_key = Column(LargeBinary, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(64), nullable=False)
    action_type = Column(String(64), nullable=False)
    target = Column(String(64), nullable=True)
    channel_id = Column(String(64), nullable=True)
    timestamp = Column(Float, default=time.time)
    details = Column(JSON, default=dict)

    __table_args__ = (Index("ix_audit_log_timestamp", "timestamp"),)


class SealedKey(Base):
    __tablename__ = "sealed_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    channel_id = Column(String(64), ForeignKey("channels.id"), nullable=False)
    epoch = Column(Integer, nullable=False)
    encrypted_key_blob = Column(LargeBinary, nullable=False)
    identity_hash = Column(String(64), nullable=False)
    created_at = Column(Float, default=time.time)

    __table_args__ = (Index("ix_sealed_channel_epoch", "channel_id", "epoch"),)


class Session(Base):
    """CDSP session tracking. No transport/interface columns per spec Section 4.1.3."""

    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True)
    identity_hash = Column(String(64), index=True)
    sync_profile = Column(Integer, default=0x01)
    cdsp_version = Column(Integer, default=1)
    state = Column(String(32), default="init")
    resume_token = Column(LargeBinary(16), nullable=True)
    deferred_count = Column(Integer, default=0)
    created_at = Column(Float, default=time.time)
    last_activity = Column(Float, default=time.time)
    expires_at = Column(Float, nullable=True)


class FederationEpochState(Base):
    """Forward secrecy epoch state for a federation peer."""

    __tablename__ = "federation_epoch_state"

    peer_identity_hash = Column(String(64), primary_key=True)
    current_epoch_id = Column(Integer, default=0)
    epoch_duration = Column(Integer, default=3600)
    is_initiator = Column(Boolean, default=False)
    epoch_start_time = Column(Float, nullable=True)
    current_key_send = Column(LargeBinary, nullable=True)
    current_key_recv = Column(LargeBinary, nullable=True)
    nonce_prefix = Column(LargeBinary(16), nullable=True)
    message_counter = Column(Integer, default=0)
    last_chain_hash = Column(LargeBinary(32), nullable=True)
    updated_at = Column(Float, default=time.time)


class DeferredSyncItem(Base):
    """Items deferred due to CDSP profile constraints."""

    __tablename__ = "deferred_sync_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(
        String(64),
        ForeignKey("sessions.session_id", ondelete="CASCADE"),
        index=True,
    )
    channel_id = Column(String(64), nullable=True)
    sync_action = Column(Integer)
    payload = Column(JSON, nullable=True)
    priority = Column(Integer, default=0)
    created_at = Column(Float, default=time.time)
    expires_at = Column(Float, nullable=True)


class PendingSealedDistribution(Base):
    """Deferred sealed-key distribution queue.

    Populated when an operator-issued ``hokora role assign`` against a sealed
    channel cannot complete envelope encryption because the recipient is
    not in RNS's path cache. Drained by
    ``federation.peering.PeerDiscovery.handle_announce`` when an announce
    arrives matching ``identity_hash``.
    """

    __tablename__ = "pending_sealed_distributions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    channel_id = Column(
        String(64),
        ForeignKey("channels.id", ondelete="CASCADE"),
        nullable=False,
    )
    identity_hash = Column(String(64), nullable=False, index=True)
    role_id = Column(
        String(64),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    queued_at = Column(Float, nullable=False, default=time.time)
    last_attempt_at = Column(Float, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    last_error = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "channel_id",
            "identity_hash",
            "role_id",
            name="uq_pending_sealed_distributions_triple",
        ),
    )

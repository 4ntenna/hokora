# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for newly wired features: write_restricted, display name truncation,
channel description validation, sealed key auto-rotation, FTS rebuild CLI,
TUI /download and /profile commands, constant wiring."""

import time
from unittest.mock import MagicMock, AsyncMock

import pytest

from hokora.constants import (
    PERM_SEND_MESSAGES,
    PERM_SEND_MEDIA,
    PERM_READ_HISTORY,
    PERM_EVERYONE_DEFAULT,
    MAX_DISPLAY_NAME_LENGTH,
    MAX_CHANNEL_DESCRIPTION_LENGTH,
    MAX_AVATAR_BYTES,
    SEALED_KEY_ROTATION_DAYS,
    CDSP_RESUME_TOKEN_SIZE,
)
from hokora.db.models import (
    Channel,
    Role,
    SealedKey,
)
from hokora.db.queries import ChannelRepo, RoleRepo, IdentityRepo
from hokora.security.permissions import PermissionResolver
from hokora.core.message import MessageEnvelope, MessageProcessor
from hokora.core.sequencer import SequenceManager


# ---------------------------------------------------------------------------
# F5: ACCESS_WRITE_RESTRICTED enforcement
# ---------------------------------------------------------------------------


class TestWriteRestricted:
    async def test_write_restricted_blocks_send_for_roleless_user(self, session):
        """Users with no explicit roles on a write_restricted channel cannot send."""
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id="wrch1", name="write_restricted_test", access_mode="write_restricted", latest_seq=0
        )
        await ch_repo.create(channel)

        # Ensure @everyone role with default permissions (includes SEND_MESSAGES)
        role_repo = RoleRepo(session)
        everyone = Role(
            id="everyone_wr", name="everyone", permissions=PERM_EVERYONE_DEFAULT, position=0
        )
        await role_repo.create(everyone)

        resolver = PermissionResolver(node_owner_hash="nodeowner")
        perms = await resolver.get_effective_permissions(session, "roleless_user", channel)

        assert not (perms & PERM_SEND_MESSAGES), "roleless user should not have SEND_MESSAGES"
        assert not (perms & PERM_SEND_MEDIA), "roleless user should not have SEND_MEDIA"

    async def test_write_restricted_allows_read_for_roleless_user(self, session):
        """Users with no explicit roles on a write_restricted channel can still read."""
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id="wrch2", name="wr_read_test", access_mode="write_restricted", latest_seq=0
        )
        await ch_repo.create(channel)

        role_repo = RoleRepo(session)
        everyone = Role(
            id="everyone_wr2", name="everyone", permissions=PERM_EVERYONE_DEFAULT, position=0
        )
        await role_repo.create(everyone)

        resolver = PermissionResolver(node_owner_hash="nodeowner")
        perms = await resolver.get_effective_permissions(session, "roleless_user2", channel)

        assert perms & PERM_READ_HISTORY, "roleless user should have READ_HISTORY"

    async def test_write_restricted_allows_send_for_member(self, session):
        """Users with an explicit role on a write_restricted channel can send."""
        ch_repo = ChannelRepo(session)
        channel = Channel(
            id="wrch3", name="wr_member_test", access_mode="write_restricted", latest_seq=0
        )
        await ch_repo.create(channel)

        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("wr_member")

        role_repo = RoleRepo(session)
        everyone = Role(
            id="everyone_wr3", name="everyone", permissions=PERM_EVERYONE_DEFAULT, position=0
        )
        await role_repo.create(everyone)
        member_role = Role(
            id="member_wr3", name="member_wr3", permissions=PERM_SEND_MESSAGES, position=1
        )
        await role_repo.create(member_role)
        await role_repo.assign_role(member_role.id, "wr_member", "wrch3")

        resolver = PermissionResolver(node_owner_hash="nodeowner")
        perms = await resolver.get_effective_permissions(session, "wr_member", channel)

        assert perms & PERM_SEND_MESSAGES, "member should have SEND_MESSAGES"


# ---------------------------------------------------------------------------
# F7: MAX_DISPLAY_NAME_LENGTH truncation
# ---------------------------------------------------------------------------


class TestDisplayNameTruncation:
    async def test_ingest_truncates_long_display_name(self, session):
        """Display names longer than MAX_DISPLAY_NAME_LENGTH are truncated."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="dnch1", name="dn_test", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)

        long_name = "A" * 100
        envelope = MessageEnvelope(
            channel_id="dnch1",
            sender_hash="sender1" + "0" * 57,
            timestamp=time.time(),
            body="test",
            display_name=long_name,
        )
        msg = await processor.ingest(session, envelope)
        assert len(msg.display_name) == MAX_DISPLAY_NAME_LENGTH

    async def test_ingest_preserves_short_display_name(self, session):
        """Display names within the limit are not modified."""
        ch_repo = ChannelRepo(session)
        channel = Channel(id="dnch2", name="dn_test2", latest_seq=0)
        await ch_repo.create(channel)

        sequencer = SequenceManager()
        processor = MessageProcessor(sequencer)

        envelope = MessageEnvelope(
            channel_id="dnch2",
            sender_hash="sender2" + "0" * 57,
            timestamp=time.time(),
            body="test",
            display_name="Normal Name",
        )
        msg = await processor.ingest(session, envelope)
        assert msg.display_name == "Normal Name"


# ---------------------------------------------------------------------------
# F8: MAX_CHANNEL_DESCRIPTION_LENGTH validation
# ---------------------------------------------------------------------------


class TestChannelDescriptionValidation:
    def test_max_channel_description_length_constant(self):
        """Ensure the constant matches the DB schema."""
        assert MAX_CHANNEL_DESCRIPTION_LENGTH == 512


# ---------------------------------------------------------------------------
# F4: MAX_AVATAR_BYTES constant wiring
# ---------------------------------------------------------------------------


class TestAvatarBytesConstant:
    def test_build_profile_announce_respects_constant(self):
        """Profile announce should use MAX_AVATAR_BYTES, not a hardcoded value."""
        from hokora.core.announce import AnnounceHandler

        # Avatar within limit
        small_avatar = b"\x00" * 100
        payload = AnnounceHandler.build_profile_announce("test", avatar=small_avatar)
        import msgpack

        data = msgpack.unpackb(payload)
        assert "avatar" in data

        # Avatar over limit
        big_avatar = b"\x00" * (MAX_AVATAR_BYTES + 1)
        payload = AnnounceHandler.build_profile_announce("test", avatar=big_avatar)
        data = msgpack.unpackb(payload)
        assert "avatar" not in data


# ---------------------------------------------------------------------------
# F9: CDSP_RESUME_TOKEN_SIZE constant wiring
# ---------------------------------------------------------------------------


class TestResumeTokenSize:
    def test_constant_value(self):
        assert CDSP_RESUME_TOKEN_SIZE == 16


# ---------------------------------------------------------------------------
# F6: Sealed key auto-rotation
# ---------------------------------------------------------------------------


class TestSealedKeyAutoRotation:
    async def test_stale_key_triggers_rotation(self, session_factory):
        """Maintenance scheduler should rotate sealed keys older than threshold."""
        from hokora.core.maintenance_scheduler import MaintenanceScheduler

        # Set up: sealed channel with a stale key
        async with session_factory() as session:
            async with session.begin():
                ch_repo = ChannelRepo(session)
                channel = Channel(id="sealch1", name="sealed_test", sealed=True, latest_seq=0)
                await ch_repo.create(channel)

                ident_repo = IdentityRepo(session)
                await ident_repo.upsert("member1")

                role_repo = RoleRepo(session)
                role = Role(id="seal_member", name="seal_member", permissions=0, position=1)
                await role_repo.create(role)
                await role_repo.assign_role(role.id, "member1", "sealch1")

                # Create a stale sealed key (older than SEALED_KEY_ROTATION_DAYS)
                stale_time = time.time() - (SEALED_KEY_ROTATION_DAYS + 1) * 86400
                sk = SealedKey(
                    channel_id="sealch1",
                    epoch=1,
                    encrypted_key_blob=b"fake_key",
                    identity_hash="member1",
                    created_at=stale_time,
                )
                session.add(sk)

        sealed_manager = MagicMock()
        sealed_manager.rotate_and_distribute = MagicMock(return_value=(b"newkey", 2, []))
        sealed_manager.persist_key = AsyncMock()

        node_identity = MagicMock()
        lxmf_bridge = MagicMock()
        lxmf_bridge.get_router = MagicMock(return_value=MagicMock())
        lxmf_bridge.get_any_router = MagicMock(return_value=MagicMock())

        scheduler = MaintenanceScheduler(
            session_factory=session_factory,
            maintenance_manager=MagicMock(),
            config=MagicMock(retention_days=0, metadata_scrub_days=0),
            sealed_manager=sealed_manager,
            node_rns_identity=node_identity,
            lxmf_bridge=lxmf_bridge,
        )

        await scheduler._check_sealed_key_rotation()

        sealed_manager.rotate_and_distribute.assert_called_once()
        call_args = sealed_manager.rotate_and_distribute.call_args
        assert call_args[0][0] == "sealch1"
        assert "member1" in call_args[0][1]

    async def test_fresh_key_not_rotated(self, session_factory):
        """Keys newer than the threshold should not be rotated."""
        from hokora.core.maintenance_scheduler import MaintenanceScheduler

        async with session_factory() as session:
            async with session.begin():
                ch_repo = ChannelRepo(session)
                channel = Channel(id="sealch2", name="sealed_fresh", sealed=True, latest_seq=0)
                await ch_repo.create(channel)

                sk = SealedKey(
                    channel_id="sealch2",
                    epoch=1,
                    encrypted_key_blob=b"fresh_key",
                    identity_hash="node",
                    created_at=time.time(),
                )
                session.add(sk)

        sealed_manager = MagicMock()
        scheduler = MaintenanceScheduler(
            session_factory=session_factory,
            maintenance_manager=MagicMock(),
            config=MagicMock(retention_days=0, metadata_scrub_days=0),
            sealed_manager=sealed_manager,
            node_rns_identity=MagicMock(),
            lxmf_bridge=MagicMock(),
        )

        await scheduler._check_sealed_key_rotation()
        sealed_manager.rotate_and_distribute.assert_not_called()


# ---------------------------------------------------------------------------
# F3: hokora db rebuild-fts CLI command
# ---------------------------------------------------------------------------


class TestRebuildFtsCli:
    def test_rebuild_fts_command_registered(self):
        """The rebuild-fts command should exist in the db group."""
        from hokora.cli.db import db_group

        commands = {cmd.name for cmd in db_group.commands.values()}
        assert "rebuild-fts" in commands


# ---------------------------------------------------------------------------
# F1 + F2: TUI /download and /profile commands
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# RoleRepo.get_channel_member_hashes
# ---------------------------------------------------------------------------


class TestGetChannelMemberHashes:
    async def test_returns_distinct_members(self, session):
        """get_channel_member_hashes returns unique identity hashes for a channel."""
        ident_repo = IdentityRepo(session)
        await ident_repo.upsert("mem1")
        await ident_repo.upsert("mem2")

        ch_repo = ChannelRepo(session)
        channel = Channel(id="memch1", name="member_test", latest_seq=0)
        await ch_repo.create(channel)

        role_repo = RoleRepo(session)
        role = Role(id="testrole_mem", name="test_member_role", permissions=0, position=1)
        await role_repo.create(role)
        await role_repo.assign_role(role.id, "mem1", "memch1")
        await role_repo.assign_role(role.id, "mem2", "memch1")

        hashes = await role_repo.get_channel_member_hashes("memch1")
        assert set(hashes) == {"mem1", "mem2"}

    async def test_returns_empty_for_no_members(self, session):
        ch_repo = ChannelRepo(session)
        channel = Channel(id="memch2", name="empty_test", latest_seq=0)
        await ch_repo.create(channel)

        role_repo = RoleRepo(session)
        hashes = await role_repo.get_channel_member_hashes("memch2")
        assert hashes == []


# ---------------------------------------------------------------------------
# Multi-channel LXMF delivery (per-channel LXMRouter)
# ---------------------------------------------------------------------------


class TestLXMFBridgeMultiChannel:
    def test_register_channel_creates_per_channel_router(self, tmp_path):
        """Each channel gets its own LXMRouter instance."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        bridge = LXMFBridge(base_storagepath=str(tmp_path / "lxmf"))

        # Register two channels with mock identities
        id1 = MagicMock()
        id1.hexhash = "aaa"
        dest1 = MagicMock()
        dest1.hash = b"\x01" * 16

        id2 = MagicMock()
        id2.hexhash = "bbb"
        dest2 = MagicMock()
        dest2.hash = b"\x02" * 16

        # Mock LXMF.LXMRouter to avoid real Reticulum
        with pytest.MonkeyPatch.context() as m:
            routers_created = []

            def mock_lxm_router(**kwargs):
                router = MagicMock()
                router.storagepath = kwargs.get("storagepath", "")
                routers_created.append(router)
                return router

            import LXMF

            m.setattr(LXMF, "LXMRouter", mock_lxm_router)

            bridge.register_channel("ch1", id1, dest1)
            bridge.register_channel("ch2", id2, dest2)

        assert len(routers_created) == 2
        assert bridge.get_router("ch1") is not None
        assert bridge.get_router("ch2") is not None
        assert bridge.get_router("ch1") is not bridge.get_router("ch2")

    def test_get_router_returns_none_for_unknown(self, tmp_path):
        """get_router returns None for unregistered channels."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        bridge = LXMFBridge(base_storagepath=str(tmp_path / "lxmf"))
        assert bridge.get_router("nonexistent") is None

    def test_get_any_router_prefers_node_router(self, tmp_path):
        """get_any_router returns the node-level router when available."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        node_router = MagicMock()
        bridge = LXMFBridge(
            base_storagepath=str(tmp_path / "lxmf"),
            node_lxm_router=node_router,
        )
        assert bridge.get_any_router() is node_router

    def test_get_any_router_falls_back_to_channel_router(self, tmp_path):
        """get_any_router returns a channel router when no node router."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        bridge = LXMFBridge(base_storagepath=str(tmp_path / "lxmf"))
        channel_router = MagicMock()
        bridge._routers["ch1"] = channel_router
        assert bridge.get_any_router() is channel_router

    def test_delivery_callback_routes_to_correct_channel(self, tmp_path):
        """Delivery callback routes messages based on destination hash."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        received = []
        bridge = LXMFBridge(
            base_storagepath=str(tmp_path / "lxmf"),
            ingest_callback=lambda env: received.append(env),
        )

        # Register a channel
        dest = MagicMock()
        dest.hash = b"\x01" * 16
        bridge._registered_destinations["ch1"] = {
            "identity": MagicMock(),
            "destination": dest,
        }

        # Simulate an incoming LXMF message
        msg = MagicMock()
        msg.signature_validated = True
        msg.source_hash = b"\x03" * 16
        msg.source = MagicMock()
        msg.source.identity = MagicMock()
        msg.source.identity.get_public_key = MagicMock(return_value=b"pk")
        msg.destination_hash = b"\x01" * 16
        msg.hash = b"\x04" * 16
        msg.timestamp = 1700000000.0
        msg.signature = b"\x00" * 64
        msg.content = None
        msg.payload = None

        bridge._on_lxmf_delivery(msg)

        assert len(received) == 1
        assert received[0].channel_id == "ch1"

    def test_duplicate_register_is_idempotent(self, tmp_path):
        """Registering the same channel twice doesn't create a second router."""
        from hokora.protocol.lxmf_bridge import LXMFBridge

        bridge = LXMFBridge(base_storagepath=str(tmp_path / "lxmf"))

        with pytest.MonkeyPatch.context() as m:
            call_count = 0

            def mock_lxm_router(**kwargs):
                nonlocal call_count
                call_count += 1
                return MagicMock()

            import LXMF

            m.setattr(LXMF, "LXMRouter", mock_lxm_router)

            id1 = MagicMock()
            dest1 = MagicMock()
            bridge.register_channel("ch1", id1, dest1)
            bridge.register_channel("ch1", id1, dest1)

        assert call_count == 1

    def test_storage_directories_created_per_channel(self, tmp_path):
        """Each channel gets its own storage subdirectory."""
        from hokora.protocol.lxmf_bridge import LXMFBridge
        import os

        base = str(tmp_path / "lxmf")
        bridge = LXMFBridge(base_storagepath=base)

        with pytest.MonkeyPatch.context() as m:
            import LXMF

            m.setattr(LXMF, "LXMRouter", lambda **kw: MagicMock())

            bridge.register_channel("general", MagicMock(), MagicMock())
            bridge.register_channel("random", MagicMock(), MagicMock())

        assert os.path.isdir(os.path.join(base, "general"))
        assert os.path.isdir(os.path.join(base, "random"))

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for core managers: ChannelManager, AnnounceHandler."""

import time
from unittest.mock import MagicMock

import msgpack

from hokora.core.announce import AnnounceHandler
from hokora.core.channel import ChannelManager


class TestAnnounceHandler:
    def test_build_channel_announce_roundtrip(self):
        """announce_channel payload round-trips through parse_channel_announce."""
        AnnounceHandler(MagicMock())
        # Build payload manually (announce_channel calls dest.announce internally)
        payload = msgpack.packb(
            {
                "type": "channel",
                "name": "general",
                "description": "Main chat",
                "node": "TestNode",
                "time": time.time(),
            }
        )
        parsed = AnnounceHandler.parse_channel_announce(payload)
        assert parsed is not None
        assert parsed["name"] == "general"
        assert parsed["description"] == "Main chat"
        assert parsed["node"] == "TestNode"

    def test_parse_channel_announce_invalid(self):
        assert AnnounceHandler.parse_channel_announce(b"not msgpack") is None

    def test_parse_channel_announce_wrong_type(self):
        payload = msgpack.packb({"type": "profile", "display_name": "test"})
        assert AnnounceHandler.parse_channel_announce(payload) is None

    def test_build_profile_announce(self):
        data = AnnounceHandler.build_profile_announce(
            display_name="Alice",
            status_text="Online",
            bio="Mesh enthusiast",
        )
        parsed = msgpack.unpackb(data, raw=False)
        assert parsed["type"] == "profile"
        assert parsed["display_name"] == "Alice"
        assert parsed["status_text"] == "Online"

    def test_build_profile_announce_with_avatar(self):
        avatar = b"\x89PNG" + b"\x00" * 100
        data = AnnounceHandler.build_profile_announce("Bob", avatar=avatar)
        parsed = msgpack.unpackb(data, raw=False)
        assert parsed["avatar"] == avatar

    def test_build_profile_announce_avatar_too_large(self):
        avatar = b"\x00" * 40000  # > 32768
        data = AnnounceHandler.build_profile_announce("Bob", avatar=avatar)
        parsed = msgpack.unpackb(data, raw=False)
        assert "avatar" not in parsed

    def test_announce_channel_no_destination(self):
        identity_mgr = MagicMock()
        identity_mgr.get_destination.return_value = None
        handler = AnnounceHandler(identity_mgr)
        # Should not raise, just log warning
        handler.announce_channel("ch1", "test", "desc", "Node")


class TestChannelManager:
    async def test_get_channel(self, session, config):
        identity_mgr = MagicMock()
        identity_mgr.get_or_create_channel_identity.return_value = MagicMock(hexhash="a" * 32)
        dest_mock = MagicMock()
        dest_mock.hash = b"\x01" * 16
        identity_mgr.register_channel_destination.return_value = dest_mock
        identity_mgr.get_identity.return_value = MagicMock(hexhash="a" * 32)
        identity_mgr.get_destination.return_value = dest_mock

        mgr = ChannelManager(config, identity_mgr)
        ch = await mgr.create_channel(session, "test-get")
        result = mgr.get_channel(ch.id)
        assert result is not None
        assert result.name == "test-get"

    async def test_get_channel_not_found(self, config):
        identity_mgr = MagicMock()
        mgr = ChannelManager(config, identity_mgr)
        assert mgr.get_channel("nonexistent") is None

    async def test_list_channels(self, session, config):
        identity_mgr = MagicMock()
        identity_mgr.get_or_create_channel_identity.return_value = MagicMock(hexhash="b" * 32)
        dest_mock = MagicMock()
        dest_mock.hash = b"\x02" * 16
        identity_mgr.register_channel_destination.return_value = dest_mock
        identity_mgr.get_identity.return_value = MagicMock(hexhash="b" * 32)
        identity_mgr.get_destination.return_value = dest_mock

        mgr = ChannelManager(config, identity_mgr)
        await mgr.create_channel(session, "list-ch1")
        await mgr.create_channel(session, "list-ch2")
        channels = mgr.list_channels()
        assert len(channels) >= 2

    async def test_get_channel_id_by_destination(self, session, config):
        identity_mgr = MagicMock()
        identity_mgr.get_or_create_channel_identity.return_value = MagicMock(hexhash="c" * 32)
        dest_mock = MagicMock()
        dest_mock.hash = b"\x03" * 16
        identity_mgr.register_channel_destination.return_value = dest_mock
        identity_mgr.get_identity.return_value = MagicMock(hexhash="c" * 32)
        identity_mgr.get_destination.return_value = dest_mock

        mgr = ChannelManager(config, identity_mgr)
        ch = await mgr.create_channel(session, "dest-test")
        found = mgr.get_channel_id_by_destination(b"\x03" * 16)
        assert found == ch.id

    async def test_get_channel_id_by_destination_not_found(self, config):
        identity_mgr = MagicMock()
        identity_mgr.get_destination.return_value = None
        mgr = ChannelManager(config, identity_mgr)
        assert mgr.get_channel_id_by_destination(b"\xff" * 16) is None

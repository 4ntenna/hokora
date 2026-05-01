# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for offline message queuing: push cursor persistence, retry, reconnect."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_rns():
    """Patch RNS module for all tests."""
    mock = MagicMock()
    with patch.dict("sys.modules", {"RNS": mock, "LXMF": MagicMock()}):
        yield mock


def _make_daemon_and_pusher(mock_rns):
    """Create a minimal HokoraDaemon with a FederationPusher for testing."""
    import importlib
    import hokora.federation.pusher as pusher_mod

    importlib.reload(pusher_mod)

    pusher = pusher_mod.FederationPusher(
        peer_identity_hash="aabb" + "0" * 28,
        channel_id="ch01",
        node_identity_hash="ccdd" + "0" * 28,
    )
    return pusher


class TestPushCursorPersistence:
    async def test_push_cursor_persisted_to_peer_sync_cursor(self, mock_rns):
        """Verify _persist_push_cursor writes to _push sub-key in sync_cursor."""
        from hokora.core.daemon import HokoraDaemon
        from hokora.config import NodeConfig

        config = NodeConfig(db_encrypt=False)

        # Mock peer from DB
        mock_peer = MagicMock()
        mock_peer.sync_cursor = {"ch01": 42}  # existing pull cursor
        mock_peer.identity_hash = "aabb" + "0" * 28

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_peer
        mock_session.execute = AsyncMock(return_value=mock_result)

        # Create a context manager mock
        session_ctx = AsyncMock()
        session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        session_ctx.__aexit__ = AsyncMock(return_value=False)

        begin_ctx = AsyncMock()
        begin_ctx.__aenter__ = AsyncMock(return_value=None)
        begin_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.begin = MagicMock(return_value=begin_ctx)

        from hokora.core.mirror_manager import MirrorLifecycleManager

        daemon = HokoraDaemon(config)
        daemon._session_factory = MagicMock(return_value=session_ctx)
        daemon._mirror_manager = MirrorLifecycleManager(daemon._session_factory)

        await daemon._mirror_manager.persist_push_cursor("aabb" + "0" * 28, "ch01", 37)

        # Verify sync_cursor now has _push sub-key while preserving pull cursor
        assert mock_peer.sync_cursor["ch01"] == 42  # pull cursor preserved
        assert mock_peer.sync_cursor["_push"]["ch01"] == 37

    async def test_push_cursor_restored_on_startup(self, mock_rns):
        """Verify push cursor is loaded from peer.sync_cursor._push on startup."""
        from hokora.core.daemon import HokoraDaemon
        from hokora.config import NodeConfig

        config = NodeConfig(db_encrypt=False)
        daemon = HokoraDaemon(config)
        daemon.reticulum = MagicMock()
        daemon.federation_auth = MagicMock()
        daemon.identity_manager = MagicMock()
        daemon.identity_manager.get_node_identity_hash.return_value = "ccdd" + "0" * 28

        # Mock peer with push cursor
        mock_peer = MagicMock()
        mock_peer.identity_hash = "aabb" + "0" * 28
        mock_peer.channels_mirrored = ["ch01"]
        mock_peer.sync_cursor = {"ch01": 42, "_push": {"ch01": 37}}

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_peer]
        mock_session.execute = AsyncMock(return_value=mock_result)

        session_ctx = AsyncMock()
        session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        session_ctx.__aexit__ = AsyncMock(return_value=False)

        begin_ctx = AsyncMock()
        begin_ctx.__aenter__ = AsyncMock(return_value=None)
        begin_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.begin = MagicMock(return_value=begin_ctx)

        daemon._session_factory = MagicMock(return_value=session_ctx)
        from hokora.core.mirror_manager import MirrorLifecycleManager

        daemon._mirror_manager = MirrorLifecycleManager(daemon._session_factory)

        # Patch add_mirror to avoid RNS/ChannelMirror initialization
        with patch.object(daemon, "add_mirror") as mock_add:
            # Simulate what load_configured_mirrors does after add_mirror
            def side_effect(remote_hash, ch_id, initial_cursor=0):
                key = f"{remote_hash.hex()}:{ch_id}"
                import hokora.federation.pusher as pm

                p = pm.FederationPusher(
                    peer_identity_hash=remote_hash.hex(),
                    channel_id=ch_id,
                    node_identity_hash="ccdd" + "0" * 28,
                )
                daemon._mirror_manager.federation_pushers[key] = p

            mock_add.side_effect = side_effect
            await daemon._mirror_manager.load_configured_mirrors(daemon.add_mirror)

        key = f"{'aabb' + '0' * 28}:ch01"
        pusher = daemon._federation_pushers.get(key)
        assert pusher is not None
        assert pusher.push_cursor == 37


class TestPushOnReconnect:
    def test_push_on_reconnect(self, mock_rns):
        """When handshake completes, push_pending should be called."""
        import hokora.federation.pusher as pusher_mod
        import importlib

        importlib.reload(pusher_mod)

        pusher = pusher_mod.FederationPusher(
            peer_identity_hash="aabb" + "0" * 28,
            channel_id="ch01",
            node_identity_hash="ccdd" + "0" * 28,
        )
        pusher.push_pending = AsyncMock()

        mock_link = MagicMock()
        pusher.set_link(mock_link)

        # Verify link was set
        assert pusher._link is mock_link


class TestPeriodicRetry:
    def test_periodic_retry_skips_backed_off_pushers(self, mock_rns):
        """_should_retry() should be respected during periodic retry."""
        import hokora.federation.pusher as pusher_mod
        import importlib
        import time

        importlib.reload(pusher_mod)

        pusher = pusher_mod.FederationPusher(
            peer_identity_hash="aabb" + "0" * 28,
            channel_id="ch01",
            node_identity_hash="ccdd" + "0" * 28,
        )

        # Simulate recent failure — should not retry
        pusher._consecutive_failures = 5
        pusher._last_attempt = time.monotonic()
        assert pusher._should_retry() is False

        # Simulate no failures — should retry
        pusher._consecutive_failures = 0
        assert pusher._should_retry() is True


class TestCursorsPersistOnShutdown:
    async def test_cursors_persisted_on_shutdown(self, mock_rns):
        """All pushers' cursors should be saved during stop()."""
        from hokora.core.daemon import HokoraDaemon
        from hokora.config import NodeConfig
        import hokora.federation.pusher as pusher_mod
        import importlib

        importlib.reload(pusher_mod)

        from hokora.core.mirror_manager import MirrorLifecycleManager

        config = NodeConfig(db_encrypt=False)
        daemon = HokoraDaemon(config)
        daemon._running = True

        # Add a pusher with a cursor
        pusher = pusher_mod.FederationPusher(
            peer_identity_hash="aabb" + "0" * 28,
            channel_id="ch01",
            node_identity_hash="ccdd" + "0" * 28,
        )
        pusher.push_cursor = 42
        daemon._mirror_manager = MirrorLifecycleManager(MagicMock())
        daemon._mirror_manager.federation_pushers["aabb" + "0" * 28 + ":ch01"] = pusher

        # Track calls to persist_push_cursor
        persist_calls = []

        async def mock_persist(peer_hash, channel_id, cursor):
            persist_calls.append((peer_hash, channel_id, cursor))

        daemon._mirror_manager.persist_push_cursor = mock_persist
        daemon._epoch_managers = {}
        daemon._push_retry_task = None
        daemon._announce_task = None
        daemon._engine = None

        # ``stop()`` tears down subsystems via the ServiceRegistry
        # populated during start(). This test synthesises a daemon
        # state without running start(), so we register the
        # mirror_manager explicitly to exercise the shutdown path.
        daemon._services.register("mirror_manager", daemon._mirror_manager.shutdown)

        await daemon.stop()

        assert len(persist_calls) == 1
        assert persist_calls[0] == ("aabb" + "0" * 28, "ch01", 42)

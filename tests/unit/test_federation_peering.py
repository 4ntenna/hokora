# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Federation peer discovery tests: announce handling, peer tracking, error resilience."""

from unittest.mock import MagicMock, patch

import msgpack


class TestPeerDiscovery:
    """Test PeerDiscovery.handle_announce and get_peers/get_peer."""

    def _make_discovery(self):
        with patch("hokora.federation.peering.RNS"):
            from hokora.federation.peering import PeerDiscovery

            return PeerDiscovery()

    def _make_app_data(self, name="general", node="TestNode"):
        return msgpack.packb(
            {"type": "channel", "name": name, "node": node},
            use_bin_type=True,
        )

    def test_handle_announce_valid_creates_peer(self):
        discovery = self._make_discovery()
        app_data = self._make_app_data()
        peer_hex = "abcd1234" * 4

        with patch("hokora.federation.peering.RNS") as mock_rns:
            mock_rns.hexrep.return_value = peer_hex
            discovery.handle_announce(b"\x01" * 16, MagicMock(), app_data)

        peers = discovery.get_peers()
        assert peer_hex in peers
        assert peers[peer_hex]["node_name"] == "TestNode"
        assert "general" in peers[peer_hex]["channels"]

    def test_handle_announce_empty_app_data_ignored(self):
        discovery = self._make_discovery()

        with patch("hokora.federation.peering.RNS"):
            discovery.handle_announce(b"\x01" * 16, MagicMock(), b"")

        assert len(discovery.get_peers()) == 0

    def test_handle_announce_none_app_data_ignored(self):
        discovery = self._make_discovery()

        with patch("hokora.federation.peering.RNS"):
            discovery.handle_announce(b"\x01" * 16, MagicMock(), None)

        assert len(discovery.get_peers()) == 0

    def test_handle_announce_non_channel_type_ignored(self):
        discovery = self._make_discovery()
        app_data = msgpack.packb(
            {"type": "profile", "display_name": "Alice"},
            use_bin_type=True,
        )

        with patch("hokora.federation.peering.RNS") as mock_rns:
            mock_rns.hexrep.return_value = "ff" * 16
            discovery.handle_announce(b"\x02" * 16, MagicMock(), app_data)

        assert len(discovery.get_peers()) == 0

    def test_get_peer_returns_none_for_unknown(self):
        discovery = self._make_discovery()
        assert discovery.get_peer("nonexistent_hash") is None

    def test_handle_announce_updates_existing_peer(self):
        discovery = self._make_discovery()
        peer_hex = "1234abcd" * 4

        with patch("hokora.federation.peering.RNS") as mock_rns:
            mock_rns.hexrep.return_value = peer_hex

            # First announce with channel "general"
            discovery.handle_announce(
                b"\x01" * 16,
                MagicMock(),
                self._make_app_data(name="general", node="Node1"),
            )
            # Second announce with channel "random"
            discovery.handle_announce(
                b"\x01" * 16,
                MagicMock(),
                self._make_app_data(name="random", node="Node1"),
            )

        peer = discovery.get_peer(peer_hex)
        assert peer is not None
        assert "general" in peer["channels"]
        assert "random" in peer["channels"]

    def test_handle_announce_invalid_msgpack_ignored(self):
        discovery = self._make_discovery()

        with patch("hokora.federation.peering.RNS") as mock_rns:
            mock_rns.hexrep.return_value = "ee" * 16
            # Invalid msgpack data
            discovery.handle_announce(b"\x01" * 16, MagicMock(), b"\xff\xfe\xfd")

        assert len(discovery.get_peers()) == 0


class TestPeerDiscoveryKeyRotation:
    """Channel RNS identity rotation propagated via peer announce."""

    def _build_rotation_envelope(
        self,
        channel_id: str = "ch01",
        old_hash: str = "a" * 64,
        new_hash: str = "b" * 64,
        timestamp: float | None = None,
        grace_period: int = 48 * 3600,
    ) -> bytes:
        import time

        if timestamp is None:
            timestamp = time.time()
        payload = msgpack.packb(
            {
                "type": "key_rotation",
                "channel_id": channel_id,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "timestamp": timestamp,
                "grace_period": grace_period,
            }
        )
        return msgpack.packb(
            {
                "payload": payload,
                "old_signature": b"\x01" * 64,
                "new_signature": b"\x02" * 64,
            }
        )

    async def _seed_channel(self, session_factory, identity_hash: str, channel_id: str = "ch01"):
        from hokora.db.models import Channel

        async with session_factory() as session:
            async with session.begin():
                session.add(
                    Channel(
                        id=channel_id,
                        name="rotatable",
                        identity_hash=identity_hash,
                        destination_hash="d" * 32,
                    )
                )

    async def _get_channel(self, session_factory, channel_id: str = "ch01"):
        from sqlalchemy import select
        from hokora.db.models import Channel

        async with session_factory() as session:
            row = await session.execute(select(Channel).where(Channel.id == channel_id))
            return row.scalar_one_or_none()

    async def _run_and_wait(self, discovery, envelope, loop):
        """Invoke handle_announce (sync — RNS callbacks run on non-async
        threads) and await the scheduled rotation coroutine.

        ``run_coroutine_threadsafe`` bridges into the loop via
        ``call_soon_threadsafe``, so the new task is NOT visible on
        ``asyncio.all_tasks`` synchronously — we must yield once first,
        then enumerate. Then wait for the discovered tasks to finish."""
        import asyncio

        current = asyncio.current_task()
        discovery.handle_announce(b"\x01" * 16, MagicMock(), envelope)
        # Yield repeatedly until the rotation task has been scheduled and
        # completed (poll rather than guessing a fixed count of sleeps).
        for _ in range(50):
            await asyncio.sleep(0)
            pending = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            if not pending:
                return
        # If we're still here, drain whatever remains so the test doesn't
        # silently pass with an unapplied rotation.
        await asyncio.gather(*pending, return_exceptions=True)

    async def test_rotation_applied_when_old_hash_matches(self, tmp_dir):
        import asyncio

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "rot.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        await self._seed_channel(sf, identity_hash="a" * 64)

        with (
            patch("hokora.federation.peering.RNS"),
            patch(
                "hokora.federation.key_rotation.KeyRotationManager.verify_rotation",
                side_effect=lambda env: msgpack.unpackb(
                    msgpack.unpackb(env, raw=False)["payload"], raw=False
                ),
            ),
        ):
            loop = asyncio.get_running_loop()
            discovery = PeerDiscovery(session_factory=sf, loop=loop)
            envelope = self._build_rotation_envelope()
            await self._run_and_wait(discovery, envelope, loop)

        ch = await self._get_channel(sf)
        assert ch.identity_hash == "b" * 64
        assert ch.rotation_old_hash == "a" * 64
        assert ch.rotation_grace_end is not None

        await engine.dispose()

    async def test_rotation_ignored_when_old_hash_mismatch(self, tmp_dir):
        import asyncio

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "rot-mismatch.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        # Our channel's current identity is "z...", but the announce claims
        # old_hash is "a...". Reject.
        await self._seed_channel(sf, identity_hash="z" * 64)

        with (
            patch("hokora.federation.peering.RNS"),
            patch(
                "hokora.federation.key_rotation.KeyRotationManager.verify_rotation",
                side_effect=lambda env: msgpack.unpackb(
                    msgpack.unpackb(env, raw=False)["payload"], raw=False
                ),
            ),
        ):
            loop = asyncio.get_running_loop()
            discovery = PeerDiscovery(session_factory=sf, loop=loop)
            envelope = self._build_rotation_envelope(old_hash="a" * 64)
            await self._run_and_wait(discovery, envelope, loop)

        ch = await self._get_channel(sf)
        assert ch.identity_hash == "z" * 64  # unchanged
        assert ch.rotation_old_hash is None
        assert ch.rotation_grace_end is None

        await engine.dispose()

    async def test_rotation_ignored_when_verification_fails(self, tmp_dir):
        import asyncio

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "rot-badsig.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        await self._seed_channel(sf, identity_hash="a" * 64)

        with (
            patch("hokora.federation.peering.RNS"),
            patch(
                "hokora.federation.key_rotation.KeyRotationManager.verify_rotation",
                return_value=None,  # signature failure
            ),
        ):
            loop = asyncio.get_running_loop()
            discovery = PeerDiscovery(session_factory=sf, loop=loop)
            envelope = self._build_rotation_envelope()
            await self._run_and_wait(discovery, envelope, loop)

        ch = await self._get_channel(sf)
        assert ch.identity_hash == "a" * 64
        await engine.dispose()

    def test_rotation_noop_without_session_factory(self):
        """When no session_factory/loop is provided (e.g. during tests that
        only track in-memory peer list), rotation announces parse + verify
        but do not attempt DB writes."""
        with (
            patch("hokora.federation.peering.RNS"),
            patch(
                "hokora.federation.key_rotation.KeyRotationManager.verify_rotation",
                return_value={"channel_id": "ch01", "old_hash": "a", "new_hash": "b"},
            ),
        ):
            from hokora.federation.peering import PeerDiscovery

            discovery = PeerDiscovery()
            envelope = msgpack.packb(
                {
                    "payload": msgpack.packb({"type": "key_rotation"}),
                    "old_signature": b"\x00",
                    "new_signature": b"\x00",
                }
            )
            # Should not raise despite no session factory.
            discovery.handle_announce(b"\x01" * 16, MagicMock(), envelope)


class TestPeerDiscoveryChannelIdentityCheck:
    """Rotation-aware channel-announce identity check.

    When a federated peer broadcasts a channel announce, PeerDiscovery
    cross-references the announcing RNS identity against our locally
    stored Channel.identity_hash. Mismatches outside the rotation grace
    window are logged at warning; within-grace pre-rotation announces
    are tolerated at debug. Peer tracking itself is unaffected.
    """

    def _build_channel_announce(self, channel_id="ch01", node="Node1", name="gen"):
        return msgpack.packb(
            {
                "type": "channel",
                "name": name,
                "node": node,
                "channel_id": channel_id,
            }
        )

    async def _seed_channel(
        self,
        session_factory,
        identity_hash: str,
        rotation_old_hash=None,
        rotation_grace_end=None,
        channel_id: str = "ch01",
    ):
        from hokora.db.models import Channel

        async with session_factory() as session:
            async with session.begin():
                session.add(
                    Channel(
                        id=channel_id,
                        name="rotatable",
                        identity_hash=identity_hash,
                        destination_hash="d" * 32,
                        rotation_old_hash=rotation_old_hash,
                        rotation_grace_end=rotation_grace_end,
                    )
                )

    async def _drive(self, discovery, app_data, announcer_hash, loop):
        """Invoke handle_announce with a mock announced_identity and wait
        for any scheduled mismatch-log coroutine to complete."""
        import asyncio

        current = asyncio.current_task()
        announced = MagicMock()
        announced.hexhash = announcer_hash
        with patch("hokora.federation.peering.RNS") as mock_rns:
            mock_rns.hexrep.return_value = "aa" * 16
            discovery.handle_announce(b"\x01" * 16, announced, app_data)
        for _ in range(50):
            await asyncio.sleep(0)
            pending = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            if not pending:
                return
        await asyncio.gather(*pending, return_exceptions=True)

    async def test_matching_identity_no_warning(self, tmp_dir, caplog):
        import asyncio
        import logging

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "match.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        await self._seed_channel(sf, identity_hash="a" * 64)

        loop = asyncio.get_running_loop()
        discovery = PeerDiscovery(session_factory=sf, loop=loop)

        with caplog.at_level(logging.WARNING, logger="hokora.federation.peering"):
            await self._drive(discovery, self._build_channel_announce(), "a" * 64, loop)

        assert not [r for r in caplog.records if "identity mismatch" in r.message]
        await engine.dispose()

    async def test_old_identity_within_grace_tolerated(self, tmp_dir, caplog):
        import asyncio
        import logging
        import time as _t

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "grace.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        await self._seed_channel(
            sf,
            identity_hash="b" * 64,
            rotation_old_hash="a" * 64,
            rotation_grace_end=_t.time() + 48 * 3600,
        )

        loop = asyncio.get_running_loop()
        discovery = PeerDiscovery(session_factory=sf, loop=loop)

        with caplog.at_level(logging.DEBUG, logger="hokora.federation.peering"):
            await self._drive(discovery, self._build_channel_announce(), "a" * 64, loop)

        # Tolerated → no warning, debug-level log.
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        debugs = [r for r in caplog.records if "pre-rotation" in r.message]
        assert debugs, "expected a debug log for pre-rotation announce"
        await engine.dispose()

    async def test_old_identity_after_grace_warns(self, tmp_dir, caplog):
        import asyncio
        import logging

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "expired.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        # Grace expired 1 hour ago.
        import time as _t

        await self._seed_channel(
            sf,
            identity_hash="b" * 64,
            rotation_old_hash="a" * 64,
            rotation_grace_end=_t.time() - 3600,
        )

        loop = asyncio.get_running_loop()
        discovery = PeerDiscovery(session_factory=sf, loop=loop)

        with caplog.at_level(logging.WARNING, logger="hokora.federation.peering"):
            await self._drive(discovery, self._build_channel_announce(), "a" * 64, loop)

        warnings = [r for r in caplog.records if "identity mismatch" in r.message]
        assert warnings, "expected identity-mismatch warning after grace expiry"
        await engine.dispose()

    async def test_unrelated_identity_warns(self, tmp_dir, caplog):
        import asyncio
        import logging

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "stranger.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        await self._seed_channel(sf, identity_hash="a" * 64)

        loop = asyncio.get_running_loop()
        discovery = PeerDiscovery(session_factory=sf, loop=loop)

        with caplog.at_level(logging.WARNING, logger="hokora.federation.peering"):
            await self._drive(discovery, self._build_channel_announce(), "z" * 64, loop)

        warnings = [r for r in caplog.records if "identity mismatch" in r.message]
        assert warnings, "expected identity-mismatch warning for unrelated announcer"
        await engine.dispose()

    async def test_unknown_channel_no_warning(self, tmp_dir, caplog):
        import asyncio
        import logging

        from hokora.db.engine import create_db_engine, create_session_factory, init_db
        from hokora.federation.peering import PeerDiscovery

        db_path = tmp_dir / "empty.db"
        engine = create_db_engine(db_path)
        await init_db(engine)
        sf = create_session_factory(engine)

        loop = asyncio.get_running_loop()
        discovery = PeerDiscovery(session_factory=sf, loop=loop)

        with caplog.at_level(logging.WARNING, logger="hokora.federation.peering"):
            await self._drive(discovery, self._build_channel_announce(), "z" * 64, loop)

        # No Channel row exists → helper returns silently.
        assert not [r for r in caplog.records if "identity mismatch" in r.message]
        await engine.dispose()

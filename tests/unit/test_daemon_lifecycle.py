# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Daemon lifecycle tests: instantiation, attribute presence, initial state."""

from unittest.mock import patch

from hokora.config import NodeConfig


class TestDaemonInstantiation:
    """Test that HokoraDaemon can be instantiated and has expected attributes."""

    def test_daemon_init_sets_config(self, tmp_dir):
        config = NodeConfig(
            node_name="Daemon Test",
            data_dir=tmp_dir,
            db_path=tmp_dir / "daemon.db",
            db_encrypt=False,
        )

        with patch("hokora.core.daemon.RNS"), patch("hokora.core.daemon.LXMF"):
            from hokora.core.daemon import HokoraDaemon

            daemon = HokoraDaemon(config)

        assert daemon.config is config
        assert daemon.config.node_name == "Daemon Test"

    def test_daemon_has_manager_attributes(self, tmp_dir):
        config = NodeConfig(
            node_name="Attr Test",
            data_dir=tmp_dir,
            db_path=tmp_dir / "daemon.db",
            db_encrypt=False,
        )

        with patch("hokora.core.daemon.RNS"), patch("hokora.core.daemon.LXMF"):
            from hokora.core.daemon import HokoraDaemon

            daemon = HokoraDaemon(config)

        # Constructor must wire every manager attribute — `is None`
        # check below proves the attribute exists (AttributeError would
        # raise instead) so a separate ``hasattr`` chain is redundant.
        for name in (
            "identity_manager",
            "channel_manager",
            "sequencer",
            "message_processor",
            "sync_handler",
            "live_manager",
            "fts_manager",
            "maintenance",
            "role_manager",
            "rate_limiter",
            "permission_resolver",
            "announce_handler",
        ):
            assert getattr(daemon, name) is None, f"{name} should be None pre-start"

        assert daemon.reticulum is None
        assert daemon._running is False

    def test_daemon_not_running_after_init(self, tmp_dir):
        config = NodeConfig(
            node_name="Running Test",
            data_dir=tmp_dir,
            db_path=tmp_dir / "daemon.db",
            db_encrypt=False,
        )

        with patch("hokora.core.daemon.RNS"), patch("hokora.core.daemon.LXMF"):
            from hokora.core.daemon import HokoraDaemon

            daemon = HokoraDaemon(config)

        assert daemon._running is False
        assert daemon.loop is None

    def test_daemon_background_task_attrs_initialised_to_none(self, tmp_dir):
        """All three background task handles must exist as None pre-start so
        stop() can safely cancel them regardless of how far start() got."""
        config = NodeConfig(
            node_name="Tasks Test",
            data_dir=tmp_dir,
            db_path=tmp_dir / "daemon.db",
            db_encrypt=False,
        )

        with patch("hokora.core.daemon.RNS"), patch("hokora.core.daemon.LXMF"):
            from hokora.core.daemon import HokoraDaemon

            daemon = HokoraDaemon(config)

        assert daemon._announce_task is None
        assert daemon._push_retry_task is None
        assert daemon._batch_flush_task is None


class TestDaemonStopCancelsBackgroundTasks:
    """Regression: stop() must cancel every background task it created,
    not just _announce_task + _push_retry_task. Leaking
    _batch_flush_task past engine.dispose() risks a partial SQLCipher+WAL
    write when systemd escalates SIGTERM to SIGKILL."""

    def test_stop_cancels_all_three_background_tasks(self, tmp_dir):
        import asyncio
        from unittest.mock import MagicMock

        config = NodeConfig(
            node_name="Stop Test",
            data_dir=tmp_dir,
            db_path=tmp_dir / "daemon.db",
            db_encrypt=False,
        )

        with patch("hokora.core.daemon.RNS"), patch("hokora.core.daemon.LXMF"):
            from hokora.core.daemon import HokoraDaemon

            daemon = HokoraDaemon(config)

        async def run():
            async def _forever():
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise

            daemon._running = True
            daemon._announce_task = asyncio.create_task(_forever())
            daemon._push_retry_task = asyncio.create_task(_forever())
            daemon._batch_flush_task = asyncio.create_task(_forever())

            # Tasks are torn down via the ServiceRegistry, so we must
            # explicitly register them — mimicking what daemon.start()
            # would have done. The name strings match what start() uses
            # so future ordering changes stay testable.
            daemon._services.register_task("announce_task", daemon._announce_task)
            daemon._services.register_task("push_retry_task", daemon._push_retry_task)
            daemon._services.register_task("batch_flush_task", daemon._batch_flush_task)

            # Neuter every non-task side effect of stop(): the test is scoped
            # to task-cancellation behaviour only.
            daemon._pid_file = MagicMock()

            await daemon.stop()

            assert daemon._announce_task.cancelled()
            assert daemon._push_retry_task.cancelled()
            assert daemon._batch_flush_task.cancelled()

        asyncio.run(run())

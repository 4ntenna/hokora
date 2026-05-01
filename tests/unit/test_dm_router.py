# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for DmRouter — Step B of the sync_engine refactor."""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.sync.dm_router import DmRouter
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    s = SyncState()
    s.display_name = "alice"
    return s


@pytest.fixture
def identity():
    ident = MagicMock()
    ident.hexhash = "a" * 32
    return ident


class TestStart:
    def test_no_identity_is_noop(self, tmp_path, state):
        router = DmRouter(identity=None, data_dir=tmp_path, state=state)
        router.start()
        assert router.lxm_router is None
        assert router.lxmf_source is None

    def _lxm_mock_with_delivery(self) -> MagicMock:
        """Build an LXMRouter mock with a populated delivery_destinations
        dict so DmRouter.start() doesn't hit the RNS.Destination fallback."""
        lxm = MagicMock()
        lxm.delivery_destinations = {"k": MagicMock()}
        return lxm

    def test_happy_path_constructs_router(self, tmp_path, identity, state):
        with patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf:
            mock_lxmf.LXMRouter.return_value = self._lxm_mock_with_delivery()
            router = DmRouter(identity, tmp_path, state)
            router.start()
            mock_lxmf.LXMRouter.assert_called_once()
            kwargs = mock_lxmf.LXMRouter.call_args.kwargs
            assert kwargs["identity"] is identity
            assert kwargs["storagepath"].endswith("/lxmf")

    def test_start_creates_storage_dir(self, tmp_path, identity, state):
        with patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf:
            mock_lxmf.LXMRouter.return_value = self._lxm_mock_with_delivery()
            router = DmRouter(identity, tmp_path, state)
            router.start()
            assert (tmp_path / "lxmf").is_dir()

    def test_default_data_dir_when_none(self, identity, state, monkeypatch):
        """data_dir=None → default to ~/.hokora-client."""
        fake_home = Path("/tmp/hokora-test-home-noexist")
        with (
            patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf,
            patch("hokora_tui.sync.dm_router.os.makedirs") as mock_mkdir,
        ):
            mock_lxmf.LXMRouter.return_value = self._lxm_mock_with_delivery()
            monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
            router = DmRouter(identity, None, state)
            router.start()
            storage = mock_lxmf.LXMRouter.call_args.kwargs["storagepath"]
            assert ".hokora-client/lxmf" in storage
            mock_mkdir.assert_called_once()

    def test_is_idempotent(self, tmp_path, identity, state):
        with patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf:
            mock_lxmf.LXMRouter.return_value = self._lxm_mock_with_delivery()
            router = DmRouter(identity, tmp_path, state)
            router.start()
            router.start()
            mock_lxmf.LXMRouter.assert_called_once()

    def test_announces_delivery_destination(self, tmp_path, identity, state):
        with patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf:
            lxm_router = MagicMock()
            delivery_dest = MagicMock()
            lxm_router.delivery_destinations = {"k": delivery_dest}
            mock_lxmf.LXMRouter.return_value = lxm_router
            router = DmRouter(identity, tmp_path, state)
            router.start()
            assert router.lxmf_source is delivery_dest
            delivery_dest.announce.assert_called_once()

    def test_fallback_destination_on_empty_deliveries(self, tmp_path, identity, state):
        """If delivery_destinations dict is empty, fall back to an OUT dest."""
        with (
            patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf,
            patch("hokora_tui.sync.dm_router.RNS") as mock_rns,
        ):
            lxm_router = MagicMock()
            lxm_router.delivery_destinations = {}
            mock_lxmf.LXMRouter.return_value = lxm_router
            fallback_dest = MagicMock()
            mock_rns.Destination.return_value = fallback_dest
            router = DmRouter(identity, tmp_path, state)
            router.start()
            assert router.lxmf_source is fallback_dest


class TestSendDm:
    def test_no_router_returns_false(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        assert router.send_dm("f" * 32, "hi") is False

    def test_unknown_peer_requests_path_and_returns_false(self, tmp_path, identity, state):
        with (
            patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf,
            patch("hokora_tui.sync.dm_router.RNS") as mock_rns,
        ):
            mock_lxmf.LXMRouter.return_value = MagicMock()
            mock_rns.Identity.recall.return_value = None
            router = DmRouter(identity, tmp_path, state)
            router.start()
            result = router.send_dm("bb" * 16, "hi")
            assert result is False
            mock_rns.Transport.request_path.assert_called_with(b"\xbb" * 16)

    def test_happy_path_calls_handle_outbound(self, tmp_path, identity, state):
        with (
            patch("hokora_tui.sync.dm_router.LXMF") as mock_lxmf,
            patch("hokora_tui.sync.dm_router.RNS") as mock_rns,
        ):
            inner_router = MagicMock()
            mock_lxmf.LXMRouter.return_value = inner_router
            peer = MagicMock()
            mock_rns.Identity.recall.return_value = peer
            mock_rns.Transport.has_path.return_value = True
            mock_rns.Destination.return_value = MagicMock()
            router = DmRouter(identity, tmp_path, state)
            router.start()
            result = router.send_dm("cc" * 16, "hello")
            assert result is True
            inner_router.handle_outbound.assert_called_once()


class TestDeliveryCallback:
    def test_dm_dispatches_to_callback(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        received: list[tuple] = []
        router.set_on_delivery(lambda *args: received.append(args))

        import msgpack as _mp

        msg = MagicMock()
        msg.content = _mp.packb(
            {"type": "dm", "body": "hi", "sender_name": "bob"},
            use_bin_type=True,
        )
        msg.source.identity.hexhash = "d" * 32
        msg.timestamp = 123.0
        router._on_lxmf_delivery(msg)
        assert len(received) == 1
        sender, display, body, ts = received[0]
        assert sender == "d" * 32
        assert display == "bob"
        assert body == "hi"
        assert ts == 123.0

    def test_dm_without_identity_uses_source_hash(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        received: list = []
        router.set_on_delivery(lambda *args: received.append(args))

        import msgpack as _mp

        with patch("hokora_tui.sync.dm_router.RNS") as mock_rns:
            mock_rns.hexrep.return_value = "fallback-hex"
            msg = MagicMock()
            msg.content = _mp.packb({"type": "dm", "body": "x"}, use_bin_type=True)
            msg.source.identity = None
            msg.source_hash = b"\xaa" * 16
            msg.timestamp = 42.0
            router._on_lxmf_delivery(msg)
        assert received[0][0] == "fallback-hex"

    def test_dm_missing_timestamp_uses_now(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        received: list = []
        router.set_on_delivery(lambda *args: received.append(args))

        import msgpack as _mp

        msg = MagicMock(spec=["source", "source_hash", "content"])
        msg.content = _mp.packb({"type": "dm", "body": "x"}, use_bin_type=True)
        msg.source.identity.hexhash = "e" * 32
        before = time.time()
        router._on_lxmf_delivery(msg)
        after = time.time()
        assert before <= received[0][3] <= after

    def test_batch_dispatches_each_event(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        seen_events: list[bytes] = []
        router.register_batch_dispatch(lambda ev, pkt: seen_events.append(ev))

        import msgpack as _mp

        msg = MagicMock()
        msg.content = _mp.packb(
            {
                "type": "batch",
                "events": [b"\x01\x02", b"\x03\x04"],
                "count": 2,
            },
            use_bin_type=True,
        )
        router._on_lxmf_delivery(msg)
        assert seen_events == [b"\x01\x02", b"\x03\x04"]

    def test_batch_without_handler_is_silent(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)

        import msgpack as _mp

        msg = MagicMock()
        msg.content = _mp.packb(
            {"type": "batch", "events": [b"\x01"], "count": 1},
            use_bin_type=True,
        )
        # Should not raise
        router._on_lxmf_delivery(msg)

    def test_malformed_content_does_not_raise(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        msg = MagicMock()
        msg.content = b"\xff\xff\xff-not-msgpack"
        router._on_lxmf_delivery(msg)  # swallowed via logger.exception

    def test_no_callback_is_silent(self, tmp_path, state):
        """DM arrives but no callback registered — must not raise."""
        router = DmRouter(None, tmp_path, state)
        import msgpack as _mp

        msg = MagicMock()
        msg.content = _mp.packb(
            {"type": "dm", "body": "x", "sender_name": "bob"},
            use_bin_type=True,
        )
        msg.source.identity.hexhash = "0" * 32
        msg.timestamp = 1.0
        router._on_lxmf_delivery(msg)


class TestCompatShims:
    def test_lxm_router_setter(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        assert router.lxm_router is None
        fake = MagicMock()
        router.lxm_router = fake
        assert router.lxm_router is fake

    def test_lxmf_source_setter(self, tmp_path, state):
        router = DmRouter(None, tmp_path, state)
        fake = MagicMock()
        router.lxmf_source = fake
        assert router.lxmf_source is fake

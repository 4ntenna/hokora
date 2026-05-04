# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for MediaClient — Step C of the sync_engine refactor."""

from unittest.mock import MagicMock, patch

import pytest

from hokora_tui.sync.media_client import MediaClient
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    return SyncState()


@pytest.fixture
def link_manager():
    lm = MagicMock()
    lm.resolve_channel_identity.return_value = MagicMock()
    return lm


@pytest.fixture
def dm_router():
    r = MagicMock()
    r.lxm_router = MagicMock()
    r.lxmf_source = MagicMock()
    return r


@pytest.fixture
def packet_dispatcher_calls():
    return []


@pytest.fixture
def event_cb_ref():
    return {"cb": None}


@pytest.fixture
def client(link_manager, dm_router, state, packet_dispatcher_calls, event_cb_ref):
    return MediaClient(
        link_manager,
        dm_router,
        state,
        identity=MagicMock(),
        packet_dispatcher=lambda data, pkt: packet_dispatcher_calls.append((data, pkt)),
        event_callback_getter=lambda: event_cb_ref["cb"],
    )


class TestSendMedia:
    def test_no_link_returns_false(self, client, link_manager, tmp_path):
        link_manager.get_link.return_value = None
        f = tmp_path / "x.txt"
        f.write_bytes(b"data")
        assert client.send_media("ch1", str(f)) is False

    def test_missing_file_returns_false(self, client, link_manager):
        active = MagicMock()
        active.status = "active"
        link_manager.get_link.return_value = active
        with patch("hokora_tui.sync.media_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            assert client.send_media("ch1", "/nonexistent/file.bin") is False

    def test_happy_path_calls_handle_outbound(self, client, link_manager, dm_router, tmp_path):
        active = MagicMock()
        active.status = "active"
        link_manager.get_link.return_value = active
        f = tmp_path / "hello.txt"
        f.write_bytes(b"hello world")
        with (
            patch("hokora_tui.sync.media_client.RNS") as rns,
            patch("hokora_tui.sync.media_client.LXMF") as lxmf,
        ):
            rns.Link.ACTIVE = "active"
            rns.Transport.has_path.return_value = True
            lxmf.LXMessage.return_value = MagicMock()
            assert client.send_media("ch1", str(f)) is True
            dm_router.lxm_router.handle_outbound.assert_called_once()


class TestRequestMediaDownload:
    def test_sets_pending_path_and_sends(self, client, state, link_manager):
        active = MagicMock()
        active.status = "active"
        link_manager.get_link.return_value = active
        with patch("hokora_tui.sync.media_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            client.request_media_download("ch1", "media/foo.bin", "/tmp/save")
            assert state.pending_media_path == "media/foo.bin"
            assert state.pending_media_save_path == "/tmp/save"
            rns.Packet.assert_called_once()

    def test_no_link_skips(self, client, state, link_manager):
        link_manager.get_link.return_value = None
        client.request_media_download("ch1", "x")
        assert state.pending_media_path is None


class TestOnResourceConcluded:
    def _make_resource(self, data: bytes, status: str = "complete"):
        r = MagicMock()
        r.status = status
        r.data = data
        return r

    def test_failed_status_logs_and_returns(self, client, packet_dispatcher_calls):
        with patch("hokora_tui.sync.media_client.RNS") as rns:
            rns.Resource.COMPLETE = "complete"
            r = self._make_resource(b"x", status="failed")
            client.on_resource_concluded(r)
            assert packet_dispatcher_calls == []

    def test_msgpack_response_routed_to_packet_dispatcher(self, client, packet_dispatcher_calls):
        with patch("hokora_tui.sync.media_client.RNS") as rns:
            rns.Resource.COMPLETE = "complete"
            # 0x82 = msgpack map of 2 entries; not media.
            payload = b"\x82\xa1k\xa1v"
            r = self._make_resource(payload)
            client.on_resource_concluded(r)
            assert packet_dispatcher_calls == [(payload, None)]

    def test_media_payload_saved_when_pending(
        self, client, state, packet_dispatcher_calls, tmp_path
    ):
        state.pending_media_path = "media/big.bin"
        state.pending_media_save_path = str(tmp_path)
        with patch("hokora_tui.sync.media_client.RNS") as rns:
            rns.Resource.COMPLETE = "complete"
            # raw bytes that don't match the msgpack map heuristic
            payload = b"\x00\x01\x02\x03random-binary"
            r = self._make_resource(payload)
            client.on_resource_concluded(r)
            saved = tmp_path / "big.bin"
            assert saved.read_bytes() == payload
            # Cleared pending state
            assert state.pending_media_path is None
            assert state.pending_media_save_path is None
            # Did not fall through to packet dispatcher
            assert packet_dispatcher_calls == []

    def test_msgpack_payload_with_pending_still_dispatched(
        self, client, state, packet_dispatcher_calls
    ):
        """If pending_media_path is set but the response IS msgpack, route
        to dispatcher — pending stays set so a later raw response gets
        the file save."""
        state.pending_media_path = "media/foo.bin"
        with patch("hokora_tui.sync.media_client.RNS") as rns:
            rns.Resource.COMPLETE = "complete"
            payload = b"\x82\xa1k\xa1v"
            r = self._make_resource(payload)
            client.on_resource_concluded(r)
            assert packet_dispatcher_calls == [(payload, None)]
            assert state.pending_media_path == "media/foo.bin"  # still set


class TestSaveMediaDownload:
    def test_uses_save_path_dir_with_filename(self, client, event_cb_ref, tmp_path):
        events = []
        event_cb_ref["cb"] = lambda ev, data: events.append((ev, data))
        client._save_media_download(b"abc", "remote/foo.bin", str(tmp_path))
        assert (tmp_path / "foo.bin").read_bytes() == b"abc"
        assert events[0][0] == "media_downloaded"
        assert events[0][1]["filename"] == "foo.bin"
        assert events[0][1]["size"] == 3

    def test_default_download_dir(self, client, monkeypatch, tmp_path):
        fake_home = tmp_path / "home"
        monkeypatch.setattr(
            "hokora_tui.sync.media_client.Path.home", classmethod(lambda cls: fake_home)
        )
        client._save_media_download(b"xy", "media/bar.bin", save_path=None)
        assert (fake_home / ".hokora-client/downloads/bar.bin").read_bytes() == b"xy"

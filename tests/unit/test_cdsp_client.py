# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for CdspClient — Step B of the sync_engine refactor."""

from unittest.mock import MagicMock, patch

import pytest

from hokora.constants import (
    CDSP_PROFILE_BATCHED,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_PRIORITIZED,
    SYNC_CDSP_PROFILE_UPDATE,
    SYNC_CDSP_SESSION_INIT,
)
from hokora_tui.sync.cdsp_client import CdspClient
from hokora_tui.sync.state import SyncState


@pytest.fixture
def state():
    return SyncState()


@pytest.fixture
def link_manager():
    lm = MagicMock()
    lm.links_snapshot.return_value = {}
    return lm


@pytest.fixture
def dm_router():
    r = MagicMock()
    src = MagicMock()
    src.hexhash = "deadbeef" * 4
    r.lxmf_source = src
    return r


class TestProfileAccessors:
    def test_set_profile_updates_state(self, state, link_manager, dm_router):
        c = CdspClient(link_manager, dm_router, state)
        c.set_profile(CDSP_PROFILE_PRIORITIZED)
        assert state.sync_profile == CDSP_PROFILE_PRIORITIZED
        assert c.current_profile() == CDSP_PROFILE_PRIORITIZED

    def test_session_accessors_reflect_state(self, state, link_manager, dm_router):
        state.cdsp_session_id = "sess-xyz"
        state.resume_token = b"\xaa" * 16
        state.deferred_count = 7
        c = CdspClient(link_manager, dm_router, state)
        assert c.session_id() == "sess-xyz"
        assert c.resume_token() == b"\xaa" * 16
        assert c.deferred_count() == 7


class TestInitSession:
    def test_no_link_is_noop(self, state, link_manager, dm_router):
        link_manager.get_link.return_value = None
        c = CdspClient(link_manager, dm_router, state)
        with patch("hokora_tui.sync.cdsp_client.RNS") as rns:
            c.init_session("ch1")
            rns.Packet.assert_not_called()

    def test_inactive_link_is_noop(self, state, link_manager, dm_router):
        link = MagicMock(status="closed")
        link_manager.get_link.return_value = link
        c = CdspClient(link_manager, dm_router, state)
        with patch("hokora_tui.sync.cdsp_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            c.init_session("ch1")
            rns.Packet.assert_not_called()

    def test_happy_path_sends_request(self, state, link_manager, dm_router):
        active = MagicMock(status="active")
        link_manager.get_link.return_value = active
        c = CdspClient(link_manager, dm_router, state)
        state.sync_profile = CDSP_PROFILE_FULL
        with patch("hokora_tui.sync.cdsp_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            rns.Packet.return_value = MagicMock()
            c.init_session("ch1")
            rns.Packet.assert_called_once()
            # Payload stored a nonce in pending_nonces
            assert len(state.pending_nonces) == 1

    def test_resume_token_in_payload_when_present(self, state, link_manager, dm_router):
        active = MagicMock(status="active")
        link_manager.get_link.return_value = active
        state.resume_token = b"\xbb" * 32
        c = CdspClient(link_manager, dm_router, state)
        with (
            patch("hokora_tui.sync.cdsp_client.RNS") as rns,
            patch("hokora_tui.sync.cdsp_client.encode_sync_request") as enc,
        ):
            rns.Link.ACTIVE = "active"
            enc.return_value = b"encoded"
            c.init_session("ch1")
            enc.assert_called_once()
            action_arg, nonce_arg, payload_arg = enc.call_args.args
            assert action_arg == SYNC_CDSP_SESSION_INIT
            assert payload_arg["resume_token"] == b"\xbb" * 32

    def test_lxmf_destination_hexhash_in_payload(self, state, link_manager, dm_router):
        active = MagicMock(status="active")
        link_manager.get_link.return_value = active
        c = CdspClient(link_manager, dm_router, state)
        with (
            patch("hokora_tui.sync.cdsp_client.RNS") as rns,
            patch("hokora_tui.sync.cdsp_client.encode_sync_request") as enc,
        ):
            rns.Link.ACTIVE = "active"
            enc.return_value = b"encoded"
            c.init_session("ch1")
            payload = enc.call_args.args[2]
            assert payload["lxmf_destination"] == "deadbeef" * 4


class TestUpdateProfile:
    def test_no_session_warns_and_skips(self, state, link_manager, dm_router):
        active = MagicMock(status="active")
        link_manager.get_link.return_value = active
        state.cdsp_session_id = None
        c = CdspClient(link_manager, dm_router, state)
        with patch("hokora_tui.sync.cdsp_client.RNS") as rns:
            rns.Link.ACTIVE = "active"
            c.update_profile("ch1", CDSP_PROFILE_PRIORITIZED)
            rns.Packet.assert_not_called()

    def test_updates_state_on_send(self, state, link_manager, dm_router):
        active = MagicMock(status="active")
        link_manager.get_link.return_value = active
        state.cdsp_session_id = "sess-1"
        c = CdspClient(link_manager, dm_router, state)
        with (
            patch("hokora_tui.sync.cdsp_client.RNS") as rns,
            patch("hokora_tui.sync.cdsp_client.encode_sync_request") as enc,
        ):
            rns.Link.ACTIVE = "active"
            enc.return_value = b"encoded"
            c.update_profile("ch1", CDSP_PROFILE_PRIORITIZED)
            assert state.sync_profile == CDSP_PROFILE_PRIORITIZED
            action = enc.call_args.args[0]
            assert action == SYNC_CDSP_PROFILE_UPDATE

    def test_update_profile_all_applies_to_every_link(self, state, link_manager, dm_router):
        active = MagicMock(status="active")
        link_manager.get_link.return_value = active
        link_manager.links_snapshot.return_value = {"ch1": active, "ch2": active}
        state.cdsp_session_id = "sess-x"
        c = CdspClient(link_manager, dm_router, state)
        with (
            patch("hokora_tui.sync.cdsp_client.RNS") as rns,
            patch("hokora_tui.sync.cdsp_client.encode_sync_request") as enc,
        ):
            rns.Link.ACTIVE = "active"
            enc.return_value = b"encoded"
            c.update_profile_all(CDSP_PROFILE_BATCHED)
            assert state.sync_profile == CDSP_PROFILE_BATCHED
            # 2 channels × 1 update request each
            assert enc.call_count == 2


class TestHandleSessionAck:
    def test_extracts_state_fields(self, state, link_manager, dm_router):
        c = CdspClient(link_manager, dm_router, state)
        flushed = c.handle_session_ack(
            {
                "session_id": "sess-abc",
                "resume_token": b"\xcc" * 24,
                "deferred_count": 3,
                "accepted_profile": CDSP_PROFILE_PRIORITIZED,
            }
        )
        assert state.cdsp_session_id == "sess-abc"
        assert state.resume_token == b"\xcc" * 24
        assert state.deferred_count == 3
        assert state.sync_profile == CDSP_PROFILE_PRIORITIZED
        assert flushed == []

    def test_preserves_resume_token_on_resume_without_new(self, state, link_manager, dm_router):
        """Resumes don't carry resume_token; preserve the prior one."""
        state.resume_token = b"\xdd" * 16
        c = CdspClient(link_manager, dm_router, state)
        c.handle_session_ack(
            {
                "session_id": "sess-resume",
                "deferred_count": 0,
                "accepted_profile": CDSP_PROFILE_FULL,
            }
        )
        assert state.resume_token == b"\xdd" * 16

    def test_returns_flushed_items(self, state, link_manager, dm_router):
        c = CdspClient(link_manager, dm_router, state)
        items = [{"payload": {"event": "message", "data": {"seq": 1}}}]
        out = c.handle_session_ack(
            {
                "session_id": "sess-flush",
                "accepted_profile": CDSP_PROFILE_FULL,
                "flushed_items": items,
            }
        )
        assert out == items

    def test_missing_profile_defaults_to_full(self, state, link_manager, dm_router):
        c = CdspClient(link_manager, dm_router, state)
        c.handle_session_ack({"session_id": "x"})
        assert state.sync_profile == CDSP_PROFILE_FULL


class TestHandleProfileAck:
    def test_updates_profile_and_deferred_count(self, state, link_manager, dm_router):
        state.sync_profile = CDSP_PROFILE_FULL
        c = CdspClient(link_manager, dm_router, state)
        c.handle_profile_ack({"accepted_profile": CDSP_PROFILE_BATCHED, "deferred_count": 42})
        assert state.sync_profile == CDSP_PROFILE_BATCHED
        assert state.deferred_count == 42

    def test_missing_fields_preserve_current_profile(self, state, link_manager, dm_router):
        state.sync_profile = CDSP_PROFILE_PRIORITIZED
        c = CdspClient(link_manager, dm_router, state)
        c.handle_profile_ack({})
        assert state.sync_profile == CDSP_PROFILE_PRIORITIZED


class TestHandleSessionReject:
    def test_logs_without_state_change(self, state, link_manager, dm_router, caplog):
        state.cdsp_session_id = "preserved"
        c = CdspClient(link_manager, dm_router, state)
        c.handle_session_reject({"error_code": "TOO_MANY_SESSIONS"})
        assert state.cdsp_session_id == "preserved"

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Bridge-level integration: SOURCE_UNKNOWN binding + recovery + reject."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import LXMF
import pytest

from hokora.protocol.lxmf_bridge import LXMFBridge
from hokora.security.lxmf_inbound import reset_for_tests


class _FakeConfig:
    def __init__(self, require_signed=True, wait=0.5):
        self.require_signed_lxmf = require_signed
        self.lxmf_path_wait_seconds = wait


@pytest.fixture(autouse=True)
def _reset():
    reset_for_tests()
    yield
    reset_for_tests()


def _build_message(*, validated, source_hash=b"\x09" * 16, channel_id="ch_test"):
    msg = MagicMock(spec=LXMF.LXMessage)
    msg.signature_validated = validated
    msg.unverified_reason = None if validated else LXMF.LXMessage.SOURCE_UNKNOWN
    msg.source_hash = source_hash
    msg.destination_hash = b"\x77" * 16
    msg.signature = b"\x33" * 64
    msg.hash = b"\x44" * 32
    msg.packed = b"\x55" * 200
    msg.timestamp = 1700000000.0
    msg.content = b""
    msg.fields = None
    msg.title = b""
    msg.source = None
    return msg


def _wire_channel(bridge, channel_id, dest_hash):
    mock_dest = MagicMock()
    mock_dest.hash = dest_hash
    bridge._registered_destinations[channel_id] = {
        "identity": MagicMock(),
        "destination": mock_dest,
    }


async def test_source_unknown_recovers_via_path_request(tmp_path):
    cb = AsyncMock()
    bridge = LXMFBridge(
        base_storagepath=str(tmp_path),
        ingest_callback=cb,
        config=_FakeConfig(require_signed=True, wait=0.5),
    )

    msg = _build_message(validated=False)
    _wire_channel(bridge, "ch_test", msg.destination_hash)

    ident = MagicMock()
    ident.sig_pub_bytes = b"\x10" * 32
    ident.hexhash = "ab" * 16

    with (
        patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
        patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=ident),
        patch(
            "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
            return_value=b"signed",
        ),
        patch(
            "hokora.security.verification.VerificationService.verify_ed25519_signature",
            return_value=True,
        ),
        patch.object(
            bridge,
            "_decode_content",
            return_value={"type": 1, "body": "first contact"},
        ),
    ):
        await bridge._validate_and_dispatch(msg)

    cb.assert_awaited_once()
    envelope = cb.await_args.args[0]
    assert envelope.sender_hash == ident.hexhash
    assert envelope.sender_public_key == b"\x10" * 32
    assert envelope.body == "first contact"


async def test_source_unknown_rejects_when_recall_never_resolves(tmp_path):
    cb = AsyncMock()
    bridge = LXMFBridge(
        base_storagepath=str(tmp_path),
        ingest_callback=cb,
        config=_FakeConfig(require_signed=True, wait=0.3),
    )

    msg = _build_message(validated=False)
    _wire_channel(bridge, "ch_test", msg.destination_hash)

    with (
        patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
        patch("hokora.security.lxmf_inbound.RNS.Identity.recall", return_value=None),
        patch.object(
            bridge,
            "_decode_content",
            return_value={"type": 1, "body": "should be dropped"},
        ),
    ):
        await bridge._validate_and_dispatch(msg)

    cb.assert_not_called()


async def test_source_unknown_passes_through_when_require_signed_false(tmp_path):
    cb = AsyncMock()
    bridge = LXMFBridge(
        base_storagepath=str(tmp_path),
        ingest_callback=cb,
        config=_FakeConfig(require_signed=False, wait=0.3),
    )

    msg = _build_message(validated=False)
    _wire_channel(bridge, "ch_test", msg.destination_hash)

    with patch.object(
        bridge,
        "_decode_content",
        return_value={"type": 1, "body": "lab opt out"},
    ):
        await bridge._validate_and_dispatch(msg)

    cb.assert_awaited_once()
    envelope = cb.await_args.args[0]
    assert envelope.body == "lab opt out"


async def test_attacker_forging_known_source_hash_rejected(tmp_path):
    cb = AsyncMock()
    bridge = LXMFBridge(
        base_storagepath=str(tmp_path),
        ingest_callback=cb,
        config=_FakeConfig(require_signed=True, wait=0.3),
    )

    msg = _build_message(validated=False)
    _wire_channel(bridge, "ch_test", msg.destination_hash)

    victim_identity = MagicMock()
    victim_identity.sig_pub_bytes = b"\x10" * 32
    victim_identity.hexhash = "ab" * 16

    with (
        patch("hokora.security.lxmf_inbound.RNS.Transport.request_path"),
        patch(
            "hokora.security.lxmf_inbound.RNS.Identity.recall",
            return_value=victim_identity,
        ),
        patch(
            "hokora.security.lxmf_inbound.reconstruct_lxmf_signed_part",
            return_value=b"signed",
        ),
        patch(
            "hokora.security.verification.VerificationService.verify_ed25519_signature",
            return_value=False,
        ),
        patch.object(
            bridge,
            "_decode_content",
            return_value={"type": 1, "body": "forged"},
        ),
    ):
        await bridge._validate_and_dispatch(msg)

    cb.assert_not_called()


def test_sync_entry_schedules_on_explicit_loop(tmp_path):
    bridge = LXMFBridge(
        base_storagepath=str(tmp_path),
        config=_FakeConfig(require_signed=True),
    )

    captured: dict[str, object] = {}

    class _FakeLoop:
        pass

    loop = _FakeLoop()
    bridge._loop = loop

    def _fake_schedule(coro, target_loop):
        captured["coro"] = coro
        captured["loop"] = target_loop
        future = MagicMock()
        return future

    msg = _build_message(validated=True)
    msg.source = MagicMock()
    msg.source.identity = MagicMock(sig_pub_bytes=b"\x10" * 32, hexhash="cd" * 16)

    with patch(
        "hokora.protocol.lxmf_bridge.asyncio.run_coroutine_threadsafe",
        side_effect=_fake_schedule,
    ):
        bridge._on_lxmf_delivery(msg)

    assert captured["loop"] is loop
    coro = captured["coro"]
    assert asyncio.iscoroutine(coro)
    coro.close()

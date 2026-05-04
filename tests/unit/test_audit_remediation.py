# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for audit remediation fixes (C2, C5, H3)."""

import time

import msgpack
import pytest

from hokora.constants import MAX_EDIT_CHAIN_LENGTH, NONCE_SIZE, SYNC_HISTORY
from hokora.exceptions import MediaError, MessageError, SyncError
from hokora.media.storage import MediaStorage
from hokora.protocol.wire import (
    _add_length_header,
    decode_sync_request,
)


class TestMediaPathTraversal:
    """C2: get() and delete() must reject path traversal."""

    def test_get_path_traversal(self, tmp_dir):
        storage = MediaStorage(tmp_dir / "media")
        with pytest.raises(MediaError, match="Path traversal"):
            storage.get("../../etc/passwd")

    def test_delete_path_traversal(self, tmp_dir):
        storage = MediaStorage(tmp_dir / "media")
        with pytest.raises(MediaError, match="Path traversal"):
            storage.delete("../../etc/passwd")

    def test_get_valid_path_still_works(self, tmp_dir):
        storage = MediaStorage(tmp_dir / "media")
        path = storage.store("ch1", "msg1", b"data", "bin")
        assert storage.get(path) == b"data"

    def test_delete_valid_path_still_works(self, tmp_dir):
        storage = MediaStorage(tmp_dir / "media")
        path = storage.store("ch1", "msg2", b"data", "bin")
        storage.delete(path)
        assert storage.get(path) is None


class TestNonceTypeRejection:
    """C5: non-bytes nonce must raise SyncError."""

    def test_string_nonce_rejected(self):
        raw = msgpack.packb(
            {
                "v": 1,
                "action": SYNC_HISTORY,
                "nonce": "not_bytes_nonce_val",
            },
            use_bin_type=True,
        )
        with pytest.raises(SyncError, match="Invalid nonce"):
            decode_sync_request(_add_length_header(raw))

    def test_int_nonce_rejected(self):
        raw = msgpack.packb(
            {
                "v": 1,
                "action": SYNC_HISTORY,
                "nonce": 12345,
            },
            use_bin_type=True,
        )
        with pytest.raises(SyncError, match="Invalid nonce|expected"):
            decode_sync_request(_add_length_header(raw))

    def test_valid_bytes_nonce_accepted(self):
        raw = msgpack.packb(
            {
                "v": 1,
                "action": SYNC_HISTORY,
                "nonce": b"\x00" * NONCE_SIZE,
            },
            use_bin_type=True,
        )
        result = decode_sync_request(_add_length_header(raw))
        assert result["nonce"] == b"\x00" * NONCE_SIZE


class TestEditChainLimit:
    """H3: edit chain must be capped at MAX_EDIT_CHAIN_LENGTH."""

    @pytest.fixture
    def processor(self):
        from hokora.core.message import MessageProcessor
        from hokora.core.sequencer import SequenceManager

        return MessageProcessor(sequencer=SequenceManager())

    async def test_edit_chain_limit_enforced(self, processor):
        from unittest.mock import AsyncMock, MagicMock
        from hokora.core.message import MessageEnvelope

        session = AsyncMock()
        session.flush = AsyncMock()

        # Create an original message mock with a full edit chain
        original = MagicMock()
        original.sender_hash = "sender_aaa"
        original.channel_id = "ch1"
        original.edit_chain = [f"edit_{i}" for i in range(MAX_EDIT_CHAIN_LENGTH)]

        envelope = MessageEnvelope(
            channel_id="ch1",
            sender_hash="sender_aaa",
            timestamp=time.time(),
            type=0x08,  # MSG_EDIT
            body="edited body",
            reply_to="original_hash",
        )

        with pytest.MonkeyPatch.context() as mp:

            async def mock_get_by_hash(h):
                return original

            repo_instance = AsyncMock()
            repo_instance.get_by_hash = mock_get_by_hash
            repo_instance.insert = AsyncMock()
            mp.setattr(
                "hokora.core.message.MessageRepo",
                lambda s: repo_instance,
            )

            with pytest.raises(MessageError, match="Edit chain limit"):
                await processor.process_edit(session, envelope)

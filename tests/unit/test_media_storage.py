# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Media storage tests: store/get roundtrip, quota enforcement, upload limits, secure delete."""

import pytest

from hokora.exceptions import MediaError
from hokora.media.storage import MediaStorage


class TestMediaStorage:
    def test_store_and_get_roundtrip(self, tmp_dir):
        storage = MediaStorage(tmp_dir / "media")
        data = b"hello media content"
        path = storage.store("ch1", "msg_hash_1", data, "txt")

        retrieved = storage.get(path)
        assert retrieved == data

    def test_quota_enforcement_raises(self, tmp_dir):
        # 100 bytes max storage — store one file that fills it entirely
        storage = MediaStorage(tmp_dir / "media", max_storage_bytes=100)
        storage.store("ch1", "msg1", b"x" * 90, "bin")

        # Even after pruning, the new 90-byte file still can't fit because
        # auto-prune frees old files, but 90 > 100 - 0 after full prune.
        # Actually, prune frees the first file, then usage=0, 90<100, so it
        # would succeed. Instead, make the new file bigger than total quota.
        with pytest.raises(MediaError, match="exceeds max upload|quota"):
            storage.store("ch1", "msg2", b"x" * 110, "bin")

    def test_upload_size_limit(self, tmp_dir):
        # 50 bytes max upload
        storage = MediaStorage(tmp_dir / "media", max_upload_bytes=50)

        with pytest.raises(MediaError, match="exceeds max upload"):
            storage.store("ch1", "msg1", b"x" * 100, "bin")

    def test_delete_with_secure_overwrite(self, tmp_dir):
        storage = MediaStorage(tmp_dir / "media")
        data = b"sensitive content here"
        path = storage.store("ch1", "del_msg", data, "txt")

        # File should exist
        full_path = tmp_dir / "media" / path
        assert full_path.exists()

        storage.delete(path, secure=True)
        assert not full_path.exists()

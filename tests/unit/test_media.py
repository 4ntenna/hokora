# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for media/thumbnail.py and media/transfer.py."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hokora.constants import MAX_THUMBNAIL_BYTES
from hokora.media.thumbnail import generate_thumbnail
from hokora.media.transfer import MediaTransfer
from hokora.media.storage import MediaStorage


class TestThumbnail:
    def _make_png(self, width=256, height=256):
        """Create a small in-memory PNG image."""
        try:
            from PIL import Image
            from io import BytesIO

            img = Image.new("RGB", (width, height), color=(255, 0, 0))
            buf = BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except ImportError:
            pytest.skip("PIL not available")

    def test_generate_thumbnail(self):
        png_data = self._make_png()
        thumb = generate_thumbnail(png_data)
        assert thumb is not None
        assert len(thumb) <= MAX_THUMBNAIL_BYTES
        # Should be JPEG
        assert thumb[:2] == b"\xff\xd8"

    def test_generate_thumbnail_rgba(self):
        """RGBA images should be converted to RGB."""
        try:
            from PIL import Image
            from io import BytesIO

            img = Image.new("RGBA", (128, 128), color=(255, 0, 0, 128))
            buf = BytesIO()
            img.save(buf, format="PNG")
            thumb = generate_thumbnail(buf.getvalue())
            assert thumb is not None
            assert len(thumb) <= MAX_THUMBNAIL_BYTES
        except ImportError:
            pytest.skip("PIL not available")

    def test_generate_thumbnail_respects_max_size(self):
        png_data = self._make_png(512, 512)
        thumb = generate_thumbnail(png_data, max_size=(64, 64))
        assert thumb is not None
        try:
            from PIL import Image
            from io import BytesIO

            img = Image.open(BytesIO(thumb))
            assert img.size[0] <= 64
            assert img.size[1] <= 64
        except ImportError:
            pass

    def test_generate_thumbnail_invalid_data(self):
        result = generate_thumbnail(b"not an image")
        assert result is None

    def test_generate_thumbnail_empty_data(self):
        result = generate_thumbnail(b"")
        assert result is None


class TestMediaStorageGlobalQuota:
    def test_get_global_usage_sums_across_channels(self):
        with tempfile.TemporaryDirectory() as td:
            storage = MediaStorage(Path(td), max_global_storage_bytes=1024 * 1024)
            storage.store("ch1", "hash1", b"a" * 100, "bin")
            storage.store("ch2", "hash2", b"b" * 200, "bin")
            assert storage._get_global_usage() == 300

    def test_store_rejects_when_global_quota_exceeded(self):
        with tempfile.TemporaryDirectory() as td:
            storage = MediaStorage(Path(td), max_global_storage_bytes=500)
            storage.store("ch1", "hash1", b"a" * 300, "bin")
            storage.store("ch2", "hash2", b"b" * 150, "bin")
            with pytest.raises(Exception, match="Global storage quota exceeded"):
                storage.store("ch3", "hash3", b"c" * 100, "bin")

    def test_store_allows_within_global_limit(self):
        with tempfile.TemporaryDirectory() as td:
            storage = MediaStorage(Path(td), max_global_storage_bytes=1000)
            path = storage.store("ch1", "hash1", b"a" * 400, "bin")
            assert path == "ch1/hash1.bin"
            path2 = storage.store("ch2", "hash2", b"b" * 400, "bin")
            assert path2 == "ch2/hash2.bin"

    def test_empty_media_dir_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            storage = MediaStorage(Path(td), max_global_storage_bytes=1024)
            assert storage._get_global_usage() == 0


class TestMediaTransfer:
    def test_serve_media_found(self):
        with tempfile.TemporaryDirectory() as td:
            storage = MediaStorage(Path(td))
            # Store a test file
            path = storage.store("ch1", "hash1", b"test file data", "bin")

            transfer = MediaTransfer(storage)
            link = MagicMock()

            with pytest.MonkeyPatch.context() as mp:
                mp.setattr("hokora.media.transfer.RNS.Resource", MagicMock())
                result = transfer.serve_media(link, path)
                assert result is True

    def test_serve_media_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            storage = MediaStorage(Path(td))
            transfer = MediaTransfer(storage)
            link = MagicMock()
            result = transfer.serve_media(link, "nonexistent/file.bin")
            assert result is False

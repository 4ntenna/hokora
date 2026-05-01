# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Filesystem media storage with per-channel and global quotas."""

import logging
import os
from pathlib import Path
from typing import Optional

from hokora.constants import (
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_BYTES_LIMIT,
    MAX_STORAGE_BYTES,
    MAX_GLOBAL_STORAGE_BYTES,
)
from hokora.exceptions import MediaError

logger = logging.getLogger(__name__)


class MediaStorage:
    """Manages media file storage with per-channel and global quotas."""

    def __init__(
        self,
        media_dir: Path,
        max_upload_bytes: int = MAX_UPLOAD_BYTES,
        max_storage_bytes: int = MAX_STORAGE_BYTES,
        max_global_storage_bytes: int = MAX_GLOBAL_STORAGE_BYTES,
    ):
        self.media_dir = media_dir
        self.max_upload_bytes = min(max_upload_bytes, MAX_UPLOAD_BYTES_LIMIT)
        self.max_storage_bytes = max_storage_bytes
        self.max_global_storage_bytes = max_global_storage_bytes
        self.media_dir.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        channel_id: str,
        msg_hash: str,
        data: bytes,
        extension: str = "bin",
    ) -> str:
        """Store media data. Returns the relative file path."""
        if len(data) > self.max_upload_bytes:
            raise MediaError(
                f"File size {len(data)} exceeds max upload size {self.max_upload_bytes}"
            )

        # Check global quota before per-channel
        global_usage = self._get_global_usage()
        if global_usage + len(data) > self.max_global_storage_bytes:
            raise MediaError("Global storage quota exceeded")

        # Check channel quota
        current_usage = self._get_channel_usage(channel_id)
        if current_usage + len(data) > self.max_storage_bytes:
            # Try to prune oldest media
            self._prune_oldest(channel_id, len(data))
            current_usage = self._get_channel_usage(channel_id)
            if current_usage + len(data) > self.max_storage_bytes:
                raise MediaError("Channel storage quota exceeded")

        filename = f"{msg_hash}.{extension}"
        relative_path = f"{channel_id}/{filename}"
        filepath = self._validate_path(relative_path)

        # Ensure channel directory exists (after path validation)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "wb") as f:
            f.write(data)
        logger.info(f"Stored media: {relative_path} ({len(data)} bytes)")
        return relative_path

    def _validate_path(self, relative_path: str) -> Path:
        """Validate that relative_path stays within media_dir."""
        resolved = (self.media_dir / relative_path).resolve()
        if not resolved.is_relative_to(self.media_dir.resolve()):
            raise MediaError("Path traversal blocked")
        return resolved

    def get(self, relative_path: str) -> Optional[bytes]:
        """Retrieve media data by relative path."""
        filepath = self._validate_path(relative_path)
        if filepath.exists():
            return filepath.read_bytes()
        return None

    def delete(self, relative_path: str, secure: bool = True):
        """Delete media file, optionally with secure overwrite."""
        filepath = self._validate_path(relative_path)
        if filepath.exists():
            if secure:
                size = filepath.stat().st_size
                with open(filepath, "wb") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
            filepath.unlink()

    def _get_channel_usage(self, channel_id: str) -> int:
        """Calculate total storage used by a channel."""
        channel_dir = self.media_dir / channel_id
        if not channel_dir.exists():
            return 0
        return sum(f.stat().st_size for f in channel_dir.iterdir() if f.is_file())

    def _get_global_usage(self) -> int:
        """Calculate total storage used across all channels."""
        if not self.media_dir.exists():
            return 0
        total = 0
        for child in self.media_dir.iterdir():
            if child.is_dir():
                total += sum(f.stat().st_size for f in child.iterdir() if f.is_file())
        return total

    def _prune_oldest(self, channel_id: str, needed_bytes: int):
        """Remove oldest media files to free space."""
        channel_dir = self.media_dir / channel_id
        if not channel_dir.exists():
            return

        files = sorted(channel_dir.iterdir(), key=lambda f: f.stat().st_mtime)
        freed = 0
        for f in files:
            if freed >= needed_bytes:
                break
            if f.is_file():
                freed += f.stat().st_size
                self.delete(f"{channel_id}/{f.name}", secure=True)
                logger.info(f"Pruned media: {channel_id}/{f.name}")

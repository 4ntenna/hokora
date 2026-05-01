# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""UploadCommand — upload a media file to the current channel."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext

# Hard cap on inline media — must match the daemon's MediaStorage limit.
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


class UploadCommand:
    """``/upload <filepath>`` — embed a file into an LXMF MSG_MEDIA delivery.

    The file bytes are passed to ``engine.send_media`` which packs them
    into the LXMF content for the daemon to extract via MediaStorage.
    Files over 5MB are rejected client-side; the daemon enforces the
    same limit server-side.
    """

    name = "upload"
    aliases: tuple[str, ...] = ()
    summary = "Upload a media file (/upload <path>)"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        filepath = args.strip()
        if not filepath:
            ctx.status.set_notice("Usage: /upload <filepath>", level="warn")
            return

        channel_id = ctx.state.current_channel_id
        if not channel_id:
            ctx.status.set_notice("Select a channel first.", level="warn")
            return

        if not os.path.exists(filepath):
            ctx.status.set_notice(f"File not found: {filepath}", level="error")
            return

        size = os.path.getsize(filepath)
        if size > _MAX_UPLOAD_BYTES:
            ctx.status.set_notice(
                f"File too large ({size} bytes, max 5MB)",
                level="error",
                duration=5.0,
            )
            return

        if ctx.engine is None:
            ctx.status.set_notice("Not connected.", level="warn")
            return

        if ctx.engine.send_media(channel_id, filepath):
            filename = os.path.basename(filepath)
            ctx.status.set_notice(f"Uploading {filename}...", level="info")
        else:
            ctx.status.set_notice(
                "Upload failed — check connection",
                level="error",
                duration=5.0,
            )

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""DownloadCommand — download a media file referenced in the current channel."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class DownloadCommand:
    """``/download <filename> [save_path]`` — fetch a media file from the daemon.

    Searches the current channel's cached messages for a media_path
    matching ``filename`` (exact match or basename suffix), then issues
    a SYNC_FETCH_MEDIA request via the sync engine. The daemon serves
    the bytes via RNS.Resource; the engine writes them to disk.
    """

    name = "download"
    aliases: tuple[str, ...] = ()
    summary = "Download a media file (/download <filename> [save_path])"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        parts = args.strip().split(None, 1)
        if not parts:
            ctx.status.set_notice(
                "Usage: /download <filename> [save_path]",
                level="warn",
            )
            return
        filename = parts[0]
        save_path = parts[1] if len(parts) > 1 else None

        channel_id = ctx.state.current_channel_id
        if not channel_id:
            ctx.status.set_notice("Select a channel first.", level="warn")
            return

        # Search channel messages for a matching media_path
        messages = ctx.state.messages.get(channel_id, [])
        media_path = None
        for msg in messages:
            mp = msg.get("media_path", "")
            if mp and (mp == filename or mp.endswith(f"/{filename}") or mp.endswith(filename)):
                media_path = mp
                break

        if not media_path:
            ctx.status.set_notice(
                f"No media '{filename}' found in this channel",
                level="warn",
                duration=5.0,
            )
            return

        if ctx.engine is None:
            ctx.status.set_notice("Not connected.", level="warn")
            return

        ctx.engine.request_media_download(channel_id, media_path, save_path=save_path)
        dest = save_path or "~/.hokora-client/downloads/"
        ctx.status.set_notice(f"Downloading {filename} -> {dest}", level="info")

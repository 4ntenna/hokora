# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ConnectCommand — connect to a remote node via RNS."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext

logger = logging.getLogger(__name__)


class ConnectCommand:
    """``/connect <dest_hash> [channel_id]`` — open an RNS Link to a remote node.

    With only ``dest_hash``: requests node metadata first (channel list).
    With both: connects directly to that channel.

    Path resolution may take several minutes over I2P/Tor; the command
    spawns a background retry loop with a 5-minute deadline. The UI
    transitions through "connecting" → "connected" via the sync engine's
    on_link_established callback regardless of which path resolved
    (immediate, retry-loop, or announce-driven).
    """

    name = "connect"
    aliases: tuple[str, ...] = ()
    summary = "Connect to a remote node (/connect <dest_hash> [channel_id])"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        parts = args.strip().split()
        if not parts:
            ctx.status.set_notice(
                "Usage: /connect <destination_hash> [channel_id]",
                level="warn",
                duration=5.0,
            )
            return

        dest_hash_hex = parts[0]
        channel_id = parts[1] if len(parts) > 1 else None
        logger.info("/connect: dest=%s channel=%s", dest_hash_hex, channel_id)

        try:
            dest_bytes = bytes.fromhex(dest_hash_hex)
            if len(dest_bytes) != 16:
                raise ValueError("expected 16-byte (32 hex char) destination hash")
        except ValueError:
            logger.warning("/connect: invalid hex hash: %s", dest_hash_hex)
            ctx.status.set_notice(
                f"Invalid destination hash: {dest_hash_hex}",
                level="error",
                duration=5.0,
            )
            return

        ctx.status.set_connection("connecting")
        ctx.status.set_context(f"Connecting to {dest_hash_hex[:16]}...")
        ctx.app._schedule_redraw()

        threading.Thread(
            target=lambda: self._do_connect(ctx, dest_bytes, dest_hash_hex, channel_id),
            daemon=True,
        ).start()

    def _do_connect(
        self,
        ctx: "CommandContext",
        dest_bytes: bytes,
        dest_hash_hex: str,
        channel_id: str | None,
    ) -> None:
        """Background thread: ONLY network I/O. No urwid widget calls."""
        try:
            logger.info("/connect: ensuring sync engine")
            from hokora_tui.commands.helpers import ensure_sync_engine

            ensure_sync_engine(ctx.app)
            engine = ctx.app.sync_engine
            if engine is None:
                logger.error("/connect: sync engine init failed")
                self._schedule_main(ctx, lambda: self._on_engine_fail(ctx))
                return

            if channel_id:
                logger.info(
                    "/connect: connecting channel %s on %s",
                    channel_id,
                    dest_hash_hex[:16],
                )
                engine.connect_channel(dest_bytes, channel_id)
            else:
                logger.info("/connect: requesting metadata from %s", dest_hash_hex[:16])
                engine.connect_channel(dest_bytes, "__meta__")

            # If path not yet resolved, retry until it is (or 5 min elapses).
            # _on_link_established drives the UI to "connected" when the link
            # opens — whether from this retry loop, an announce-driven retry
            # in the Announcer, or a pubkey-seeded immediate connect.
            if engine.has_pending_connects():
                threading.Thread(
                    target=lambda: self._retry_loop(ctx, engine),
                    daemon=True,
                ).start()
                self._schedule_main(ctx, lambda: self._on_connecting(ctx, dest_hash_hex))
            else:
                self._schedule_main(ctx, lambda: self._on_connected(ctx, dest_hash_hex, channel_id))

        except Exception as e:
            logger.error("Connect failed: %s", e, exc_info=True)
            err_msg = str(e)
            self._schedule_main(ctx, lambda: self._on_connect_error(ctx, err_msg))

    @staticmethod
    def _retry_loop(ctx: "CommandContext", engine) -> None:
        """Background retry loop for slow path resolution (e.g. I2P)."""
        import time as _t

        deadline = _t.time() + 300  # 5 minutes
        while _t.time() < deadline:
            _t.sleep(5)
            if not engine.has_pending_connects():
                return
            engine.retry_pending_connects()
        # Timed out with pending connects still queued
        if engine.has_pending_connects():
            ConnectCommand._schedule_main(ctx, lambda: ConnectCommand._on_timeout(ctx))

    @staticmethod
    def _schedule_main(ctx: "CommandContext", fn) -> None:
        if ctx.app.loop:
            ctx.app.loop.set_alarm_in(0, lambda _l, _d: fn())
            ctx.app._wake_loop()
        else:
            fn()

    @staticmethod
    def _on_engine_fail(ctx: "CommandContext") -> None:
        ctx.status.set_connection("disconnected")
        ctx.status.set_notice(
            "Failed to initialize sync engine.",
            level="error",
            duration=6.0,
        )
        ctx.app._schedule_redraw()

    @staticmethod
    def _on_connecting(ctx: "CommandContext", dest_hash_hex: str) -> None:
        ctx.state.connection_status = "connecting"
        ctx.state.connected_node_hash = dest_hash_hex
        ctx.status.set_connection("connecting", dest_hash_hex[:16])
        ctx.status.set_context("Resolving path... (can take several minutes over I2P)")
        ctx.app._schedule_redraw()

    @staticmethod
    def _on_connected(ctx: "CommandContext", dest_hash_hex: str, channel_id: str | None) -> None:
        ctx.state.connection_status = "connected"
        ctx.state.connected_node_hash = dest_hash_hex
        ctx.state.connected_node_name = ctx.state.connected_node_name or dest_hash_hex[:16]
        label = ctx.state.connected_node_name
        ctx.status.set_connection("connected", label)
        ctx.status.set_context(f"Connected to channel {channel_id or 'meta'}. Syncing...")
        ctx.app._schedule_redraw()

    @staticmethod
    def _on_timeout(ctx: "CommandContext") -> None:
        ctx.state.connection_status = "disconnected"
        ctx.status.set_connection("disconnected")
        ctx.status.set_notice(
            "Timed out waiting for node announce — check I2P tunnel status (rnstatus).",
            level="error",
            duration=8.0,
        )
        ctx.app._schedule_redraw()

    @staticmethod
    def _on_connect_error(ctx: "CommandContext", err_msg: str) -> None:
        ctx.status.set_connection("disconnected")
        ctx.status.set_notice(f"Connect failed: {err_msg}", level="error", duration=6.0)
        ctx.app._schedule_redraw()

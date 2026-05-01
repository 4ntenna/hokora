# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""InviteCommand — create / list / redeem invites."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext


class InviteCommand:
    """``/invite [create|redeem|list]`` — invite management.

    Subcommands:
    - ``/invite``                  → open invite dialog
    - ``/invite create [N]``       → create an invite for the current channel (max_uses=N, default 1)
    - ``/invite redeem <code>``    → redeem an invite code
    - ``/invite list``             → list active invites for the current channel
    """

    name = "invite"
    aliases: tuple[str, ...] = ()
    summary = "Manage invites (/invite [create|redeem <code>|list])"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        subcmd = args.strip().split(None, 1)
        action = subcmd[0].lower() if subcmd else ""
        sub_args = subcmd[1] if len(subcmd) > 1 else ""

        if not action:
            ctx.app.open_invite()
            return

        if action == "create":
            self._create(ctx, sub_args)
        elif action == "redeem":
            self._redeem(ctx, sub_args)
        elif action == "list":
            self._list(ctx)
        else:
            ctx.status.set_context(f"Unknown invite subcommand: {action}")

        ctx.app._schedule_redraw()

    @staticmethod
    def _create(ctx: "CommandContext", sub_args: str) -> None:
        channel_id = ctx.state.current_channel_id
        if not channel_id:
            ctx.status.set_context("Select a channel first.")
            return
        if ctx.engine is None:
            ctx.status.set_context("Not connected.")
            return
        max_uses = 1
        if sub_args.strip().isdigit():
            max_uses = int(sub_args.strip())
        ctx.engine.create_invite(channel_id, max_uses=max_uses)
        ctx.status.set_context("Creating invite...")

    @staticmethod
    def _redeem(ctx: "CommandContext", sub_args: str) -> None:
        code = sub_args.strip()
        if not code:
            ctx.status.set_context("Usage: /invite redeem <code>")
            return
        # Use current channel or any connected channel to send the redeem.
        channel_id = ctx.state.current_channel_id
        if not channel_id and ctx.engine is not None:
            channel_id = ctx.engine.first_connected_channel_id()
        if not channel_id:
            ctx.status.set_context("Connect to a node first.")
            return
        if ctx.engine is not None and hasattr(ctx.engine, "redeem_invite"):
            ctx.engine.redeem_invite(channel_id, code)
            ctx.status.set_context(f"Redeeming invite {code}...")
        else:
            ctx.status.set_context(f"No sync engine to redeem invite {code}")

    @staticmethod
    def _list(ctx: "CommandContext") -> None:
        if ctx.engine is None:
            ctx.status.set_context("Not connected.")
            return
        channel_id = ctx.state.current_channel_id
        ctx.engine.list_invites(channel_id)
        ctx.status.set_context("Fetching invites...")

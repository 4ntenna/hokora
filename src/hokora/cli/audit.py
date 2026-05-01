# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora audit: list audit-log entries from the local DB."""

import datetime
import json

import click

from hokora.cli._helpers import db_session
from hokora.db.queries import AuditLogRepo


def _run(coro):
    import asyncio

    return asyncio.run(coro)


@click.group("audit")
def audit_group():
    """Audit log inspection."""
    pass


@audit_group.command("list")
@click.option("--limit", type=int, default=50, show_default=True)
@click.option("--channel", "channel_id", default=None, help="Filter by channel ID.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON instead of text.")
def list_entries(limit: int, channel_id: str | None, as_json: bool):
    """List recent audit-log entries."""
    if limit < 1:
        raise click.BadParameter("--limit must be >= 1")
    _run(_list_entries(limit, channel_id, as_json))


async def _list_entries(limit: int, channel_id: str | None, as_json: bool):
    async with db_session() as session:
        repo = AuditLogRepo(session)
        entries = await repo.get_recent(limit=limit, channel_id=channel_id)

    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "id": e.id,
                        "actor": e.actor,
                        "action_type": e.action_type,
                        "target": e.target,
                        "channel_id": e.channel_id,
                        "timestamp": e.timestamp,
                        "details": e.details,
                    }
                    for e in entries
                ],
                indent=2,
            )
        )
        return

    if not entries:
        click.echo("No audit log entries.")
        return

    for e in entries:
        ts = datetime.datetime.fromtimestamp(e.timestamp).isoformat(timespec="seconds")
        actor = (e.actor or "")[:16]
        action = e.action_type or ""
        target = (e.target or "")[:32]
        ch = (e.channel_id or "-")[:16]
        click.echo(f"  {ts}  {actor:16s}  {action:20s}  {target:32s}  channel={ch}")

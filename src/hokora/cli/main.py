# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Click group entry point for hokora CLI."""

import click

from hokora.cli.init import init_cmd
from hokora.cli.audit import audit_group
from hokora.cli.ban import ban_group
from hokora.cli.channel import channel_group
from hokora.cli.identity import identity_group
from hokora.cli.role import role_group
from hokora.cli.node import node_group
from hokora.cli.invite import invite_group
from hokora.cli.daemon_cmd import daemon_group
from hokora.cli.mirror import mirror_group
from hokora.cli.db import db_group
from hokora.cli.seed import seed_group
from hokora.cli.config_cmd import config_group


@click.group()
@click.version_option(package_name="hokora")
def cli():
    """Hokora — Federated encrypted social platform on Reticulum."""
    pass


cli.add_command(init_cmd, "init")
cli.add_command(audit_group, "audit")
cli.add_command(ban_group, "ban")
cli.add_command(channel_group, "channel")
cli.add_command(identity_group, "identity")
cli.add_command(role_group, "role")
cli.add_command(node_group, "node")
cli.add_command(invite_group, "invite")
cli.add_command(daemon_group, "daemon")
cli.add_command(mirror_group, "mirror")
cli.add_command(db_group, "db")
cli.add_command(seed_group, "seed")
cli.add_command(config_group, "config")


if __name__ == "__main__":
    cli()

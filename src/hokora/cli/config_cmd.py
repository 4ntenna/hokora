# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora config: inspect / validate operator-editable config files.

Currently exposes ``hokora config validate-rns`` — a dry-run parse of
the daemon's RNS config that catches seed-structural issues before a
restart commits them.
"""

from __future__ import annotations

from pathlib import Path

import click

from hokora.config import load_config
from hokora.security import rns_config


@click.group("config")
def config_group():
    """Inspect or validate Hokora configuration."""
    pass


@config_group.command("validate-rns")
def validate_rns_cmd():
    """Parse and validate the RNS config; non-seed interfaces are skipped.

    Exits 0 on success, non-zero on issues. Server / Auto / RNode
    interfaces depend on runtime RNS state and aren't validated here.
    """
    fallback = Path.home() / ".reticulum"
    try:
        cfg = load_config()
        rns_dir = cfg.rns_config_dir
    except Exception:
        rns_dir = None
        click.echo(
            f"  (hokora.toml not loadable; validating {fallback}/config)",
            err=True,
        )
    if rns_dir is None:
        rns_dir = fallback
        click.echo(
            f"  (No rns_config_dir in hokora.toml; validating {rns_dir}/config)",
            err=True,
        )
    issues = rns_config.validate_config_file(rns_dir)
    if not issues:
        click.echo("OK — no issues found.")
        return
    click.echo(f"Found {len(issues)} issue(s):", err=True)
    for item in issues:
        click.echo(f"  - {item}", err=True)
    raise SystemExit(1)

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora daemon: start, stop, status."""

import os
import signal
import subprocess
import sys

import click

from hokora.config import load_config


@click.group("daemon")
def daemon_group():
    """Daemon management."""
    pass


@daemon_group.command("start")
@click.option("--foreground", "-f", is_flag=True, default=False)
@click.option("--relay-only", is_flag=True, default=False, help="Run as transport relay only")
def start(foreground, relay_only):
    """Start the Hokora daemon."""
    config = load_config()

    # Use relay_only from config if set there
    if config.relay_only:
        relay_only = True

    mode = "relay" if relay_only else "daemon"

    if foreground:
        click.echo(f"Starting hokorad {mode} in foreground ({config.node_name})...")
        if relay_only:
            sys.argv.append("--relay-only")
        from hokora.__main__ import main

        main()
    else:
        click.echo(f"Starting hokorad {mode} ({config.node_name})...")
        env = os.environ.copy()
        env["HOKORA_CONFIG"] = str(config.data_dir / "hokora.toml")

        pid_file = config.data_dir / "hokorad.pid"

        # Stale PID check: if old daemon is still running, abort
        if pid_file.exists():
            try:
                old_pid = int(pid_file.read_text().strip())
                os.kill(old_pid, 0)
                click.echo(f"Daemon already running (PID: {old_pid})")
                return
            except (ProcessLookupError, ValueError):
                pid_file.unlink(missing_ok=True)

        cmd = [sys.executable, "-m", "hokora"]
        if relay_only:
            cmd.append("--relay-only")

        with open(config.data_dir / "hokorad.log", "a") as log_fh:
            proc = subprocess.Popen(
                cmd,
                env=env,
                start_new_session=True,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            )

        # Atomic PID file write
        tmp = pid_file.with_suffix(".tmp")
        tmp.write_text(str(proc.pid))
        os.chmod(tmp, 0o600)
        tmp.rename(pid_file)
        click.echo(f"Daemon {mode} started (PID: {proc.pid})")


@daemon_group.command("stop")
def stop():
    """Stop the Hokora daemon."""
    config = load_config()
    pid_file = config.data_dir / "hokorad.pid"

    if not pid_file.exists():
        click.echo("No PID file found. Daemon may not be running.")
        return

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        click.echo("Corrupt PID file. Removing.")
        pid_file.unlink(missing_ok=True)
        return

    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"Sent SIGTERM to daemon (PID: {pid})")
        pid_file.unlink()
    except ProcessLookupError:
        click.echo(f"Process {pid} not found. Cleaning up PID file.")
        pid_file.unlink()
    except PermissionError:
        click.echo(f"Permission denied to stop process {pid}.")


@daemon_group.command("status")
def status():
    """Check daemon status."""
    config = load_config()
    pid_file = config.data_dir / "hokorad.pid"

    if not pid_file.exists():
        click.echo("Daemon: not running (no PID file)")
        return

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        click.echo("Daemon: corrupt PID file, removing")
        pid_file.unlink(missing_ok=True)
        return

    try:
        os.kill(pid, 0)  # Check if process exists
        click.echo(f"Daemon: running (PID: {pid})")
    except ProcessLookupError:
        click.echo(f"Daemon: not running (stale PID: {pid})")
        pid_file.unlink()
    except PermissionError:
        click.echo(f"Daemon: running (PID: {pid}, no permission to check)")

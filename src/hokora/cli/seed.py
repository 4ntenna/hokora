# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora seed: add, remove, list, and apply RNS seed-node interfaces.

Filesystem-authored seed management, CLI-gated by ownership of the
daemon's ``hokora.toml``. The CLI mutates the daemon's RNS config file
on disk via :mod:`hokora.security.rns_config`, then prompts the
operator (or, with ``--restart``, triggers) a daemon restart so RNS
reads the new config at startup.

The matching read surface is the ``SYNC_LIST_SEEDS`` sync action (see
``protocol/handlers/transport.py``), used by the TUI Network tab to
render the live seed list without parsing config files client-side.

Subcommands:

* ``hokora seed list`` — print the seeds currently configured.
* ``hokora seed add <name> <host[:port]>`` — add a TCP or I2P seed.
* ``hokora seed remove <name>`` — remove a seed by section name.
* ``hokora seed apply [--restart]`` — signal the daemon to reload
  (by SIGTERM + optional respawn if ``hokorad.argv`` is present).

Authorization is implicit: the CLI operates on the filesystem, which is
protected by unix permissions (``hokora.toml`` 0o600, identity files
0o600, RNS config 0o600 after first write). If the invoker can read
``hokora.toml`` and write the RNS config directory, they are by
definition the node owner — no additional auth layer required.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import click

from hokora.config import load_config
from hokora.security import rns_config


logger = logging.getLogger(__name__)


def _parse_host_port(raw: str) -> tuple[str, int, str]:
    """Normalize a user-typed address into ``(host, port, type)``.

    Accepts ``host``, ``host:port``, ``[ipv6]:port``, ``*.b32.i2p``,
    ``*.i2p``. TCP default port is 4242. Raises :class:`click.UsageError`
    on malformed input.
    """
    raw = raw.strip()
    if not raw:
        raise click.UsageError("Address must be non-empty")
    if raw.endswith(".i2p") or raw.endswith(".b32.i2p"):
        if ":" in raw:
            raise click.UsageError("I2P addresses do not take a port")
        return raw, 0, "i2p"
    if raw.startswith("["):
        # IPv6 with optional :port.
        end = raw.find("]")
        if end == -1:
            raise click.UsageError("Malformed IPv6 address (missing ']')")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError as exc:
                raise click.UsageError(f"Invalid port: {rest[1:]!r}") from exc
        else:
            port = 4242
        return host, port, "tcp"
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        try:
            port = int(port_str)
        except ValueError as exc:
            raise click.UsageError(f"Invalid port: {port_str!r}") from exc
        return host, port, "tcp"
    return raw, 4242, "tcp"


def _rns_config_dir() -> Optional[Path]:
    """Resolve the RNS config directory the CLI should operate on.

    Precedence:
      1. ``hokora.toml``'s ``rns_config_dir`` if set (operator-owned daemon).
      2. Fall back to ``~/.reticulum`` (the RNS default) with a visible
         stderr notice so the operator always knows which file the CLI
         is about to edit. Silent misdirection of seed writes would be
         worse than a missing CLI command — make the fallback loud.

    ``hokora seed`` operates on the RNS config file, not the database, so
    we deliberately tolerate ``load_config()`` failures (e.g. the pydantic
    validator that requires ``db_key`` when ``db_encrypt=true`` blocks
    load on a bare install with no ``hokora.toml``). In those cases we
    also fall back to ``~/.reticulum`` — the CLI is still useful.
    """
    fallback = Path.home() / ".reticulum"
    try:
        config = load_config()
    except Exception:
        click.echo(
            f"  (hokora.toml not loadable; operating on {fallback}/config)",
            err=True,
        )
        return fallback
    if config.rns_config_dir is not None:
        return config.rns_config_dir
    click.echo(
        f"  (No rns_config_dir in hokora.toml; operating on {fallback}/config)",
        err=True,
    )
    return fallback


def _pid_file_candidates() -> list[Path]:
    """Return candidate ``hokorad.pid`` paths for daemon discovery."""
    home = Path.home()
    candidates = list(home.glob(".hokora*/hokorad.pid"))
    # Also respect explicit HOKORA_CONFIG if it points at a data dir.
    cfg_env = os.environ.get("HOKORA_CONFIG")
    if cfg_env:
        toml_path = Path(cfg_env)
        if toml_path.is_file():
            maybe = toml_path.parent / "hokorad.pid"
            if maybe.exists() and maybe not in candidates:
                candidates.append(maybe)
    return candidates


def _discover_running_daemon_pid() -> Optional[tuple[int, Path]]:
    """Return ``(pid, data_dir)`` of a live daemon, or None if none running.

    Checks every candidate pid file for process liveness via ``kill(pid, 0)``.
    Returns the first live match. Stale pid files are ignored.
    """
    for pid_path in _pid_file_candidates():
        try:
            pid = int(pid_path.read_text().strip())
        except (OSError, ValueError):
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            # Process exists, owned by someone else — we can't restart it
            # anyway. Still report it so the operator sees the conflict.
            pass
        except OSError:
            continue
        return pid, pid_path.parent
    return None


@click.group("seed")
def seed_group():
    """Manage the daemon's RNS seed-node interfaces."""
    pass


@seed_group.command("list")
def list_cmd():
    """List the seed-node interfaces configured in the daemon's RNS config."""
    rns_dir = _rns_config_dir()
    try:
        seeds = rns_config.list_seeds(rns_dir)
    except rns_config.SeedConfigError as exc:
        raise click.ClickException(f"Failed to read RNS config: {exc}")
    if not seeds:
        click.echo("No seeds configured.")
        return
    for s in seeds:
        state = "enabled" if s.enabled else "disabled"
        if s.type == "tcp":
            addr = f"{s.target_host}:{s.target_port}"
        else:
            addr = s.target_host
        click.echo(f"  {s.name}  ({s.type}, {state})  →  {addr}")


@seed_group.command("add")
@click.argument("name")
@click.argument("address")
@click.option("--disabled", is_flag=True, help="Add but leave enabled=no.")
def add_cmd(name: str, address: str, disabled: bool):
    """Add a TCP or I2P seed: ``hokora seed add <name> <host[:port]>``.

    ``<name>`` becomes the RNS ``[[Section Name]]`` — must be unique and
    must not contain ``[`` or ``]``. ``<address>`` is either
    ``host[:port]`` for TCP (default port 4242) or an ``*.i2p`` /
    ``*.b32.i2p`` address for I2P (no port).
    """
    host, port, seed_type = _parse_host_port(address)
    entry = rns_config.SeedEntry(
        name=name,
        type=seed_type,
        target_host=host,
        target_port=port,
        enabled=not disabled,
    )
    try:
        rns_config.validate_seed_entry(entry)
    except rns_config.InvalidSeed as exc:
        raise click.UsageError(str(exc))
    rns_dir = _rns_config_dir()
    try:
        rns_config.apply_add(rns_dir, entry)
    except rns_config.DuplicateSeed as exc:
        raise click.ClickException(str(exc))
    except rns_config.SeedConfigError as exc:
        raise click.ClickException(f"Failed to update RNS config: {exc}")
    click.echo(f"Added seed {name!r} ({seed_type} → {host}" + (f":{port}" if port else "") + ")")
    click.echo("Restart the daemon to apply: sudo systemctl restart hokorad")
    click.echo("  (or: hokora seed apply --restart on dev boxes)")


@seed_group.command("remove")
@click.argument("name")
def remove_cmd(name: str):
    """Remove a seed by section name."""
    rns_dir = _rns_config_dir()
    try:
        rns_config.apply_remove(rns_dir, name)
    except rns_config.SeedNotFound as exc:
        raise click.ClickException(str(exc))
    except rns_config.SeedConfigError as exc:
        raise click.ClickException(f"Failed to update RNS config: {exc}")
    click.echo(f"Removed seed {name!r}")
    click.echo("Restart the daemon to apply: sudo systemctl restart hokorad")


@seed_group.command("apply")
@click.option(
    "--restart",
    is_flag=True,
    help="Send SIGTERM to the running daemon and re-exec from hokorad.argv (dev-mode).",
)
def apply_cmd(restart: bool):
    """Apply pending seed changes by signalling the daemon.

    Without ``--restart``: print the supervisor command the operator
    should run (systemd / docker compose).

    With ``--restart``: attempt a dev-mode respawn. Refuses if the
    daemon's ``hokorad.argv`` sibling file is missing — on supervised
    deployments the supervisor is the correct restart mechanism.
    """
    discovery = _discover_running_daemon_pid()
    if discovery is None:
        click.echo("No running daemon found. Start it with: hokora daemon start")
        return
    pid, data_dir = discovery

    if not restart:
        click.echo(f"Daemon running (pid={pid}).")
        click.echo("Apply seed changes by restarting:")
        click.echo("  sudo systemctl restart hokorad     # systemd")
        click.echo("  docker compose restart hokorad     # docker")
        click.echo("  hokora seed apply --restart        # dev-mode respawn")
        return

    argv_file = data_dir / "hokorad.argv"
    if not argv_file.exists():
        raise click.ClickException(
            f"Dev-mode respawn unavailable: {argv_file} not found. "
            "Restart via systemd / docker instead."
        )
    try:
        argv_spec = json.loads(argv_file.read_text())
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Malformed argv file: {exc}")

    click.echo(f"Stopping daemon (pid={pid}) via SIGTERM...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        click.echo("Daemon already exited.")
    except PermissionError as exc:
        raise click.ClickException(f"Cannot signal daemon pid={pid}: {exc}. Run as the same user.")

    # Wait for clean exit (up to 10 s).
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.2)
    else:
        raise click.ClickException(
            f"Daemon pid={pid} did not exit within 10 s. Check logs before re-launching."
        )

    # Double-fork detached respawn so the new daemon doesn't die with this CLI.
    argv = argv_spec.get("argv") or []
    cwd = argv_spec.get("cwd") or os.getcwd()
    env_overlay = argv_spec.get("env") or {}
    if not argv:
        raise click.ClickException("argv file had no argv entry; cannot respawn")

    pid_fork_1 = os.fork()
    if pid_fork_1 == 0:
        # First child: detach from CLI session.
        os.setsid()
        pid_fork_2 = os.fork()
        if pid_fork_2 == 0:
            # Grandchild: actually re-exec the daemon.
            try:
                os.chdir(cwd)
            except OSError:
                pass
            env = dict(os.environ)
            env.update(env_overlay)
            # Redirect stdio to /dev/null so the child doesn't die when the
            # parent shell closes.
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            if devnull > 2:
                os.close(devnull)
            try:
                os.execvpe(argv[0], argv, env)
            except OSError:
                os._exit(1)
        os._exit(0)
    os.waitpid(pid_fork_1, 0)
    click.echo("Daemon restart triggered. Check 'hokora daemon status' in a moment.")
    sys.exit(0)

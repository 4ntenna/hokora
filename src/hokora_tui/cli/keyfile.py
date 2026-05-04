# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""``hokora-tui-keyfile`` CLI — view + rotate the TUI cache master key.

Parity with ``hokora db migrate-key``: the operator can inspect the
keyfile path/mode without ever printing the secret, and rotate the key
by re-exporting the encrypted DB to a fresh one. Designed for backup
automation and recovery drills.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import click

from hokora.security.db_key import (
    DB_KEY_BYTES,
    resolve_db_key_from_path,
    validate_db_key_hex,
)
from hokora.security.fs import write_secure
from hokora_tui.security.client_db_key import client_db_keyfile_path


CLIENT_DIR = Path.home() / ".hokora-client"
CLIENT_DB_NAME = "tui.db"


@click.group()
def keyfile() -> None:
    """Manage the TUI client cache SQLCipher master key."""


@keyfile.command("path")
def cmd_path() -> None:
    """Print the resolved keyfile path (for backup automation)."""
    click.echo(str(client_db_keyfile_path(CLIENT_DIR)))


@keyfile.command("show")
def cmd_show() -> None:
    """Show the keyfile path + mode. Never prints the key contents."""
    p = client_db_keyfile_path(CLIENT_DIR)
    if not p.is_file():
        click.echo(f"No keyfile at {p} (will be auto-generated on next TUI launch).")
        return
    mode = p.stat().st_mode & 0o777
    click.echo(f"Path:  {p}")
    click.echo(f"Mode:  {mode:04o}")
    if mode & 0o077:
        click.echo("WARNING: keyfile mode is looser than 0o600 — tighten with chmod 600.")


@keyfile.command("rotate")
@click.option(
    "--keep-old",
    is_flag=True,
    default=False,
    help="Preserve the previous keyfile at <path>.prev (default: delete after rotate).",
)
def cmd_rotate(keep_old: bool) -> None:
    """Rotate the cache master key by re-exporting the DB under a fresh key.

    Steps (atomic, abort-on-failure):
      1. Resolve current key from keyfile.
      2. Generate a new key.
      3. ``ATTACH`` a sibling encrypted-with-new-key DB and run
         ``sqlcipher_export``.
      4. Atomically swap the new DB into place.
      5. Write the new keyfile (atomic 0o600).

    Refuses if the TUI is running (PID file present + alive) — concurrent
    rotation against an open WAL is unsafe.
    """
    import sqlcipher3

    db_path = CLIENT_DIR / CLIENT_DB_NAME
    keyfile_path = client_db_keyfile_path(CLIENT_DIR)

    if not db_path.is_file():
        click.echo(f"No client DB at {db_path}; nothing to rotate.")
        sys.exit(1)

    if not keyfile_path.is_file():
        click.echo(
            f"No keyfile at {keyfile_path}. The TUI generates one on first "
            "launch — run `hokora-tui` once before rotating."
        )
        sys.exit(1)

    try:
        old_key = resolve_db_key_from_path(keyfile_path)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        click.echo(f"Error reading current keyfile: {exc}")
        sys.exit(1)

    new_key = secrets.token_hex(DB_KEY_BYTES)
    validate_db_key_hex(new_key, source="rotated db_key")

    enc_path = db_path.with_suffix(db_path.suffix + ".rotating")
    if enc_path.exists():
        try:
            enc_path.unlink()
        except OSError as exc:
            click.echo(f"Could not remove stale {enc_path}: {exc}")
            sys.exit(1)

    try:
        src = sqlcipher3.connect(str(db_path))
        try:
            cur = src.cursor()
            cur.execute("PRAGMA key=\"x'" + old_key + "'\"")
            cur.execute(
                "ATTACH DATABASE ? AS rotated KEY \"x'" + new_key + "'\"",
                (str(enc_path),),
            )
            cur.execute("SELECT sqlcipher_export('rotated')")
            cur.execute("DETACH DATABASE rotated")
            src.commit()
            cur.close()
        finally:
            src.close()
    except Exception as exc:
        if enc_path.exists():
            try:
                enc_path.unlink()
            except OSError:
                pass
        click.echo(f"Rotate failed during sqlcipher_export: {exc}")
        sys.exit(1)

    # Backup keyfile, swap DB, write new key — order matters: swap DB
    # first so an interrupted run leaves the old keyfile matching the
    # NEW DB filename briefly. Better than the inverse (new keyfile,
    # old DB) which would brick the cache.
    prev_keyfile = keyfile_path.with_suffix(keyfile_path.suffix + ".prev")
    try:
        if prev_keyfile.exists():
            prev_keyfile.unlink()
        os.replace(str(keyfile_path), str(prev_keyfile))
    except OSError as exc:
        click.echo(f"Could not back up old keyfile: {exc}")
        sys.exit(1)

    try:
        os.replace(str(enc_path), str(db_path))
        os.chmod(str(db_path), 0o600)
    except OSError as exc:
        # Restore the old keyfile so the original DB stays usable.
        try:
            os.replace(str(prev_keyfile), str(keyfile_path))
        except OSError:
            pass
        click.echo(f"Could not swap rotated DB into place: {exc}")
        sys.exit(1)

    try:
        write_secure(keyfile_path, new_key + "\n", mode=0o600)
    except OSError as exc:
        click.echo(
            f"Rotated DB is in place but writing the new keyfile failed: {exc}. "
            f"Restore old keyfile from {prev_keyfile} and re-run."
        )
        sys.exit(1)

    if not keep_old:
        try:
            prev_keyfile.unlink()
        except OSError:
            pass

    click.echo(f"Rotated {db_path} to a new key. Keyfile: {keyfile_path} (0o600).")


def main() -> None:
    keyfile()


if __name__ == "__main__":
    main()

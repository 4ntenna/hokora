# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora db: database management commands (migrations, FTS rebuild, etc.)."""

import asyncio
from pathlib import Path
from typing import Optional

import click


def _find_alembic_root() -> Optional[Path]:
    """Walk up from this file until we find an ``alembic/`` directory next to
    an ``alembic.ini``. Mirrors ``hokora.db.engine.check_alembic_revision``
    so ``hokora db`` works regardless of the caller's cwd.
    """
    search = Path(__file__).resolve().parent
    for _ in range(10):
        candidate = search / "alembic"
        if candidate.is_dir() and (candidate / "env.py").exists():
            return search
        search = search.parent
    return None


def _load_alembic_config():
    """Load alembic.Config with an absolute ``script_location`` so the command
    works from any cwd. Raises ``click.ClickException`` (exit 1) on failure
    so CI/CD pipelines and Docker entrypoints surface the error.
    """
    from alembic.config import Config as AlembicConfig

    root = _find_alembic_root()
    if root is None:
        raise click.ClickException(
            "could not locate an 'alembic/' directory next to this "
            "package. Ensure the project layout is intact."
        )

    ini_path = root / "alembic.ini"
    cfg = AlembicConfig(str(ini_path) if ini_path.exists() else None)
    cfg.set_main_option("script_location", str(root / "alembic"))
    return cfg


@click.group("db")
def db_group():
    """Database management."""
    pass


@db_group.command("upgrade")
@click.option("--revision", default="head", help="Target revision (default: head)")
def upgrade(revision):
    """Run database migrations to the target revision."""
    try:
        from alembic import command
    except ImportError as exc:
        raise click.ClickException(
            "Alembic is not installed. Install with: pip install alembic"
        ) from exc

    cfg = _load_alembic_config()
    try:
        command.upgrade(cfg, revision)
    except Exception as exc:
        raise click.ClickException(f"Migration failed: {exc}") from exc
    click.echo(f"Database upgraded to: {revision}")


@db_group.command("downgrade")
@click.option("--revision", default="-1", help="Target revision (default: -1)")
def downgrade(revision):
    """Downgrade database to a previous revision."""
    try:
        from alembic import command
    except ImportError as exc:
        raise click.ClickException(
            "Alembic is not installed. Install with: pip install alembic"
        ) from exc

    cfg = _load_alembic_config()
    try:
        command.downgrade(cfg, revision)
    except Exception as exc:
        raise click.ClickException(f"Migration failed: {exc}") from exc
    click.echo(f"Database downgraded to: {revision}")


@db_group.command("current")
def current():
    """Show current database revision."""
    try:
        from alembic import command
    except ImportError as exc:
        raise click.ClickException(
            "Alembic is not installed. Install with: pip install alembic"
        ) from exc

    cfg = _load_alembic_config()
    try:
        command.current(cfg)
    except Exception as exc:
        raise click.ClickException(f"Error: {exc}") from exc


@db_group.command("history")
def history():
    """Show migration history."""
    try:
        from alembic import command
    except ImportError as exc:
        raise click.ClickException(
            "Alembic is not installed. Install with: pip install alembic"
        ) from exc

    cfg = _load_alembic_config()
    try:
        command.history(cfg)
    except Exception as exc:
        raise click.ClickException(f"Error: {exc}") from exc


@db_group.command("rebuild-fts")
def rebuild_fts():
    """Rebuild the full-text search index from the messages table."""
    asyncio.run(_rebuild_fts())


async def _rebuild_fts():
    from hokora.config import load_config
    from hokora.db.engine import create_db_engine
    from hokora.db.fts import FTSManager

    try:
        config = load_config()
        engine = create_db_engine(
            config.db_path, encrypt=config.db_encrypt, db_key=config.resolve_db_key()
        )
        fts = FTSManager(engine)
        await fts.rebuild()
        await engine.dispose()
    except Exception as exc:
        raise click.ClickException(f"FTS rebuild failed: {exc}") from exc
    click.echo("FTS index rebuilt successfully.")


@db_group.command("migrate-key")
@click.option(
    "--to-file",
    type=click.Path(),
    default=None,
    help="Destination keyfile path (default: <data_dir>/db_key).",
)
def migrate_key(to_file):
    """Move the SQLCipher master key from inline ``db_key`` into a separate
    0o600 keyfile.

    Reads the inline key from ``hokora.toml``, writes it to the keyfile
    atomically with 0o600, then rewrites ``hokora.toml`` to replace
    ``db_key = "..."`` with ``db_keyfile = "<path>"``. The previous
    config is preserved at ``<hokora.toml>.prev``.

    Idempotent: refuses with a clear message if already migrated, or if
    encryption is disabled. Restart the daemon afterwards.
    """
    import os
    import re as _re
    import shutil

    from hokora.config import load_config
    from hokora.security.fs import write_secure

    # Resolve config path the same way load_config() does so the message
    # accurately reflects which file is being edited.
    config_path = _resolve_config_path()
    if not config_path.exists():
        click.echo(f"Error: config not found at {config_path}.")
        return

    try:
        config = load_config(config_path)
    except Exception as exc:
        click.echo(f"Error: could not load config: {exc}")
        return

    if not config.db_encrypt:
        click.echo("Refusing to migrate: db_encrypt is false (no key to move).")
        return

    if config.db_keyfile is not None and config.db_key is None:
        click.echo(f"Already migrated: db_keyfile = {config.db_keyfile}")
        return

    if config.db_key is None:
        click.echo("Refusing to migrate: no inline db_key found in config.")
        return

    target = Path(to_file) if to_file else (config.data_dir / "db_key")
    if target.exists():
        click.echo(
            f"Refusing to overwrite existing keyfile at {target}. "
            "Move or delete it before re-running."
        )
        return

    # 1. Write keyfile (atomic 0o600)
    try:
        write_secure(target, config.db_key + "\n", mode=0o600)
    except OSError as exc:
        click.echo(f"Error: could not write keyfile {target}: {exc}")
        return

    # 2. Verify resolver returns the same key from the new location
    from hokora.config import NodeConfig

    probe = NodeConfig(
        data_dir=config.data_dir,
        db_encrypt=True,
        db_keyfile=target,
        relay_only=config.relay_only,
    )
    try:
        resolved = probe.resolve_db_key()
    except Exception as exc:
        target.unlink(missing_ok=True)
        click.echo(f"Error: keyfile readback failed ({exc}); aborted, no config changes.")
        return
    if resolved != config.db_key:
        target.unlink(missing_ok=True)
        click.echo("Error: keyfile readback did not match inline db_key; aborted.")
        return

    # 3. Backup hokora.toml then rewrite atomically
    backup_path = config_path.with_suffix(config_path.suffix + ".prev")
    try:
        shutil.copy2(config_path, backup_path)
        os.chmod(backup_path, 0o600)
    except OSError as exc:
        target.unlink(missing_ok=True)
        click.echo(f"Error: could not back up {config_path} -> {backup_path}: {exc}")
        return

    safe_target = str(target).replace("\\", "\\\\").replace('"', '\\"')
    new_line = f'db_keyfile = "{safe_target}"'
    original = config_path.read_text(encoding="utf-8")
    rewritten = _re.sub(
        r'^[ \t]*db_key[ \t]*=[ \t]*"[^"\n]*"[ \t]*$',
        new_line,
        original,
        count=1,
        flags=_re.MULTILINE,
    )
    if rewritten == original:
        # No literal db_key line to substitute — append a fresh db_keyfile
        # entry rather than leave the toml inconsistent. This handles
        # multi-line / commented variants safely.
        rewritten = original.rstrip() + "\n" + new_line + "\n"

    try:
        write_secure(config_path, rewritten, mode=0o600)
    except OSError as exc:
        # Restore from backup if the atomic write failed mid-flight.
        try:
            shutil.copy2(backup_path, config_path)
        except OSError:
            pass
        target.unlink(missing_ok=True)
        click.echo(f"Error: could not rewrite {config_path}: {exc}; restored from .prev")
        return

    click.echo(f"Migrated db_key from {config_path} to {target}.")
    click.echo(f"Previous config saved at {backup_path}.")
    click.echo("Restart hokorad to take effect (the key is read at engine creation).")


def _resolve_config_path() -> Path:
    """Mirror ``load_config()``'s path resolution so ``migrate-key`` edits
    the same file the daemon reads. Avoids env-var/cwd surprises.
    """
    import os

    from hokora.config import DEFAULT_DATA_DIR

    explicit = os.environ.get("HOKORA_CONFIG")
    if explicit:
        return Path(explicit)
    data_dir = os.environ.get("HOKORA_DATA_DIR")
    if data_dir:
        return Path(data_dir) / "hokora.toml"
    return DEFAULT_DATA_DIR / "hokora.toml"

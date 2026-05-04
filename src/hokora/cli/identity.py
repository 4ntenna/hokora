# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora identity: create, list, export, import."""

import click
import RNS

from hokora.config import load_config
from hokora.security.fs import secure_existing_file, write_identity_secure


@click.group("identity")
def identity_group():
    """Manage identities."""
    pass


@identity_group.command("create")
@click.argument("name")
def create(name):
    """Create a new identity."""
    config = load_config()
    identity_dir = config.identity_dir
    identity_dir.mkdir(parents=True, exist_ok=True)

    path = identity_dir / f"custom_{name}"
    if path.exists():
        click.echo(f"Identity '{name}' already exists.")
        return

    identity = RNS.Identity()
    write_identity_secure(identity, path)
    click.echo(f"Created identity '{name}': {identity.hexhash}")


@identity_group.command("list")
def list_identities():
    """List all identities."""
    config = load_config()
    identity_dir = config.identity_dir

    if not identity_dir.exists():
        click.echo("No identities found.")
        return

    for path in sorted(identity_dir.iterdir()):
        if path.is_file():
            try:
                identity = RNS.Identity.from_file(str(path))
                click.echo(f"  {path.name:<30} {identity.hexhash}")
            except Exception:
                click.echo(f"  {path.name:<30} (invalid)")


@identity_group.command("export")
@click.argument("name")
@click.argument("output", type=click.Path())
def export_identity(name, output):
    """Export an identity to a file."""
    config = load_config()
    identity_dir = config.identity_dir

    # Try to find the identity (most-specific first)
    candidates = [f"custom_{name}", f"channel_{name}"]
    if name == "node_identity":
        candidates.append("node_identity")

    for prefix in candidates:
        path = identity_dir / prefix
        if path.exists():
            import shutil

            shutil.copy2(str(path), output)
            click.echo(f"Exported identity '{name}' to {output}")
            return

    click.echo(f"Identity '{name}' not found.")


@identity_group.command("import")
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("name")
def import_identity(input_file, name):
    """Import an identity from a file."""
    config = load_config()
    identity_dir = config.identity_dir
    identity_dir.mkdir(parents=True, exist_ok=True)

    dest = identity_dir / f"custom_{name}"
    if dest.exists():
        click.echo(f"Identity '{name}' already exists.")
        return

    import shutil

    shutil.copy2(input_file, str(dest))
    secure_existing_file(dest, 0o600)

    # Verify
    try:
        identity = RNS.Identity.from_file(str(dest))
        click.echo(f"Imported identity '{name}': {identity.hexhash}")
    except Exception:
        dest.unlink()
        click.echo("Failed to import: invalid identity file.")

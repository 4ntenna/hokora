# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""hokora init: setup node directory, DB, default channel, systemd units."""

import asyncio
import os
import secrets
import subprocess
import uuid
from pathlib import Path

import click

from hokora.cli._helpers import write_secure
from hokora.config import NodeConfig, DEFAULT_DATA_DIR
from hokora.security.db_key import DB_KEY_BYTES
from hokora.security.fs import secure_identity_dir, write_identity_secure


@click.command("init")
@click.option("--data-dir", type=click.Path(), default=str(DEFAULT_DATA_DIR))
@click.option("--node-name", default="Hokora Node", prompt="Node name")
@click.option(
    "--node-type",
    type=click.Choice(["community", "relay"]),
    prompt="Node type\n  community = channels, messaging, roles\n  relay     = transport + LXMF propagation only\nChoose",
)
@click.option("--skip-luks-check", is_flag=True, default=False)
@click.option(
    "--no-db-encrypt",
    is_flag=True,
    default=False,
    help="Disable SQLCipher database encryption (NOT recommended for production)",
)
def init_cmd(data_dir, node_name, node_type, skip_luks_check, no_db_encrypt):
    """Initialize a new Hokora node."""
    data_path = Path(data_dir)
    is_relay = node_type == "relay"

    # LUKS check
    if not skip_luks_check:
        _check_luks(data_path)

    config_path = data_path / "hokora.toml"
    db_path = data_path / "hokora.db"

    # Prevent re-init from destroying an existing node
    if config_path.exists() and db_path.exists():
        click.echo("Error: Node already initialized at this location.")
        click.echo(f"  Config: {config_path}")
        click.echo(f"  Database: {db_path}")
        click.echo("  To reinitialize, remove the data directory first.")
        return

    click.echo(f"Initializing Hokora {'relay' if is_relay else 'community'} node at {data_path}")

    # Create directory structure
    dirs = [
        data_path,
        data_path / "identities",
        data_path / "media",
        data_path / "lxmf",
        data_path / "rns",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        click.echo(f"  Created {d}")

    if config_path.exists():
        # Config exists but no DB — reload existing config to preserve db_key
        from hokora.config import load_config

        config = load_config(config_path)
        click.echo(f"  Using existing config: {config_path}")
    else:
        # Fresh init — generate new config
        db_encrypt = not no_db_encrypt
        # Relay nodes don't need DB encryption (no community data)
        if is_relay and not no_db_encrypt:
            db_encrypt = False
            click.echo("  Relay mode: database encryption disabled (no community data)")
        # Write the SQLCipher master key to a separate 0o600 file rather
        # than embedding it in hokora.toml. Lets the operator back up
        # config without leaking the master key, and gives a clean
        # substrate for systemd LoadCredential / agent delivery later.
        db_keyfile_path: Path | None = None
        if db_encrypt:
            db_keyfile_path = data_path / "db_key"
            write_secure(db_keyfile_path, secrets.token_hex(DB_KEY_BYTES) + "\n", mode=0o600)
        config = NodeConfig(
            node_name=node_name,
            data_dir=data_path,
            db_encrypt=db_encrypt,
            db_keyfile=db_keyfile_path,
            relay_only=is_relay,
            propagation_enabled=is_relay,
        )
        if no_db_encrypt and not is_relay:
            click.echo("  WARNING: Database encryption disabled. NOT recommended for production.")
        _write_config(config_path, config, is_relay=is_relay)
        click.echo(f"  Created config: {config_path}")
        if config.db_encrypt and db_keyfile_path is not None:
            click.echo(f"  Wrote db_key file (0o600): {db_keyfile_path}")
            click.echo(
                "  WARNING: Back up your db_key file! Without it, your database "
                "cannot be decrypted."
            )

    # Generate RNS config
    rns_config_path = data_path / "rns" / "config"
    if not rns_config_path.exists():
        _write_rns_config(rns_config_path, is_relay=is_relay)
        click.echo(f"  Created RNS config: {rns_config_path}")

    # Initialize RNS
    import RNS

    RNS.Reticulum(configdir=str(data_path / "rns"))
    click.echo("  Reticulum initialized")

    # Create node identity
    identity_path = data_path / "identities" / "node_identity"
    secure_identity_dir(identity_path.parent)
    if not identity_path.exists():
        identity = RNS.Identity()
        write_identity_secure(identity, identity_path)
        click.echo(f"  Created node identity: {identity.hexhash}")
    else:
        identity = RNS.Identity.from_file(str(identity_path))
        click.echo(f"  Loaded node identity: {identity.hexhash}")

    # Initialize database and create default channel (community only)
    if not is_relay:
        asyncio.run(_init_db_and_channel(config))
    else:
        click.echo("  Relay mode: skipping database and channel initialization")

    # API key for the daemon's loopback /api/metrics/ endpoint. Atomic
    # O_EXCL create at 0o600 — skip if a key already exists (idempotent
    # re-init). Pure entropy, no derivation from any other secret.
    _ensure_api_key(data_path)

    # Generate systemd unit files
    _generate_systemd(data_path, is_relay=is_relay)

    click.echo()
    click.echo("Node initialized successfully!")
    click.echo(f"  Config: {config_path}")
    click.echo()

    if is_relay:
        click.echo("Next steps:")
        click.echo(f"  1. Edit RNS interfaces: {rns_config_path}")
        click.echo("  2. Start relay:  hokora daemon start --relay-only")
        click.echo("  3. For I2P:     install i2pd, uncomment I2P section in RNS config")
        click.echo(
            f"  4. For systemd: sudo cp {data_path}/systemd/hokorad.service /etc/systemd/system/"
        )
    else:
        click.echo("Next steps:")
        click.echo("  1. Start daemon:    hokora daemon start")
        click.echo("  2. Start TUI:       hokora-tui")
        click.echo("  3. Add seed nodes:  TUI Network tab (F2)")


def _ensure_api_key(data_path: Path) -> None:
    """Atomically create ``<data_dir>/api_key`` (0o600) if absent."""
    api_key_path = data_path / "api_key"
    if api_key_path.exists():
        return
    fd = os.open(str(api_key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, secrets.token_hex(32).encode())
    finally:
        os.close(fd)
    click.echo(f"  Wrote api_key file (0o600): {api_key_path}")


def _check_luks(data_path: Path):
    """Check if the data directory is on a LUKS-encrypted volume."""
    try:
        result = subprocess.run(
            ["lsblk", "-f", "-J"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "crypto_LUKS" not in result.stdout:
            click.echo(
                "WARNING: Data directory does not appear to be on a LUKS-encrypted volume.\n"
                "Full-disk encryption is strongly recommended for Hokora nodes.\n"
                "Use --skip-luks-check to proceed anyway."
            )
            if not click.confirm("Continue without LUKS?"):
                raise SystemExit(1)
    except (subprocess.SubprocessError, FileNotFoundError):
        pass  # lsblk not available, skip check


async def _init_db_and_channel(config: NodeConfig):
    """Initialize database and create default #general channel."""
    from hokora.db.engine import (
        create_db_engine,
        init_db,
        create_session_factory,
        check_alembic_revision,
    )
    from hokora.db.models import Channel
    from hokora.db.fts import FTSManager
    from hokora.security.roles import RoleManager

    engine = create_db_engine(
        config.db_path, encrypt=config.db_encrypt, db_key=config.resolve_db_key()
    )
    await init_db(engine)

    # Stamp alembic version table so daemon and 'hokora db upgrade' work correctly
    await check_alembic_revision(engine)

    # Init FTS
    fts = FTSManager(engine)
    await fts.init_fts()

    # Ensure built-in roles
    session_factory = create_session_factory(engine)
    async with session_factory() as session:
        async with session.begin():
            role_mgr = RoleManager()
            await role_mgr.ensure_builtin_roles(session)

            # Create default channel
            from hokora.db.queries import ChannelRepo

            repo = ChannelRepo(session)
            channels = await repo.list_all()
            if not channels:
                channel = Channel(
                    id=uuid.uuid4().hex[:16],
                    name=config.default_channel_name,
                    description="Default channel",
                )
                await repo.create(channel)
                click.echo(f"  Created #{config.default_channel_name} channel")

    await engine.dispose()


def _write_config(path: Path, config: NodeConfig, is_relay: bool = False):
    """Write a TOML config file."""
    safe_name = config.node_name.replace("\\", "\\\\").replace('"', '\\"')
    safe_data_dir = str(config.data_dir).replace("\\", "\\\\").replace('"', '\\"')
    rns_config_dir = str(config.data_dir / "rns").replace("\\", "\\\\").replace('"', '\\"')

    # Prefer ``db_keyfile`` (path on disk, 0o600) over inline ``db_key``
    # (deprecated). Fresh ``hokora init`` always writes a keyfile when
    # encryption is on; only legacy paths pass inline keys.
    if config.db_keyfile is not None:
        safe_keyfile = str(config.db_keyfile).replace("\\", "\\\\").replace('"', '\\"')
        key_lines = f'db_keyfile = "{safe_keyfile}"'
    elif config.db_key:
        safe_db_key = config.db_key.replace("\\", "\\\\").replace('"', '\\"')
        key_lines = f'db_key = "{safe_db_key}"'
    else:
        key_lines = "# (no db key — db_encrypt is false)"

    content = f'''# Hokora Node Configuration
node_name = "{safe_name}"
data_dir = "{safe_data_dir}"
log_level = "INFO"

# Database encryption (default for community nodes — SQLCipher; opt-out
# with `hokora init --no-db-encrypt` for relay/lab use only).
# The master key lives in db_keyfile (a separate 0o600 file); back it up
# offline. Inline ``db_key = "..."`` is still honored for legacy nodes
# but emits a DeprecationWarning at daemon start — migrate with
# ``hokora db migrate-key``.
db_encrypt = {"true" if config.db_encrypt else "false"}
{key_lines}

# RNS configuration directory
rns_config_dir = "{rns_config_dir}"

# Announce behaviour.
# Set announce_enabled = false for silent/invite-only nodes that should only
# be reached via pubkey-seeded invite tokens, not ambient discovery.
# announce_interval (seconds) is the cadence when announces are enabled.
# Lower values (e.g. 120) improve discovery on lossy transports like I2P;
# higher values (e.g. 1800+) conserve bandwidth on LoRa/constrained links.
announce_enabled = true
announce_interval = 600
'''

    if is_relay:
        content += """
# Relay mode: transport + LXMF propagation only (no channels, no chat)
relay_only = true
propagation_enabled = true
propagation_storage_mb = 500
propagation_autopeer = true
propagation_autopeer_maxdepth = 4
propagation_max_peers = 20
"""
    else:
        content += """
# Rate limiting
rate_limit_tokens = 10
rate_limit_refill = 1.0

# Media
max_upload_bytes = 5242880
max_storage_bytes = 1073741824

# Message retention (0 = unlimited)
retention_days = 0

# Full-text search
enable_fts = true
"""

    write_secure(path, content, mode=0o600)


def _write_rns_config(path: Path, is_relay: bool = False):
    """Generate a default RNS config file with commented examples."""
    if is_relay:
        content = """[reticulum]
  enable_transport = Yes
  share_instance = Yes

[logging]
  loglevel = 4

[interfaces]
  # TCP server for inbound connections
  [[TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4242

  # Uncomment to enable I2P anonymous connectivity
  # Requires i2pd running with SAM enabled (apt install i2pd)
  # [[I2P Network]]
  #   type = I2PInterface
  #   enabled = yes
  #   connectable = yes
  #   name = Relay-I2P

  # Uncomment for Tor hidden service connectivity
  # Requires Tor running with HiddenService configured
  # [[TCP Server Tor]]
  #   type = TCPServerInterface
  #   enabled = yes
  #   listen_ip = 127.0.0.1
  #   listen_port = 4243
"""
    else:
        content = """[reticulum]
  enable_transport = Yes
  share_instance = Yes

[logging]
  loglevel = 4

[interfaces]
  # Add seed nodes here or use the TUI Network tab (F2)
  # Example TCP seed:
  # [[TCP Seed]]
  #   type = TCPClientInterface
  #   target_host = 192.0.2.1
  #   target_port = 4242
  #   enabled = yes

  # Example I2P seed (requires i2pd with SAM enabled):
  # [[I2P Network]]
  #   type = I2PInterface
  #   enabled = yes
  #   name = I2P-Seed
  #   peers = <seed-address>.b32.i2p
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    write_secure(path, content, mode=0o644)


def _generate_systemd(data_path: Path, is_relay: bool = False):
    """Generate systemd unit file templates."""
    systemd_dir = data_path / "systemd"
    systemd_dir.mkdir(exist_ok=True)

    relay_flag = " --relay-only" if is_relay else ""
    # Sandbox-tightening systemd directives. These options are safe
    # defaults for a daemon that only talks to the network, reads its
    # config+identity under the data dir, writes SQLCipher DB +
    # heartbeat there, and doesn't need kernel/module access or /home
    # visibility. Operators who need an escape hatch (e.g. a custom
    # Python interpreter outside /usr) should override the unit rather
    # than weaken these globally.
    hokorad_unit = f"""[Unit]
Description=Hokora {"Relay" if is_relay else "Daemon"}
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=hokora
ExecStart={_get_python_path()} -m hokora{relay_flag}
Environment=HOKORA_CONFIG={data_path}/hokora.toml
Restart=on-failure
RestartSec=5
StopTimeoutSec=30
UMask=0077

# Sandbox hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=yes
ReadWritePaths={data_path}

[Install]
WantedBy=multi-user.target
"""
    (systemd_dir / "hokorad.service").write_text(hokorad_unit)
    click.echo(f"  Created systemd unit: {systemd_dir}/hokorad.service")


def _get_python_path() -> str:
    import sys

    return sys.executable

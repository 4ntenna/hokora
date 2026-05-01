# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration management with Pydantic and TOML loading."""

import logging
import os
import warnings
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from pydantic import BaseModel

from hokora.security.db_key import (
    resolve_db_key_from_path,
    validate_db_key_hex,
)

logger = logging.getLogger(__name__)

DEFAULT_DATA_DIR = Path.home() / ".hokora"

# Environment variable values that should be treated as boolean False
_ENV_FALSE_VALUES = {"false", "0", "", "no", "off"}

# Process-scoped flag so the inline-db_key DeprecationWarning fires at most
# once per process. Resolver call-sites (CLI tools, daemon startup) read the
# resolver several times during a single invocation; we don't want to spam.
_inline_db_key_warned = False


class NodeConfig(BaseModel):
    """Node configuration model."""

    node_name: str = "Hokora Node"
    node_description: str = ""
    data_dir: Path = DEFAULT_DATA_DIR
    db_path: Optional[Path] = None
    media_dir: Optional[Path] = None
    identity_dir: Optional[Path] = None
    db_encrypt: bool = True
    db_key: Optional[str] = None
    # Separate keyfile path for the SQLCipher master key. Preferred over
    # inline ``db_key``; lets operators back up hokora.toml without leaking
    # the key, and gives a clean substrate for systemd LoadCredential or
    # agent-style delivery. When unset, the resolver auto-discovers
    # ``<data_dir>/db_key`` if present, then falls back to inline ``db_key``
    # (deprecated).
    db_keyfile: Optional[Path] = None
    rns_config_dir: Optional[Path] = None
    log_level: str = "INFO"
    log_json: bool = False  # Emit logs as JSON lines (for central aggregators)
    log_to_stdout: bool = False  # Also write logs to stdout (in addition to file)
    announce_enabled: bool = True  # Disable for silent/invite-only nodes
    announce_interval: int = 600  # seconds; cadence when announce_enabled is True
    # ms between per-channel announces in a cycle; 0 disables. Spreads the burst
    # so RNS's per-interface announce-cap never has to queue.
    announce_stagger_ms: int = 50
    default_channel_name: str = "general"
    max_sync_limit: int = 100
    retention_days: int = 0  # 0 = no limit
    metadata_scrub_days: int = 0  # 0 = disabled; null sender_hash after N days
    enable_fts: bool = True
    # Visibility of private channel names to non-members. Membership
    # still gates content access; this only affects whether the channel
    # appears in listings.
    show_private_channels: bool = True

    # Relay mode — transport + LXMF propagation only, no community subsystems
    relay_only: bool = False
    propagation_enabled: bool = False  # LXMF store-and-forward propagation node
    propagation_storage_mb: int = 500
    propagation_static_peers: list[str] = []  # Peer dest_hash hex strings (always peer)
    propagation_autopeer: bool = True  # Auto-discover peers from announces
    propagation_autopeer_maxdepth: int = 4  # Max hops for auto-peering
    propagation_max_peers: int = 20  # Max concurrent peers

    # Rate limiting
    rate_limit_tokens: int = 10
    rate_limit_refill: float = 1.0

    # Media
    max_upload_bytes: int = 5 * 1024 * 1024
    max_storage_bytes: int = 1024 * 1024 * 1024
    max_global_storage_bytes: int = 10 * 1024 * 1024 * 1024  # 10GB

    # Federation
    federation_auto_trust: bool = False
    require_signed_federation: bool = True
    federation_push_retry_interval: int = 60  # seconds between push retry sweeps
    federation_push_max_backoff: int = 600  # max backoff delay for failed push retries
    # Mirror health-check interval (N3 cold-start fix — bounded fallback
    # to the announce-driven wake-up in PeerDiscovery). Every N seconds
    # the daemon nudges any mirror parked in WAITING_FOR_PATH/CLOSED so
    # a missed announce can never permanently strand federation.
    mirror_retry_interval: int = 60

    # Forward Secrecy
    fs_enabled: bool = True
    fs_epoch_duration: int = 3600
    fs_min_epoch_duration: int = 300
    fs_max_epoch_duration: int = 86400
    fs_rotation_max_retries: int = 3
    fs_rotation_initial_backoff: int = 30

    # CDSP (Client-Declared Sync Profiles)
    cdsp_enabled: bool = True
    cdsp_session_timeout: int = 3600
    cdsp_init_timeout: int = 5
    cdsp_deferred_queue_limit: int = 1000
    cdsp_default_profile: int = 0x01  # FULL for pre-CDSP clients

    # Observability — universal liveness contract ──────────────────────
    # Heartbeat file: transport-independent daemon-liveness signal at
    # ``<data_dir>/heartbeat``. Universal across all node types —
    # community, relay, embedded, air-gapped LoRa. Readers (systemd
    # watchdog, ObservabilityListener, ops tooling) use mtime to judge
    # freshness; stale mtime means wedged or dead.
    heartbeat_enabled: bool = True
    heartbeat_interval_s: float = 30.0

    # ObservabilityListener: stdlib HTTP server on loopback exposing
    # /health/live, /health/ready, /api/metrics/ (API-key gated).
    # Bind address is NOT configurable — hard-coded to 127.0.0.1 in
    # ``core/observability.py`` so a misconfigured TOML can never
    # expose the surface publicly.
    observability_enabled: bool = True
    observability_port: int = 8421

    def model_post_init(self, __context):
        if self.db_path is None:
            self.db_path = self.data_dir / "hokora.db"
        if self.media_dir is None:
            self.media_dir = self.data_dir / "media"
        if self.identity_dir is None:
            self.identity_dir = self.data_dir / "identities"
        # Auto-discover db_keyfile at <data_dir>/db_key if neither db_keyfile
        # nor db_key was set explicitly. Keeps fresh ``hokora init`` flows
        # working without an explicit toml field, and lets operators move
        # the key to a file by simply creating it (manual path).
        if (
            self.db_encrypt
            and self.db_keyfile is None
            and self.db_key is None
            and not self.relay_only
        ):
            candidate = self.data_dir / "db_key"
            if candidate.is_file():
                self.db_keyfile = candidate

        # Validate inline db_key shape eagerly (resolver re-validates keyfile
        # contents at read time — they may not exist yet at config-load time
        # for legacy flows where keyfile was just written).
        if self.db_encrypt and self.db_key:
            validate_db_key_hex(self.db_key, source="db_key")

        # Require *some* key source for community nodes with encryption on.
        # Resolver dry-run: if the keyfile path is set we trust it (the file
        # may not exist yet during ``hokora init`` — actual read failure
        # surfaces later via ``resolve_db_key()``). If only inline db_key is
        # set, that's fine. If neither is set, error now with a clear message.
        if (
            self.db_encrypt
            and not self.relay_only
            and self.db_key is None
            and self.db_keyfile is None
        ):
            raise ValueError(
                "Database encryption is enabled (db_encrypt=true) but no key "
                "source is configured. Either set db_keyfile to a 0o600 file "
                "containing 64 hex characters (recommended), or add db_key "
                "inline to your config file (deprecated), or set the "
                "HOKORA_DB_KEYFILE / HOKORA_DB_KEY environment variable."
            )

        if self.announce_interval <= 0:
            raise ValueError(
                "announce_interval must be > 0. To disable announces entirely, "
                "set announce_enabled = false (keeps the interval as the cadence "
                "that would apply if announces were re-enabled)."
            )
        if not (0 <= self.announce_stagger_ms <= 5000):
            raise ValueError(
                f"announce_stagger_ms ({self.announce_stagger_ms}) must be in "
                "[0, 5000]. 0 disables the stagger; the default 50ms suits TCP "
                "and most LoRa configs. Values above 5000 ms would push the "
                "announce burst beyond useful first-discovery windows."
            )
        if not (10 <= self.mirror_retry_interval <= 600):
            raise ValueError(
                f"mirror_retry_interval ({self.mirror_retry_interval}) must be "
                "between 10 and 600 seconds. Lower values produce noisy retry "
                "loops; higher values delay recovery from missed announces."
            )
        if self.fs_min_epoch_duration >= self.fs_max_epoch_duration:
            raise ValueError("fs_min_epoch_duration must be less than fs_max_epoch_duration")
        if not (self.fs_min_epoch_duration <= self.fs_epoch_duration <= self.fs_max_epoch_duration):
            raise ValueError(
                f"fs_epoch_duration ({self.fs_epoch_duration}) must be between "
                f"fs_min_epoch_duration ({self.fs_min_epoch_duration}) and "
                f"fs_max_epoch_duration ({self.fs_max_epoch_duration})"
            )

    def resolve_db_key(self) -> Optional[str]:
        """Resolve the SQLCipher master key from configured sources.

        Resolution order:
        1. ``db_encrypt=False`` → ``None`` (relay/lab path, no key needed).
        2. ``db_keyfile`` set → read file, strip whitespace, validate
           64 hex chars, return.
        3. Inline ``db_key`` set → return as-is and emit a one-shot
           ``DeprecationWarning`` at module level (we only want to nag
           the operator once per process).
        4. Encryption on but neither configured → ``ValueError`` matching
           the post-init validator's wording.

        File-mode hygiene: if ``db_keyfile`` exists with a mode looser than
        0o600, log a warning. We do NOT auto-tighten — that's a separate
        operator decision (the file might be group-readable for a reason
        the daemon doesn't know about).
        """
        if not self.db_encrypt:
            return None

        if self.db_keyfile is not None:
            return resolve_db_key_from_path(Path(self.db_keyfile))

        if self.db_key is not None:
            global _inline_db_key_warned
            if not _inline_db_key_warned:
                _inline_db_key_warned = True
                warnings.warn(
                    "Inline db_key in hokora.toml is deprecated. Move the key "
                    "to a separate file with `hokora db migrate-key` so config "
                    "can be backed up without leaking the master key.",
                    DeprecationWarning,
                    stacklevel=2,
                )
            return self.db_key

        if self.relay_only:
            return None

        raise ValueError(
            "Database encryption is enabled (db_encrypt=true) but no key "
            "source is configured. Either set db_keyfile to a 0o600 file "
            "containing 64 hex characters (recommended), or add db_key "
            "inline to your config file (deprecated)."
        )


def load_config(config_path: Optional[Path] = None) -> NodeConfig:
    """Load config from TOML file with env var overlay."""
    data = {}

    if config_path is None:
        explicit_config = os.environ.get("HOKORA_CONFIG")
        if explicit_config:
            config_path = Path(explicit_config)
        else:
            data_dir = os.environ.get("HOKORA_DATA_DIR")
            if data_dir:
                config_path = Path(data_dir) / "hokora.toml"
            else:
                config_path = DEFAULT_DATA_DIR / "hokora.toml"

    if config_path.exists():
        with open(config_path, "rb") as f:
            data = tomllib.load(f)

    # Env var overlay: HOKORA_NODE_NAME, HOKORA_DATA_DIR, etc.
    for field_name, field_info in NodeConfig.model_fields.items():
        env_key = f"HOKORA_{field_name.upper()}"
        env_val = os.environ.get(env_key)
        if env_val is not None:
            # Type-aware coercion for booleans
            if field_info.annotation is bool:
                data[field_name] = env_val.lower().strip() not in _ENV_FALSE_VALUES
            elif field_info.annotation is int:
                data[field_name] = int(env_val)
            elif field_info.annotation is float:
                data[field_name] = float(env_val)
            else:
                data[field_name] = env_val

    config = NodeConfig(**data)

    # Warn about insecure federation configuration
    if config.federation_auto_trust and not config.require_signed_federation:
        logger.warning(
            "SECURITY: federation_auto_trust=True with require_signed_federation=False. "
            "Federation peers will be accepted without signature verification."
        )

    # Warn when relay mode is enabled without propagation — usually an env-var footgun
    if config.relay_only and not config.propagation_enabled:
        logger.warning(
            "relay_only=True but propagation_enabled=False. "
            "Node will relay RNS transport but will NOT store/forward LXMF messages. "
            "If you intended to run a propagation node, set propagation_enabled=true "
            "(or use the --relay-only CLI flag, which sets both)."
        )

    return config

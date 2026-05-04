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
    # Preferred over inline db_key; resolver auto-discovers <data_dir>/db_key when unset.
    db_keyfile: Optional[Path] = None
    rns_config_dir: Optional[Path] = None
    log_level: str = "INFO"
    log_json: bool = False  # JSON-lines output for central aggregators
    log_to_stdout: bool = False  # also write logs to stdout
    announce_enabled: bool = True  # disable for silent/invite-only nodes
    announce_interval: int = 600  # seconds
    # Per-channel announce stagger (ms) — bypasses RNS announce-cap queueing.
    announce_stagger_ms: int = 50
    default_channel_name: str = "general"
    max_sync_limit: int = 100
    retention_days: int = 0  # 0 disables
    metadata_scrub_days: int = 0  # 0 disables; nulls sender_hash after N days
    enable_fts: bool = True
    # Listing visibility only — content access is still membership-gated.
    show_private_channels: bool = True

    # Relay mode — transport + LXMF propagation only, no community subsystems
    relay_only: bool = False
    propagation_enabled: bool = False  # LXMF store-and-forward propagation node
    propagation_storage_mb: int = 500
    propagation_static_peers: list[str] = []  # always-peer dest_hash hex
    propagation_autopeer: bool = True  # auto-discover peers from announces
    propagation_autopeer_maxdepth: int = 4  # max hops for auto-peering
    propagation_max_peers: int = 20  # max concurrent peers

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

    # LXMF inbound
    require_signed_lxmf: bool = True
    lxmf_path_wait_seconds: float = 5.0
    federation_push_retry_interval: int = 60  # seconds between push retry sweeps
    federation_push_max_backoff: int = 600  # max backoff for failed push retries
    # Mirror health-check fallback for missed announces — prevents
    # WAITING_FOR_PATH stalls becoming permanent.
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

    # Liveness — heartbeat file mtime is the cross-runtime liveness signal.
    heartbeat_enabled: bool = True
    heartbeat_interval_s: float = 30.0

    # Loopback HTTP for /health + /api/metrics. Bind address is hard-coded
    # to 127.0.0.1 in core/observability.py — not a TOML field — so a
    # misconfigured config can never expose the surface publicly.
    observability_enabled: bool = True
    observability_port: int = 8421

    def model_post_init(self, __context):
        if self.db_path is None:
            self.db_path = self.data_dir / "hokora.db"
        if self.media_dir is None:
            self.media_dir = self.data_dir / "media"
        if self.identity_dir is None:
            self.identity_dir = self.data_dir / "identities"
        # Auto-discover <data_dir>/db_key if neither key source is set explicitly.
        if (
            self.db_encrypt
            and self.db_keyfile is None
            and self.db_key is None
            and not self.relay_only
        ):
            candidate = self.data_dir / "db_key"
            if candidate.is_file():
                self.db_keyfile = candidate

        # Inline key shape is validated eagerly; keyfile content is resolved on read.
        if self.db_encrypt and self.db_key:
            validate_db_key_hex(self.db_key, source="db_key")

        # Community + encryption requires at least one key source.
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
        """Resolve the SQLCipher master key.

        Order: ``db_encrypt=False`` → None; ``db_keyfile`` → file content;
        inline ``db_key`` → value (with deprecation warning). Errors when
        encryption is on and no source is configured.

        File-mode hygiene: warns when ``db_keyfile`` is looser than 0o600
        but does NOT auto-tighten — the file may be group-readable for a
        deployment reason the daemon doesn't know about; remediation is
        an explicit operator action.
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

    if not config.require_signed_lxmf:
        logger.warning(
            "SECURITY: require_signed_lxmf=False. Inbound LXMF channel "
            "messages from unknown sources will be accepted without "
            "structural sender binding; sender_hash becomes spoofable."
        )

    if config.lxmf_path_wait_seconds < 0:
        config.lxmf_path_wait_seconds = 0.0
    elif config.lxmf_path_wait_seconds > 30:
        logger.warning(
            "lxmf_path_wait_seconds=%.1f is unusually large; clamping to 30s.",
            config.lxmf_path_wait_seconds,
        )
        config.lxmf_path_wait_seconds = 30.0

    # Warn when relay mode is enabled without propagation — usually an env-var footgun
    if config.relay_only and not config.propagation_enabled:
        logger.warning(
            "relay_only=True but propagation_enabled=False. "
            "Node will relay RNS transport but will NOT store/forward LXMF messages. "
            "If you intended to run a propagation node, set propagation_enabled=true "
            "(or use the --relay-only CLI flag, which sets both)."
        )

    return config

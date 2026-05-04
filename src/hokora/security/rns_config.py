# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure-function read/validate/write for the daemon's RNS config file.

Seed management is filesystem-authored: helpers mutate the config file
on disk, then the operator restarts the daemon so RNS re-reads it.
``SYNC_LIST_SEEDS`` is the only sync-protocol surface; no daemon RPC
mutates transport config.

Invariants: parse via ``RNS.vendor.configobj.ConfigObj`` (same parser
Reticulum uses at startup); atomic 0o600 writes via
``security.fs.write_secure``; ``config.prev`` rollback copy before
every mutation; comments are preserved across round-trip; ``list_seeds``
filters down to outbound client interfaces.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from RNS.vendor.configobj import ConfigObj

from hokora.security.fs import write_secure

logger = logging.getLogger(__name__)


# RNS section-name for the top-level interfaces container.
_INTERFACES_SECTION = "interfaces"

# RNS type string → our simplified seed-type label.
_SEED_TYPES = {
    "TCPClientInterface": "tcp",
    "I2PInterface": "i2p",
}

# Reverse mapping for writes.
_RNS_TYPES = {v: k for k, v in _SEED_TYPES.items()}


class SeedConfigError(Exception):
    """Raised for any failure in validate/add/remove paths."""


class SeedNotFound(SeedConfigError):
    """Raised when a remove target has no matching section."""


class DuplicateSeed(SeedConfigError):
    """Raised when an add target collides with an existing section name."""


class InvalidSeed(SeedConfigError):
    """Raised when a seed entry fails validation."""


@dataclass(frozen=True)
class SeedEntry:
    """Canonical seed representation; ``target_port`` is 0 for I2P."""

    name: str
    type: str
    target_host: str
    target_port: int = 0
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


def _resolve_config_path(rns_config_dir: Optional[Path]) -> Path:
    """Given a Reticulum config directory, return the ``config`` file path."""
    if rns_config_dir is None:
        # RNS default — matches Reticulum.__init__ fallback.
        return Path.home() / ".reticulum" / "config"
    return Path(rns_config_dir) / "config"


def _load_configobj(config_path: Path) -> ConfigObj:
    """Parse the RNS config; missing file yields an empty ConfigObj,
    malformed file raises :class:`SeedConfigError` with parse context."""
    if not config_path.exists():
        return ConfigObj()
    try:
        return ConfigObj(str(config_path))
    except Exception as exc:
        raise SeedConfigError(f"Failed to parse {config_path}: {exc}") from exc


def _parse_entry(name: str, section: dict) -> Optional[SeedEntry]:
    """Convert an RNS interface section into a SeedEntry, or None if
    this interface isn't a seed (e.g., server/auto/rnode)."""
    rns_type = section.get("type", "")
    seed_type = _SEED_TYPES.get(rns_type)
    if seed_type is None:
        return None

    enabled_raw = str(section.get("enabled", "yes")).strip().lower()
    enabled = enabled_raw in ("yes", "true", "1", "on")

    if seed_type == "tcp":
        target_host = str(section.get("target_host", "")).strip()
        try:
            target_port = int(section.get("target_port", "0"))
        except (TypeError, ValueError):
            target_port = 0
        if not target_host or target_port <= 0:
            # Not a valid outbound TCP seed — skip rather than surface as broken.
            return None
        return SeedEntry(
            name=name,
            type="tcp",
            target_host=target_host,
            target_port=target_port,
            enabled=enabled,
        )

    # I2P seeds are identified by a ``peers`` attribute.
    peers_raw = section.get("peers")
    if not peers_raw:
        return None
    # RNS accepts comma-separated peers; surface the first as canonical.
    first_peer = str(peers_raw).split(",")[0].strip()
    if not first_peer:
        return None
    return SeedEntry(
        name=name,
        type="i2p",
        target_host=first_peer,
        target_port=0,
        enabled=enabled,
    )


def list_seeds(rns_config_dir: Optional[Path]) -> list[SeedEntry]:
    """Return seed entries from the RNS config; non-seed interfaces filtered out."""
    config_path = _resolve_config_path(rns_config_dir)
    co = _load_configobj(config_path)
    interfaces = co.get(_INTERFACES_SECTION)
    if not interfaces:
        return []
    result: list[SeedEntry] = []
    for name in interfaces.keys():
        section = interfaces[name]
        if not isinstance(section, dict):
            continue
        entry = _parse_entry(name, section)
        if entry is not None:
            result.append(entry)
    return result


def validate_seed_entry(entry: SeedEntry) -> None:
    """Pure structural validator; collision check is done separately in ``apply_add``."""
    if not entry.name or not entry.name.strip():
        raise InvalidSeed("Seed name must be non-empty")
    if "[" in entry.name or "]" in entry.name:
        # ConfigObj section headers use brackets; embedding them in a
        # section name corrupts the round-trip.
        raise InvalidSeed("Seed name cannot contain '[' or ']'")
    if entry.type not in _RNS_TYPES:
        raise InvalidSeed(f"Unsupported seed type {entry.type!r}; expected tcp or i2p")
    if not entry.target_host or not entry.target_host.strip():
        raise InvalidSeed("Seed target_host must be non-empty")
    if entry.type == "tcp":
        if not (1 <= entry.target_port <= 65535):
            raise InvalidSeed(f"TCP seed port out of range (1..65535): {entry.target_port}")
        if entry.target_host.endswith(".i2p") or entry.target_host.endswith(".b32.i2p"):
            raise InvalidSeed("I2P address with type=tcp — drop the port and set type=i2p")
    elif entry.type == "i2p":
        if entry.target_port != 0:
            raise InvalidSeed("I2P seeds must not carry a port")
        if not (entry.target_host.endswith(".i2p") or entry.target_host.endswith(".b32.i2p")):
            raise InvalidSeed("I2P target_host must end with .i2p or .b32.i2p")


def _backup_existing(config_path: Path) -> None:
    """Atomic 0o600 copy to ``config.prev``; no-op if the current config doesn't exist."""
    if not config_path.exists():
        return
    try:
        content = config_path.read_text()
    except OSError as exc:
        raise SeedConfigError(f"Cannot read {config_path} for backup: {exc}") from exc
    backup_path = config_path.with_suffix(config_path.suffix + ".prev")
    write_secure(backup_path, content, mode=0o600)
    logger.debug("RNS config backed up to %s", backup_path)


def _render_configobj(co: ConfigObj) -> str:
    """Serialize a ConfigObj to string with RNS's standard format."""
    buf = io.BytesIO()
    co.write(buf)
    return buf.getvalue().decode("utf-8")


def _write_config(config_path: Path, co: ConfigObj) -> None:
    """Atomically write ``co`` to ``config_path`` at 0o600 with a prior backup."""
    _backup_existing(config_path)
    rendered = _render_configobj(co)
    write_secure(config_path, rendered, mode=0o600)
    logger.info("RNS config updated at %s", config_path)


def apply_add(rns_config_dir: Optional[Path], entry: SeedEntry) -> None:
    """Add ``entry`` to the RNS config; daemon restart required to apply.

    Raises :class:`DuplicateSeed` on name collision, :class:`InvalidSeed`
    on structural problems.
    """
    validate_seed_entry(entry)
    config_path = _resolve_config_path(rns_config_dir)
    co = _load_configobj(config_path)

    interfaces = co.setdefault(_INTERFACES_SECTION, {})
    if entry.name in interfaces:
        raise DuplicateSeed(f"Seed {entry.name!r} already exists in {config_path}")

    section: dict[str, str] = {
        "type": _RNS_TYPES[entry.type],
        "enabled": "yes" if entry.enabled else "no",
    }
    if entry.type == "tcp":
        section["target_host"] = entry.target_host
        section["target_port"] = str(entry.target_port)
    else:  # i2p
        section["peers"] = entry.target_host

    interfaces[entry.name] = section
    _write_config(config_path, co)


def apply_remove(rns_config_dir: Optional[Path], name: str) -> None:
    """Remove a seed section by name; refuses to delete non-seed interfaces.

    Raises :class:`SeedNotFound` for missing/non-seed targets.
    """
    if not name or not name.strip():
        raise InvalidSeed("Seed name must be non-empty")
    config_path = _resolve_config_path(rns_config_dir)
    co = _load_configobj(config_path)

    interfaces = co.get(_INTERFACES_SECTION)
    if not interfaces or name not in interfaces:
        raise SeedNotFound(f"No seed named {name!r} in {config_path}")

    section = interfaces[name]
    if not isinstance(section, dict):
        raise SeedNotFound(f"{name!r} exists but is not a seed section")

    # Server / rnode interfaces need operator judgement; not deletable here.
    rns_type = section.get("type", "")
    if rns_type not in _RNS_TYPES.values():
        raise SeedNotFound(
            f"Interface {name!r} is type {rns_type!r}; not a seed — edit config manually"
        )

    del interfaces[name]
    _write_config(config_path, co)


def validate_config_file(rns_config_dir: Optional[Path]) -> list[str]:
    """Return a list of structural issues; empty list means OK.

    Non-seed interfaces are skipped — we can't validate RNode/Auto without RNS.
    """
    config_path = _resolve_config_path(rns_config_dir)
    issues: list[str] = []
    if not config_path.exists():
        return [f"RNS config not found at {config_path}"]
    try:
        co = ConfigObj(str(config_path))
    except Exception as exc:
        return [f"Parse error: {exc}"]
    interfaces = co.get(_INTERFACES_SECTION, {}) or {}
    for name in interfaces.keys():
        section = interfaces[name]
        if not isinstance(section, dict):
            issues.append(f"[{name}] is not a section")
            continue
        rns_type = section.get("type")
        if rns_type not in _RNS_TYPES:
            continue  # Non-seed interface — skip validation.
        entry = _parse_entry(name, section)
        if entry is None:
            issues.append(f"[{name}] type={rns_type} but target fields are missing or invalid")
            continue
        try:
            validate_seed_entry(entry)
        except InvalidSeed as exc:
            issues.append(f"[{name}]: {exc}")
    return issues

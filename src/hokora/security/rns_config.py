# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure-function read/validate/write for the daemon's RNS config file.

Seed management is **filesystem-authored**: the operator (or the TUI
running as the operator's UID) mutates the daemon's RNS config file
via these helpers, then restarts the daemon so RNS re-reads the file
at startup. No daemon RPC mutates transport config; the read path
(``SYNC_LIST_SEEDS``) is the only sync-protocol surface.

Design invariants:

* **RNS's own parser is the source of truth.** Reads and writes go
  through ``RNS.vendor.configobj.ConfigObj`` — the same parser
  Reticulum will use at startup. Validation that succeeds here can't
  disagree with what the daemon sees post-restart.
* **Atomic writes, 0o600.** Reuse :func:`hokora.security.fs.write_secure`
  so the target never exists at a looser permission than requested, and a
  mid-write crash can't leave a half-written config.
* **Backup before mutate.** Every mutating call copies the current config
  to ``config.prev`` (also 0o600, atomic) before overwriting. Operators
  who accidentally brick their RNS config can ``mv config.prev config``
  to roll back.
* **Comment preservation.** ConfigObj preserves top-level, section, and
  inline comments across a round-trip — operator annotations survive.
* **Seeds only.** ``list_seeds`` filters the ``[interfaces]`` section
  down to outbound client interfaces (``TCPClientInterface`` and
  ``I2PInterface`` with a ``peers`` attribute). Server interfaces,
  ``AutoInterface``, ``RNodeInterface`` etc. are ignored — they're
  transport primitives, not seed-node connections.
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
    """Canonical seed representation.

    ``name`` is the RNS ``[[Section Name]]`` — operator-chosen label,
    unique within the config. ``type`` is ``"tcp"`` or ``"i2p"``.
    ``target_host`` is the hostname/IP (TCP) or ``.b32.i2p`` address
    (I2P). ``target_port`` is the TCP port; for I2P it is always 0.
    ``enabled`` reflects the RNS ``enabled`` flag.
    """

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
    """Parse the RNS config at ``config_path``.

    Missing file → an empty ConfigObj the caller can populate. Malformed
    file → ``SeedConfigError`` (re-raised from ConfigObj's parse error,
    with context).
    """
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

    # I2P: outbound interfaces carry a ``peers`` attribute with one or more
    # destination addresses. Endpoints without ``peers`` are not seeds.
    peers_raw = section.get("peers")
    if not peers_raw:
        return None
    # RNS accepts comma-separated peers; we surface the first as the
    # canonical seed address. Multi-peer I2P interfaces are out of scope
    # for this phase and must be edited by hand.
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
    """Return the seed entries currently present in the RNS config.

    Filters out non-seed interfaces (``TCPServerInterface``,
    ``AutoInterface``, ``RNodeInterface``, I2P endpoints without
    ``peers``). Missing config file → empty list.
    """
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
    """Raise :class:`InvalidSeed` if the entry is malformed.

    Does not consult the existing config — that's a collision check,
    performed separately inside :func:`apply_add`. This is a pure
    per-entry structural validator.
    """
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
    """Copy the current config to ``config.prev`` atomically, 0o600.

    No-op if the current config doesn't exist yet (first seed add on a
    fresh node).
    """
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
    """Add ``entry`` to the RNS config.

    Raises :class:`DuplicateSeed` if a section with the same name already
    exists, :class:`InvalidSeed` for structural problems. On success the
    caller must restart the daemon to apply.
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
    """Remove the seed section named ``name`` from the RNS config.

    Raises :class:`SeedNotFound` if no matching section exists, or if the
    matching section is not a seed (e.g., a server interface — operator
    should edit manually rather than delete via this path).
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

    # Refuse to remove non-seed interfaces via this path — server
    # interfaces and rnode interfaces need operator judgement.
    rns_type = section.get("type", "")
    if rns_type not in _RNS_TYPES.values():
        raise SeedNotFound(
            f"Interface {name!r} is type {rns_type!r}; not a seed — edit config manually"
        )

    del interfaces[name]
    _write_config(config_path, co)


def validate_config_file(rns_config_dir: Optional[Path]) -> list[str]:
    """Parse the current RNS config and return a list of issues.

    Intended for ``hokora config validate-rns``. Empty list means the
    config parses and every seed-shaped interface is structurally sound.
    Non-seed interfaces are ignored — we can't validate RNode serial
    ports or AutoInterface scopes without running RNS itself.
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

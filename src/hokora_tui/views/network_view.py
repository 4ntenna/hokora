# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Network tab — connection status, seed nodes, announce configuration.

Seed management:

The Network tab reads the TUI's own RNS config file directly to
display seeds, and mutates that same file in-process via
:mod:`hokora.security.rns_config`. This works in every topology
(standalone TUI, local daemon-attached TUI, remote daemon-attached
TUI) because the TUI always has filesystem access to its own RNS
config — the file ``RNS.Reticulum(configdir=...)`` was constructed
against at startup. The ``SYNC_LIST_SEEDS`` sync action remains
defined for callers that want a daemon's seed list over the wire
(e.g. web dashboard, admin-over-RNS tooling), but the Network tab no
longer routes through it.

Apply behaviour is topology-aware:

* **Daemon-attached** (local ``hokorad.pid`` points at a live process):
  shell to ``hokora seed apply --restart`` so the supervisor respawns
  the daemon. TUI's ``LocalClientInterface`` auto-reattaches.
* **Standalone TUI** (no live daemon): display "Restart TUI to
  apply" — the TUI owns its own Reticulum and must be restarted to
  pick up the new config.
* **Remote daemon-attached** (TUI connected via RNS Link to a daemon
  on a different host): display "Config saved to your local RNS.
  Restart TUI to apply." The edit only affects this TUI's transport,
  not the remote daemon's.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import urwid

from hokora.security import rns_config
from hokora_tui.widgets.confirm_dialog import ConfirmDialog
from hokora_tui.widgets.hokora_button import HokoraButton

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Preset:
    name: str
    host: str
    port: int


# Curated quick-connect targets surfaced in the Network tab. Empty list
# hides the presets section; add entries here to surface them.
_PRESETS: list[_Preset] = []


def _parse_address(raw: str) -> tuple[str, int, str, Optional[str]]:
    """Normalise a user-typed seed address into ``(host, port, type, error)``.

    Same semantics as :func:`parse_seed_input` but returns the seed-type
    label (``"tcp"`` or ``"i2p"``) expected by :class:`rns_config.SeedEntry`
    rather than a display label. ``error`` is a user-readable message
    when input is invalid; ``host`` is empty in that case.
    """
    host, port, _label, err = parse_seed_input(raw)
    if err is not None:
        return "", 0, "", err
    seed_type = "i2p" if host.endswith(".i2p") or host.endswith(".b32.i2p") else "tcp"
    return host, port, seed_type, None


def _detect_local_daemon_pid() -> Optional[int]:
    """Return the PID of a live local daemon, or None if none is running.

    Mirrors ``cli/seed.py::_discover_running_daemon_pid`` — globs for
    ``~/.hokora*/hokorad.pid`` and returns the first live PID. Used by
    the Apply button to pick between "restart daemon" and "restart TUI"
    affordances.
    """
    for pid_path in sorted(Path.home().glob(".hokora*/hokorad.pid")):
        try:
            pid = int(pid_path.read_text().strip())
        except (OSError, ValueError):
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            # Process alive, owned by another user — not ours to restart.
            continue
        except OSError:
            continue
        return pid
    return None


def parse_seed_input(addr: str) -> tuple[str, int, str, str | None]:
    """Normalize a user-typed seed-node address.

    Accepts TCP forms ``host``, ``host:port``, ``1.2.3.4:4242`` and I2P
    forms ``*.b32.i2p`` / ``*.i2p``. Returns
    ``(host, port, label, error)`` where ``error`` is a user-readable
    message if input is invalid; in that case ``host`` is empty.

    Port defaults to 4242 for a bare TCP hostname. I2P addresses use
    ``port=0`` as a sentinel (they do not take a port).
    """
    addr = addr.strip()
    if not addr:
        return "", 0, "", "Enter host:port (TCP) or address.b32.i2p (I2P)"

    # Check for I2P intent on the host portion (before any colon).
    # Users sometimes type `foo.b32.i2p:4242` expecting TCP-over-port — reject it.
    host_portion = addr.rpartition(":")[0] or addr
    looks_like_i2p = (
        addr.endswith(".b32.i2p")
        or addr.endswith(".i2p")
        or host_portion.endswith(".b32.i2p")
        or host_portion.endswith(".i2p")
    )

    if looks_like_i2p:
        if ":" in addr:
            return "", 0, "", "I2P addresses do not take a port"
        return addr, 0, f"I2P {addr[:20]}", None

    if ":" in addr:
        host, _, port_str = addr.rpartition(":")
        if not host:
            return "", 0, "", "Missing host before ':'"
        try:
            port = int(port_str)
        except ValueError:
            return "", 0, "", f"Invalid port: {port_str!r}"
        if not (1 <= port <= 65535):
            return "", 0, "", f"Port out of range (1..65535): {port}"
        return host, port, f"Seed {host}:{port}", None

    # Bare hostname or IP — default RNS TCP port
    return addr, 4242, f"Seed {addr}:4242", None


class NetworkView:
    """Network configuration and monitoring view.

    Layout::

        Pile [
            LineBox("Connection") [
                connection_status_text  (Connected/Disconnected)
                uptime_text
                link_count_text
                [Disconnect] button
            ]

            LineBox("Seed Nodes") [
                ListBox of current seed nodes
                Columns [add_edit | [Add] button]
            ]

            LineBox("Announce Configuration") [
                Columns ["Auto-announce:" toggle | "Interval:" int_edit "s"]
                [Announce Now] button
            ]
        ]
    """

    def __init__(self, app: HokoraTUI) -> None:
        self.app = app
        self._connect_time: float | None = None
        # Seeds reported by the daemon via SYNC_LIST_SEEDS. Populated
        # on tab activation and refreshed after every successful
        # add/remove subprocess call. List of dicts from the daemon,
        # each with keys: name, type, target_host, target_port, enabled.
        self._seeds: list[dict] = []
        # Whether add/remove was attempted since the last successful
        # daemon restart. Drives the "Apply (restart daemon)" prompt.
        self._pending_restart: bool = False

        # --- RNS Transport Status section ---
        self._rns_status_text = urwid.Text(("default", "RNS: Checking..."))
        self._rns_interfaces_walker = urwid.SimpleFocusListWalker([])
        self._rns_interfaces_list = urwid.ListBox(self._rns_interfaces_walker)
        self._rns_interfaces_box = urwid.BoxAdapter(self._rns_interfaces_list, height=4)

        rns_pile = urwid.Pile([self._rns_status_text, urwid.Divider(), self._rns_interfaces_box])
        rns_box = urwid.LineBox(rns_pile, title="RNS Transport")

        # --- Connection section ---
        self._status_text = urwid.Text(("status_disconnected", "\u25cb Disconnected"))
        self._uptime_text = urwid.Text(("default", "Uptime: --"))
        self._link_count_text = urwid.Text(("default", "Links: 0"))
        self._disconnect_btn = urwid.AttrMap(
            HokoraButton("Disconnect", on_press=lambda _: self._do_disconnect()),
            "button_normal",
            "button_focus",
        )

        connection_pile = urwid.Pile(
            [
                self._status_text,
                self._uptime_text,
                self._link_count_text,
                urwid.Divider(),
                self._disconnect_btn,
            ]
        )
        connection_box = urwid.LineBox(connection_pile, title="Connection")

        # --- Seed Nodes section ---
        self._seed_walker = urwid.SimpleFocusListWalker([])
        self._seed_listbox = urwid.ListBox(self._seed_walker)
        self._seed_listbox_box = urwid.BoxAdapter(self._seed_listbox, height=5)

        # Add row: separate name + address inputs. Name is operator-chosen
        # (becomes the RNS [[Section]] header), address is host:port or
        # .b32.i2p.
        self._name_edit = urwid.Edit(("input_prompt", "Name > "))
        self._addr_edit = urwid.Edit(("input_prompt", "Host:Port / .b32.i2p > "))
        self._add_btn = urwid.AttrMap(
            HokoraButton("Add", on_press=lambda _: self._add_seed_node()),
            "button_normal",
            "button_focus",
        )
        add_row = urwid.Columns(
            [
                ("weight", 2, urwid.AttrMap(self._name_edit, "input_text")),
                ("weight", 3, urwid.AttrMap(self._addr_edit, "input_text")),
                ("pack", self._add_btn),
            ]
        )

        # Apply-changes button: visible text updated via _refresh_apply_button
        # based on whether add/remove has been attempted since last restart.
        self._apply_btn = urwid.AttrMap(
            HokoraButton(
                "Apply (restart daemon)",
                on_press=lambda _: self._apply_changes(),
            ),
            "button_normal",
            "button_focus",
        )
        self._apply_status = urwid.Text(("default", ""))

        preset_buttons = [
            urwid.AttrMap(
                HokoraButton(
                    f"{p.name} ({p.host}:{p.port})",
                    on_press=lambda _btn, p=p: self._add_preset(p.name, p.host, p.port),
                ),
                "button_normal",
                "button_focus",
            )
            for p in _PRESETS
        ]

        seed_pile_items: list = [
            self._seed_listbox_box,
            urwid.Divider(),
            add_row,
            urwid.Divider(),
            urwid.Columns(
                [
                    ("pack", self._apply_btn),
                    ("pack", urwid.Text("  ")),
                    ("weight", 1, self._apply_status),
                ]
            ),
        ]
        if preset_buttons:
            seed_pile_items.append(urwid.Divider())
            seed_pile_items.append(urwid.Text(("category_header", " Quick Connect Presets:")))
            seed_pile_items.extend(preset_buttons)
        seed_pile = urwid.Pile(seed_pile_items)
        seed_box = urwid.LineBox(seed_pile, title="Seed Nodes")

        # --- Announce Configuration section ---
        self._auto_announce_label = urwid.Text(("default", "Auto-announce: OFF"))
        self._auto_toggle_btn = urwid.AttrMap(
            HokoraButton("Toggle", on_press=lambda _: self._toggle_auto_announce()),
            "button_normal",
            "button_focus",
        )

        self._interval_edit = urwid.IntEdit(
            ("input_prompt", "Interval (s): "),
            default=self.app.state.announce_interval,
        )
        self._interval_apply_btn = urwid.AttrMap(
            HokoraButton("Apply", on_press=lambda _: self._apply_interval()),
            "button_normal",
            "button_focus",
        )

        self._announce_now_btn = urwid.AttrMap(
            HokoraButton("Announce Now", on_press=lambda _: self._do_announce_now()),
            "button_normal",
            "button_focus",
        )

        announce_row1 = urwid.Columns(
            [
                ("pack", self._auto_announce_label),
                ("pack", urwid.Text("  ")),
                ("pack", self._auto_toggle_btn),
                ("pack", urwid.Text("    ")),
                ("weight", 1, urwid.AttrMap(self._interval_edit, "input_text")),
                ("pack", self._interval_apply_btn),
            ]
        )

        announce_pile = urwid.Pile(
            [
                announce_row1,
                urwid.Divider(),
                self._announce_now_btn,
            ]
        )
        announce_box = urwid.LineBox(announce_pile, title="Announce Configuration")

        # --- Main layout ---
        self.widget = urwid.Filler(
            urwid.Pile(
                [
                    ("pack", rns_box),
                    ("pack", urwid.Divider()),
                    ("pack", connection_box),
                    ("pack", urwid.Divider()),
                    ("pack", seed_box),
                    ("pack", urwid.Divider()),
                    ("pack", announce_box),
                ]
            ),
            valign="top",
        )

        # Subscribe to state events
        app.state.on("connection_changed", lambda _=None: self._refresh_connection())

        # Initial state: seed list is populated by a direct filesystem
        # read against the TUI's own RNS config dir, not via a sync
        # action round-trip — works in every topology.
        self._load_seeds_from_disk()
        self._refresh_rns_interfaces()
        self._refresh_connection()
        self._refresh_seed_nodes()
        self._refresh_announce_state()

    def on_activate(self) -> None:
        """Called when this tab becomes active."""
        self._load_seeds_from_disk()
        self._refresh_rns_interfaces()
        self._refresh_connection()
        self._refresh_seed_nodes()

    def update(self):
        """Called periodically by refresh job."""
        self._refresh_rns_interfaces()
        self._refresh_connection()

    def _refresh_rns_interfaces(self) -> None:
        """Show active RNS transport interfaces with actual online status."""
        self._rns_interfaces_walker.clear()
        try:
            import RNS

            if self.app._reticulum is None:
                self._rns_status_text.set_text(("status_disconnected", "RNS: Not initialized"))
                self._rns_interfaces_walker.append(
                    urwid.Text(("default", "  Use 'Add Seed Node' below to connect."))
                )
                return

            interfaces = getattr(RNS.Transport, "interfaces", [])

            if not interfaces:
                self._rns_status_text.set_text(
                    ("status_connecting", "\u25cc RNS: No interfaces active")
                )
                self._rns_interfaces_walker.append(
                    urwid.Text(("default", "  Add a seed node to connect to the network."))
                )
                return

            # Count actual online status per interface
            total = len(interfaces)
            online_count = sum(1 for iface in interfaces if getattr(iface, "online", False))

            # Seed names for informational context
            seed_names = [str(s.get("name", "")) for s in self._seeds if s.get("name")]
            context = f" \u2014 {', '.join(seed_names)}" if seed_names else ""

            # Build status line based on actual online count
            if online_count > 0:
                self._rns_status_text.set_text(
                    (
                        "status_connected",
                        f"\u25cf Connected ({online_count}/{total} interfaces online){context}",
                    )
                )
            else:
                self._rns_status_text.set_text(
                    (
                        "status_disconnected",
                        f"\u25cb Disconnected (0/{total} online){context}",
                    )
                )

            # Show individual interfaces
            for iface in interfaces:
                name = getattr(iface, "name", type(iface).__name__)
                online = getattr(iface, "online", False)
                target_ip = getattr(iface, "target_ip", None)
                target_port = getattr(iface, "target_port", None)
                status_icon = "\u25cf" if online else "\u25cb"
                attr = "status_connected" if online else "status_disconnected"

                detail = ""
                if target_ip and target_port:
                    detail = f" \u2192 {target_ip}:{target_port}"

                self._rns_interfaces_walker.append(
                    urwid.Text((attr, f"  {status_icon} {name}{detail}"))
                )

            # If using shared instance, note the seed connections from the daemon
            if not any(getattr(i, "target_ip", None) for i in interfaces):
                if seed_names:
                    self._rns_interfaces_walker.append(
                        urwid.Text(("status_info", "  (Connected via shared RNS instance)"))
                    )

        except ImportError:
            self._rns_status_text.set_text(("status_disconnected", "RNS: Not installed"))

    def _add_preset(self, name: str, host: str, port: int) -> None:
        """Add a preset seed in-process (no subprocess)."""
        entry = rns_config.SeedEntry(
            name=name, type="tcp", target_host=host, target_port=port, enabled=True
        )
        self._apply_seed_mutation("add", entry=entry)

    def _refresh_connection(self) -> None:
        """Update connection status display from app state."""
        status = self.app.state.connection_status
        node_name = self.app.state.connected_node_name

        if status == "connected":
            suffix = f" to {node_name}" if node_name else ""
            self._status_text.set_text(("status_connected", f"\u25cf Connected{suffix}"))
            if self._connect_time is None:
                self._connect_time = time.time()
            uptime = int(time.time() - self._connect_time)
            h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
            self._uptime_text.set_text(("default", f"Uptime: {h}h {m}m {s}s"))
        elif status == "connecting":
            self._status_text.set_text(("status_connecting", "\u25cc Connecting..."))
            self._uptime_text.set_text(("default", "Uptime: --"))
        else:
            self._status_text.set_text(("status_disconnected", "\u25cb Disconnected"))
            self._uptime_text.set_text(("default", "Uptime: --"))
            self._connect_time = None

        # Link count from sync engine
        link_count = self.app.sync_engine.link_count() if self.app.sync_engine else 0
        self._link_count_text.set_text(("default", f"Links: {link_count}"))

    def _do_disconnect(self) -> None:
        """Disconnect from current node — confirm-gated to prevent stray clicks."""
        confirm_pref = "true"
        if self.app.db is not None:
            confirm_pref = self.app.db.get_setting("confirm_destructive_actions") or "true"

        def _go() -> None:
            self.app.handle_command("/disconnect")
            self._refresh_connection()
            self.app._schedule_redraw()

        if confirm_pref == "false":
            _go()
            return

        node_name = self.app.state.connected_node_name or "the current node"
        ConfirmDialog.show(
            self.app,
            f"Disconnect from {node_name}?",
            on_confirm=_go,
        )

    # --- Seed Nodes ---

    def _load_seeds_from_disk(self) -> None:
        """Populate ``self._seeds`` from the TUI's own RNS config file.

        Direct filesystem read. Works in every topology — standalone
        TUI, local daemon-attached, remote daemon-attached — because
        the TUI always has filesystem access to its own RNS config dir
        (the one ``RNS.Reticulum(configdir=...)`` was built against).
        The ``rns_config_dir`` attribute is set by ``app._init_rns``;
        ``None`` means RNS default (~/.reticulum),
        which :func:`rns_config.list_seeds` resolves correctly.
        """
        rns_dir = getattr(self.app, "_rns_config_dir", None)
        try:
            entries = rns_config.list_seeds(rns_dir)
        except rns_config.SeedConfigError as exc:
            logger.warning("Failed to read RNS config for seed list: %s", exc)
            self._seeds = []
            self.app.status.set_notice(
                f"Reading RNS config failed: {exc}",
                level="error",
                duration=6.0,
            )
            return
        self._seeds = [e.to_dict() for e in entries]

    def _refresh_seed_nodes(self) -> None:
        """Rebuild the seed nodes list display from ``self._seeds``."""
        self._seed_walker.clear()
        if not self._seeds:
            self._seed_walker.append(
                urwid.Text(("default", "  No seeds configured. Use the Add row below."))
            )
            self._refresh_apply_status()
            return

        for node in self._seeds:
            name = str(node.get("name", ""))
            seed_type = str(node.get("type", "tcp"))
            host = str(node.get("target_host", ""))
            port = int(node.get("target_port", 0) or 0)
            enabled = bool(node.get("enabled", True))
            addr = host if seed_type == "i2p" or not port else f"{host}:{port}"
            state = "" if enabled else " [disabled]"

            remove_btn = urwid.AttrMap(
                HokoraButton(
                    "Remove",
                    on_press=lambda _, n=name: self._remove_seed_node(n),
                ),
                "button_normal",
                "button_focus",
            )
            row = urwid.Columns(
                [
                    (
                        "weight",
                        3,
                        urwid.Text(
                            (
                                "node_name",
                                f"  {name} ({seed_type}://{addr}){state}",
                            )
                        ),
                    ),
                    ("pack", remove_btn),
                ]
            )
            self._seed_walker.append(row)
        self._refresh_apply_status()

    def _apply_mode(self) -> str:
        """Return the applicable apply mode for the current topology.

        * ``"daemon"`` — local ``hokorad.pid`` points at a live process;
          restart the daemon via ``hokora seed apply --restart`` pathway.
        * ``"standalone"`` — no live daemon on this host; user must
          restart the TUI process to pick up the new config.
        * ``"remote"`` — TUI is attached via sync_engine to a daemon on
          another host (heuristic: no local daemon pid but sync link
          active). Config change affects only this TUI's local RNS.
        """
        if _detect_local_daemon_pid() is not None:
            return "daemon"
        engine = getattr(self.app, "sync_engine", None)
        if engine is not None:
            try:
                if engine.link_count() > 0:
                    return "remote"
            except Exception:
                logger.debug("link_count probe failed", exc_info=True)
        return "standalone"

    def _refresh_apply_status(self) -> None:
        """Update the 'apply changes' hint text."""
        if not self._pending_restart:
            self._apply_status.set_text(("default", ""))
            return
        mode = self._apply_mode()
        if mode == "daemon":
            text = "Changes pending — restart daemon to apply"
        elif mode == "remote":
            text = "Changes pending — restart TUI to apply (affects only this TUI)"
        else:
            text = "Changes pending — restart TUI to apply"
        self._apply_status.set_text(("status_connecting", text))

    def _apply_seed_mutation(
        self,
        op: str,
        entry: Optional[rns_config.SeedEntry] = None,
        name: Optional[str] = None,
    ) -> None:
        """Apply an add/remove against the TUI's local RNS config in-process.

        Wraps :mod:`hokora.security.rns_config` with the same atomic
        write + 0o600 + ``config.prev`` backup used by ``hokora seed``.
        Post-mutation, the ``_pending_restart`` flag is set so the user
        is prompted to apply via the topology-appropriate restart.
        """
        rns_dir = getattr(self.app, "_rns_config_dir", None)
        try:
            if op == "add":
                assert entry is not None
                rns_config.validate_seed_entry(entry)
                rns_config.apply_add(rns_dir, entry)
                addr = (
                    f"{entry.target_host}:{entry.target_port}"
                    if entry.type == "tcp"
                    else entry.target_host
                )
                self.app.status.set_notice(
                    f"Added seed {entry.name!r} ({entry.type} -> {addr})",
                    level="info",
                    duration=5.0,
                )
            elif op == "remove":
                assert name is not None
                rns_config.apply_remove(rns_dir, name)
                self.app.status.set_notice(f"Removed seed {name!r}", level="info", duration=5.0)
            else:
                raise ValueError(f"Unknown seed mutation op: {op!r}")
        except rns_config.InvalidSeed as exc:
            self.app.status.set_notice(f"Invalid seed: {exc}", level="error", duration=6.0)
            self.app._schedule_redraw()
            return
        except rns_config.DuplicateSeed as exc:
            self.app.status.set_notice(str(exc), level="error", duration=6.0)
            self.app._schedule_redraw()
            return
        except rns_config.SeedNotFound as exc:
            self.app.status.set_notice(str(exc), level="error", duration=6.0)
            self.app._schedule_redraw()
            return
        except rns_config.SeedConfigError as exc:
            self.app.status.set_notice(
                f"Updating RNS config failed: {exc}",
                level="error",
                duration=6.0,
            )
            self.app._schedule_redraw()
            return

        self._pending_restart = True
        self._load_seeds_from_disk()
        self._refresh_seed_nodes()
        self._refresh_rns_interfaces()
        self.app._schedule_redraw()

    def _add_seed_node(self) -> None:
        """Add a seed in-process from the Name + Address edit widgets."""
        name = self._name_edit.get_edit_text().strip()
        addr = self._addr_edit.get_edit_text().strip()
        if not name:
            self.app.status.set_notice(
                "Seed name required (free-form label).",
                level="warn",
            )
            self.app._schedule_redraw()
            return
        if not addr:
            self.app.status.set_notice(
                "Address required (host:port or .b32.i2p).",
                level="warn",
            )
            self.app._schedule_redraw()
            return
        host, port, seed_type, err = _parse_address(addr)
        if err is not None:
            self.app.status.set_notice(str(err), level="error", duration=5.0)
            self.app._schedule_redraw()
            return
        entry = rns_config.SeedEntry(
            name=name,
            type=seed_type,
            target_host=host,
            target_port=port,
            enabled=True,
        )
        self._apply_seed_mutation("add", entry=entry)
        self._name_edit.set_edit_text("")
        self._addr_edit.set_edit_text("")

    def _remove_seed_node(self, name: str) -> None:
        """Remove a seed in-process by section name — confirm-gated."""
        if not name:
            return

        confirm_pref = "true"
        if self.app.db is not None:
            confirm_pref = self.app.db.get_setting("confirm_destructive_actions") or "true"

        if confirm_pref == "false":
            self._apply_seed_mutation("remove", name=name)
            return

        ConfirmDialog.show(
            self.app,
            f"Remove seed {name!r} from RNS config?",
            on_confirm=lambda: self._apply_seed_mutation("remove", name=name),
        )

    def _apply_changes(self) -> None:
        """Apply pending changes by restarting the appropriate process.

        Daemon-attached mode: signal the local daemon (same behaviour
        as ``hokora seed apply --restart``). Confirm-gated since
        SIGTERM on the daemon is operator-visible. Standalone or
        remote-daemon mode: ask the user to restart the TUI themselves
        — we never kill a process we don't own, and we don't try to
        re-initialise ``RNS.Reticulum()`` in-process (that requires
        upstream detach-safety support that isn't in place yet).
        """
        mode = self._apply_mode()
        if mode != "daemon":
            self._apply_changes_no_daemon(mode)
            return

        confirm_pref = "true"
        if self.app.db is not None:
            confirm_pref = self.app.db.get_setting("confirm_destructive_actions") or "true"

        if confirm_pref == "false":
            self._restart_daemon()
            return

        ConfirmDialog.show(
            self.app,
            "Restart the local daemon to apply seed changes?\n\n"
            "Active links will drop briefly. Supervisor will respawn.",
            on_confirm=self._restart_daemon,
        )

    def _restart_daemon(self) -> None:
        """SIGTERM the local daemon; supervisor respawns it. Confirm-gated above."""
        pid = _detect_local_daemon_pid()
        if pid is None:
            self.app.status.set_notice(
                "Daemon disappeared — restart manually.",
                level="error",
                duration=6.0,
            )
            self.app._schedule_redraw()
            return
        import signal as _signal

        try:
            os.kill(pid, _signal.SIGTERM)
        except ProcessLookupError:
            self.app.status.set_notice("Daemon already exited.", level="warn")
        except PermissionError:
            self.app.status.set_notice(
                f"Cannot signal daemon pid={pid} (wrong user).",
                level="error",
                duration=6.0,
            )
            self.app._schedule_redraw()
            return
        self.app.status.set_notice(
            "Daemon restart signalled — reconnect in a few seconds.",
            level="info",
            duration=6.0,
        )
        self._pending_restart = False
        self._refresh_apply_status()
        self.app._schedule_redraw()

    def _apply_changes_no_daemon(self, mode: str) -> None:
        """Standalone/remote: instruct the user to restart the TUI themselves."""
        if mode == "remote":
            msg = (
                "Config saved to your local RNS. Restart TUI to apply "
                "(affects only this TUI's transport)."
            )
        else:
            msg = "Config saved. Restart TUI to apply (Ctrl+C then re-run hokora-tui)."
        self.app.status.set_notice(msg, level="info", duration=6.0)
        self._pending_restart = False
        self._refresh_apply_status()
        self.app._schedule_redraw()

    # --- Announce Configuration ---

    def _refresh_announce_state(self) -> None:
        """Update announce toggle display."""
        state_str = "ON" if self.app.state.auto_announce else "OFF"
        self._auto_announce_label.set_text(("default", f"Auto-announce: {state_str}"))

    def _toggle_auto_announce(self) -> None:
        """Toggle auto-announce on/off."""
        self.app.state.auto_announce = not self.app.state.auto_announce
        self._refresh_announce_state()

        # Start/stop announcer auto loop if it exists
        if hasattr(self.app, "announcer") and self.app.announcer is not None:
            if self.app.state.auto_announce:
                self.app.announcer._start_auto_announce()
            else:
                self.app.announcer.stop()

        state_str = "enabled" if self.app.state.auto_announce else "disabled"
        self.app.status.set_notice(f"Auto-announce {state_str}", level="info")
        self.app._schedule_redraw()

    def _apply_interval(self) -> None:
        """Apply the announce interval from the input."""
        try:
            val = self._interval_edit.value()
            if val < 30:
                self.app.status.set_notice("Minimum interval is 30 seconds.", level="warn")
                return
            self.app.state.announce_interval = val
            self.app.status.set_notice(
                f"Announce interval set to {val}s",
                level="info",
            )
        except (ValueError, TypeError):
            self.app.status.set_notice("Invalid interval value.", level="error")
        self.app._schedule_redraw()

    def _do_announce_now(self) -> None:
        """Trigger an immediate profile announce."""
        if hasattr(self.app, "announcer") and self.app.announcer is not None:
            self.app.announcer.announce_profile()
        else:
            self.app.trigger_announce()

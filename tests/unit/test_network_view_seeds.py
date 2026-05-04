# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the Network-tab seed state machine.

Seed management is direct-filesystem-read + in-process-mutation; the
sync-action round-trip remains as a separate read surface for callers
that don't share the daemon's filesystem. Tests assert:

* Seed list is populated from the TUI's own ``_rns_config_dir`` via
  :func:`rns_config.list_seeds`.
* Add / Remove invoke :func:`rns_config.apply_add` /
  :func:`rns_config.apply_remove` directly against that same directory.
* Apply button behaviour branches on topology — daemon-attached vs
  standalone vs remote-daemon — and never kills a process it does not
  own.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path

import pytest
import urwid


class _FakeSyncEngine:
    """Minimal SyncEngine stand-in — the view uses only ``link_count``."""

    def __init__(self, link_count: int = 0):
        self._link_count = link_count

    def link_count(self) -> int:
        return self._link_count


class _FakeState:
    def __init__(self):
        self.connection_status = "disconnected"
        self.connected_node_name = None
        self.auto_announce = False
        self.announce_interval = 600
        self._handlers: dict[str, list] = {}

    def on(self, event, cb):
        self._handlers.setdefault(event, []).append(cb)


class _FakeStatus:
    """Records both ``set_context`` and ``set_notice`` calls into ``messages``.

    Tests assert on ``messages`` regardless of which API was used — the
    distinction is purely UX (TTL'd vs persistent), not semantic. Notice
    level/duration are kept on ``notice_calls`` for tests that care.
    """

    def __init__(self):
        self.messages: list[str] = []
        self.notice_calls: list[tuple[str, str, float]] = []  # (text, level, duration)

    def set_context(self, msg):
        self.messages.append(msg)

    def set_notice(self, msg, level="info", duration=4.0):
        self.messages.append(msg)
        self.notice_calls.append((msg, level, duration))


class _FakeLoop:
    def __init__(self):
        self.alarms: list = []

    def set_alarm_in(self, delay, cb):
        self.alarms.append((delay, cb))


class _FakeApp:
    def __init__(self, rns_config_dir: Path, link_count: int = 0):
        self.state = _FakeState()
        self.status = _FakeStatus()
        self.sync_engine = _FakeSyncEngine(link_count=link_count)
        self.loop = _FakeLoop()
        self._reticulum = None
        self._rns_config_dir = rns_config_dir
        self._redraws = 0
        self.announcer = None
        self.db = None

    def _schedule_redraw(self):
        self._redraws += 1

    def handle_command(self, cmd):
        pass

    def trigger_announce(self):
        pass


def _write_config(rns_dir: Path, body: str) -> None:
    rns_dir.mkdir(parents=True, exist_ok=True)
    (rns_dir / "config").write_text(body)
    os.chmod(rns_dir / "config", 0o600)


@pytest.fixture
def rns_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rns"
    _write_config(
        d,
        "[interfaces]\n  [[TCP Server]]\n    type = TCPServerInterface\n    listen_port = 4242\n",
    )
    return d


@pytest.fixture
def view(rns_dir: Path):
    from hokora_tui.views.network_view import NetworkView

    app = _FakeApp(rns_config_dir=rns_dir)
    return NetworkView(app)


# ── Seed-list display ──────────────────────────────────────────────


def test_initial_seed_list_empty_shows_hint(view):
    walker_texts = [str(w) for w in view._seed_walker]
    assert len(view._seed_walker) == 1
    label = view._seed_walker[0].get_text()[0]
    assert "No seeds" in label
    _ = walker_texts  # repr probe


def test_load_seeds_from_disk_populates_from_config(view, rns_dir: Path):
    # Operator edits the config file while TUI is open.
    _write_config(
        rns_dir,
        "[interfaces]\n"
        "  [[TCP Server]]\n"
        "    type = TCPServerInterface\n"
        "    listen_port = 4242\n"
        "  [[VPS Seed]]\n"
        "    type = TCPClientInterface\n"
        "    enabled = yes\n"
        "    target_host = 1.2.3.4\n"
        "    target_port = 4242\n",
    )
    view._load_seeds_from_disk()
    assert len(view._seeds) == 1
    assert view._seeds[0]["name"] == "VPS Seed"
    assert view._seeds[0]["type"] == "tcp"
    assert view._seeds[0]["target_host"] == "1.2.3.4"


def test_load_seeds_surfaces_parse_errors_gracefully(view, rns_dir: Path, monkeypatch):
    from hokora.security import rns_config as rns_config_mod

    def boom(_path):
        raise rns_config_mod.SeedConfigError("bang")

    monkeypatch.setattr(rns_config_mod, "list_seeds", boom)
    view._load_seeds_from_disk()
    assert view._seeds == []
    assert any("Reading RNS config failed" in m for m in view.app.status.messages)


def test_refresh_seed_nodes_renders_entries(view):
    view._seeds = [
        {"name": "A", "type": "tcp", "target_host": "h", "target_port": 4242, "enabled": True},
        {
            "name": "B",
            "type": "i2p",
            "target_host": "x.b32.i2p",
            "target_port": 0,
            "enabled": False,
        },
    ]
    view._refresh_seed_nodes()
    assert len(view._seed_walker) == 2
    a_text = view._seed_walker[0].contents[0][0].get_text()[0]
    assert "A" in a_text
    assert "h:4242" in a_text
    b_text = view._seed_walker[1].contents[0][0].get_text()[0]
    assert "B" in b_text
    assert "x.b32.i2p" in b_text
    assert "[disabled]" in b_text


# ── Add / Remove via in-process rns_config ─────────────────────────


def test_add_requires_name(view):
    view._addr_edit.set_edit_text("1.2.3.4:4242")
    view._add_seed_node()
    assert any("name required" in m.lower() for m in view.app.status.messages)


def test_add_requires_address(view):
    view._name_edit.set_edit_text("VPS")
    view._add_seed_node()
    assert any("address required" in m.lower() for m in view.app.status.messages)


def test_add_rejects_invalid_address(view):
    view._name_edit.set_edit_text("VPS")
    view._addr_edit.set_edit_text("1.2.3.4:99999")
    view._add_seed_node()
    # Notice-level "error" replaces the bare "ERROR:" prefix prose.
    assert any(lvl == "error" for _msg, lvl, _d in view.app.status.notice_calls)


def test_add_writes_config_file(view, rns_dir: Path):
    view._name_edit.set_edit_text("VPS")
    view._addr_edit.set_edit_text("1.2.3.4:4242")
    view._add_seed_node()
    # Config file on disk should now include the new section.
    cfg = (rns_dir / "config").read_text()
    assert "[[VPS]]" in cfg
    assert "target_host = 1.2.3.4" in cfg
    assert "target_port = 4242" in cfg
    # Backup written.
    assert (rns_dir / "config.prev").exists()
    # Pending-restart indicator on.
    assert view._pending_restart is True
    # Seed list refreshed from disk.
    assert any(s["name"] == "VPS" for s in view._seeds)
    # Name/address edits cleared.
    assert view._name_edit.get_edit_text() == ""
    assert view._addr_edit.get_edit_text() == ""


def test_add_i2p_writes_peers_not_target_host(view, rns_dir: Path):
    view._name_edit.set_edit_text("I2P")
    view._addr_edit.set_edit_text("abcdefgh.b32.i2p")
    view._add_seed_node()
    cfg = (rns_dir / "config").read_text()
    assert "type = I2PInterface" in cfg
    assert "peers = abcdefgh.b32.i2p" in cfg


def test_add_duplicate_surfaces_error(view, rns_dir: Path):
    view._name_edit.set_edit_text("VPS")
    view._addr_edit.set_edit_text("1.2.3.4:4242")
    view._add_seed_node()
    # Clear messages to only see the second add's result.
    view.app.status.messages.clear()
    view._name_edit.set_edit_text("VPS")
    view._addr_edit.set_edit_text("5.6.7.8:4242")
    view._add_seed_node()
    assert any("already exists" in m for m in view.app.status.messages)


def test_remove_deletes_section(view, rns_dir: Path):
    # Seed it with an entry first.
    view._name_edit.set_edit_text("VPS")
    view._addr_edit.set_edit_text("1.2.3.4:4242")
    view._add_seed_node()
    assert "[[VPS]]" in (rns_dir / "config").read_text()
    view.app.status.messages.clear()

    # `_remove_seed_node` now confirms first; assert on the post-confirm
    # mutator. The confirm-gate behaviour is covered by a separate test.
    view._apply_seed_mutation("remove", name="VPS")
    assert "[[VPS]]" not in (rns_dir / "config").read_text()
    assert any("Removed seed" in m for m in view.app.status.messages)


def test_remove_seed_node_opens_confirm_dialog(view, monkeypatch):
    """Public `_remove_seed_node` must NOT mutate config until confirm fires."""
    view._name_edit.set_edit_text("VPS")
    view._addr_edit.set_edit_text("1.2.3.4:4242")
    view._add_seed_node()  # seed it
    view.app.status.messages.clear()

    shown: list = []
    monkeypatch.setattr(
        "hokora_tui.views.network_view.ConfirmDialog.show",
        lambda app, msg, on_confirm: shown.append((msg, on_confirm)),
    )
    view._remove_seed_node("VPS")
    assert len(shown) == 1
    assert "Remove seed 'VPS'" in shown[0][0]


def test_remove_of_server_interface_refused(view, rns_dir: Path):
    # TCP Server exists in the fixture — must not be deletable as a seed.
    # Confirm dialog is bypassed in the test because db is None defaults to
    # confirm-on; bypass by removing through _apply_seed_mutation directly.
    view._apply_seed_mutation("remove", name="TCP Server")
    # Server section still present.
    assert "[[TCP Server]]" in (rns_dir / "config").read_text()
    assert any(lvl == "error" for _m, lvl, _d in view.app.status.notice_calls)


def test_remove_missing_surfaces_error(view):
    view._apply_seed_mutation("remove", name="Nope")
    assert any(lvl == "error" for _m, lvl, _d in view.app.status.notice_calls)


def test_remove_empty_name_is_noop(view, rns_dir: Path):
    pre = (rns_dir / "config").read_text()
    view._remove_seed_node("")
    assert (rns_dir / "config").read_text() == pre


# ── Apply button topology branching ────────────────────────────────


def test_apply_mode_daemon_when_live_pid(view, monkeypatch):
    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: 12345)
    assert view._apply_mode() == "daemon"


def test_apply_mode_standalone_when_no_daemon_no_link(view, monkeypatch):
    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: None)
    assert view._apply_mode() == "standalone"


def test_apply_mode_remote_when_no_daemon_but_link(rns_dir: Path, monkeypatch):
    from hokora_tui.views.network_view import NetworkView

    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: None)
    app = _FakeApp(rns_config_dir=rns_dir, link_count=1)
    v = NetworkView(app)
    assert v._apply_mode() == "remote"


def test_apply_in_daemon_mode_signals_pid(view, monkeypatch):
    """Daemon-mode restart now goes through ConfirmDialog; test the post-confirm
    path directly via ``_restart_daemon``. Separate test covers the confirm
    gate itself."""
    kills: list = []

    def fake_kill(pid, sig):
        kills.append((pid, sig))

    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: 99999)
    monkeypatch.setattr(os, "kill", fake_kill)
    view._pending_restart = True
    view._restart_daemon()
    assert kills == [(99999, signal.SIGTERM)]
    assert view._pending_restart is False
    assert any("Daemon restart signalled" in m for m in view.app.status.messages)


def test_apply_in_daemon_mode_opens_confirm_dialog(view, monkeypatch):
    """`_apply_changes` in daemon mode must NOT signal until the confirm
    dialog's on_confirm fires — guards against accidental SIGTERM."""
    kills: list = []
    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: 99999)
    monkeypatch.setattr(os, "kill", lambda *a: kills.append(a))

    shown: list = []
    monkeypatch.setattr(
        "hokora_tui.views.network_view.ConfirmDialog.show",
        lambda app, msg, on_confirm: shown.append((msg, on_confirm)),
    )
    view._pending_restart = True
    view._apply_changes()
    assert kills == []  # Not yet — waiting on confirm.
    assert len(shown) == 1
    assert "Restart" in shown[0][0]


def test_apply_in_standalone_mode_shows_restart_tui(view, monkeypatch):
    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: None)
    view._pending_restart = True
    view._apply_changes()
    assert view._pending_restart is False
    assert any("Restart TUI to apply" in m for m in view.app.status.messages)


def test_apply_in_remote_mode_surfaces_local_only_note(rns_dir: Path, monkeypatch):
    from hokora_tui.views.network_view import NetworkView

    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: None)
    app = _FakeApp(rns_config_dir=rns_dir, link_count=1)
    v = NetworkView(app)
    v._pending_restart = True
    v._apply_changes()
    assert any(
        "Config saved to your local RNS" in m and "only this TUI" in m for m in app.status.messages
    )


def test_apply_daemon_disappeared_between_check_and_signal(view, monkeypatch):
    # Detector returns live PID, os.kill raises ProcessLookupError.
    # Test the post-confirm restart path directly.
    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: 55555)

    def raise_lookup(_pid, _sig):
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", raise_lookup)
    view._pending_restart = True
    view._restart_daemon()
    assert any("Daemon already exited" in m for m in view.app.status.messages)


# ── Preset button ──────────────────────────────────────────────────


def test_add_preset_writes_tcp_seed(view, rns_dir: Path):
    view._add_preset("ExamplePreset", "192.0.2.1", 4242)
    cfg = (rns_dir / "config").read_text()
    assert "[[ExamplePreset]]" in cfg
    assert "target_host = 192.0.2.1" in cfg
    assert view._pending_restart is True


# ── Apply-status display ───────────────────────────────────────────


def test_apply_status_clears_when_no_pending(view):
    view._pending_restart = False
    view._refresh_apply_status()
    text, _ = view._apply_status.get_text()
    assert text == ""


def test_apply_status_shows_topology_hint_when_pending(view, monkeypatch):
    monkeypatch.setattr("hokora_tui.views.network_view._detect_local_daemon_pid", lambda: 12345)
    view._pending_restart = True
    view._refresh_apply_status()
    text, _ = view._apply_status.get_text()
    assert "daemon" in text.lower()


# ── Structural sanity ──────────────────────────────────────────────


def test_seed_row_structure_is_stable(view):
    view._seeds = [
        {"name": "X", "type": "tcp", "target_host": "h", "target_port": 4242, "enabled": True}
    ]
    view._refresh_seed_nodes()
    assert isinstance(view._seed_walker[0], urwid.Columns)

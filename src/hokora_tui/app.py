# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Main application class for Hokora TUI v2."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import urwid

from hokora_tui.announcer import Announcer
from hokora_tui.commands import CommandContext, CommandRouter, UIGate
from hokora_tui.keybindings import handle_keypress
from hokora_tui.navigation import DEFAULT_TAB, NavigationController
from hokora_tui.palette import PALETTE
from hokora_tui.state import AppState
from hokora_tui.views.channels_view import ChannelsView
from hokora_tui.views.conversations_view import ConversationsView
from hokora_tui.views.discovery_view import DiscoveryView
from hokora_tui.views.identity_view import IdentityView
from hokora_tui.views.messages_view import MessagesView
from hokora_tui.views.network_view import NetworkView
from hokora_tui.views.settings_view import SettingsView
from hokora_tui.views.tab_bar import TabBarView
from hokora_tui.widgets.compose_box import ComposeBox
from hokora_tui.widgets.status_area import StatusArea


def _discover_daemon_rns_config(
    explicit_config: Optional[str] = None,
    home: Optional[Path] = None,
    pid_alive=None,
) -> Optional[str]:
    """Return an ``rns_config_dir`` path to attach to, or None for standalone.

    Precedence:
      1. ``explicit_config`` (typically from ``$HOKORA_CONFIG``) wins if provided.
      2. Live-daemon auto-discovery: glob ``<home>/.hokora*/hokorad.pid``,
         pick the first PID whose process is alive, read its ``hokora.toml``
         to get ``rns_config_dir``.
      3. None — caller uses ``RNS.Reticulum(configdir=None)`` (standalone).

    Pure function: no urwid, no side effects beyond reading config files.
    ``pid_alive`` is a seam for tests (defaults to ``os.kill(pid, 0)``).
    """
    log = logging.getLogger(__name__)
    if explicit_config:
        try:
            from hokora.config import load_config

            cfg = load_config(Path(explicit_config))
            rdir = getattr(cfg, "rns_config_dir", None)
            if rdir is not None:
                return str(rdir)
        except Exception:
            log.debug("Explicit HOKORA_CONFIG load failed", exc_info=True)
        return None

    if home is None:
        home = Path.home()
    if pid_alive is None:

        def pid_alive(pid: int) -> bool:
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                # Process exists, we just can't signal it — treat as alive.
                return True

    pid_files = sorted(home.glob(".hokora*/hokorad.pid"))
    alive_data_dirs: list[Path] = []
    for pid_file in pid_files:
        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, OSError):
            continue
        if pid_alive(pid):
            alive_data_dirs.append(pid_file.parent)

    if len(alive_data_dirs) > 1:
        log.warning(
            "Multiple running daemons found (%s); using first. Set HOKORA_CONFIG to disambiguate.",
            ", ".join(str(p) for p in alive_data_dirs),
        )
    if alive_data_dirs:
        data_dir = alive_data_dirs[0]
        toml_path = data_dir / "hokora.toml"
        if toml_path.exists():
            try:
                from hokora.config import load_config

                cfg = load_config(toml_path)
                rdir = getattr(cfg, "rns_config_dir", None)
                if rdir is not None:
                    return str(rdir)
            except Exception:
                log.debug("Could not load %s", toml_path, exc_info=True)

    return None


class HokoraFrame(urwid.Frame):
    """Custom Frame that intercepts global hotkeys before body widgets see them."""

    def __init__(self, app, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app = app

    def keypress(self, size, key):
        # Global hotkeys — ALWAYS work regardless of focus
        if key == "tab":
            self._app.nav.next_tab()
            return None
        if key == "shift tab":
            self._app.nav.prev_tab()
            return None
        if key in ("f1", "f2", "f3", "f4", "f5", "f6"):
            idx = int(key[1]) - 1
            self._app.nav.switch_to(idx)
            return None
        for i in range(1, 7):
            if key == f"meta {i}":
                self._app.nav.switch_to(i - 1)
                return None
        if key == "ctrl q":
            self._app.quit()
            return None

        # Pass everything else to normal Frame handling
        return super().keypress(size, key)


class HokoraTUI:
    """Top-level TUI application."""

    def __init__(self) -> None:
        # State
        self.state = AppState()

        # Configure logging FIRST — before anything that might write to stderr
        self._setup_logging()

        # Client DB — initialized lazily; can be set externally
        self.db = None
        self._init_client_db()

        # Load saved settings from client DB
        self._load_settings()

        # Initialize RNS on startup so we can receive announces immediately
        self._reticulum = None
        self._init_rns()

        # Create sync engine on main thread (LXMF.LXMRouter requires it)
        self.sync_engine = None
        self._init_sync_engine()

        # Final filesystem hardening pass: catches the LXMF spool dir
        # that LXMRouter created during _init_sync_engine (it would be
        # too early to harden in _init_client_db — the dir didn't exist
        # yet). Recursive so any LXMF spool subdirs land at 0o700/0o600.
        try:
            from hokora.security.fs import secure_client_dir as _scd

            _scd(Path.home() / ".hokora-client", recursive=True)
        except Exception:
            logging.getLogger(__name__).debug("post-sync-engine harden failed", exc_info=True)

        # Announcer — created here, started in run() after loop is set
        self.announcer = Announcer(self)
        # Wire the AppState chokepoint helpers to the announcer so toggling
        # auto_announce wakes the loop for immediate effect.
        self.state.set_announcer(self.announcer)

        # Messages view and compose box (wired into channels view)
        self.messages_view = MessagesView(self)
        self.compose_box = ComposeBox(self)

        # Command subsystem: CommandRouter handles every /cmd via the
        # commands/ package. Built in run() once urwid loop exists so
        # UIGate has something to schedule against.
        self.commands: CommandRouter | None = None

        # Views (order must match TAB_NAMES)
        self.views = [
            IdentityView(self),
            NetworkView(self),
            DiscoveryView(self),
            ChannelsView(self),
            ConversationsView(self),
            SettingsView(self),
        ]

        # Convenience references
        self.identity_view = self.views[0]
        self.network_view = self.views[1]
        self.discovery_view = self.views[2]
        self.channels_view = self.views[3]
        self.conversations_view = self.views[4]

        # Tab bar & status footer
        self.tab_bar = TabBarView()
        self.status = StatusArea()

        # Frame — body starts on the default tab
        self._normal_body = self.views[DEFAULT_TAB].widget
        self.frame = HokoraFrame(
            self,
            header=self.tab_bar.widget,
            body=self._normal_body,
            footer=self.status.widget,
        )

        # Navigation controller (needs frame + tab_bar)
        self.nav = NavigationController(self.views, self.frame, self.tab_bar)
        self.nav.switch_to(DEFAULT_TAB)

        # Loop placeholder
        self.loop: urwid.MainLoop | None = None

        # Subscribe to message arrival events for unread tracking
        self.state.on("message_received", self._on_message_received)

        # Wire DM callback from sync engine when it is set
        self._wire_dm_callback()

    def _init_rns(self) -> None:
        """Initialize Reticulum and load/create client identity.

        This connects to the shared RNS instance if running (e.g., daemon),
        which gives us access to the network and lets us receive announces.
        """
        try:
            import RNS

            # Discover which RNS to attach to:
            #   HOKORA_CONFIG env var (explicit) → live daemon via PID file →
            #   legacy scan list → standalone (~/.reticulum).
            # See ``_discover_daemon_rns_config`` above for precedence rules.
            rns_config = _discover_daemon_rns_config(os.environ.get("HOKORA_CONFIG"))

            # Redirect RNS logging to file — RNS uses print() to stdout
            # which urwid captures and displays on screen. Must set BEFORE
            # Reticulum() init (which reads these globals).
            rns_log = Path.home() / ".hokora-client" / "rns.log"
            rns_log.parent.mkdir(parents=True, exist_ok=True)
            RNS.logdest = RNS.LOG_FILE
            RNS.logfile = str(rns_log)
            RNS.loglevel = RNS.LOG_WARNING

            self._reticulum = RNS.Reticulum(configdir=rns_config)
            # Keep the resolved RNS config dir so the Network tab can
            # read the TUI's own seeds directly from disk without
            # round-tripping a sync action to a daemon. ``None`` means
            # ``RNS.Reticulum`` used its default (~/.reticulum), which
            # ``rns_config.list_seeds(None)`` resolves the same way.
            self._rns_config_dir: Optional[Path] = Path(rns_config) if rns_config else None

            # Load or create persistent client identity. Private key
            # material MUST be 0o600 on disk and live inside a 0o700
            # directory — same invariant as the daemon's identity store.
            # We route through ``security/fs.py`` for the write, and
            # migrate any pre-existing permissive files at startup
            # (matches ``IdentityManager.__init__`` on the daemon side).
            from hokora.security.fs import (
                secure_existing_file,
                secure_identity_dir,
                write_identity_secure,
            )

            client_dir = Path.home() / ".hokora-client"
            client_dir.mkdir(parents=True, exist_ok=True)
            secure_identity_dir(client_dir)
            id_path = client_dir / "client_identity"

            if id_path.exists():
                # Idempotent migration: tighten any pre-existing
                # client_identity file to 0o600.
                secure_existing_file(id_path)
                self.state.identity = RNS.Identity.from_file(str(id_path))
            else:
                self.state.identity = RNS.Identity()
                write_identity_secure(self.state.identity, id_path)

        except ImportError:
            pass  # RNS not installed — TUI works without network
        except Exception:
            # Non-fatal — TUI works in offline mode.
            logging.getLogger(__name__).debug("identity init failed", exc_info=True)

    def _init_sync_engine(self) -> None:
        """Create the SyncEngine on the main thread.

        LXMF.LXMRouter uses signal handlers internally, which only work
        on the main thread. Creating the engine here (during __init__)
        ensures it's always on the main thread. The engine persists across
        disconnect/reconnect cycles — only channel Links are torn down.
        """
        if self._reticulum is None or self.state.identity is None:
            return
        try:
            from pathlib import Path

            from hokora_tui.sync_engine import SyncEngine

            client_dir = Path.home() / ".hokora-client"
            client_dir.mkdir(parents=True, exist_ok=True)

            self.sync_engine = SyncEngine(
                reticulum=self._reticulum,
                identity=self.state.identity,
                data_dir=client_dir,
            )
            self.sync_engine.set_display_name(self.state.display_name)
            # Load persisted cursors immediately so register_channel
            # uses correct cursor (prevents full re-fetch on restart)
            if self.db is not None:
                try:
                    saved = self.db.get_all_cursors()
                    if saved:
                        self.sync_engine.update_cursors(saved)
                except Exception:
                    logging.getLogger(__name__).debug(
                        "failed to restore sync cursors", exc_info=True
                    )
                # Persist daemon-served sealed keys via the SealedKeyStore.
                # SyncEngine fires this callback after decrypting the
                # envelope with our RNS identity.
                try:
                    sealed_store = self.db.sealed_keys
                    self.sync_engine.set_sealed_key_callback(
                        lambda ch, k, ep: sealed_store.upsert(ch, k, ep)
                    )
                except Exception:
                    logging.getLogger(__name__).debug(
                        "failed to wire sealed-key callback", exc_info=True
                    )
        except Exception:
            # Non-fatal — TUI works without sync engine.
            logging.getLogger(__name__).debug("sync engine init failed", exc_info=True)

    def _init_client_db(self) -> None:
        """Initialize the client-side SQLite cache (SQLCipher-encrypted).

        Resolves or generates the master key via
        ``resolve_client_db_key`` and opens the cache through ClientDB,
        which runs the one-time plaintext→encrypted migration if a
        pre-encryption ``tui.db`` is detected. Migration failure aborts
        TUI startup rather than silently degrading to plaintext.
        """
        try:
            from hokora.security.fs import secure_client_dir
            from hokora_tui.client_db import ClientDB
            from hokora_tui.client_db._migration import ClientDBMigrationError
            from hokora_tui.security.client_db_key import resolve_client_db_key

            db_dir = Path.home() / ".hokora-client"
            db_dir.mkdir(parents=True, exist_ok=True)

            key_hex = resolve_client_db_key(db_dir)

            def _notice(msg: str) -> None:
                # Status surface may not exist yet during __init__; route
                # through the logger and stash the message for surface
                # later if the migration runs.
                logging.getLogger(__name__).info("client_db: %s", msg)

            self.db = ClientDB(db_dir / "tui.db", key_hex, notice=_notice)
            # Recursive harden after open: catches the freshly-opened DB,
            # the keyfile, and any LXMF spool already on disk.
            secure_client_dir(db_dir, recursive=True)
        except (ValueError, FileNotFoundError, ClientDBMigrationError):
            # Encryption / key / migration failures must not silently fall
            # back to a plaintext-or-no-db state. Re-raise so the TUI
            # aborts with the actionable error message.
            raise
        except Exception:
            # Operational failures (disk full, permission denied on a
            # non-key file) — log and degrade to no-cache rather than
            # blocking TUI launch entirely.
            logging.getLogger(__name__).exception("client_db init failed")
            self.db = None

    def _load_settings(self) -> None:
        """Load saved display name, status, and announce settings from DB.

        Wires the ``AppState.set_*`` chokepoints to the DB persister so any
        future mutation routes through them; without this, settings mutated
        from either the Identity tab or the Settings tab would not survive a
        TUI restart.
        """
        if self.db is not None:
            dn = self.db.get_setting("display_name")
            if dn:
                self.state.display_name = dn
            st = self.db.get_setting("status_text")
            if st:
                self.state.status_text = st
            aa = self.db.get_setting("auto_announce")
            if aa is not None:
                self.state.auto_announce = aa == "true"
            ai = self.db.get_setting("announce_interval")
            if ai is not None:
                try:
                    interval = int(ai)
                    # Clamp on read in case an out-of-range value was
                    # stored before bounds-checking landed.
                    self.state.announce_interval = max(30, min(interval, 86400))
                except (TypeError, ValueError):
                    pass
            # Wire the persister chokepoint for any future mutation.
            self.state.set_setting_persister(self.db.set_setting)

    def _setup_logging(self) -> None:
        """Route all logging to file — no stderr output during urwid."""
        import os
        import sys

        from hokora.core.logging_config import configure_logging
        from hokora.security.fs import secure_client_dir, secure_existing_file

        log_dir = Path.home() / ".hokora-client"
        # Harden directory up-front (before any log/file lands inside) so
        # umask cannot leak permissive modes during this startup window.
        secure_client_dir(log_dir)
        log_file = log_dir / "tui.log"
        configure_logging(
            log_dir=log_dir,
            log_level="INFO",
            json_logging=False,
            log_to_stdout=False,
            log_filename="tui.log",
            max_bytes=5_000_000,
            backup_count=3,
        )
        # RotatingFileHandler opens with default umask — chmod after the fact.
        secure_existing_file(log_file)

        # Redirect stderr to log file (catches Python exceptions/warnings).
        # Do NOT redirect stdout — urwid uses sys.stdout for terminal output.
        # RNS errors are handled by RNS.logdest=LOG_FILE (set in _init_rns).
        # Open with explicit 0o600 — bypasses umask so a permissive shell
        # umask cannot leave the log world-readable.
        self._original_stderr = sys.stderr
        fd = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        sys.stderr = os.fdopen(fd, "a")

    def _restore_stderr(self) -> None:
        """Restore stderr and stdout after TUI exits."""
        import sys

        if hasattr(self, "_original_stderr") and self._original_stderr is not None:
            try:
                if sys.stderr is not self._original_stderr:
                    sys.stderr.close()
            except Exception:
                logging.getLogger(__name__).debug(
                    "stderr close during restore failed", exc_info=True
                )
            sys.stderr = self._original_stderr

    def run(self) -> None:
        """Create the urwid MainLoop and start the event loop."""
        self.loop = urwid.MainLoop(
            self.frame,
            palette=PALETTE,
            unhandled_input=self._unhandled_input,
        )
        self.state.set_loop(self.loop, wake_fn=self._wake_loop)
        self.status.set_loop(self.loop)

        # Build CommandRouter now that the urwid loop exists (UIGate
        # needs it for set_alarm_in scheduling).
        self.commands = self._build_command_router()

        # Set up watch_pipe for thread-safe event loop wakeup.
        # Background threads call _wake_loop() to trigger pending alarms.
        self._pipe_fd = self.loop.watch_pipe(self._on_pipe_data)

        # Start announcer immediately (doesn't need loop running)
        if self._reticulum is not None:
            self.announcer.start()

        # Set initial status
        self._update_rns_status()

        # Schedule startup tasks as alarms so they fire AFTER loop.run().
        # Seed-node authority lives in the daemon's RNS config; this
        # one-shot migration surfaces legacy TUI seed-state to the
        # operator before dropping it.
        self.loop.set_alarm_in(0.1, lambda *_: self._migrate_legacy_seed_state())
        # ``_auto_connect_local`` runs /local when a daemon is discoverable
        # locally (via HOKORA_CONFIG or PID-file scan).
        self.loop.set_alarm_in(0.5, lambda *_: self._auto_connect_local())
        self.loop.set_alarm_in(2.0, self._ui_refresh_job)

        self.loop.run()

    def _auto_connect_local(self):
        """Auto-connect to a locally discoverable daemon.

        Precedence:
        1. ``HOKORA_CONFIG`` env var — explicit opt-in path.
        2. PID-file discovery at ``~/.hokora*/hokorad.pid`` — matches the
           same scan ``_discover_daemon_rns_config`` uses. When a live
           daemon is found, we point HOKORA_CONFIG at its ``hokora.toml`` for
           this process so ``load_config()`` picks it up.

        No-op if neither applies (fresh client install with no local
        daemon). Idempotent: if ``/local`` fails the sync engine stays
        disconnected and the user can retry manually.
        """
        import os
        from pathlib import Path

        config_path = os.environ.get("HOKORA_CONFIG")
        if not config_path:
            # PID-file auto-discovery fallback — per the documented
            # "local user runs hokora-tui with no env vars" UX. We reuse
            # the same glob used for RNS shared-instance discovery so
            # the TUI's network attach and DB attach agree on which
            # daemon to talk to.
            home = Path.home()
            for pid_file in sorted(home.glob(".hokora*/hokorad.pid")):
                try:
                    pid = int(pid_file.read_text().strip())
                except (OSError, ValueError):
                    continue
                try:
                    os.kill(pid, 0)  # liveness probe
                except OSError:
                    continue
                toml = pid_file.parent / "hokora.toml"
                if toml.exists():
                    os.environ["HOKORA_CONFIG"] = str(toml)
                    config_path = str(toml)
                    break
            if not config_path:
                return

        # Check if the daemon DB file exists
        try:
            from hokora.config import load_config

            config = load_config()
            db_path = config.db_path
            if not os.path.exists(str(db_path)):
                return
        except Exception:
            return

        self.status.set_connection("connecting")
        self.status.set_context("Found local daemon. Loading channels...")

        # Run /local through the router
        self.handle_command("/local")

    def _ui_refresh_job(self, loop=None, user_data=None):
        """Periodic UI refresh -- polls state and redraws visible widgets."""
        self._update_rns_status()

        # Refresh active view if it has an update() method
        active_view = self.nav.views[self.nav.active_tab]
        if hasattr(active_view, "update"):
            active_view.update()

        # Schedule next refresh
        if self.loop is not None:
            self.loop.set_alarm_in(2.0, self._ui_refresh_job)

    def _unhandled_input(self, key: str) -> None:
        """Delegate unhandled keys to the global keybindings handler."""
        handle_keypress(self, key)

    def quit(self) -> None:
        """Exit the application."""
        log = logging.getLogger(__name__)
        # Stop announcer
        if self.announcer is not None:
            try:
                self.announcer.stop()
            except Exception:
                log.debug("announcer stop during quit failed", exc_info=True)
        if self.db is not None:
            try:
                self.db.close()
            except Exception:
                log.debug("client DB close during quit failed", exc_info=True)
        self._restore_stderr()
        raise urwid.ExitMainLoop()

    def _on_pipe_data(self, data: bytes) -> bool:
        """Handle pipe wakeup — just triggers the event loop to process alarms."""
        return True  # Keep the pipe open

    def _wake_loop(self) -> None:
        """Wake the urwid event loop from a background thread.

        Writing a byte to the pipe causes urwid's select/poll to return,
        which then processes any pending alarms set by background threads.
        """
        import os

        if hasattr(self, "_pipe_fd") and self._pipe_fd is not None:
            try:
                os.write(self._pipe_fd, b"\x00")
            except OSError:
                pass

    def _schedule_redraw(self) -> None:
        """Request an asynchronous screen redraw (thread-safe)."""
        if self.loop is not None:
            self.loop.set_alarm_in(0, lambda *_: self.loop.draw_screen())
            self._wake_loop()

    def handle_command(self, text: str) -> None:
        """Dispatch a /command through CommandRouter."""
        if self.commands is not None:
            self.commands.dispatch(text)

    def _build_command_router(self) -> CommandRouter:
        """Construct CommandRouter with a CommandContext bound to this app.

        Called once urwid's main loop exists (so UIGate has something to
        schedule against). Registers the built-in commands.
        """
        ctx = CommandContext(
            app=self,
            state=self.state,
            db=self.db,
            engine=self.sync_engine,
            gate=UIGate(getattr(self, "loop", None)),
            log=logging.getLogger("hokora_tui.commands"),
            status=self.status,
            emit=lambda ev, data: self.state.emit(ev, data),
        )
        router = CommandRouter(ctx)
        router.register_builtins()
        return router

    def _update_rns_status(self) -> None:
        """Update the status footer with actual RNS interface online status."""
        # If the app is connected or connecting to a node, preserve that status.
        # Don't let RNS interface checks overwrite the node connection indicator.
        if self.state.connection_status == "connected" and self.state.connected_node_name:
            self.status.set_connection("connected", self.state.connected_node_name)
            ch_count = len(self.state.channels)
            self.status.set_context(
                f"Connected to {self.state.connected_node_name} ({ch_count} channels)"
            )
            return
        if self.state.connection_status == "connecting":
            self.status.set_connection("connecting")
            self.status.set_context("Connecting to node...")
            return

        if self._reticulum is None:
            self.status.set_connection("disconnected")
            self.status.set_context("RNS not available. Use Network tab (F2) to add a seed node.")
            return

        try:
            import RNS

            interfaces = getattr(RNS.Transport, "interfaces", [])

            # Check actual online status of non-local interfaces
            non_local_ifaces = [
                iface
                for iface in interfaces
                if not getattr(iface, "IN", False)  # skip LocalClientInterface
            ]
            online_count = sum(1 for iface in non_local_ifaces if getattr(iface, "online", False))

            if online_count > 0:
                self.status.set_connection("connected", "RNS Active")
                self.status.set_context(
                    "Listening for announces. Switch to Discovery (F3) to see nodes."
                )
            elif non_local_ifaces:
                # Interfaces exist but none online yet
                self.status.set_connection("connecting", "RNS")
                self.status.set_context("Interfaces present but not online yet. Waiting...")
            else:
                self.status.set_connection("disconnected")
                self.status.set_context(
                    "No network interfaces. Use Network tab (F2) to add a seed node."
                )
        except ImportError:
            self.status.set_connection("disconnected")
            self.status.set_context("RNS not installed.")
        except Exception:
            self.status.set_connection("disconnected")
            self.status.set_context("Error checking RNS status.")

    def _migrate_legacy_seed_state(self) -> None:
        """One-shot: surface + drop any legacy ``seed_nodes`` ClientDB row.

        Earlier TUI builds mirrored the seed list into a ClientDB
        ``settings`` row and attempted to ``_synthesize_interface``
        client-side on startup. Both behaviours are gone: the daemon's
        RNS config is the sole source of truth, managed by the
        ``hokora seed`` CLI (and relayed to the TUI via ``SYNC_LIST_SEEDS``).

        This migration runs on every startup but is idempotent — once the
        legacy row is cleared, subsequent runs short-circuit without
        surfacing anything. The operator sees the notice exactly once,
        then ``hokora seed list`` is the only visible seed surface.
        """
        if self.db is None:
            return
        log = logging.getLogger(__name__)
        try:
            legacy = self.db.get_setting("seed_nodes", "")
        except Exception:
            log.debug("legacy seed_nodes migration read failed", exc_info=True)
            return
        if not legacy or legacy == "[]":
            return
        log.info("Dropping legacy TUI seed_nodes row; daemon RNS config is authoritative")
        try:
            self.db.set_setting("seed_nodes", "")
        except Exception:
            log.debug("legacy seed_nodes migration write failed", exc_info=True)
            return
        self.status.set_context(
            "Seeds moved to daemon RNS config — run 'hokora seed list' to verify."
        )
        self._schedule_redraw()
        # Always refresh status after restoration attempts
        self._update_rns_status()

    def trigger_announce(self) -> None:
        """Trigger an immediate profile announce to the network."""
        if self.announcer and self._reticulum:
            self.announcer.announce_profile()
            self.status.set_context("Profile announced")
        else:
            self.status.set_context("No RNS identity available for announce")
        self._schedule_redraw()

    def open_thread(self, msg_hash: str) -> None:
        """Open thread overlay in the Channels tab."""
        # Switch to Channels tab if not there
        if self.nav.active_tab != 3:
            self.nav.switch_to(3)
        if self.channels_view is not None:
            self.channels_view.open_thread(msg_hash)

    def open_search(self) -> None:
        """Open search overlay in the Channels tab."""
        if self.nav.active_tab != 3:
            self.nav.switch_to(3)
        if self.channels_view is not None:
            self.channels_view.open_search()

    def open_invite(self) -> None:
        """Open the invite modal dialog."""
        from hokora_tui.views.invite_view import InviteView
        from hokora_tui.widgets.modal import Modal

        if not hasattr(self, "_invite_view") or self._invite_view is None:
            self._invite_view = InviteView(self)

        self._invite_view.open_invite()
        Modal.show(self, "Invites", self._invite_view.widget, width=60, height=50)

    def close_invite(self) -> None:
        """Close the invite modal dialog."""
        from hokora_tui.widgets.modal import Modal

        Modal.close(self)

    def load_older_messages(self) -> None:
        """Load older messages for the current channel via pagination.

        Called when user presses Page Up at the top of the message list.
        """
        channel_id = self.state.current_channel_id
        if not channel_id:
            return

        # Get the oldest loaded message's seq
        current_messages = self.state.messages.get(channel_id, [])
        if not current_messages:
            return

        oldest_seq = None
        for msg in current_messages:
            seq = msg.get("seq")
            if seq is not None:
                if oldest_seq is None or seq < oldest_seq:
                    oldest_seq = seq

        if oldest_seq is None or oldest_seq <= 1:
            self.status.set_notice("No older messages available.", level="info")
            return

        # Try client DB first
        older = []
        if self.db is not None:
            older = self.db.get_messages(channel_id, limit=50, before_seq=oldest_seq)

        if older:
            # Prepend to state and view
            self.state.messages[channel_id] = older + current_messages
            if self.messages_view is not None:
                self.messages_view.prepend_messages(older)
            self.status.set_notice(f"Loaded {len(older)} older messages", level="info")
            self._schedule_redraw()
        elif self.sync_engine:
            # Request from server
            self.sync_engine.sync_history(channel_id, since_seq=0, limit=50)
            self.status.set_notice(
                "Requesting older messages from server...",
                level="info",
            )
        else:
            self.status.set_notice("No older messages in local cache.", level="warn")

    def _wire_dm_callback(self) -> None:
        """Wire the sync engine DM callback to the conversations view.

        Called at init and can be called again when a sync engine is attached.
        """
        if self.sync_engine is not None and hasattr(self.sync_engine, "set_dm_callback"):
            self.sync_engine.set_dm_callback(self._on_dm_from_engine)
        if self.sync_engine is not None and hasattr(self.sync_engine, "set_connected_callback"):
            self.sync_engine.set_connected_callback(self._on_link_connected)

    def _on_link_connected(self, channel_id: str, destination_hash: bytes | None) -> None:
        """Fired by SyncEngine on _on_link_established. RNS thread — hop to loop."""

        def _update(_loop=None, _data=None):
            self.state.connection_status = "connected"
            label = self.state.connected_node_name
            if not label and destination_hash:
                label = destination_hash.hex()[:16]
            if not label:
                label = channel_id
            self.state.connected_node_name = self.state.connected_node_name or label
            self.status.set_connection("connected", label)
            self._schedule_redraw()

        if self.loop is not None:
            self.loop.set_alarm_in(0, _update)
            self._wake_loop()

    def _on_dm_from_engine(
        self, sender_hash: str, display_name: str | None, body: str, timestamp: float
    ) -> None:
        """Handle an incoming DM from the sync engine and route to state/view."""
        data = {
            "sender_hash": sender_hash,
            "display_name": display_name,
            "body": body,
            "timestamp": timestamp,
        }
        self.state.emit("dm_received", data)

    def _on_message_received(self, data: dict | None = None) -> None:
        """Handle incoming message — increment unread for non-current channels."""
        if data is None:
            return
        channel_id = data.get("channel_id")
        if not channel_id:
            return

        # If message is for a different channel, increment unread
        if channel_id != self.state.current_channel_id:
            count = self.state.unread_counts.get(channel_id, 0) + 1
            self.state.unread_counts[channel_id] = count

            if self.db is not None:
                self.db.increment_channel_unread(channel_id)

            # Update the channel item badge in sidebar
            if hasattr(self, "channels_view") and self.channels_view is not None:
                self.channels_view.update_unread(channel_id, count)


def main() -> None:
    """Entry point for the TUI v2."""
    app = HokoraTUI()
    app.run()


if __name__ == "__main__":
    main()

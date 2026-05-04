# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Global keypress handler."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hokora_tui.app import HokoraTUI


_HELP_VISIBLE = False

_HELP_TEXT = (
    "F1 Identity | F2 Network | F3 Discovery | F4 Channels | "
    "F5 Conversations | F6 Settings | Tab/Shift+Tab cycle | Ctrl+Q quit\n"
    "Ctrl+S Search | Ctrl+I Invites | Ctrl+A Announce | "
    "Ctrl+B Bookmarks | ? toggle help"
)


def handle_keypress(app: HokoraTUI, key: str) -> str | None:
    """Process a global keypress. Return the key if unhandled.

    Note: Tab, Shift+Tab, F1-F6, Alt+1-6, and Ctrl+Q are handled by
    HokoraFrame.keypress() before reaching here.
    """
    global _HELP_VISIBLE

    # Ctrl+S — open search (if on Channels tab)
    if key == "ctrl s":
        if hasattr(app, "nav") and app.nav.active_tab == 3:
            app.open_search()
        return None

    # Ctrl+I — open invite dialog
    if key == "ctrl i":
        app.open_invite()
        return None

    # Ctrl+A — trigger announce
    if key == "ctrl a":
        app.trigger_announce()
        return None

    # Ctrl+B — show bookmarks in status
    if key == "ctrl b":
        bookmarks = app.state.bookmarks
        if bookmarks:
            names = [b.get("name", b.get("destination_hash", "?")[:8]) for b in bookmarks[:5]]
            app.status.set_context(f"Bookmarks: {', '.join(names)}")
        else:
            app.status.set_context("No bookmarks saved.")
        return None

    if key == "?":
        _HELP_VISIBLE = not _HELP_VISIBLE
        if _HELP_VISIBLE:
            # Show help as a modal overlay
            from hokora_tui.widgets.modal import Modal

            import urwid

            help_lines = [
                "F1-F6         Switch tabs",
                "Tab/Shift+Tab Cycle tabs",
                "Ctrl+Q        Quit",
                "Ctrl+S        Search (Channels tab)",
                "Ctrl+I        Invites",
                "Ctrl+A        Announce",
                "Ctrl+B        Bookmarks",
                "",
                "Message keys (Channels tab):",
                "  r  Reply    e  Edit    d  Delete",
                "  t  Thread   p  Pin     +  React",
                "",
                "Discovery tab:",
                "  i  Info panel    b  Toggle bookmark",
                "",
                "Press ? or Esc to close",
            ]
            body = urwid.Filler(
                urwid.Text(("modal_body", "\n".join(help_lines))),
                valign="top",
            )
            Modal.show(app, "Keyboard Shortcuts", body, width=50, height=60)
        else:
            from hokora_tui.widgets.modal import Modal

            Modal.close(app)
        return None

    # Esc — close any modal
    if key == "esc":
        from hokora_tui.widgets.modal import Modal

        if Modal._saved_body is not None:
            Modal.close(app)
            _HELP_VISIBLE = False
            return None

    return key

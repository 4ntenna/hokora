# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Dark theme color palette for the Hokora TUI v2."""

from __future__ import annotations


def attrs_with_prefix(prefix: str) -> list[str]:
    """All palette attribute names starting with ``prefix``.

    Used by single-namespace list widgets (e.g. ``MessageWidget`` covers
    only ``msg_*``) to derive a focus-map dict from the palette so new
    palette entries automatically participate in the full-row highlight.
    Cross-prefix widgets should prefer ``make_full_focus_map`` instead.
    """
    return [name for name, *_ in PALETTE if name.startswith(prefix)]


def make_full_focus_map(target: str) -> dict[str | None, str]:
    """Focus-map that remaps every palette attribute (and ``None``) to
    ``target``. Used by list-item widgets whose inner tree spans multiple
    palette prefix groups (e.g. ``ConversationItem`` mixes ``dm_*`` +
    ``default``; ``PeerItem`` mixes ``peer_*`` + ``node_*`` + ``default``;
    ``NodeItem`` mixes ``node_*`` + ``default`` + ``msg_thread``).

    Single source of truth — drift impossible: any future palette entry
    a widget happens to render is automatically covered. The semantic is
    "every segment of this row flips to the highlight attribute on focus,"
    which is exactly what the channel-sidebar / tab-bar reference
    behaviour expresses.
    """
    return {None: target, **{name: target for name, *_ in PALETTE}}


PALETTE = [
    # Base
    ("default", "light gray", "black"),
    ("bold", "white,bold", "black"),
    # Tab bar
    ("tab_active", "white,bold", "dark gray"),
    ("tab_inactive", "dark gray", "black"),
    # Sidebar — channels
    ("channel", "light gray", "black"),
    ("channel_selected", "white,bold", "dark gray"),
    ("channel_unread", "white,bold", "black"),
    ("channel_sealed", "light magenta", "black"),
    ("category_header", "dark cyan,bold", "black"),
    ("unread_badge", "white", "dark red"),
    # Messages
    ("msg_sender", "light cyan,bold", "black"),
    ("msg_time", "dark gray", "black"),
    ("msg_body", "light gray", "black"),
    ("msg_system", "dark green", "black"),
    ("msg_deleted", "dark red", "black"),
    ("msg_edited", "brown", "black"),
    ("msg_pinned", "yellow", "black"),
    ("msg_reaction", "light magenta", "black"),
    ("msg_thread", "dark cyan", "black"),
    ("msg_mention", "yellow,bold", "black"),
    ("msg_unverified", "light red", "black"),
    ("msg_selected", "white,bold", "dark gray"),
    # Status indicators
    ("status_connected", "light green,bold", "black"),
    ("status_disconnected", "light red,bold", "black"),
    ("status_connecting", "yellow,bold", "black"),
    ("status_info", "light blue", "black"),
    ("status_error", "light red,bold", "black"),
    ("status_sync", "dark cyan", "black"),
    # Input
    ("input_prompt", "light cyan,bold", "black"),
    ("input_text", "white", "black"),
    # Discovery
    ("node_name", "light green", "black"),
    ("node_hash", "dark gray", "black"),
    ("node_recent", "light green", "black"),
    ("node_stale", "dark gray", "black"),
    ("node_bookmarked", "yellow", "black"),
    ("peer_name", "light cyan", "black"),
    ("peer_hash", "dark gray", "black"),
    ("peer_status", "light gray", "black"),
    # Dialogs / modals
    ("modal_border", "light cyan", "black"),
    ("modal_title", "white,bold", "dark gray"),
    ("modal_body", "light gray", "black"),
    ("button_focus", "white,bold", "dark gray"),
    ("button_normal", "light gray", "dark gray"),
    # Identity
    ("id_hash", "dark cyan", "black"),
    ("id_fingerprint", "dark gray", "black"),
    ("id_label", "white,bold", "black"),
    # Settings
    ("setting_key", "light cyan", "black"),
    ("setting_value", "white", "black"),
    ("setting_changed", "yellow,bold", "black"),
    # Info panels (Discovery → press ``i`` on a focused node/peer)
    ("info_section_header", "white,bold", "black"),
    ("info_label", "light cyan", "black"),
    ("info_value", "white", "black"),
    ("info_hash", "dark cyan", "black"),
    ("info_dim", "dark gray", "black"),
    # DM / conversations
    ("dm_self", "light cyan,bold", "black"),
    ("dm_peer", "light green,bold", "black"),
    ("dm_time", "dark gray", "black"),
    ("dm_unread", "white,bold", "dark red"),
]

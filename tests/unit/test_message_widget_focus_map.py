# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the MessageWidget full-row focus highlight.

The bug being locked out: previously the AttrMap used the shorthand
``focus_map="msg_selected"`` which urwid expands to ``{None: "msg_selected"}``.
Because every segment of a rendered message has an explicit attribute
(``msg_time``, ``msg_sender``, ``msg_body``, etc.), the focus map's
``None``-keyed transform applied only to the trailing fill space —
producing the "highlight only on the right" visual.

Fix: derive the focus map from ``palette.attrs_with_prefix("msg_")`` so
every ``msg_*`` attribute remaps to ``msg_selected`` on focus. New
palette entries automatically participate — no hand-maintained list to
drift against the palette declaration.
"""

from __future__ import annotations

from hokora_tui.palette import PALETTE, attrs_with_prefix, make_full_focus_map
from hokora_tui.widgets.conversation_item import _CONVO_FOCUS_MAP
from hokora_tui.widgets.message_widget import _MSG_FOCUS_MAP
from hokora_tui.widgets.node_item import _NODE_FOCUS_MAP
from hokora_tui.widgets.peer_item import _PEER_FOCUS_MAP


class TestAttrsWithPrefix:
    """Single-source-of-truth palette query used by the four list widgets."""

    def test_returns_msg_attrs(self):
        names = attrs_with_prefix("msg_")
        assert "msg_time" in names
        assert "msg_sender" in names
        assert "msg_body" in names
        assert "msg_unverified" in names

    def test_excludes_other_prefixes(self):
        names = attrs_with_prefix("msg_")
        assert "channel_selected" not in names
        assert "tab_active" not in names
        assert "default" not in names

    def test_empty_prefix_returns_all(self):
        names = attrs_with_prefix("")
        # Sanity: every palette entry is included.
        assert len(names) == len(PALETTE)

    def test_unknown_prefix_returns_empty(self):
        assert attrs_with_prefix("nonexistent_") == []

    def test_ordering_matches_palette_declaration(self):
        names = attrs_with_prefix("msg_")
        palette_msg_names = [n for n, *_ in PALETTE if n.startswith("msg_")]
        assert names == palette_msg_names


class TestMsgFocusMap:
    """The MessageWidget focus map covers every ``msg_*`` palette attr +
    None. Drift between palette and map is impossible because the map is
    generated from the palette, not hand-maintained.
    """

    def test_every_msg_palette_attr_remaps_to_msg_selected(self):
        for name in attrs_with_prefix("msg_"):
            assert _MSG_FOCUS_MAP.get(name) == "msg_selected", (
                f"palette attr {name!r} is not in _MSG_FOCUS_MAP — full-row "
                "highlight will leak the unmapped segment's base color."
            )

    def test_none_remaps_to_msg_selected(self):
        """Trailing fill space (attribute None) flips on focus too."""
        assert _MSG_FOCUS_MAP[None] == "msg_selected"

    def test_focus_map_size_matches_palette_msg_count_plus_none(self):
        msg_count = len(attrs_with_prefix("msg_"))
        # Map size = msg_* count + 1 for None.
        assert len(_MSG_FOCUS_MAP) == msg_count + 1

    def test_no_unknown_keys_in_focus_map(self):
        """Every key (other than None) must correspond to a real palette entry.
        Catches a typo'd or stale key that wouldn't match any rendered segment.
        """
        valid = set(attrs_with_prefix("msg_")) | {None}
        for key in _MSG_FOCUS_MAP:
            assert key in valid, f"unknown focus-map key {key!r} (no matching palette entry)"

    def test_all_targets_are_msg_selected(self):
        """Sanity: every value in the focus map is the single highlight attr.
        Prevents accidental partial-color schemes that would defeat the
        full-row highlight intent.
        """
        for value in _MSG_FOCUS_MAP.values():
            assert value == "msg_selected"

    def test_msg_selected_is_a_real_palette_entry(self):
        """The highlight target attr must exist in the palette or urwid
        renders it as the fallback (default) color.
        """
        names = [n for n, *_ in PALETTE]
        assert "msg_selected" in names

    def test_msg_selected_is_bold(self):
        """``msg_selected`` foreground must include ``bold`` so the highlighted
        row reads with the same weight as ``tab_active`` / ``channel_selected``.
        Plain ``"white"`` looked thin against the dark blue background and was
        the original visual-mismatch the user flagged.
        """
        for name, fg, *_bg in PALETTE:
            if name == "msg_selected":
                assert "bold" in fg, (
                    f"msg_selected fg={fg!r} — must include 'bold' to match "
                    "tab_active / channel_selected on focus."
                )
                return
        raise AssertionError("msg_selected not in PALETTE")


# ─────────────────────────────────────────────────────────────────────
# make_full_focus_map helper + sibling list-widget focus maps
# ─────────────────────────────────────────────────────────────────────


class TestMakeFullFocusMap:
    """``make_full_focus_map(target)`` produces a focus map covering every
    palette attribute (and ``None``) → ``target``. Used by list-item
    widgets that mix attributes from multiple palette prefix groups.
    """

    def test_includes_none(self):
        m = make_full_focus_map("channel_selected")
        assert m[None] == "channel_selected"

    def test_includes_every_palette_attr(self):
        m = make_full_focus_map("channel_selected")
        for name, *_ in PALETTE:
            assert m.get(name) == "channel_selected", (
                f"palette attr {name!r} missing from full focus map"
            )

    def test_size_matches_palette_plus_none(self):
        m = make_full_focus_map("channel_selected")
        assert len(m) == len(PALETTE) + 1

    def test_target_is_independent(self):
        """Calling with different targets returns independent dicts."""
        m1 = make_full_focus_map("channel_selected")
        m2 = make_full_focus_map("msg_selected")
        assert m1[None] == "channel_selected"
        assert m2[None] == "msg_selected"
        # Sanity: every value in m1 is the m1 target, not the m2 target.
        assert all(v == "channel_selected" for v in m1.values())
        assert all(v == "msg_selected" for v in m2.values())


class _ListItemFocusMapMixin:
    """Shared assertions for the three list-item widgets that use
    ``make_full_focus_map``. Each subclass plugs in its own focus_map.
    """

    FOCUS_MAP: dict[str | None, str]
    TARGET = "channel_selected"

    def test_none_remaps_to_target(self):
        assert self.FOCUS_MAP[None] == self.TARGET

    def test_every_palette_attr_remaps_to_target(self):
        for name, *_ in PALETTE:
            assert self.FOCUS_MAP.get(name) == self.TARGET, (
                f"palette attr {name!r} not in widget focus map — segments "
                "rendered with that attribute will leak their base color "
                "on focus."
            )

    def test_size_matches_full_palette(self):
        assert len(self.FOCUS_MAP) == len(PALETTE) + 1

    def test_target_is_a_real_palette_entry(self):
        names = [n for n, *_ in PALETTE]
        assert self.TARGET in names


class TestConversationFocusMap(_ListItemFocusMapMixin):
    FOCUS_MAP = _CONVO_FOCUS_MAP


class TestNodeFocusMap(_ListItemFocusMapMixin):
    FOCUS_MAP = _NODE_FOCUS_MAP


class TestPeerFocusMap(_ListItemFocusMapMixin):
    FOCUS_MAP = _PEER_FOCUS_MAP

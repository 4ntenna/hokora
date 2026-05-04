# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Cursor-suppression invariant for HokoraButton.

urwid's ``Button`` builds its label as a ``SelectableIcon`` with
``cursor_position=0``. ``SelectableIcon.render`` then draws the terminal
hardware cursor on the first cell of the label whenever the widget is
focused. On any focus background palette pair the cursor inverts that
single cell and produces a one-character highlight artefact distinct
from the rest of the row.

``HokoraButton`` moves the cursor past end-of-text so
``SelectableIcon.get_cursor_coords`` returns ``None`` and no cursor is
drawn. These tests pin that contract across label changes and signal
delivery so future urwid upgrades or accidental refactors cannot
silently re-introduce the artefact.

CheckBox and RadioButton intentionally keep their cursor on the state
glyph (the X / space inside ``[X]`` / ``[ ]``) - that inverted cell is
the visible "this row is focused" affordance. ``HokoraRadioButton``
exists only to swap glyphs, not to suppress the cursor.
"""

from __future__ import annotations

from hokora_tui.widgets.hokora_button import _NO_CURSOR_POSITION, HokoraButton
from hokora_tui.widgets.hokora_radio import HokoraRadioButton


def _focused_canvas(widget, cols: int = 30):
    """Render *widget* focused at *cols* width and return the canvas."""
    return widget.render((cols,), focus=True)


# ── Button: cursor suppressed ─────────────────────────────────────────


def test_button_focused_canvas_has_no_cursor() -> None:
    btn = HokoraButton("Click me")
    assert _focused_canvas(btn).cursor is None


def test_button_set_label_preserves_no_cursor() -> None:
    """``Button.set_label`` mutates the inner SelectableIcon's text in
    place; verify the cursor-position invariant survives the rewrite."""
    btn = HokoraButton("Original")
    btn.set_label("A new label that is much longer than the original was")
    assert _focused_canvas(btn).cursor is None


def test_button_empty_label_has_no_cursor() -> None:
    """Edge case: zero-length label. SelectableIcon's
    ``cursor_position > len(text)`` check still suppresses the cursor
    since ``_NO_CURSOR_POSITION`` >> 0."""
    btn = HokoraButton("")
    assert _focused_canvas(btn).cursor is None


def test_button_click_signal_still_fires() -> None:
    """Cursor suppression must not break the click-signal contract."""
    seen: list = []
    btn = HokoraButton("Click", on_press=lambda b: seen.append(b))
    btn.keypress((10,), "enter")
    assert seen == [btn]


def test_button_label_text_unchanged() -> None:
    """Label text must round-trip identically (no glyph mutation)."""
    btn = HokoraButton("Disconnect")
    assert btn.get_label() == "Disconnect"


def test_sentinel_is_past_any_plausible_label() -> None:
    """The sentinel must be larger than any realistic UI label so the
    ``cursor_position > len(text)`` check in
    ``SelectableIcon.get_cursor_coords`` always fires."""
    assert _NO_CURSOR_POSITION > 1_000_000


# ── RadioButton: cursor INTENTIONALLY preserved on state glyph ────────


def test_radio_state_glyph_cursor_preserved() -> None:
    """RadioButton state icons (`[X]` / `[ ]`) keep ``cursor_position=1``
    so the focused row inverts the X / space cell against the focus
    background. That inverted cell is the visible focus affordance for
    radio rows; removing it would make the focused option indistinct
    from the unfocused options."""
    for icon in HokoraRadioButton.states.values():
        assert icon._cursor_position == 1


def test_radio_glyphs_unchanged() -> None:
    """``[X]`` / ``[ ]`` glyphs (Hokora override of urwid's ``(X)``/``( )``)
    must still appear on focused render."""
    group: list = []
    rb_on = HokoraRadioButton(group, "A", state=True)
    rb_off = HokoraRadioButton(group, "B", state=False)
    text_on = b"".join(_focused_canvas(rb_on).text).decode("utf-8")
    text_off = b"".join(_focused_canvas(rb_off).text).decode("utf-8")
    assert "[X]" in text_on
    assert "[ ]" in text_off


def test_radio_group_membership_intact() -> None:
    """Group registration must work unchanged."""
    group: list = []
    HokoraRadioButton(group, "A")
    HokoraRadioButton(group, "B")
    HokoraRadioButton(group, "C")
    assert len(group) == 3

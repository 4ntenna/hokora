# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the two-tier StatusArea notice-TTL contract (T1c).

Covers:

* ``set_context`` updates the underlying text but does NOT render while
  a notice is active (the gating that stops the periodic refresh job
  from clobbering user-facing notices).
* ``set_notice`` renders immediately with the level-attr glyph.
* TTL expiry restores the latest ``set_context`` text — not stale text.
* A second ``set_notice`` cancels the first's pending alarm
  (replacement, not queue).
* No-loop fallback: ``set_notice`` still renders synchronously when the
  loop hasn't been attached yet (used during early init / tests).
"""

from __future__ import annotations

from hokora_tui.widgets.status_area import StatusArea


class _FakeLoop:
    """Minimal urwid.MainLoop stand-in capturing alarm scheduling."""

    def __init__(self):
        self.alarms: list = []
        self.removed: list = []
        self._next_handle = 0

    def set_alarm_in(self, delay, cb):
        self._next_handle += 1
        handle = self._next_handle
        self.alarms.append((handle, delay, cb))
        return handle

    def remove_alarm(self, handle):
        self.removed.append(handle)


def _ctx_text(area: StatusArea) -> str:
    """Extract the rendered text on the middle (context) line."""
    raw = area._context.get_text()[0]
    return raw if isinstance(raw, str) else "".join(s for _a, s in raw)


def test_set_context_renders_immediately_when_no_notice():
    area = StatusArea()
    area.set_context("# general")
    assert _ctx_text(area) == "# general"


def test_set_notice_renders_with_prefix():
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_notice("This channel is read-only", level="warn")
    rendered = _ctx_text(area)
    # Text-only prefix; no emoji/unicode glyph (operator preference).
    assert "[warn]" in rendered
    assert "This channel is read-only" in rendered


def test_set_context_during_notice_does_not_render():
    """Periodic refresh job must not clobber a live notice."""
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_notice("Cache cleared", level="info", duration=4.0)
    # Refresh job calls set_context — should NOT visibly replace the notice.
    area.set_context("# general")
    assert "Cache cleared" in _ctx_text(area)
    # But the underlying context text IS updated, so when notice expires
    # the user sees current state.
    assert area._context_text == "# general"


def test_notice_ttl_restores_latest_context():
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_context("# old-channel")
    area.set_notice("Switching channels", level="info", duration=4.0)
    # Refresh job updates the context line during the notice's TTL.
    area.set_context("# new-channel")
    # Manually fire the alarm to simulate TTL expiry.
    assert len(loop.alarms) == 1
    _h, _delay, cb = loop.alarms[0]
    cb(None, None)
    # Notice cleared, user sees the LATEST context (not stale "# old-channel").
    assert _ctx_text(area) == "# new-channel"
    assert area._notice_text is None


def test_second_notice_cancels_first_alarm():
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_notice("First", level="info", duration=4.0)
    first_handle = loop.alarms[0][0]
    area.set_notice("Second", level="warn", duration=4.0)
    # First alarm cancelled; second alarm scheduled.
    assert first_handle in loop.removed
    assert len(loop.alarms) == 2  # one cancelled + one new
    assert "Second" in _ctx_text(area)


def test_no_loop_fallback_renders_synchronously():
    """Without a loop attached, notice persists until explicitly replaced.

    Used by early-init call sites before MainLoop construction.
    """
    area = StatusArea()
    # No set_loop call — _loop is None.
    area.set_notice("Bootstrap message", level="info")
    assert "Bootstrap message" in _ctx_text(area)
    # No alarm scheduled.
    # set_context with no notice should still work (notice still stuck).
    area.set_context("# channel")
    # Notice still visible — TTL never fires without a loop.
    assert "Bootstrap message" in _ctx_text(area)


def test_minimum_duration_clamp():
    """Duration < 0.5s is clamped to prevent invisible flashes."""
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_notice("Quick", level="info", duration=0.1)
    _h, delay, _cb = loop.alarms[0]
    assert delay == 0.5


def test_level_prefix_mapping():
    """Each level maps to its expected text prefix. info has no prefix."""
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)

    area.set_notice("info-msg", level="info")
    rendered = _ctx_text(area)
    assert "[warn]" not in rendered
    assert "[error]" not in rendered
    assert "info-msg" in rendered

    area.set_notice("warn-msg", level="warn")
    assert "[warn]" in _ctx_text(area)

    area.set_notice("err-msg", level="error")
    assert "[error]" in _ctx_text(area)


def test_unknown_level_falls_back_to_info():
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_notice("strange", level="bogus")
    rendered = _ctx_text(area)
    # Unknown level → info → no prefix.
    assert "[warn]" not in rendered
    assert "[error]" not in rendered
    assert "strange" in rendered


def test_set_connection_unaffected_by_notice():
    """Notices live on the context line; connection line is independent."""
    area = StatusArea()
    loop = _FakeLoop()
    area.set_loop(loop)
    area.set_notice("Some warning", level="warn")
    area.set_connection("connected", "MyNode")
    conn_text = area._connection.get_text()[0]
    rendered = conn_text if isinstance(conn_text, str) else "".join(s for _a, s in conn_text)
    assert "Connected" in rendered
    assert "MyNode" in rendered

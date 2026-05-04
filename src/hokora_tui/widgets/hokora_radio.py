# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""RadioButton with `[X]` / `[ ]` glyphs for visual parity with CheckBox.

urwid's stock `RadioButton` renders `(X)` / `( )`. The rest of the Settings
tab uses `CheckBox` (`[X]` / `[ ]`), so radio rows stand out for no good
reason. Mutual-exclusion semantics + keypress flow are unchanged - only
the icon glyphs differ.

The cursor on each state icon is intentional: it sits on the X / space
inside the brackets and inverts that cell on focus, which is the visible
"this row is focused" affordance for radio + checkbox rows. Buttons get
the cursor suppressed instead - see ``HokoraButton``.
"""

from __future__ import annotations

import urwid


class HokoraRadioButton(urwid.RadioButton):
    states = {
        True: urwid.SelectableIcon("[X]", 1),
        False: urwid.SelectableIcon("[ ]", 1),
        "mixed": urwid.SelectableIcon("[#]", 1),
    }

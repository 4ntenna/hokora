# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Structural invariants on the permission bitmask.

Per-bit literal checks were dropped: ``assert PERM_X == 0x0040`` is a
literal-equals-itself tautology that would also typo if ``constants.py``
typo'd. The remaining tests cover the two real invariants — that
``PERM_ALL`` is the canonical full-mask value, and that
``PERM_EVERYONE_DEFAULT`` includes the flags that were added after the
initial role layout.
"""

from hokora.constants import (
    PERM_ALL,
    PERM_DELETE_OWN,
    PERM_EVERYONE_DEFAULT,
    PERM_READ_HISTORY,
    PERM_USE_MENTIONS,
)


def test_perm_all_is_full_mask():
    assert PERM_ALL == 0xFFFF


def test_everyone_default_includes_new_flags():
    assert PERM_EVERYONE_DEFAULT & PERM_USE_MENTIONS
    assert PERM_EVERYONE_DEFAULT & PERM_READ_HISTORY
    assert PERM_EVERYONE_DEFAULT & PERM_DELETE_OWN

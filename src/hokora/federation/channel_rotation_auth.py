# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Channel RNS identity rotation grace-window helpers.

After a channel's RNS identity is rotated, federated peers may still
re-broadcast stale announces from the old identity for a time bounded
by ``channels.rotation_grace_end``. Rather than treating
every old-identity sighting as an attack or silently accepting it, we
centralise the grace check so every consumer uses the same semantics:

* Outside the grace window: announces from the old identity MUST be
  treated as identity-mismatch and logged.
* Inside the grace window: announces from the old identity are
  tolerated (the peer simply hasn't observed the rotation announce yet),
  but still logged at debug so operators can see the settling behaviour.

Note: per-message signature verification on ``handle_push_messages`` /
``MirrorMessageIngestor`` does NOT need this helper. Those paths trust
the peer via the NODE identity (stored in ``Peer.identity_hash`` after
the federation handshake) and verify per-message LXMF sender signatures
— neither surface references the channel's RNS identity, so channel
rotation doesn't create a federation signature gap there. This module
only gates announce-reception decisions.
"""

from __future__ import annotations

import time
from typing import Optional


def is_within_grace(grace_end: Optional[float], now: Optional[float] = None) -> bool:
    """Return True when the channel's rotation grace window has not expired.

    Args:
        grace_end: UNIX timestamp captured at rotation time by
            ``hokora channel rotate-rns-key``, or None if the channel has
            never been rotated.
        now: Optional override for the current time (used in tests to
            pin the clock). Defaults to ``time.time()``.

    Returns False when ``grace_end`` is None (no rotation recorded) or
    the grace window has already expired.
    """
    if grace_end is None:
        return False
    if now is None:
        now = time.time()
    return now < grace_end


def matches_identity(
    current_identity_hash: Optional[str],
    rotation_old_hash: Optional[str],
    rotation_grace_end: Optional[float],
    candidate_hash: str,
    now: Optional[float] = None,
) -> bool:
    """Accept a candidate identity hash under rotation-aware semantics.

    A candidate matches when it is either:
      * equal to the channel's current ``identity_hash`` (ordinary case), OR
      * equal to the channel's pre-rotation identity AND the grace
        window is still open.

    Passing three discrete fields rather than the whole Channel row keeps
    the helper ORM-agnostic (useful in unit tests and non-daemon
    contexts that don't have a loaded Channel object).
    """
    if not candidate_hash:
        return False
    if current_identity_hash and candidate_hash == current_identity_hash:
        return True
    if (
        rotation_old_hash
        and candidate_hash == rotation_old_hash
        and is_within_grace(rotation_grace_end, now=now)
    ):
        return True
    return False

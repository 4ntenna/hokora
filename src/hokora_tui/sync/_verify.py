# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""TUI-side Ed25519 verification of incoming message wire dicts.

Single chokepoint used by both the history-sync path
(``HistoryClient.handle_history``) and the live-event path
(``commands.event_dispatcher.dispatch_event`` for ``"message"`` events).
Without this helper, the two paths drifted: history verified, live did not.

Returns a three-state result:

* ``True``  — signature material present and verifies; sender's pubkey
              is cached for TOFU MITM detection on subsequent messages.
* ``False`` — signature material present and verification FAILS, OR
              the sender's cached pubkey changed (TOFU MITM guard).
* ``None``  — signature material absent on the wire (no opinion). The
              caller decides how to render — the storage default
              currently treats absent-as-trusted, which is being phased
              out as more wire paths populate ``sender_public_key``.

The TOFU cache is the dict passed in (typically ``SyncState.identity_keys``).
Mutations to the dict are reflected in shared state — no copy.

The optional hooks let the engine persist pins and surface key-change
warnings without duplicating TOFU logic at the two call sites:
``on_new_key`` fires once per sender on first successful verification,
``on_key_conflict`` when a cached pin no longer matches the wire key.
Both default to ``None``, leaving the bare-dict call unchanged.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from hokora.security.verification import VerificationService

logger = logging.getLogger(__name__)


def verify_message_signature(
    msg: dict,
    identity_keys: dict[str, bytes],
    *,
    on_new_key: Optional[Callable[[str, bytes], None]] = None,
    on_key_conflict: Optional[Callable[[str, bytes, bytes], None]] = None,
) -> Optional[bool]:
    """Verify a message wire dict's Ed25519 signature, with TOFU MITM check.

    Args:
        msg: wire-dict shape from ``encode_message_for_sync`` /
             ``encode_message_for_wire``. Reads ``sender_hash``,
             ``sender_public_key``, ``lxmf_signature``, ``lxmf_signed_part``.
        identity_keys: shared TOFU cache (sender_hash → pubkey bytes).
                       Updated on first successful verification per sender.
        on_new_key: called with ``(sender_hash, public_key)`` the first
                    time a sender is pinned (write-through hook). May run
                    on RNS threads.
        on_key_conflict: called with ``(sender_hash, pinned_key,
                         observed_key)`` when the cached pin differs from
                         the wire key. May run on RNS threads.

    Returns:
        True / False / None as documented in the module docstring.
    """
    sig = msg.get("lxmf_signature")
    sender = msg.get("sender_hash")
    pub_key = msg.get("sender_public_key")
    signed_part = msg.get("lxmf_signed_part")

    if not (sig and pub_key and signed_part and sender):
        return None

    cached = identity_keys.get(sender)
    if cached and cached != pub_key:
        logger.warning("PUBLIC KEY CHANGED for %s — possible MITM", sender)
        if on_key_conflict is not None:
            on_key_conflict(sender, cached, pub_key)
        return False

    verified = VerificationService.verify_ed25519_signature(pub_key, signed_part, sig)
    if verified:
        was_new = not cached
        identity_keys[sender] = pub_key
        if was_new and on_new_key is not None:
            on_new_key(sender, pub_key)
    else:
        logger.warning("Signature verification FAILED for msg %s", msg.get("msg_hash"))
    return verified

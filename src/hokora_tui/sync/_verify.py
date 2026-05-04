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
"""

from __future__ import annotations

import logging
from typing import Optional

from hokora.security.verification import VerificationService

logger = logging.getLogger(__name__)


def verify_message_signature(
    msg: dict,
    identity_keys: dict[str, bytes],
) -> Optional[bool]:
    """Verify a message wire dict's Ed25519 signature, with TOFU MITM check.

    Args:
        msg: wire-dict shape from ``encode_message_for_sync`` /
             ``encode_message_for_wire``. Reads ``sender_hash``,
             ``sender_public_key``, ``lxmf_signature``, ``lxmf_signed_part``.
        identity_keys: shared TOFU cache (sender_hash → pubkey bytes).
                       Updated on first successful verification per sender.

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
        return False

    verified = VerificationService.verify_ed25519_signature(pub_key, signed_part, sig)
    if verified:
        identity_keys[sender] = pub_key
    else:
        logger.warning("Signature verification FAILED for msg %s", msg.get("msg_hash"))
    return verified

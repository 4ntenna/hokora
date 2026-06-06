# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""ForgetKeyCommand — drop a pinned TOFU sender key (store + in-memory)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from hokora.federation.auth import IDENTITY_HASH_HEX_LENGTH

if TYPE_CHECKING:
    from hokora_tui.commands._base import CommandContext

# Sender hashes are RNS identity.hexhash values (truncated-hash width),
# not the 64-hex SHA-256 width used for message hashes.
_SENDER_HASH = re.compile(r"^[0-9a-f]{%d}$" % IDENTITY_HASH_HEX_LENGTH)


class ForgetKeyCommand:
    """``/forget-key <sender_hash>`` — un-pin a sender's TOFU key.

    Drops the persisted pin and the in-memory entry so the sender is
    re-pinned on next contact. The explicit reset after a key-change
    warning; use only once the change is verified out-of-band (the
    client mirror of ``PeerKeyStore.update_key``). Requires the full
    sender hash, no prefix matching, on a security-critical delete.

    Deletes the persisted pin before the in-memory one so an in-flight
    verify re-persists rather than diverging from the store.
    """

    name = "forget-key"
    aliases: tuple[str, ...] = ()
    summary = "Forget a pinned sender key (/forget-key <sender_hash>)"

    def execute(self, ctx: "CommandContext", args: str) -> None:
        sender = args.strip().lower()
        if not _SENDER_HASH.match(sender):
            ctx.status.set_context(
                f"Usage: /forget-key <{IDENTITY_HASH_HEX_LENGTH}-hex sender hash>"
            )
            return
        short = sender[:16]
        removed = False
        store_failed = False
        if ctx.db is not None:
            try:
                if ctx.db.tofu_keys.get(sender) is not None:
                    removed = True
                ctx.db.tofu_keys.delete(sender)
            except Exception:
                store_failed = True
                ctx.log.exception("/forget-key: persisted pin delete failed")
        if ctx.engine is not None:
            removed = ctx.engine.forget_identity_key(sender) or removed
        if store_failed:
            ctx.status.set_context(f"Client DB error; persisted pin for {short} not cleared")
        elif ctx.db is None and removed:
            ctx.status.set_context(
                f"Forgot in-memory key for {short}; client DB unavailable, "
                "persisted pin (if any) not cleared"
            )
        elif removed:
            ctx.status.set_context(f"Forgot pinned key for {short}")
        else:
            ctx.status.set_context(f"No pinned key for {short}")

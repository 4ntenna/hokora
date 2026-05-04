# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""MessageStore — per-channel message cache for the TUI.

The on-disk shape of ``reactions`` is JSON text; the in-memory contract
across every consumer (MessageWidget, sync_callbacks merge logic, search
and thread views) is dict. The ``_serialize_reactions`` /
``_deserialize_reactions`` chokepoint pair keeps the store/get round-trip
symmetric so a cached row can be loaded, mutated, and re-stored without
the value getting doubly-JSON-encoded.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from hokora_tui.client_db._base import StoreBase


class MessageStore(StoreBase):
    """Stores + retrieves cached channel messages."""

    def store(self, messages: list[dict]) -> None:
        with self._lock_unless_tx():
            self._store_unlocked(messages)

    def _store_unlocked(self, messages: list[dict]) -> None:
        for msg in messages:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO messages
                (msg_hash, channel_id, sender_hash, seq, timestamp, type, body,
                 display_name, reply_to, deleted, pinned, reactions, lxmf_signature,
                 received_at, verified, edited, has_thread,
                 encrypted_body, encryption_nonce, encryption_epoch)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    msg.get("msg_hash"),
                    msg.get("channel_id"),
                    msg.get("sender_hash"),
                    msg.get("seq"),
                    msg.get("timestamp"),
                    msg.get("type"),
                    msg.get("body"),
                    msg.get("display_name"),
                    msg.get("reply_to"),
                    1 if msg.get("deleted") else 0,
                    1 if msg.get("pinned") else 0,
                    _serialize_reactions(msg.get("reactions")),
                    msg.get("lxmf_signature"),
                    time.time(),
                    # ``verified`` is set explicitly by ``verify_message_signature``
                    # on both live (event_dispatcher) and history (HistoryClient)
                    # paths. Absent field → no cryptographic check was performed
                    # → store False so [UNVERIFIED] renders honestly.
                    1 if msg.get("verified") else 0,
                    1 if msg.get("edited") else 0,
                    1 if msg.get("has_thread") else 0,
                    msg.get("encrypted_body"),
                    msg.get("encryption_nonce"),
                    msg.get("encryption_epoch"),
                ),
            )
        self._commit_unless_tx()

    def get(self, channel_id: str, limit: int = 50, before_seq: Optional[int] = None) -> list[dict]:
        if before_seq is not None:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE channel_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?",
                (channel_id, before_seq, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE channel_id = ? ORDER BY seq DESC LIMIT ?",
                (channel_id, limit),
            ).fetchall()
        out = []
        for r in reversed(rows):
            d = dict(r)
            # Symmetric round-trip: storage encodes via _serialize_reactions,
            # read decodes via _deserialize_reactions. Without this, callers
            # like ``handle_thread_reply_push`` that mutate a cached message
            # dict and re-store it via ``store_messages([m])`` end up
            # double-encoding the JSON string, which crashes the widget.
            d["reactions"] = _deserialize_reactions(d.get("reactions"))
            out.append(d)
        return out

    def delete_channel(self, channel_id: str) -> None:
        """Delete all cached messages for a channel."""
        with self._lock_unless_tx():
            self._conn.execute("DELETE FROM messages WHERE channel_id = ?", (channel_id,))
            self._commit_unless_tx()


# ─────────────────────────────────────────────────────────────────────
# Reactions JSON round-trip — single chokepoint pair.
# ─────────────────────────────────────────────────────────────────────


def _serialize_reactions(value) -> str:
    """Serialise the reactions field to JSON text for the on-disk column.

    Defensive against pre-fix doubly-encoded inputs and any unaudited
    caller path that passes a JSON-string instead of a dict: if ``value``
    is already a string that parses as a dict, treat it as already
    serialised and pass through. Anything else round-trips via
    ``json.dumps``, with a fallback to ``'{}'`` on encoding failure or
    non-dict input.
    """
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return "{}"
        return value if isinstance(parsed, dict) else "{}"
    if not isinstance(value, dict):
        return "{}"
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return "{}"


def _deserialize_reactions(value) -> dict:
    """Coerce the reactions column back to a dict for in-memory consumers.

    Tolerates the historical doubly-encoded shape (e.g. ``'"{}"'``):
    iteratively unwraps JSON layers until a dict is reached, or gives up
    to ``{}`` on any failure path. Safe to call on already-deserialised
    dicts (no-op).
    """
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    cur = value
    for _ in range(3):
        try:
            cur = json.loads(cur)
        except (json.JSONDecodeError, TypeError):
            return {}
        if isinstance(cur, dict):
            return cur
        if not isinstance(cur, str):
            return {}
    return {}

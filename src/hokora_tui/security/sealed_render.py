# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Render-time sealed-channel decrypt for the TUI.

Sealed channel ciphertext is persisted in ``messages.encrypted_body`` /
``encryption_nonce`` / ``encryption_epoch`` (schema v8). This
helper resolves a row's renderable body — preferring the plaintext
``body`` column if set (e.g., non-sealed channels, or a sealed row
already migrated through), otherwise decrypting the ciphertext via the
SealedKeyStore.

Cryptographic shape mirrors the daemon's ``SealedChannelManager``:
AES-256-GCM with the channel_id encoded as additional authenticated
data. Decrypt failure yields a stable user-facing marker so the wire
dict is still well-formed and the TUI never silently drops a message.
"""

from __future__ import annotations

import logging
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

DECRYPT_FAILED_MARKER = "[encrypted - key unavailable]"


def body_for_render(msg: dict[str, Any], sealed_keys) -> str:
    """Return the renderable body string for a message dict.

    ``msg`` is a row dict (the shape produced by ``MessageStore.get`` or
    a live-push wire payload). ``sealed_keys`` is a ``SealedKeyStore``
    instance (or anything with a ``get(channel_id) -> (key, epoch) | None``
    method, for testability).

    Resolution order:
      1. ``msg["body"]`` set → return it (plain channel, or a sealed row
         that arrived as plaintext over the legacy wire shape).
      2. ``msg["encrypted_body"]`` set → AES-256-GCM decrypt with the
         channel-scoped key, AAD = channel_id.
      3. Anything else → empty string (deleted-stub rows).

    Decrypt failures (missing key, wrong epoch, integrity mismatch) log
    at WARNING and return the stable marker.
    """
    body = msg.get("body")
    if body is not None and body != "":
        return body

    enc = msg.get("encrypted_body")
    nonce = msg.get("encryption_nonce")
    if not enc or not nonce:
        return ""

    channel_id = msg.get("channel_id") or ""
    if not channel_id:
        logger.warning("sealed render: ciphertext row missing channel_id")
        return DECRYPT_FAILED_MARKER

    held = sealed_keys.get(channel_id)
    if held is None:
        return DECRYPT_FAILED_MARKER
    key, current_epoch = held

    msg_epoch = msg.get("encryption_epoch")
    if msg_epoch is not None and msg_epoch != current_epoch:
        # Epoch rotation — caller may hold a previous key in a future
        # rev. For now, mismatch is unrenderable but not fatal.
        logger.warning(
            "sealed render: epoch mismatch ch=%s msg_epoch=%s held=%s",
            channel_id,
            msg_epoch,
            current_epoch,
        )
        return DECRYPT_FAILED_MARKER

    try:
        plaintext = AESGCM(key).decrypt(bytes(nonce), bytes(enc), channel_id.encode("utf-8"))
        return plaintext.decode("utf-8")
    except Exception:
        logger.warning(
            "sealed render: decrypt failed ch=%s seq=%s",
            channel_id,
            msg.get("seq"),
            exc_info=True,
        )
        return DECRYPT_FAILED_MARKER

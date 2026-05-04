# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Sealed-channel invariant: source of truth for every Message-write path.

Two fail-closed entry points share one ``_channel_is_sealed`` predicate:

  * :func:`seal_for_origin` — locally-originated writes (ingest, edit,
    pin system messages). Encrypts plaintext for sealed channels.
  * :func:`validate_mirror_payload` — federation-pushed rows. Validates
    that ciphertext is present and rejects plaintext-on-sealed; never
    re-encrypts.

Defence in depth: ``db/fts.py`` triggers gate on
``body IS NOT NULL AND encrypted_body IS NULL`` so a direct INSERT that
bypassed both helpers cannot leak sealed plaintext into the FTS index.
"""

from __future__ import annotations

from typing import Optional

from hokora.exceptions import PermissionDenied, SealedChannelError


def _channel_is_sealed(channel) -> bool:
    return bool(channel is not None and getattr(channel, "sealed", False))


def seal_for_origin(
    channel,
    plaintext: Optional[str],
    sealed_manager,
) -> tuple[Optional[str], Optional[bytes], Optional[bytes], Optional[int]]:
    """Encrypt ``plaintext`` for storage on a locally-originated write.

    Returns the ``(body, encrypted_body, nonce, epoch)`` 4-tuple to insert.
    A sealed channel with no group key raises ``PermissionDenied`` —
    never a silent plaintext fallback.
    """
    if not _channel_is_sealed(channel):
        return plaintext, None, None, None
    if not plaintext:
        return None, None, None, None
    if not sealed_manager:
        raise PermissionDenied("Sealed channel: sealed manager not initialised")
    if not sealed_manager.get_key(channel.id):
        raise PermissionDenied("Sealed channel: no encryption key available for this channel")
    try:
        nonce, ciphertext, epoch = sealed_manager.encrypt(channel.id, plaintext.encode("utf-8"))
    except Exception as exc:
        raise PermissionDenied(f"Sealed channel: encryption failed ({exc})") from exc
    return None, ciphertext, nonce, epoch


def validate_mirror_payload(
    channel,
    wire_body,
    wire_encrypted_body: Optional[bytes],
    wire_encryption_nonce: Optional[bytes],
    wire_encryption_epoch: Optional[int],
) -> tuple[Optional[str], Optional[bytes], Optional[bytes], Optional[int]]:
    """Validate a federation-pushed payload and return the row 4-tuple.

    Sealed channels require ciphertext and forbid plaintext — violations
    raise :class:`SealedChannelError` (caller maps to drop+log; no seq
    consumed). Non-sealed channels store plaintext and discard any
    ciphertext fields the peer sent.
    """
    if _channel_is_sealed(channel):
        if wire_body or not wire_encrypted_body:
            raise SealedChannelError(
                f"sealed channel requires ciphertext "
                f"(body_len={len(wire_body) if wire_body else 0} "
                f"enc_len={len(wire_encrypted_body) if wire_encrypted_body else 0})"
            )
        return None, wire_encrypted_body, wire_encryption_nonce, wire_encryption_epoch
    return wire_body, None, None, None

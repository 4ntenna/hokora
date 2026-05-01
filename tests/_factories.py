# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared mock factories for tests.

Module-level helpers (not pytest fixtures) so they can be called from
fixture bodies, parametrize decorators, and ad-hoc setup. Per-file
factories that have the same name but different shapes (e.g. multiple
``_make_mirror`` variants across the federation tests) are intentionally
kept local — the cost of unifying mock surfaces outweighs the benefit
of saving a few lines.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def make_mock_rns_identity() -> MagicMock:
    """A bare RNS-identity-shaped mock that can ``sign`` / ``validate``
    / ``get_public_key``. Used by epoch-handshake tests.

    The signing key returned here is 32 bytes (the Ed25519 signing-key
    portion of an RNS identity). Tests that need the full 64-byte
    X25519+Ed25519 wire blob construct that locally — see
    ``test_federation_handshake_orchestrator._make_identity_manager``.
    """
    identity = MagicMock()
    identity.sign = MagicMock(return_value=b"\x00" * 64)
    identity.validate = MagicMock(return_value=True)
    identity.get_public_key = MagicMock(return_value=b"\x01" * 32)
    return identity

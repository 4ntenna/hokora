# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Behavioral tests for the TOFU PeerKeyStore — fills audit gap 7c.

Critical security invariant: the default ``reject_key_change=True``
must actually raise ``FederationError`` when a peer's public key
changes without an explicit ``update_key`` override.
"""

import pytest

from hokora.federation.auth import PeerKeyStore
from hokora.exceptions import FederationError


def test_default_reject_key_change_is_true():
    ks = PeerKeyStore()
    assert ks._reject_key_change is True


def test_first_contact_stores_key():
    ks = PeerKeyStore()
    r = ks.check_and_store("a" * 64, b"\x01" * 32)
    assert r is True
    assert ks.get_key("a" * 64) == b"\x01" * 32


def test_same_key_returns_true():
    ks = PeerKeyStore()
    ks.check_and_store("a" * 64, b"\x01" * 32)
    r = ks.check_and_store("a" * 64, b"\x01" * 32)
    assert r is True


def test_key_change_raises_federation_error_by_default():
    """The single most important TOFU invariant."""
    ks = PeerKeyStore()
    ks.check_and_store("a" * 64, b"\x01" * 32)
    with pytest.raises(FederationError, match="public key changed"):
        ks.check_and_store("a" * 64, b"\x02" * 32)
    # The in-memory key must not have been overwritten on failed change
    assert ks.get_key("a" * 64) == b"\x01" * 32


def test_reject_key_change_false_returns_false_not_raises():
    ks = PeerKeyStore(reject_key_change=False)
    ks.check_and_store("a" * 64, b"\x01" * 32)
    r = ks.check_and_store("a" * 64, b"\x02" * 32)
    assert r is False


def test_update_key_allows_explicit_rotation():
    ks = PeerKeyStore()
    ks.check_and_store("a" * 64, b"\x01" * 32)
    with pytest.raises(FederationError):
        ks.check_and_store("a" * 64, b"\x02" * 32)
    ks.update_key("a" * 64, b"\x02" * 32)
    # After update_key, new key is accepted
    r = ks.check_and_store("a" * 64, b"\x02" * 32)
    assert r is True


def test_independent_peers_do_not_interfere():
    ks = PeerKeyStore()
    ks.check_and_store("a" * 64, b"\x01" * 32)
    ks.check_and_store("b" * 64, b"\xff" * 32)
    assert ks.get_key("a" * 64) == b"\x01" * 32
    assert ks.get_key("b" * 64) == b"\xff" * 32


def test_missing_peer_returns_none():
    ks = PeerKeyStore()
    assert ks.get_key("nonexistent" + "x" * 53) is None

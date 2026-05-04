# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for core/identity.py — IdentityManager."""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def identity_dir(tmp_dir):
    d = tmp_dir / "identities"
    d.mkdir()
    return d


@pytest.fixture
def mock_reticulum():
    return MagicMock()


def _make_mock_identity(hexhash: str) -> MagicMock:
    """Build a MagicMock that satisfies IdentityManager's write contract.

    The real RNS.Identity.to_file(path) creates the file on disk; helpers
    in security/fs.py chmod it after creation, so the mock must actually
    write or chmod raises FileNotFoundError.
    """
    ident = MagicMock()
    ident.hexhash = hexhash

    def _to_file(path):
        with open(path, "wb") as f:
            f.write(b"\x00" * 80)

    ident.to_file.side_effect = _to_file
    return ident


class TestIdentityManager:
    def test_create_node_identity(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_identity = _make_mock_identity("a" * 32)
            mock_rns.Identity.return_value = mock_identity
            mock_rns.Identity.from_file.return_value = mock_identity

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            identity = mgr.get_or_create_node_identity()
            assert identity is not None
            assert identity.hexhash == "a" * 32

    def test_load_existing_node_identity(self, identity_dir, mock_reticulum):
        # Create a fake identity file
        (identity_dir / "node_identity").write_bytes(b"fake")

        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_identity = MagicMock()
            mock_identity.hexhash = "b" * 32
            mock_rns.Identity.from_file.return_value = mock_identity

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            identity = mgr.get_or_create_node_identity()
            mock_rns.Identity.from_file.assert_called_once()
            assert identity.hexhash == "b" * 32

    def test_get_or_create_channel_identity(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_identity = _make_mock_identity("c" * 32)
            mock_rns.Identity.return_value = mock_identity

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            identity = mgr.get_or_create_channel_identity("ch1")
            assert identity is not None

            # Calling again returns cached
            identity2 = mgr.get_or_create_channel_identity("ch1")
            assert identity is identity2

    def test_register_channel_destination(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_identity = _make_mock_identity("d" * 32)
            mock_rns.Identity.return_value = mock_identity

            mock_dest = MagicMock()
            mock_dest.hash = b"\x01" * 16
            mock_rns.Destination.return_value = mock_dest

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            dest = mgr.register_channel_destination("ch1")
            assert dest is not None
            assert mgr.get_destination("ch1") is dest

    def test_get_node_identity_hash(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_identity = _make_mock_identity("e" * 32)
            mock_rns.Identity.return_value = mock_identity

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            h = mgr.get_node_identity_hash()
            assert h == "e" * 32

    def test_list_channel_ids(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_rns.Identity.side_effect = lambda: _make_mock_identity("0" * 32)

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            assert mgr.list_channel_ids() == []
            mgr.get_or_create_channel_identity("ch1")
            mgr.get_or_create_channel_identity("ch2")
            assert sorted(mgr.list_channel_ids()) == ["ch1", "ch2"]

    def test_get_identity_returns_none_for_unknown(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS"):
            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            assert mgr.get_identity("nonexistent") is None
            assert mgr.get_destination("nonexistent") is None

    def test_node_identity_cached(self, identity_dir, mock_reticulum):
        with patch("hokora.core.identity.RNS") as mock_rns:
            mock_identity = _make_mock_identity("f" * 32)
            mock_rns.Identity.return_value = mock_identity

            from hokora.core.identity import IdentityManager

            mgr = IdentityManager(identity_dir, mock_reticulum)

            id1 = mgr.get_or_create_node_identity()
            id2 = mgr.get_or_create_node_identity()
            assert id1 is id2

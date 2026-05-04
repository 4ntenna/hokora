# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for ``channel_rotation_auth`` helpers."""

from hokora.federation.channel_rotation_auth import (
    is_within_grace,
    matches_identity,
)


class TestIsWithinGrace:
    def test_none_grace_end_returns_false(self):
        assert is_within_grace(None) is False

    def test_future_grace_end_returns_true(self):
        assert is_within_grace(grace_end=100.0, now=50.0) is True

    def test_past_grace_end_returns_false(self):
        assert is_within_grace(grace_end=100.0, now=500.0) is False

    def test_equal_timestamps_returns_false(self):
        # Grace expires at exactly grace_end; equality is not "within".
        assert is_within_grace(grace_end=100.0, now=100.0) is False


class TestMatchesIdentity:
    def test_current_identity_matches(self):
        assert (
            matches_identity(
                current_identity_hash="a" * 64,
                rotation_old_hash=None,
                rotation_grace_end=None,
                candidate_hash="a" * 64,
            )
            is True
        )

    def test_old_identity_within_grace_matches(self):
        assert (
            matches_identity(
                current_identity_hash="b" * 64,
                rotation_old_hash="a" * 64,
                rotation_grace_end=1000.0,
                candidate_hash="a" * 64,
                now=500.0,
            )
            is True
        )

    def test_old_identity_after_grace_rejected(self):
        assert (
            matches_identity(
                current_identity_hash="b" * 64,
                rotation_old_hash="a" * 64,
                rotation_grace_end=1000.0,
                candidate_hash="a" * 64,
                now=5000.0,
            )
            is False
        )

    def test_unrelated_identity_rejected(self):
        assert (
            matches_identity(
                current_identity_hash="b" * 64,
                rotation_old_hash="a" * 64,
                rotation_grace_end=1e12,
                candidate_hash="z" * 64,
                now=0,
            )
            is False
        )

    def test_empty_candidate_rejected(self):
        assert (
            matches_identity(
                current_identity_hash="a" * 64,
                rotation_old_hash=None,
                rotation_grace_end=None,
                candidate_hash="",
            )
            is False
        )

    def test_no_rotation_recorded_only_current_matches(self):
        # If the channel has never been rotated, rotation_* are None — the
        # old-identity branch is unreachable regardless of candidate.
        assert (
            matches_identity(
                current_identity_hash="a" * 64,
                rotation_old_hash=None,
                rotation_grace_end=None,
                candidate_hash="b" * 64,
            )
            is False
        )

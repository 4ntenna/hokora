# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for SyncState dataclass."""

from hokora.constants import CDSP_PROFILE_FULL
from hokora_tui.sync.state import SyncState


class TestDefaults:
    def test_all_collection_fields_default_to_empty(self):
        s = SyncState()
        assert s.channel_identities == {}
        assert s.channel_dest_hashes == {}
        assert s.pending_pubkeys == {}
        assert s.pending_connects == {}
        assert s.pending_redeems == {}
        assert s.cursors == {}
        assert s.pending_nonces == {}
        assert s.seq_warnings == {}
        assert s.identity_keys == {}

    def test_scalar_defaults(self):
        s = SyncState()
        assert s.last_nonce_cleanup == 0.0
        assert s.display_name is None
        assert s.sync_profile == CDSP_PROFILE_FULL
        assert s.cdsp_session_id is None
        assert s.resume_token is None
        assert s.deferred_count == 0
        assert s.pending_media_path is None
        assert s.pending_media_save_path is None


class TestMutationIsolation:
    def test_two_instances_are_independent(self):
        """Each SyncState gets its own dict — no shared default-arg reuse."""
        a = SyncState()
        b = SyncState()
        a.cursors["ch1"] = 5
        assert "ch1" not in b.cursors

    def test_two_instances_independent_pending_nonces(self):
        a = SyncState()
        b = SyncState()
        a.pending_nonces[b"\x00" * 16] = 1.0
        assert len(b.pending_nonces) == 0


class TestLiveMutation:
    def test_dict_mutation_via_reference(self):
        """Subsystems holding a SyncState ref must see mutations via live view."""
        s = SyncState()
        cursors_ref = s.cursors
        cursors_ref["ch1"] = 42
        assert s.cursors["ch1"] == 42

    def test_scalar_mutation_via_attribute(self):
        s = SyncState()
        s.display_name = "alice"
        assert s.display_name == "alice"
        s.sync_profile = 0x02
        assert s.sync_profile == 0x02


class TestCleanupStaleNonces:
    def test_removes_nonces_older_than_max_age(self):
        import time

        s = SyncState()
        old = b"\xaa" * 16
        fresh = b"\xbb" * 16
        s.pending_nonces[old] = time.time() - (s._NONCE_MAX_AGE + 5)
        s.pending_nonces[fresh] = time.time()
        s.last_nonce_cleanup = 0.0  # bypass throttle

        stale = s.cleanup_stale_nonces()

        assert old in stale
        assert fresh not in stale
        assert old not in s.pending_nonces
        assert fresh in s.pending_nonces

    def test_throttled_within_interval(self):
        import time

        s = SyncState()
        s.pending_nonces[b"\xcc" * 16] = time.time() - (s._NONCE_MAX_AGE + 5)
        s.last_nonce_cleanup = time.time()  # just ran

        stale = s.cleanup_stale_nonces()

        assert stale == []
        assert b"\xcc" * 16 in s.pending_nonces  # not evicted because throttled

    def test_updates_last_cleanup_when_run(self):

        s = SyncState()
        before = s.last_nonce_cleanup
        s.cleanup_stale_nonces()
        assert s.last_nonce_cleanup >= before
        assert s.last_nonce_cleanup > 0

    def test_empty_pending_nonces_is_safe(self):
        s = SyncState()
        s.last_nonce_cleanup = 0.0
        assert s.cleanup_stale_nonces() == []


class TestFieldsPresent:
    """Spec test — if we drop a field expected by the plan, these fail."""

    def test_expected_fields_exist(self):
        s = SyncState()
        expected = {
            "channel_identities",
            "channel_dest_hashes",
            "pending_pubkeys",
            "pending_connects",
            "pending_redeems",
            "cursors",
            "pending_nonces",
            "last_nonce_cleanup",
            "seq_warnings",
            "identity_keys",
            "display_name",
            "sync_profile",
            "cdsp_session_id",
            "resume_token",
            "deferred_count",
            "pending_media_path",
            "pending_media_save_path",
        }
        assert expected.issubset(set(s.__dict__.keys()))

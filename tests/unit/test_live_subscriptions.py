# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for LiveSubscriptionManager subscriber limits + sender_public_key plumbing."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import msgpack

from hokora.constants import MAX_SUBSCRIBERS_PER_CHANNEL, MAX_TOTAL_SUBSCRIBERS
from hokora.protocol.live import LiveSubscriptionManager
from hokora.protocol.sync_utils import populate_sender_pubkey


def _make_link():
    """Create a unique mock RNS.Link."""
    link = MagicMock()
    link.status = 1  # RNS.Link.ACTIVE
    return link


class TestLiveSubscriptionLimits:
    def test_subscribe_returns_true(self):
        mgr = LiveSubscriptionManager()
        link = _make_link()
        assert mgr.subscribe("ch1", link) is True
        assert link in mgr.get_subscribers("ch1")

    def test_per_channel_limit_rejects(self):
        mgr = LiveSubscriptionManager()
        links = [_make_link() for _ in range(MAX_SUBSCRIBERS_PER_CHANNEL)]
        for link in links:
            assert mgr.subscribe("ch1", link) is True

        # Next one should be rejected
        extra = _make_link()
        assert mgr.subscribe("ch1", extra) is False
        assert extra not in mgr.get_subscribers("ch1")

    def test_global_limit_rejects(self):
        mgr = LiveSubscriptionManager()
        # Spread across channels to stay under per-channel limit
        channels_needed = (MAX_TOTAL_SUBSCRIBERS // MAX_SUBSCRIBERS_PER_CHANNEL) + 1
        count = 0
        for i in range(channels_needed):
            ch_id = f"ch{i}"
            per_ch = min(MAX_SUBSCRIBERS_PER_CHANNEL, MAX_TOTAL_SUBSCRIBERS - count)
            for _ in range(per_ch):
                link = _make_link()
                result = mgr.subscribe(ch_id, link)
                if result:
                    count += 1
                if count >= MAX_TOTAL_SUBSCRIBERS:
                    break
            if count >= MAX_TOTAL_SUBSCRIBERS:
                break

        assert count == MAX_TOTAL_SUBSCRIBERS
        # One more should fail
        extra = _make_link()
        assert mgr.subscribe("overflow", extra) is False

    def test_unsubscribe_frees_slot(self):
        mgr = LiveSubscriptionManager()
        links = [_make_link() for _ in range(MAX_SUBSCRIBERS_PER_CHANNEL)]
        for link in links:
            mgr.subscribe("ch1", link)

        # At limit — new subscribe fails
        extra = _make_link()
        assert mgr.subscribe("ch1", extra) is False

        # Free one slot
        mgr.unsubscribe("ch1", links[0])

        # Now it should succeed
        assert mgr.subscribe("ch1", extra) is True

    def test_unsubscribe_all_frees_global_count(self):
        mgr = LiveSubscriptionManager()
        link = _make_link()
        mgr.subscribe("ch1", link)
        mgr.subscribe("ch2", link)

        mgr.unsubscribe_all(link)
        assert len(mgr.get_subscribers("ch1")) == 0
        assert len(mgr.get_subscribers("ch2")) == 0

    def test_subscribe_idempotent(self):
        mgr = LiveSubscriptionManager()
        link = _make_link()
        assert mgr.subscribe("ch1", link) is True
        assert mgr.subscribe("ch1", link) is True
        # Should only count once
        assert len(mgr.get_subscribers("ch1")) == 1


# ─────────────────────────────────────────────────────────────────────
# populate_sender_pubkey helper + push_message wire-dict plumbing
# ─────────────────────────────────────────────────────────────────────


def _msg(channel_id="ch1", sender="s" * 32, body="hello"):
    """Build a non-sealed ORM-shaped message for encode_message_for_wire."""
    return SimpleNamespace(
        msg_hash="h" * 64,
        channel_id=channel_id,
        sender_hash=sender,
        seq=1,
        thread_seq=None,
        timestamp=1234.5,
        type=0x01,
        body=body,
        media_path=None,
        media_meta=None,
        reply_to=None,
        deleted=False,
        pinned=False,
        pinned_at=None,
        edit_chain=None,
        reactions=None,
        lxmf_signature=b"sig",
        lxmf_signed_part=b"signed",
        display_name=None,
        mentions=None,
        encrypted_body=None,
        encryption_nonce=None,
        encryption_epoch=None,
    )


class TestPopulateSenderPubkey:
    """Single-chokepoint helper for filling the wire-dict pubkey field."""

    def test_fills_when_provided(self):
        d = {"sender_public_key": None}
        populate_sender_pubkey(d, b"x" * 32)
        assert d["sender_public_key"] == b"x" * 32

    def test_noop_when_none(self):
        d = {"sender_public_key": None}
        populate_sender_pubkey(d, None)
        assert d["sender_public_key"] is None

    def test_noop_when_empty_bytes(self):
        d = {"sender_public_key": None}
        populate_sender_pubkey(d, b"")
        assert d["sender_public_key"] is None


class TestLivePushSenderPubkey:
    """``push_message`` threads ``sender_public_key`` into every wire dict
    so the TUI can re-verify Ed25519 signatures end-to-end on live events.
    Mirror chokepoint of the bulk sync-response encoder.
    """

    def _push_and_capture(self, mgr: LiveSubscriptionManager, link, sender_public_key=None) -> dict:
        """Invoke push_message on a 1-subscriber channel and return the wire dict."""
        sent_payloads: list[bytes] = []

        def _capture(*args, **kwargs):
            # _push_to_subscribers signature is (channel, subs, event_data, type, dict).
            # We only need the bytes payload (third positional arg).
            sent_payloads.append(args[2])

        mgr._push_to_subscribers = _capture  # type: ignore[method-assign]
        mgr.subscribe("ch1", link)
        mgr.push_message("ch1", _msg(), sender_public_key=sender_public_key)
        assert sent_payloads, "push_message did not emit any wire dict"
        # encode_push_event wraps msg in {"event": ..., "data": ...}
        envelope = msgpack.unpackb(sent_payloads[0], raw=False)
        return envelope["data"]

    def test_pubkey_populated_when_provided(self):
        mgr = LiveSubscriptionManager()
        link = _make_link()
        wire = self._push_and_capture(mgr, link, sender_public_key=b"k" * 32)
        assert wire.get("sender_public_key") == b"k" * 32

    def test_pubkey_absent_when_kwarg_omitted(self):
        mgr = LiveSubscriptionManager()
        link = _make_link()
        wire = self._push_and_capture(mgr, link, sender_public_key=None)
        # Backwards-compatible: field present (default from
        # encode_message_for_sync) but None — TUI treats as no opinion.
        assert wire.get("sender_public_key") is None

    def test_kwarg_default_is_none(self):
        """Calling without the kwarg behaves identically to passing None."""
        mgr = LiveSubscriptionManager()
        link = _make_link()
        sent_payloads: list[bytes] = []
        mgr._push_to_subscribers = lambda *a, **k: sent_payloads.append(a[2])  # type: ignore[method-assign]
        mgr.subscribe("ch1", link)
        mgr.push_message("ch1", _msg())  # no kwarg
        envelope = msgpack.unpackb(sent_payloads[0], raw=False)
        assert envelope["data"].get("sender_public_key") is None

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for ``LxmfMessageIngestor``."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from hokora.constants import MSG_DELETE, MSG_EDIT, MSG_PIN, MSG_REACTION, MSG_TEXT
from hokora.core.lxmf_ingestor import LxmfMessageIngestor
from hokora.core.message import MessageEnvelope


def _make_envelope(**overrides) -> MessageEnvelope:
    defaults = dict(
        channel_id="c" * 64,
        sender_hash="b" * 64,
        timestamp=1_700_000_000.0,
        type=MSG_TEXT,
        body="hello",
    )
    defaults.update(overrides)
    return MessageEnvelope(**defaults)


def _make_session_factory():
    """Return a session_factory() callable + the mock session it produces."""
    session = MagicMock()
    session.begin = MagicMock()
    session.begin.return_value.__aenter__ = AsyncMock(return_value=None)
    session.begin.return_value.__aexit__ = AsyncMock(return_value=None)

    @asynccontextmanager
    async def factory():
        yield session

    return factory, session


@pytest.fixture
def processor():
    msg = MagicMock()
    msg.body = "stored body"
    p = MagicMock()
    p.ingest = AsyncMock(return_value=msg)
    return p


@pytest.fixture
def live_manager():
    lm = MagicMock()
    lm.push_message = MagicMock()
    lm.push_event = MagicMock()
    return lm


@pytest.fixture
def media_storage():
    ms = MagicMock()
    ms.store = MagicMock(return_value="/data/media/stored.jpg")
    return ms


@pytest.fixture
def federation_trigger():
    return AsyncMock()


@pytest.fixture
def ingestor(processor, live_manager, media_storage, federation_trigger):
    factory, _session = _make_session_factory()
    loop = asyncio.new_event_loop()
    try:
        yield LxmfMessageIngestor(
            loop=loop,
            session_factory=factory,
            message_processor=processor,
            live_manager=live_manager,
            media_storage=media_storage,
            federation_trigger=federation_trigger,
        )
    finally:
        loop.close()
        asyncio.set_event_loop(None)


class TestOnLxmfDelivery:
    def test_schedules_ingest_on_loop(
        self, processor, live_manager, media_storage, federation_trigger, monkeypatch
    ):
        factory, _session = _make_session_factory()
        loop = MagicMock()
        ing = LxmfMessageIngestor(
            loop=loop,
            session_factory=factory,
            message_processor=processor,
            live_manager=live_manager,
            media_storage=media_storage,
            federation_trigger=federation_trigger,
        )
        fake_future = MagicMock()
        sched = MagicMock(return_value=fake_future)
        monkeypatch.setattr("hokora.core.lxmf_ingestor.asyncio.run_coroutine_threadsafe", sched)
        env = _make_envelope()
        ing.on_lxmf_delivery(env)
        sched.assert_called_once()
        args, _kw = sched.call_args
        coro = args[0]
        assert args[1] is loop
        fake_future.add_done_callback.assert_called_once()
        coro.close()  # avoid "never awaited" warning

    def test_log_ingest_error_swallows_exceptions(self, caplog):
        future = MagicMock()
        future.result.side_effect = RuntimeError("boom")
        LxmfMessageIngestor._log_ingest_error(future)  # must not raise


class TestIngestMedia:
    async def test_stores_media_when_bytes_present(self, ingestor, media_storage):
        env = _make_envelope(media_path="upload.jpg", media_bytes=b"\x01\x02\x03")
        await ingestor.ingest(env)
        media_storage.store.assert_called_once()
        kwargs = media_storage.store.call_args.kwargs
        assert kwargs["channel_id"] == env.channel_id
        assert kwargs["msg_hash"] == "upload"
        assert kwargs["data"] == b"\x01\x02\x03"
        assert kwargs["extension"] == "jpg"
        assert env.media_path == "/data/media/stored.jpg"
        assert env.media_bytes is None

    async def test_skips_media_store_when_no_media_storage(
        self, processor, live_manager, federation_trigger
    ):
        factory, _session = _make_session_factory()
        loop = asyncio.new_event_loop()
        try:
            ing = LxmfMessageIngestor(
                loop=loop,
                session_factory=factory,
                message_processor=processor,
                live_manager=live_manager,
                media_storage=None,
                federation_trigger=federation_trigger,
            )
            env = _make_envelope(media_path="x.jpg", media_bytes=b"\xff")
            await ing.ingest(env)
            # media_bytes should remain since no storage to consume them
            assert env.media_bytes == b"\xff"
        finally:
            loop.close()
            asyncio.set_event_loop(None)

    async def test_tolerates_media_store_failures(self, ingestor, media_storage, processor):
        media_storage.store.side_effect = OSError("disk full")
        env = _make_envelope(media_path="x.jpg", media_bytes=b"\xff")
        await ingestor.ingest(env)  # no raise
        processor.ingest.assert_awaited_once()  # continues to ingest step


class TestIngestDispatch:
    async def test_calls_processor_with_envelope(self, ingestor, processor):
        env = _make_envelope()
        await ingestor.ingest(env)
        processor.ingest.assert_awaited_once()
        _session, passed_env = processor.ingest.await_args.args
        assert passed_env is env


class TestIngestLivePush:
    async def test_pushes_normal_message(self, ingestor, live_manager):
        env = _make_envelope(type=MSG_TEXT)
        await ingestor.ingest(env)
        live_manager.push_message.assert_called_once()
        live_manager.push_event.assert_not_called()

    async def test_pushes_message_updated_for_edit(self, ingestor, live_manager, monkeypatch):
        orig = MagicMock()
        encoded = {"msg_hash": "abc"}
        monkeypatch.setattr(
            "hokora.db.queries.MessageRepo",
            lambda _s: MagicMock(get_by_hash=AsyncMock(return_value=orig)),
        )
        # ``lxmf_ingestor`` routes through
        # ``sync_utils.encode_message_for_wire`` (sealed-aware) rather
        # than ``wire.encode_message_for_sync`` directly. Tests patch
        # the name lxmf_ingestor actually imports.
        monkeypatch.setattr(
            "hokora.protocol.sync_utils.encode_message_for_wire",
            lambda _m, sealed_manager=None: encoded,
        )
        env = _make_envelope(type=MSG_EDIT, reply_to="target" * 10)
        await ingestor.ingest(env)
        live_manager.push_event.assert_called_once_with(env.channel_id, "message_updated", encoded)
        live_manager.push_message.assert_not_called()

    @pytest.mark.parametrize("mtype", [MSG_DELETE, MSG_REACTION, MSG_PIN])
    async def test_pushes_message_updated_for_delete_reaction_pin(
        self, ingestor, live_manager, monkeypatch, mtype
    ):
        orig = MagicMock()
        monkeypatch.setattr(
            "hokora.db.queries.MessageRepo",
            lambda _s: MagicMock(get_by_hash=AsyncMock(return_value=orig)),
        )
        monkeypatch.setattr(
            "hokora.protocol.sync_utils.encode_message_for_wire",
            lambda _m, sealed_manager=None: {"ok": True},
        )
        env = _make_envelope(type=mtype, reply_to="t" * 64)
        await ingestor.ingest(env)
        live_manager.push_event.assert_called_once()
        assert live_manager.push_event.call_args.args[1] == "message_updated"


class TestIngestFederation:
    async def test_triggers_federation_push_for_channel(self, ingestor, federation_trigger):
        env = _make_envelope()
        await ingestor.ingest(env)
        federation_trigger.assert_awaited_once_with(env.channel_id)

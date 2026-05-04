# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI helper for ``test_two_node_sync.TestCrossNodeMessageFlow``.

Insert a deterministic test message into a daemon's DB so the test can
verify metrics/DB-state without the multinode test embedding a 35-line
f-string Python script (which silently breaks on whitespace edits and
is hard to lint).

Usage::

    HOKORA_CONFIG=/path/to/node/hokora.toml \\
        python -m tests.multinode._helpers.insert_test_message <channel_id>

Reads ``HOKORA_CONFIG`` for the daemon DB key (encrypted nodes) and
inserts a single MSG_TEXT row at seq=9001. Idempotent because the
``msg_hash`` is fixed: a re-run hits the unique-constraint and the
test's ``returncode`` check catches the regression.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
import time

from hokora.config import load_config
from hokora.db.engine import create_db_engine, create_session_factory
from hokora.db.models import Message


async def _main(channel_id: str) -> None:
    config = load_config()
    engine = create_db_engine(
        config.db_path,
        encrypt=config.db_encrypt,
        db_key=config.resolve_db_key(),
    )
    factory = create_session_factory(engine)
    async with factory() as session:
        async with session.begin():
            session.add(
                Message(
                    msg_hash=hashlib.sha256(b"test-e2e-1").hexdigest(),
                    channel_id=channel_id,
                    sender_hash="e2e_test_sender",
                    seq=9001,
                    timestamp=time.time(),
                    type=1,
                    body="Hello from E2E test",
                    display_name="E2E Tester",
                )
            )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: insert_test_message.py <channel_id>", file=sys.stderr)
        sys.exit(2)
    asyncio.run(_main(sys.argv[1]))

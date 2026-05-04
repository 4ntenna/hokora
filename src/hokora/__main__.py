# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Entry point for hokorad daemon."""

import asyncio
import signal
import sys

from hokora.config import load_config
from hokora.core.daemon import HokoraDaemon


def main():
    config = load_config()

    # --relay-only flag: transport + LXMF propagation only
    if "--relay-only" in sys.argv:
        config.relay_only = True
        config.propagation_enabled = True
    daemon = HokoraDaemon(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def handle_signal(sig, frame):
        loop.call_soon_threadsafe(loop.stop)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        loop.run_until_complete(daemon.start())
        # LXMF.LXMRouter installs its own signal handlers during init, which
        # clobbers ours. Re-register after start() so SIGINT/SIGTERM route
        # through our graceful-shutdown path (loop.stop → daemon.stop →
        # PID-file cleanup) instead of LXMF's hard exit.
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(daemon.stop())
        loop.close()


if __name__ == "__main__":
    main()

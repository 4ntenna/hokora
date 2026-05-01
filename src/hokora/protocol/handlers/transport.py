# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Transport-management sync handlers.

Exposes a read-only ``handle_list_seeds`` for populating the TUI's
Network tab. All mutation of the daemon's RNS interface set is
filesystem-authored via :mod:`hokora.security.rns_config`, invoked by
the ``hokora seed`` CLI — there is intentionally no ``handle_add_seed``
/ ``handle_remove_seed`` in this module.

The read handler returns the seed list parsed from the daemon's
current RNS config on disk, not from RNS's in-memory
``Transport.interfaces``. That keeps the TUI's view in sync with what
will be applied on next restart — even if the operator has edited the
config by hand and not yet restarted.
"""

from __future__ import annotations

import logging
from typing import Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.security import rns_config

logger = logging.getLogger(__name__)


class _TransportCtx(Protocol):
    """Fields read by ``handle_list_seeds``.

    Narrow protocol: the handler depends only on ``config`` (for
    ``rns_config_dir``) and ``rate_limiter`` (shared across all sync
    actions).
    """

    config: object
    rate_limiter: object


async def handle_list_seeds(
    ctx: _TransportCtx,
    session: AsyncSession,
    nonce: bytes,
    payload: dict,
    channel_id: Optional[str],
    requester_hash: Optional[str] = None,
    link=None,
) -> dict:
    """Return the seed entries currently configured in the daemon's RNS config.

    Read-only. No auth gate beyond the authenticated RNS Link — the
    seed list is not secret; attackers with Link access can already
    observe which peers the daemon is reaching by watching announces.
    Rate limit reuses the shared per-identity bucket so a flooding
    caller gets throttled on the same cursor as other sync actions.
    """
    if ctx.rate_limiter is not None and requester_hash:
        try:
            ctx.rate_limiter.check_rate_limit(requester_hash)
        except Exception:
            # Rate limit exhausted — surface as a structured response
            # rather than a sync-protocol error so the TUI can render
            # "rate limited, retry in N seconds" cleanly.
            logger.debug("list_seeds rate limited for %s", requester_hash)
            raise

    rns_config_dir = getattr(ctx.config, "rns_config_dir", None) if ctx.config else None

    try:
        entries = rns_config.list_seeds(rns_config_dir)
    except rns_config.SeedConfigError as exc:
        logger.warning("Failed to read RNS config for list_seeds: %s", exc)
        return {"ok": False, "error": str(exc), "seeds": []}

    return {
        "ok": True,
        "seeds": [e.to_dict() for e in entries],
        "restart_required": False,
    }

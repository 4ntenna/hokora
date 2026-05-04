# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Transport-management sync handlers.

Read-only ``handle_list_seeds`` reads the on-disk RNS config (not
``Transport.interfaces``) so the TUI sees what will apply on next
restart. Seed mutation is filesystem-authored via the ``hokora seed``
CLI; no add/remove handler exists here by design.
"""

from __future__ import annotations

import logging
from typing import Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from hokora.security import rns_config

logger = logging.getLogger(__name__)


class _TransportCtx(Protocol):
    """Fields read by ``handle_list_seeds``."""

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
    seed list is not secret. Rate limit reuses the shared per-identity bucket.
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

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Reticulum Bridge: application-layer RNS access.

Per CDSP spec Section 4.1.3: deliberately omits interface type information.
This abstraction ensures the application layer never inspects transport type.
"""

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Process-wide counters for inbound resource rejections, scraped by the
# Prometheus exporter. Lock guards the dict against concurrent increments
# from RNS callback threads on different links.
_resource_rejection_counts: dict[str, int] = {}
_resource_rejection_lock = threading.Lock()


def increment_resource_rejection(reason: str) -> None:
    """Bump the rejection counter for ``reason`` (oversize/malformed)."""
    with _resource_rejection_lock:
        _resource_rejection_counts[reason] = _resource_rejection_counts.get(reason, 0) + 1


def get_resource_rejection_counts() -> dict[str, int]:
    """Snapshot of rejection counts for the Prometheus exporter."""
    with _resource_rejection_lock:
        return dict(_resource_rejection_counts)


def make_resource_filter(
    max_data_size: int,
    label: str,
    on_reject: Optional[Callable[[str], None]] = None,
) -> Callable:
    """Build a callback for ``Link.set_resource_callback`` that caps inbound size.

    The callback receives an ``RNS.ResourceAdvertisement`` (NOT ``RNS.Resource``)
    and must return True to accept or False to reject. Size is read via
    ``get_data_size()`` — the ``data_size`` attribute does not exist on
    ResourceAdvertisement and accessing it raises AttributeError, which RNS
    swallows in its callback dispatch (failing closed: no accept, no reject).

    Args:
        max_data_size: reject when advertised total data size exceeds this.
        label: included in rejection logs to disambiguate call sites.
        on_reject: optional metric/notice hook called with reason
            ``"oversize"`` or ``"malformed"``.
    """

    def _filter(advertisement) -> bool:
        size = advertisement.get_data_size()
        if size is None or size < 0:
            logger.warning(f"Rejecting resource on {label}: malformed size={size!r}")
            if on_reject is not None:
                on_reject("malformed")
            return False
        if size > max_data_size:
            logger.warning(f"Rejecting resource on {label}: size {size} > cap {max_data_size}")
            if on_reject is not None:
                on_reject("oversize")
            return False
        return True

    return _filter


class ReticulumBridge:
    """Application-layer RNS access. Deliberately omits interface type info."""

    def __init__(self, reticulum, lxm_router, node_identity):
        self._rns = reticulum
        self._router = lxm_router
        self._identity = node_identity

    def send_packet(self, link, data):
        import RNS

        # Auto-promote to Resource above the link MDU.
        if len(data) <= RNS.Link.MDU:
            RNS.Packet(link, data).send()
        else:
            RNS.Resource(data, link)

    def send_resource(self, link, data):
        import RNS

        RNS.Resource(data, link)

    def get_identity(self):
        return self._identity

    def get_destination(self, identity, app_name, *aspects):
        import RNS

        return RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects
        )

    def request_path(self, destination_hash):
        import RNS

        RNS.Transport.request_path(destination_hash)

    # Deliberately omitted per CDSP spec:
    # - get_interface_type()
    # - get_link_transport()
    # - get_bitrate()
    # - get_attached_interface()

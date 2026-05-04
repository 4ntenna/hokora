# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Reticulum Bridge: application-layer RNS access.

Per CDSP spec Section 4.1.3: deliberately omits interface type information.
This abstraction ensures the application layer never inspects transport type.
"""

import logging

logger = logging.getLogger(__name__)


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

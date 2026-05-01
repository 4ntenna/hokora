# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Transport log sanitizer: strip RNS interface class names from log output.

Enforces CDSP Principle 1: node must not reveal transport type.
"""

import logging


class TransportLogSanitizer(logging.Filter):
    """Strip RNS interface class names from log output."""

    INTERFACE_PATTERNS = [
        "TCPServerInterface",
        "TCPClientInterface",
        "BackboneInterface",
        "BackboneClientInterface",
        "AutoInterface",
        "AutoInterfacePeer",
        "UDPInterface",
        "LocalServerInterface",
        "LocalClientInterface",
        "RNodeInterface",
        "RNodeMultiInterface",
        "RNodeSubInterface",
        "WeaveInterface",
        "WeaveInterfacePeer",
        "KISSInterface",
        "AX25KISSInterface",
        "SerialInterface",
        "PipeInterface",
        "I2PInterface",
        "I2PInterfacePeer",
        "LoRaInterface",
        "WiFiInterface",
        "BLEInterface",
    ]

    def filter(self, record):
        msg = record.getMessage()
        for pattern in self.INTERFACE_PATTERNS:
            if pattern in msg:
                record.msg = str(record.msg).replace(pattern, "[redacted-interface]")
                if record.args:
                    # Re-format args too if present
                    try:
                        formatted = record.msg % record.args
                        for p in self.INTERFACE_PATTERNS:
                            formatted = formatted.replace(p, "[redacted-interface]")
                        record.msg = formatted
                        record.args = None
                    except (TypeError, ValueError):
                        pass
        return True

# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Structured info panel for a discovered node or peer.

Triggered by pressing ``i`` on a focused entry in the Discovery tab.
NomadNet-style: a snapshot of identity, transport, and trust state at the
moment the panel opens. Re-press ``i`` to refresh.

Pure presentation. No business logic, no callbacks, no state. Hosted by
``widgets.modal.Modal`` today; the same builder functions can be lifted
into an inline detail pane later without changes.

Security shape: every field rendered is either client-local state
(``app.state.discovered_*`` populated by the announcer) or a synchronous
read from ``RNS.Transport`` / ``SyncEngine.identity_keys``. No new wire
fields, no daemon coordination, no schema. Hashes are public RNS
identifiers; verify-state is read-only access to the existing TOFU cache
shipped with B-lite.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional

import urwid


def build_node_info_panel(node_dict: dict, sync_engine: Optional[Any] = None) -> urwid.Widget:
    """Render a NomadNet-style info panel for a discovered Hokora node.

    ``node_dict`` follows the ``app.state.discovered_nodes`` shape
    (see ``Announcer._on_announce`` channel-announce branch).
    """
    rows: list[urwid.Widget] = []

    rows.append(_top_bar("Node Info"))
    rows.append(urwid.Divider())

    rows.append(_kv_row("Type", _format_node_type(node_dict)))
    rows.append(_kv_row("Name", node_dict.get("node_name") or "(unknown)"))

    rows.append(urwid.Divider())

    identity_hash = node_dict.get("node_identity_hash")
    if identity_hash:
        rows.append(_kv_row("Identity hash", identity_hash, value_attr="info_hash"))
    else:
        rows.append(_kv_row("Identity hash", "(not announced)", value_attr="info_dim"))

    primary_dest = node_dict.get("primary_dest") or node_dict.get("hash")
    if primary_dest:
        rows.append(_kv_row("Destination", primary_dest, value_attr="info_hash"))

    rows.append(urwid.Divider())

    rows.append(_kv_row("Distance", _format_hops(node_dict.get("hops"))))
    rows.append(_kv_row("Interface", _resolve_interface(primary_dest)))
    rows.append(_kv_row("Last seen", _format_last_seen(node_dict.get("last_seen"))))

    rows.append(urwid.Divider())

    channels = node_dict.get("channels") or []
    channel_dests = node_dict.get("channel_dests") or {}
    rows.append(_kv_row("Channels", f"{len(channels)} announced"))
    if channels:
        # Render channel id alongside each name where we have it. The
        # `channel_dests` dict is keyed by channel_id, so reverse-look-up
        # is best-effort: if a name appears with no id we skip the id col.
        # We don't have direct name→id mapping; the announcer keeps
        # parallel dicts. Render id when there's a 1:1 mapping by index.
        for ch_name in channels:
            # Find the matching channel_id by name (best-effort — the
            # announcer keys by channel_id, not name; for now show the
            # name only and the count tells the user how many exist).
            rows.append(_indent_row(f"# {ch_name}"))
        # Show channel_ids separately if any are present.
        if channel_dests:
            rows.append(urwid.Divider())
            rows.append(_kv_row("Channel IDs", f"{len(channel_dests)} known"))
            for ch_id, dest in list(channel_dests.items())[:10]:
                rows.append(_indent_row(ch_id, value=dest, value_attr="info_hash"))
            if len(channel_dests) > 10:
                rows.append(
                    _indent_row(f"... +{len(channel_dests) - 10} more", value_attr="info_dim")
                )

    rows.append(urwid.Divider())

    rows.append(_kv_row("Bookmark", "★ saved" if node_dict.get("bookmarked") else "not bookmarked"))

    pile = urwid.Pile(rows)
    return urwid.Filler(pile, valign="top")


def build_peer_info_panel(peer_dict: dict, sync_engine: Optional[Any] = None) -> urwid.Widget:
    """Render a NomadNet-style info panel for a discovered peer (profile).

    ``peer_dict`` follows the ``app.state.discovered_peers`` shape
    (see ``Announcer._on_announce`` profile-announce branch).
    """
    rows: list[urwid.Widget] = []

    rows.append(_top_bar("Peer Info"))
    rows.append(urwid.Divider())

    rows.append(_kv_row("Type", "Hokora User"))
    rows.append(_kv_row("Display name", peer_dict.get("display_name") or "(unknown)"))

    status_text = peer_dict.get("status_text") or ""
    if status_text:
        rows.append(_kv_row("Status", status_text))

    rows.append(urwid.Divider())

    peer_hash = peer_dict.get("hash")
    if peer_hash:
        rows.append(_kv_row("Identity hash", peer_hash, value_attr="info_hash"))

    rows.append(urwid.Divider())

    rows.append(_kv_row("Distance", _format_hops(peer_dict.get("hops"))))
    rows.append(_kv_row("Interface", _resolve_interface(peer_hash)))
    rows.append(_kv_row("Last seen", _format_last_seen(peer_dict.get("last_seen"))))

    rows.append(urwid.Divider())

    rows.append(_kv_row("Verify state", _format_verify_state(peer_hash, sync_engine)))
    rows.append(_kv_row("Bookmark", "★ saved" if peer_dict.get("bookmarked") else "not bookmarked"))

    pile = urwid.Pile(rows)
    return urwid.Filler(pile, valign="top")


# ─────────────────────────────────────────────────────────────────────
# Internal — rendering helpers
# ─────────────────────────────────────────────────────────────────────


_LABEL_WIDTH = 16


def _top_bar(section_text: str) -> urwid.Widget:
    """First-row header: section label on the left, Esc hint on the right.

    Replaces the old centered section header + bottom-centered Esc hint
    pair. Putting the close-affordance in the top-right keeps it visible
    even when the body content scrolls or is taller than expected.
    """
    return urwid.Columns(
        [
            urwid.Text(("info_section_header", section_text), align="left"),
            urwid.Text(("info_dim", "Esc to close"), align="right"),
        ]
    )


def _kv_row(label: str, value: str, value_attr: str = "info_value") -> urwid.Widget:
    """A single label-value row with fixed-width label column."""
    return urwid.Columns(
        [
            ("fixed", _LABEL_WIDTH, urwid.Text(("info_label", label))),
            urwid.Text((value_attr, value)),
        ]
    )


def _indent_row(label: str, value: str = "", value_attr: str = "info_value") -> urwid.Widget:
    """Indented continuation row (e.g., per-channel detail under Channels)."""
    if value:
        return urwid.Columns(
            [
                ("fixed", _LABEL_WIDTH, urwid.Text(("info_dim", f"  {label}"))),
                urwid.Text((value_attr, value)),
            ]
        )
    return urwid.Text(("info_value", f"  {label}"))


def _format_node_type(node_dict: dict) -> str:
    """Compose the Type label from the announced role hints.

    Every entry in ``state.discovered_nodes`` is by construction a
    community node — only daemons that serve channels emit the
    ``type=="channel"`` announces the announcer keys on. Layer the
    optional ``propagation_enabled`` hint on top via dot-separator.
    Pre-upgrade daemons omit the field; render as plain "Community Node".
    """
    roles = ["Community Node"]
    if node_dict.get("propagation_enabled"):
        roles.append("Propagation Node")
    return " · ".join(roles)


def _format_hops(hops: Any) -> str:
    """Render distance the same way row widgets do, but with full words."""
    if hops is None:
        return "unknown (no path)"
    if hops == 0:
        return "direct (0 hops)"
    if hops == 1:
        return "1 hop"
    return f"{hops} hops"


def _format_last_seen(last_seen: Any) -> str:
    """Relative + absolute UTC ISO 8601."""
    if not last_seen:
        return "(never)"
    try:
        ts = float(last_seen)
    except (TypeError, ValueError):
        return "(unknown)"
    age = time.time() - ts
    if age < 0:
        rel = "now"
    elif age < 60:
        rel = f"{int(age)}s ago"
    elif age < 3600:
        rel = f"{int(age / 60)}m ago"
    elif age < 86400:
        rel = f"{int(age / 3600)}h ago"
    else:
        rel = f"{int(age / 86400)}d ago"
    try:
        absolute = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, ValueError, OverflowError):
        absolute = "(out-of-range)"
    return f"{rel}  ({absolute})"


def _resolve_interface(dest_hex: Optional[str]) -> str:
    """Look up the live RNS path's next-hop interface name.

    All exception paths fall through to ``(unknown)`` — RNS may not be
    initialised in tests, the path may have aged out of the table, or
    the destination hash may be malformed. None of those are panel-fatal.
    """
    if not dest_hex:
        return "(unknown)"
    try:
        import RNS  # local import — keeps test environments without RNS clean
    except ImportError:
        return "(unknown)"
    try:
        dest_bytes = bytes.fromhex(dest_hex)
    except (ValueError, TypeError):
        return "(unknown)"
    try:
        iface = RNS.Transport.next_hop_interface(dest_bytes)
    except Exception:
        return "(unknown)"
    if iface is None:
        return "(no path)"
    name = getattr(iface, "name", None) or repr(iface)
    return str(name)


def _format_verify_state(peer_hash: Optional[str], sync_engine: Optional[Any]) -> str:
    """Surface the B-lite TOFU verify cache for this peer.

    The dict is the same one ``verify_message_signature`` reads/writes;
    presence of a cached pubkey means we've successfully verified at
    least one Ed25519 signature from this party.
    """
    if not peer_hash or sync_engine is None:
        return "(no key cached)"
    try:
        identity_keys = sync_engine.identity_keys
    except AttributeError:
        return "(no key cached)"
    if peer_hash in identity_keys:
        return "verified  (Ed25519 pubkey cached)"
    return "(no key cached)"

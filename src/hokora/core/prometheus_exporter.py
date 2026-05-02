# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Prometheus text-format exporter for Hokora daemon state.

Single source of truth for the metrics surface — the daemon's
ObservabilityListener (``core/observability.py``) calls through here to
serve ``/api/metrics/`` on its loopback port.

The metric names and labels form a stable observability contract — no
renames, no label drift — so existing Prometheus configs continue to
scrape across releases.
"""

from __future__ import annotations

import re
import time
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from hokora.constants import (
    CDSP_PROFILE_BATCHED,
    CDSP_PROFILE_FULL,
    CDSP_PROFILE_MINIMAL,
    CDSP_PROFILE_PRIORITIZED,
)
from hokora.db.models import (
    Channel,
    DeferredSyncItem,
    Identity,
    Message,
    Peer,
    PendingSealedDistribution,
    SealedKey,
    Session,
)

# Prometheus label values must not contain unescaped backslashes, newlines,
# or double quotes. We sanitize rather than reject so a malformed channel
# name never blocks the scrape entirely.
_PROM_UNSAFE = re.compile(r'[\\"\n]')

# Fallback used only when the daemon doesn't pass its real start time — e.g.
# the web dashboard rendering metrics with no daemon context. Import time is
# a reasonable floor there; the daemon's actual uptime is what callers want.
_MODULE_IMPORT_TIME = time.time()

_CDSP_PROFILE_LABELS = {
    CDSP_PROFILE_FULL: "FULL",
    CDSP_PROFILE_PRIORITIZED: "PRIORITIZED",
    CDSP_PROFILE_MINIMAL: "MINIMAL",
    CDSP_PROFILE_BATCHED: "BATCHED",
}


def _sanitize_label(value: str) -> str:
    """Sanitize a string for use as a Prometheus label value."""
    return _PROM_UNSAFE.sub("_", value)


def _render_rns_interfaces(rns_transport: Any) -> list[str]:
    """Emit per-interface byte counters + up gauge from RNS.Transport.

    ``rns_transport`` must be the RNS.Transport module (or a stand-in
    exposing ``.interfaces``). Returns an empty list on any failure so
    a broken RNS internal never blocks the scrape.
    """
    if rns_transport is None:
        return []

    out: list[str] = []
    try:
        ifaces = list(getattr(rns_transport, "interfaces", []) or [])
    except Exception:
        return []

    for iface in ifaces:
        try:
            name = _sanitize_label(str(getattr(iface, "name", "unknown")))
            itype = _sanitize_label(type(iface).__name__)
            rxb = int(getattr(iface, "rxb", 0) or 0)
            txb = int(getattr(iface, "txb", 0) or 0)
            online = 1 if getattr(iface, "online", False) else 0
        except Exception:
            # Skip this one interface, keep emitting the rest.
            continue
        labels = f'interface="{name}",type="{itype}"'
        out.append(f"hokora_rns_interface_bytes_rx_total{{{labels}}} {rxb}")
        out.append(f"hokora_rns_interface_bytes_tx_total{{{labels}}} {txb}")
        out.append(f"hokora_rns_interface_up{{{labels}}} {online}")

        # RNode-specific LoRa telemetry — emitted only for
        # RNodeInterface instances. Detection via duck-typing on r_sf,
        # the spreading-factor field unique to RNode firmware, so the
        # check works without importing RNS.Interfaces.RNodeInterface
        # (which is not always present in test environments).
        if hasattr(iface, "r_sf"):
            out.extend(_render_rnode_telemetry(iface, name))
    return out


# RNode battery state enum from RNS.Interfaces.RNodeInterface.BATTERY_STATE_*.
# Mirrored here as a free dict so we don't import RNS just to render labels.
_RNODE_BATTERY_STATE_LABELS = {
    0x00: "unknown",
    0x01: "discharging",
    0x02: "charging",
    0x03: "charged",
}


def _render_rnode_telemetry(iface: Any, name: str) -> list[str]:
    """Emit per-RNode LoRa hardware telemetry as Prometheus gauges.

    Pulls live values from the ``RNodeInterface`` instance — radio config
    (frequency / bandwidth / SF / CR / TX power / bitrate), link quality
    (noise floor / last-packet RSSI / last-packet SNR), utilisation
    (airtime + channel load over both 15s and 1h windows), and host-board
    health (MCU temperature / battery state + percent).

    Every field is "omit rather than zero" — RNode firmware reports each
    value asynchronously after first KISS detection, so a freshly-attached
    RNode legitimately has ``None`` values for a few seconds. Emitting a
    fake 0 for a missing reading would corrupt rate / threshold queries
    in operator dashboards.

    All metrics carry an ``interface="<name>"`` label so they join cleanly
    with ``hokora_rns_interface_bytes_*`` for the same interface.

    Wraps every read in a try/except so a single broken attribute never
    blocks the rest of the scrape.
    """
    out: list[str] = []
    label = f'interface="{name}"'

    def _emit_scalar(metric: str, attr: str) -> None:
        """Emit one gauge from a single attribute. Each read is isolated
        so a property that raises (broken firmware reporting, attribute
        access exception) only kills its own metric, never the rest of
        the telemetry surface."""
        try:
            value = getattr(iface, attr, None)
        except Exception:
            return
        if value is None:
            return
        try:
            num = float(value)
        except (TypeError, ValueError):
            return
        out.append(f"{metric}{{{label}}} {num}")

    def _emit_windowed(metric: str, attr: str, window: str) -> None:
        try:
            value = getattr(iface, attr, None)
        except Exception:
            return
        if value is None:
            return
        try:
            num = float(value)
        except (TypeError, ValueError):
            return
        out.append(f'{metric}{{{label},window="{window}"}} {num}')

    # Radio config — emitted independently so each field's failure mode
    # (firmware glitch, missing attr) only affects its own gauge.
    _emit_scalar("hokora_rnode_frequency_hz", "r_frequency")
    _emit_scalar("hokora_rnode_bandwidth_hz", "r_bandwidth")
    _emit_scalar("hokora_rnode_spreading_factor", "r_sf")
    _emit_scalar("hokora_rnode_coding_rate", "r_cr")
    _emit_scalar("hokora_rnode_tx_power_dbm", "r_txpower")

    # bitrate defaults to 0 in __init__; only emit once it's non-zero
    # (i.e. RNS has actually computed it from radio config).
    try:
        bitrate = getattr(iface, "bitrate", None)
        if bitrate:
            out.append(f"hokora_rnode_bitrate_bps{{{label}}} {float(bitrate)}")
    except Exception:
        pass

    # Link quality
    _emit_scalar("hokora_rnode_noise_floor_dbm", "r_noise_floor")
    _emit_scalar("hokora_rnode_last_packet_rssi_dbm", "r_stat_rssi")
    _emit_scalar("hokora_rnode_last_packet_snr_db", "r_stat_snr")

    # Utilisation. RNS stores these as percentages (0–100) directly,
    # matching the format ``rnstatus`` displays. The metric name reflects
    # the unit so operators don't accidentally multiply by 100 again in
    # their dashboards.
    _emit_windowed("hokora_rnode_airtime_percent", "r_airtime_short", "15s")
    _emit_windowed("hokora_rnode_airtime_percent", "r_airtime_long", "1h")
    _emit_windowed("hokora_rnode_channel_load_percent", "r_channel_load_short", "15s")
    _emit_windowed("hokora_rnode_channel_load_percent", "r_channel_load_long", "1h")

    # Host-board health
    _emit_scalar("hokora_rnode_cpu_temp_celsius", "cpu_temp")

    # RNodes without a battery report state=0 (unknown) and percent=0;
    # treat that combination as "no battery telemetry" and omit, so a
    # mains-powered RNode does not show a permanent 0% battery alarm.
    try:
        battery_state = getattr(iface, "r_battery_state", None)
    except Exception:
        battery_state = None
    if battery_state is not None and battery_state != 0x00:
        _emit_scalar("hokora_rnode_battery_percent", "r_battery_percent")
        for code, state_label in _RNODE_BATTERY_STATE_LABELS.items():
            value = 1 if battery_state == code else 0
            out.append(f'hokora_rnode_battery_state{{{label},state="{state_label}"}} {value}')

    return out


async def render_metrics(
    session_factory: async_sessionmaker,
    rns_transport: Optional[Any] = None,
    daemon_start_time: Optional[float] = None,
    mirror_manager: Optional[Any] = None,
) -> str:
    """Render the daemon's Prometheus exposition-format text.

    ``session_factory`` is any AsyncSession-producing callable (typically
    the daemon's ``create_session_factory`` result). Opens one read-only
    session per call; callers should not hold an outer transaction.

    ``rns_transport`` is the ``RNS.Transport`` module (passed by the
    daemon's ObservabilityListener). When ``None`` (e.g., from the web
    dashboard, which has no RNS context), per-interface metrics are
    omitted entirely — no fake zeros, no blank labels.

    ``daemon_start_time`` is the UNIX timestamp of ``daemon.start()``.
    When ``None``, we fall back to the module-import time. The contract
    is that this number tracks the daemon lifetime, not the Python
    process — passing the real value makes
    ``hokora_daemon_uptime_seconds`` correct after a warm re-init and
    avoids near-zero readings right after startup.

    ``mirror_manager`` is the daemon's ``MirrorLifecycleManager``. Used
    to emit per-mirror state + connect-attempt counters so operators
    can see when federation is wedged in WAITING_FOR_PATH (the N3
    cold-start signal). Omitted entirely when ``None`` so the web
    dashboard's metrics path is unaffected.

    Safe to call from any thread as long as the session factory it was
    given is valid for the current event loop. The ObservabilityListener
    handles the cross-thread case by marshalling via
    ``asyncio.run_coroutine_threadsafe``.
    """
    lines: list[str] = []

    async with session_factory() as session:
        # ── Core metrics (stable contract) ─────────────────────────
        result = await session.execute(
            select(Message.channel_id, func.count()).group_by(Message.channel_id)
        )
        for channel_id, count in result:
            safe_id = _sanitize_label(str(channel_id))
            lines.append(f'hokora_messages_total{{channel="{safe_id}"}} {count}')

        channel_count = (await session.execute(select(func.count()).select_from(Channel))).scalar()
        lines.append(f"hokora_channels_total {channel_count}")

        msg_count = (await session.execute(select(func.count()).select_from(Message))).scalar()
        lines.append(f"hokora_messages_total_all {msg_count}")

        identity_count = (
            await session.execute(select(func.count()).select_from(Identity))
        ).scalar()
        lines.append(f"hokora_identities_total {identity_count}")

        peer_count = (await session.execute(select(func.count()).select_from(Peer))).scalar()
        lines.append(f"hokora_peers_discovered {peer_count}")

        # ── Federation + sync observability ────────────────────────

        # Per-channel ingested seq. Useful for alerting on stuck channels.
        channel_seq_rows = await session.execute(select(Channel.id, Channel.latest_seq))
        for ch_id, latest_seq in channel_seq_rows:
            safe_id = _sanitize_label(str(ch_id))
            lines.append(
                f'hokora_channel_latest_seq_ingested{{channel="{safe_id}"}} {int(latest_seq or 0)}'
            )

        # Per-(peer,channel) sync cursor. sync_cursor is JSON {channel_id: last_seq}.
        # Absent entries are omitted, not zero — distinguishes "never synced" from "synced to 0".
        peer_cursor_rows = await session.execute(
            select(Peer.identity_hash, Peer.sync_cursor).where(Peer.sync_cursor.is_not(None))
        )
        for peer_hash, cursor in peer_cursor_rows:
            if not isinstance(cursor, dict):
                continue
            safe_peer = _sanitize_label(str(peer_hash))
            for ch_id, seq in cursor.items():
                # Skip internal keys like "_push" and any non-int values.
                if not isinstance(ch_id, str) or ch_id.startswith("_"):
                    continue
                try:
                    seq_i = int(seq)
                except (TypeError, ValueError):
                    continue
                safe_ch = _sanitize_label(ch_id)
                lines.append(
                    f'hokora_peer_sync_cursor_seq{{peer="{safe_peer}",channel="{safe_ch}"}} {seq_i}'
                )

        # CDSP sessions by profile + state.
        session_rows = await session.execute(
            select(Session.sync_profile, Session.state, func.count()).group_by(
                Session.sync_profile, Session.state
            )
        )
        for profile_int, state, count in session_rows:
            profile_label = _CDSP_PROFILE_LABELS.get(profile_int, "unknown")
            safe_state = _sanitize_label(str(state or "unknown"))
            lines.append(
                f'hokora_cdsp_sessions{{profile="{profile_label}",state="{safe_state}"}} {count}'
            )

        # Deferred sync items by channel.
        deferred_rows = await session.execute(
            select(DeferredSyncItem.channel_id, func.count()).group_by(DeferredSyncItem.channel_id)
        )
        for ch_id, count in deferred_rows:
            safe_ch = _sanitize_label(str(ch_id or "null"))
            lines.append(f'hokora_deferred_sync_items{{channel="{safe_ch}"}} {count}')

        # Federation peers by trust status.
        trust_rows = await session.execute(
            select(Peer.federation_trusted, func.count()).group_by(Peer.federation_trusted)
        )
        for trusted, count in trust_rows:
            label = "true" if trusted else "false"
            lines.append(f'hokora_federation_peers{{trusted="{label}"}} {count}')

        # Sealed channel count (scalar).
        sealed_count = (
            await session.execute(
                select(func.count()).select_from(Channel).where(Channel.sealed.is_(True))
            )
        ).scalar()
        lines.append(f"hokora_sealed_channels_total {sealed_count}")

        # Sealed key-age per channel — age of the newest epoch key.
        # Channels with no SealedKey row are omitted (not reported as 0).
        now = time.time()
        sealed_age_rows = await session.execute(
            select(SealedKey.channel_id, func.max(SealedKey.created_at)).group_by(
                SealedKey.channel_id
            )
        )
        for ch_id, max_created in sealed_age_rows:
            if max_created is None:
                continue
            age = max(0.0, now - float(max_created))
            safe_ch = _sanitize_label(str(ch_id))
            lines.append(f'hokora_sealed_key_age_seconds{{channel="{safe_ch}"}} {age:.1f}')

        # Pending sealed-key distributions per channel (queued grants
        # awaiting recipient announce). Plus a separate "stuck" count
        # for entries that have crossed MAX_PENDING_DISTRIBUTION_RETRIES
        # and need operator inspection.
        from hokora.constants import MAX_PENDING_DISTRIBUTION_RETRIES

        pending_rows = await session.execute(
            select(
                PendingSealedDistribution.channel_id,
                func.count(),
            ).group_by(PendingSealedDistribution.channel_id)
        )
        for ch_id, count in pending_rows:
            safe_ch = _sanitize_label(str(ch_id))
            lines.append(f'hokora_pending_sealed_distributions{{channel="{safe_ch}"}} {count}')

        stuck_rows = await session.execute(
            select(
                PendingSealedDistribution.channel_id,
                func.count(),
            )
            .where(PendingSealedDistribution.retry_count >= MAX_PENDING_DISTRIBUTION_RETRIES)
            .group_by(PendingSealedDistribution.channel_id)
        )
        for ch_id, count in stuck_rows:
            safe_ch = _sanitize_label(str(ch_id))
            lines.append(
                f'hokora_pending_sealed_distributions_stuck{{channel="{safe_ch}"}} {count}'
            )

    # Outside the session: RNS interface metrics (synchronous attribute reads).
    lines.extend(_render_rns_interfaces(rns_transport))

    # Mirror state + connect-attempt totals for cold-start observability.
    # Both families are skipped entirely when no mirror_manager was
    # passed (web dashboard path), keeping the "omit rather than zero"
    # discipline. The state gauge emits one row per mirror keyed on
    # (channel_id, peer_hash, state) — operators alert on any peer with a
    # non-zero ``state="waiting_for_path"`` count for more than a few
    # scrapes.
    if mirror_manager is not None:
        try:
            for _key, ch_id, peer_hash, state_value in mirror_manager.iter_mirror_states():
                safe_ch = _sanitize_label(str(ch_id))
                safe_peer = _sanitize_label(str(peer_hash))
                safe_state = _sanitize_label(str(state_value))
                lines.append(
                    f"hokora_mirror_link_state{{"
                    f'channel="{safe_ch}",peer="{safe_peer}",state="{safe_state}"'
                    f"}} 1"
                )
            for result, count in sorted(mirror_manager.connect_attempts.items()):
                safe_result = _sanitize_label(str(result))
                lines.append(
                    f'hokora_mirror_connect_attempts_total{{result="{safe_result}"}} {int(count)}'
                )
        except Exception:
            # Never let metric rendering interfere with a scrape.
            pass

    # Federation sender-binding rejections. Counter family keyed on the
    # rejection-reason label. Always emitted (even at zero) so a fresh
    # scrape distinguishes "no rejections" from "metric not exposed".
    try:
        from hokora.federation.auth import get_binding_rejection_counts

        counts = get_binding_rejection_counts()
        for label in (
            "binding_mismatch",
            "missing_pubkey",
            "bad_signature",
            "missing_signature",
            "malformed",
        ):
            n = int(counts.get(label, 0))
            safe_label = _sanitize_label(label)
            lines.append(f'hokora_federation_binding_rejections_total{{reason="{safe_label}"}} {n}')
    except Exception:
        pass

    # LXMF inbound rejection + action counters. The action family
    # captures every outcome; the rejection family carries the per-reason
    # label for forensics. Both families are emitted at zero so a fresh
    # scrape distinguishes "no events" from "metric not exposed".
    try:
        from hokora.security.lxmf_inbound import (
            get_lxmf_inbound_action_counts,
            get_lxmf_inbound_counts,
        )

        action_counts = get_lxmf_inbound_action_counts()
        for label in (
            "rejected",
            "recovered",
            "signature_failed",
            "opt_out_passthrough",
        ):
            n = int(action_counts.get(label, 0))
            safe_label = _sanitize_label(label)
            lines.append(f'hokora_lxmf_inbound_actions_total{{action="{safe_label}"}} {n}')

        rejection_counts = get_lxmf_inbound_counts()
        for label in (
            "signature_invalid",
            "validation_status_unknown",
            "missing_source_hash",
            "source_unknown_after_path_request",
            "signed_part_reconstruction_failed",
            "missing_signature",
            "invalid_pubkey",
            "bad_signature",
        ):
            n = int(rejection_counts.get(label, 0))
            safe_label = _sanitize_label(label)
            lines.append(f'hokora_lxmf_inbound_rejections_total{{reason="{safe_label}"}} {n}')
    except Exception:
        pass

    # Ban-enforcement rejections. Counter family keyed on the surface
    # label. Always emitted (even at zero) for the same reason as the
    # binding-rejection family above.
    try:
        from hokora.security.ban import get_ban_rejection_counts

        ban_counts = get_ban_rejection_counts()
        for label in (
            "federation_push",
            "invite_redeem",
            "sync_read",
        ):
            n = int(ban_counts.get(label, 0))
            safe_label = _sanitize_label(label)
            lines.append(f'hokora_ban_rejections_total{{surface="{safe_label}"}} {n}')
    except Exception:
        pass

    # Daemon uptime. Prefer the daemon's real start time; fall back to the
    # module-import time only when no caller has wired it through.
    _ref = daemon_start_time if daemon_start_time is not None else _MODULE_IMPORT_TIME
    uptime = max(0.0, time.time() - _ref)
    lines.append(f"hokora_daemon_uptime_seconds {uptime:.1f}")

    return "\n".join(lines) + "\n"

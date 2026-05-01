# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Cold-start mirror federation test (N3 fix verification).

Regression test for the N3 federation cold-start stall: a NodeA daemon
booting with a configured Peer/mirror row pointing at NodeB must survive
the case where NodeA's local RNS path table doesn't yet know NodeB. Pre-
fix, ``ChannelMirror._connect()`` would silently early-return on
``RNS.Identity.recall()=None`` and never retry. Post-fix, the mirror
parks in ``WAITING_FOR_PATH`` and is woken either by an inbound announce
(``PeerDiscovery.handle_announce`` → ``mirror_manager.wake_for_hash``)
or by the bounded ``periodic_mirror_health`` task.

The test forces the cold-start race by:

1. Initializing both nodes and starting only NodeA's rnsd + daemon,
   plus NodeB's rnsd. NodeB's daemon stays down so no announces ever
   leave NodeB. NodeA's path table is therefore empty for NodeB.
2. Computing NodeB's #general destination hash from NodeB's on-disk
   channel identity (no daemon needed — pure cryptographic derivation).
3. Pre-seeding NodeA's Peer table with that destination hash.
4. Starting NodeA's daemon — the mirror loads, ``_connect()`` calls
   ``recall()`` → None → mirror parks in WAITING_FOR_PATH.
5. Asserting via NodeA's loopback observability ``/api/metrics`` that
   ``hokora_mirror_link_state{state="waiting_for_path"} 1`` and
   ``hokora_mirror_connect_attempts_total{result="recall_none"} >= 1``.
6. Starting NodeB's daemon. NodeB announces over the shared TCP fabric.
7. NodeA's announce listener calls ``wake_for_hash``; mirror reaches
   LINKED. Asserting ``state="linked"`` and
   ``connect_attempts{result="success"} >= 1``.

Run with: PYTHONPATH=src python -m pytest tests/multinode/test_cold_start_mirror.py -v -s
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        not shutil.which("rnsd"),
        reason="rnsd not available — install RNS to run multinode tests",
    ),
    # Multinode tests spawn real subprocesses + drive RNS over the wire;
    # the unit-test 60s timeout floor is much too tight. The cold-start
    # test waits up to 180s for the mirror to transition LINKED via the
    # shared-instance fallback path (PATH_REQUEST_GATE_TIMEOUT).
    pytest.mark.timeout(300),
]

REPO_DIR = Path(__file__).resolve().parent.parent.parent

# Use distinct dirs from test_two_node_sync.py so the two suites can run
# in the same pytest session without colliding.
NODE_A_DIR = Path("/tmp/hokora_cold_node_a")
NODE_B_DIR = Path("/tmp/hokora_cold_node_b")
RNS_A_DIR = Path("/tmp/hokora_cold_rns_a")
RNS_B_DIR = Path("/tmp/hokora_cold_rns_b")

# Distinct ports — observability on daemon (mirror metrics live there),
# web on the dashboard (not used here but kept in case we want it).
OBS_PORT_A = 8521
OBS_PORT_B = 8522
RNS_TCP_PORT = 4252  # also distinct from the regular two_nodes fixture

RNS_A_TEMPLATE = REPO_DIR / "tests" / "live" / "rns_a"
RNS_B_TEMPLATE = REPO_DIR / "tests" / "live" / "rns_b"


def _write_toml(data_dir: Path, node_name: str, rns_config_dir: Path, obs_port: int):
    """Minimal TOML config for a cold-start test node.

    ``federation_auto_trust=True`` + ``require_signed_federation=False``
    — the test asserts the *connect / wake-up* path; whether the
    eventual federation handshake succeeds is orthogonal to N3.
    """
    content = f'''node_name = "{node_name}"
data_dir = "{data_dir}"
log_level = "DEBUG"
db_encrypt = false
rns_config_dir = "{rns_config_dir}"
announce_interval = 5
rate_limit_tokens = 10
rate_limit_refill = 1.0
max_upload_bytes = 5242880
max_storage_bytes = 1073741824
retention_days = 0
enable_fts = true
observability_enabled = true
observability_port = {obs_port}
mirror_retry_interval = 60
federation_auto_trust = true
require_signed_federation = false
'''
    (data_dir / "hokora.toml").write_text(content)


def _wait_for_obs(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/health/live")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 503):
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.5)
    return False


def _kill(proc: subprocess.Popen, timeout: float = 5.0):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            proc.kill()
            proc.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass


def _scrape_metrics(port: int, api_key: str) -> str:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/metrics/")
    req.add_header("X-API-Key", api_key)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode()


def _has_state(metrics_text: str, state: str) -> bool:
    """True iff any hokora_mirror_link_state row with given state exists."""
    needle = f'state="{state}"'
    for line in metrics_text.splitlines():
        if line.startswith("hokora_mirror_link_state{") and needle in line:
            return True
    return False


def _attempt_count(metrics_text: str, result: str) -> int:
    needle = f'hokora_mirror_connect_attempts_total{{result="{result}"}}'
    for line in metrics_text.splitlines():
        if line.startswith(needle):
            try:
                return int(line.split()[-1])
            except (IndexError, ValueError):
                return 0
    return 0


def _wait_for_state(
    port: int,
    api_key: str,
    state: str,
    timeout: float = 30.0,
    poll: float = 0.5,
) -> tuple[bool, str]:
    """Poll the metrics endpoint until a mirror reports the given state."""
    deadline = time.monotonic() + timeout
    last_text = ""
    while time.monotonic() < deadline:
        try:
            last_text = _scrape_metrics(port, api_key)
            if _has_state(last_text, state):
                return True, last_text
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(poll)
    return False, last_text


def _init_node(node_dir: Path, node_name: str):
    """Run hokora init for a fresh node."""
    if node_dir.exists():
        shutil.rmtree(node_dir)
    env = os.environ.copy()
    env["HOKORA_DATA_DIR"] = str(node_dir)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hokora.cli.main",
            "init",
            "--node-name",
            node_name,
            "--node-type",
            "community",
            "--data-dir",
            str(node_dir),
            "--no-db-encrypt",
            "--skip-luks-check",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_DIR),
    )
    if result.returncode != 0:
        pytest.fail(f"hokora init failed for {node_name}: {result.stderr}\n{result.stdout}")


def _read_general_channel_id(node_dir: Path) -> str:
    """Read NodeB's #general channel id directly from its sqlite DB."""
    import sqlite3

    db_path = node_dir / "hokora.db"
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT id FROM channels WHERE name = 'general' LIMIT 1")
        row = cur.fetchone()
    finally:
        conn.close()
    assert row is not None, f"No #general channel in {db_path}"
    return row[0]


def _materialize_channel_identity(node_dir: Path, channel_id: str) -> Path:
    """Create the per-channel RNS identity if not already on disk.

    The daemon does this lazily at startup. For the cold-start test we
    need the identity available without ever starting NodeB's daemon
    (otherwise NodeB would announce + leak a path entry to NodeA),
    so we materialize it here in a subprocess and persist via the
    same secure-write helper the daemon uses.
    """
    identity_path = node_dir / "identities" / f"channel_{channel_id}"
    if identity_path.exists():
        return identity_path
    helper = (
        "import sys, os; "
        "from pathlib import Path; "
        "sys.path.insert(0, os.environ['REPO_SRC']); "
        "import RNS; "
        "from hokora.security.fs import write_identity_secure, secure_identity_dir; "
        "ident_dir = Path(os.environ['IDENT_DIR']); "
        "secure_identity_dir(ident_dir); "
        "ident = RNS.Identity(); "
        "write_identity_secure(ident, ident_dir / os.environ['IDENT_NAME'])"
    )
    env = os.environ.copy()
    env["REPO_SRC"] = str(REPO_DIR / "src")
    env["IDENT_DIR"] = str(node_dir / "identities")
    env["IDENT_NAME"] = f"channel_{channel_id}"
    result = subprocess.run(
        [sys.executable, "-c", helper],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        pytest.fail(f"materialize channel identity failed: {result.stderr}\n{result.stdout}")
    return identity_path


def _compute_dest_hash(identity_path: Path, channel_id: str) -> str:
    """Compute NodeB's #general destination hash standalone.

    Pure-cryptographic derivation: ``RNS.Destination(identity, IN, SINGLE,
    'hokora', channel_id).hash`` is just SHA-256 over name+aspects+pk.
    No Reticulum runtime is required, so this won't pollute path tables
    on either side.
    """
    # Use the pure-static ``Destination.hash`` helper so we don't need to
    # bring up an RNS.Reticulum() instance just to compute the hash —
    # that would also pollute the test's path tables, defeating the
    # cold-start premise.
    # Read DESTINATION_ASPECT from the canonical constant rather than
    # hard-coding ``"hokora"``: a brand rename would silently break the
    # hash derivation otherwise.
    helper = (
        "import sys, os; "
        "sys.path.insert(0, os.environ['REPO_SRC']); "
        "import RNS; "
        "from hokora.constants import DESTINATION_ASPECT; "
        "ident = RNS.Identity.from_file(os.environ['IDENT_PATH']); "
        "h = RNS.Destination.hash(ident, DESTINATION_ASPECT, os.environ['CHANNEL_ID']); "
        "print(h.hex())"
    )
    env = os.environ.copy()
    env["REPO_SRC"] = str(REPO_DIR / "src")
    env["IDENT_PATH"] = str(identity_path)
    env["CHANNEL_ID"] = channel_id
    result = subprocess.run(
        [sys.executable, "-c", helper],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        pytest.fail(f"compute dest hash failed: {result.stderr}\n{result.stdout}")
    return result.stdout.strip()


def _seed_peer_row(node_dir: Path, dest_hash_hex: str, channel_id: str):
    """Insert a Peer row into NodeA's DB pre-daemon-start.

    Mirrors what ``hokora mirror add`` would do, but invoked directly
    against the sqlite file so we don't need to drive the CLI through
    a config + rate-limiter setup.
    """
    import sqlite3

    db_path = node_dir / "hokora.db"
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute(
            "SELECT identity_hash FROM peers WHERE identity_hash = ?",
            (dest_hash_hex,),
        )
        if cur.fetchone():
            conn.execute(
                "UPDATE peers SET channels_mirrored = ?, federation_trusted = 1 "
                "WHERE identity_hash = ?",
                (json.dumps([channel_id]), dest_hash_hex),
            )
        else:
            conn.execute(
                "INSERT INTO peers (identity_hash, channels_mirrored, federation_trusted) "
                "VALUES (?, ?, 1)",
                (dest_hash_hex, json.dumps([channel_id])),
            )
        conn.commit()
    finally:
        conn.close()


def _start_rnsd(rns_dir: Path) -> subprocess.Popen:
    return subprocess.Popen(
        ["rnsd", "--config", str(rns_dir)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _start_daemon(node_dir: Path, log_path: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_DIR / "src")
    env["HOKORA_CONFIG"] = str(node_dir / "hokora.toml")
    return subprocess.Popen(
        [sys.executable, "-m", "hokora"],
        env=env,
        stdout=log_path.open("wb"),
        stderr=subprocess.STDOUT,
        cwd=str(REPO_DIR),
    )


def _prepare_rns_dir(template: Path, dest: Path, instance_name: str, listen_port: int = 0):
    """Copy an RNS config template into a fresh dir, wiping persisted storage.

    The committed ``tests/live/rns_*`` dirs accumulate path-table state
    across runs; we copy the *config* into a per-test scratch dir so the
    storage subdir starts empty every time. Optionally rewrites the TCP
    port so we don't collide with a parallel pytest run.

    ``instance_name`` is injected under ``[reticulum]`` to give each
    RNS dir a distinct AF_UNIX abstract socket. Without this, when a
    parent Python process has already initialised
    ``RNS.Reticulum()`` against ``~/.reticulum`` (default
    ``instance_name = "default"``), child rnsd attaches as a CLIENT
    to that shared instance and never binds its TCPServerInterface.
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    src_cfg = (template / "config").read_text()
    if listen_port:
        src_cfg = src_cfg.replace("listen_port = 4242", f"listen_port = {listen_port}")
        src_cfg = src_cfg.replace("target_port = 4242", f"target_port = {listen_port}")
    # rnsd silently exits on duplicate ``instance_name`` keys, so replace
    # the template's existing line if present rather than injecting a second.
    if re.search(r"^\s*instance_name\s*=", src_cfg, re.MULTILINE):
        src_cfg = re.sub(
            r"^\s*instance_name\s*=.*$",
            f"  instance_name = {instance_name}",
            src_cfg,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        src_cfg = src_cfg.replace(
            "[reticulum]\n",
            f"[reticulum]\n  instance_name = {instance_name}\n",
            1,
        )
    (dest / "config").write_text(src_cfg)
    (dest / "storage").mkdir(exist_ok=True)


@pytest.fixture
def cold_start_env():
    """Sequenced fixture: rnsd_a + rnsd_b + NodeB-init-only, then yields
    a controller dict the test uses to start NodeA + NodeB daemons.

    Teardown kills every subprocess we launched and wipes scratch dirs.
    """
    procs: list[subprocess.Popen] = []
    log_dir = Path("/tmp/hokora_cold_logs")
    if log_dir.exists():
        shutil.rmtree(log_dir)
    log_dir.mkdir()

    # 1. Init both nodes.
    _init_node(NODE_A_DIR, "ColdNodeA")
    _init_node(NODE_B_DIR, "ColdNodeB")

    # 2. Fresh RNS dirs (empty storage / no stale paths).
    _prepare_rns_dir(RNS_A_TEMPLATE, RNS_A_DIR, "cold_start_a", RNS_TCP_PORT)
    _prepare_rns_dir(RNS_B_TEMPLATE, RNS_B_DIR, "cold_start_b", RNS_TCP_PORT)

    # 3. Write per-node TOML wiring observability + isolated rns dirs.
    _write_toml(NODE_A_DIR, "ColdNodeA", RNS_A_DIR, OBS_PORT_A)
    _write_toml(NODE_B_DIR, "ColdNodeB", RNS_B_DIR, OBS_PORT_B)

    # 4. Read NodeB's #general channel id and materialize its channel
    # identity standalone (without ever running NodeB's daemon).
    channel_id = _read_general_channel_id(NODE_B_DIR)
    ident_path = _materialize_channel_identity(NODE_B_DIR, channel_id)
    dest_hash_hex = _compute_dest_hash(ident_path, channel_id)

    # 5. Pre-seed NodeA's Peer table.
    _seed_peer_row(NODE_A_DIR, dest_hash_hex, channel_id)

    # 6. Start both rnsd processes. NodeB's rnsd is up so the link can
    # later succeed; NodeA's rnsd starts with no path entry for NodeB.
    procs.append(_start_rnsd(RNS_A_DIR))
    procs.append(_start_rnsd(RNS_B_DIR))
    time.sleep(2.0)

    # ``hokora init`` does not create the daemon's api_key file (the web
    # dashboard does, on first launch). The daemon's ObservabilityListener
    # only enables /api/metrics when api_key is non-None — so for this
    # test we pre-write a stable shared secret per node before launching.
    import secrets

    api_key_a = secrets.token_hex(32)
    api_key_b = secrets.token_hex(32)
    for node_dir, key in ((NODE_A_DIR, api_key_a), (NODE_B_DIR, api_key_b)):
        api_key_path = node_dir / "api_key"
        api_key_path.write_text(key)
        os.chmod(api_key_path, 0o600)

    state = {
        "channel_id": channel_id,
        "dest_hash_hex": dest_hash_hex,
        "api_key_a": api_key_a,
        "api_key_b": api_key_b,
        "log_dir": log_dir,
        "procs": procs,
        "daemon_a": None,
        "daemon_b": None,
    }

    def start_daemon_a():
        proc = _start_daemon(NODE_A_DIR, log_dir / "daemon_a.log")
        state["daemon_a"] = proc
        procs.append(proc)
        if not _wait_for_obs(OBS_PORT_A, timeout=30):
            pytest.fail(
                "NodeA observability did not come up. Log:\n"
                + (log_dir / "daemon_a.log").read_text(errors="replace")[-4000:]
            )

    def start_daemon_b():
        proc = _start_daemon(NODE_B_DIR, log_dir / "daemon_b.log")
        state["daemon_b"] = proc
        procs.append(proc)
        if not _wait_for_obs(OBS_PORT_B, timeout=30):
            pytest.fail(
                "NodeB observability did not come up. Log:\n"
                + (log_dir / "daemon_b.log").read_text(errors="replace")[-4000:]
            )

    state["start_daemon_a"] = start_daemon_a
    state["start_daemon_b"] = start_daemon_b

    yield state

    for p in procs:
        _kill(p)
    for d in (NODE_A_DIR, NODE_B_DIR, RNS_A_DIR, RNS_B_DIR):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)


def test_cold_start_mirror_parks_then_links_after_announce(cold_start_env):
    """N3 fix end-to-end: mirror parks WAITING_FOR_PATH, then LINKED via announce wake-up.

    Assertions trace the full state-machine flow:

    1. After NodeA's daemon comes up alone, the mirror must report
       state=waiting_for_path and accumulate ``recall_none`` attempts.
    2. After NodeB's daemon comes up and announces, NodeA's mirror
       must transition to state=linked and ``success`` >= 1.
    """
    env = cold_start_env

    # Step 1 — NodeA up alone, NodeB silent. Mirror must park.
    env["start_daemon_a"]()

    t0 = time.monotonic()
    parked, metrics = _wait_for_state(
        OBS_PORT_A,
        env["api_key_a"],
        "waiting_for_path",
        timeout=30,
    )
    print(f"[cold-start] step 1 parked in {time.monotonic() - t0:.1f}s", flush=True)
    assert parked, f"Mirror did not enter waiting_for_path state.\nLast metrics:\n{metrics[-2000:]}"

    recall_attempts = _attempt_count(metrics, "recall_none")
    assert recall_attempts >= 1, (
        f"Expected at least one recall_none attempt; got {recall_attempts}.\n"
        f"Metrics:\n{metrics[-2000:]}"
    )
    assert not _has_state(metrics, "linked"), (
        f"Mirror must not be linked before NodeB has announced.\nMetrics:\n{metrics[-2000:]}"
    )

    # Step 2 — NodeB comes online. Mirror should wake on announce.
    env["start_daemon_b"]()
    t1 = time.monotonic()

    linked, metrics_after = _wait_for_state(
        OBS_PORT_A,
        env["api_key_a"],
        "linked",
        # Bound covers two distinct pathways:
        #   1. Announce-driven wake-up (production, RNS-instance owner): <1s.
        #   2. Periodic mirror-health fallback (this fixture, RNS shared-
        #      instance client): RNS >=1.1.7 introduced PATH_REQUEST_GATE_TIMEOUT
        #      (120s) which defers the link-management loop's path-request
        #      retry; the link establishes on the next periodic tick after
        #      the gate clears. Production daemons own the RNS instance and
        #      take the direct ``Identity._used_destination_data`` branch,
        #      never hitting the gate. Threshold is 180s to give 60s headroom
        #      over the gate timeout.
        timeout=180,
    )
    print(f"[cold-start] step 2 linked in {time.monotonic() - t1:.1f}s", flush=True)
    assert linked, (
        "Mirror did not transition to linked after NodeB announced. "
        "This is the regression N3 prevents.\n"
        f"Last metrics:\n{metrics_after[-2000:]}\n\n"
        f"NodeA log tail:\n" + (env["log_dir"] / "daemon_a.log").read_text(errors="replace")[-3000:]
    )

    assert _attempt_count(metrics_after, "success") >= 1, (
        "Expected ``success`` connect-attempt counter to advance after link.\n"
        f"Metrics:\n{metrics_after[-2000:]}"
    )

    # Sanity: the ``hokora_mirror_link_state`` row must reference the
    # destination hash we seeded — proves the wake-up keyed on the
    # right value. A latent bug class would match on
    # ``announced_identity.hash`` instead of ``destination_hash``; if
    # that regresses, the linked row would never appear for this peer.
    expected_peer_label = env["dest_hash_hex"]
    assert any(
        line.startswith("hokora_mirror_link_state{")
        and f'peer="{expected_peer_label}"' in line
        and 'state="linked"' in line
        for line in metrics_after.splitlines()
    ), (
        "linked-state row missing the seeded peer hash; "
        "wake-up may be matching the wrong key.\n"
        f"Metrics:\n{metrics_after[-2000:]}"
    )

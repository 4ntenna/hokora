# 04 — Transport Setup

Hokora does not implement transport itself — it runs on Reticulum (RNS). This runbook covers how to configure Reticulum interfaces for the transports Hokora is deployed over: TCP, I2P, and LoRa (via an RNode).

The canonical RNS documentation lives at <https://reticulum.network/manual/>. This runbook covers only what an operator needs to run a Hokora node.

## RNS configuration location

By default the daemon uses `~/.reticulum/config`. To point at a custom path, set `rns_config_dir` in `hokora.toml` or `HOKORA_RNS_CONFIG_DIR` in the environment. `hokora init` writes a minimal `rns/config` under the data dir with commented-out interface examples.

## The `share_instance` rule

On a co-host where both the daemon and the TUI use the same RNS config directory, set:

```ini
[reticulum]
  enable_transport = No
  share_instance   = Yes
```

**Start the daemon before the TUI.** The first process to bind the RNS shared-instance socket becomes the owner and provides transport for everyone else. If the TUI wins the race, announces propagate inconsistently.

Verify ownership:

```bash
lsof -U | grep rns/default
```

The owner is the row with `(LISTEN)`. Everything else should be `(CONNECTED)`.

If inverted, see [11-incident-response.md § Shared-instance inversion](11-incident-response.md#shared-instance-inversion).

---

## Managing seeds — `hokora seed` (recommended)

A filesystem-gated CLI edits the RNS config for you. This is the preferred way to add or remove outbound seed entries from either a shell or the TUI Network tab. The TUI mutates the same file directly in-process (no subprocess); the CLI is provided for operators who prefer a shell, and for environments where the TUI isn't running. Both paths go through the same atomic-write + `config.prev` backup helper — you can mix them freely.

```bash
hokora seed list
hokora seed add "TCP Seed" seed.example.invalid:4242    # TCP
hokora seed add "I2P Seed" abcdefgh.b32.i2p             # I2P
hokora seed remove "TCP Seed"
hokora config validate-rns                              # dry-run parse check
```

After `add` / `remove`, the daemon must be restarted to pick up the new config. On supervised deployments:

```bash
sudo systemctl restart hokorad        # systemd
docker compose restart hokorad        # docker
```

For bare `python -m hokora` dev runs the CLI can respawn the daemon itself via the `hokorad.argv` sibling file:

```bash
hokora seed apply --restart
```

`hokora seed apply` without `--restart` prints the supervisor command appropriate for your deployment.

### Which config file does the CLI edit?

`hokora seed` resolves the RNS config path in this order:

1. `rns_config_dir` set in your `hokora.toml` (operator-owned daemon install) — this is what `hokora init` configures.
2. If `hokora.toml` is absent or doesn't set `rns_config_dir`, fall back to `~/.reticulum/config` (the RNS default) and print a visible notice on stderr before operating. Standalone-TUI users who never ran `hokora init` land here naturally.

The fallback is always loud — the CLI prints which file it's about to touch. Silent misdirection of seed writes would be worse than a missing command. If you need to force a specific config across both paths, set `HOKORA_CONFIG=/path/to/hokora.toml` and `hokora seed` will obey it.

### How the Network tab reads your configuration

The TUI's Network tab reads the RNS config file its own `RNS.Reticulum()` was constructed against — the same file RNS will read at next startup. This works identically in every topology:

- **Standalone TUI** (no local daemon): reads `~/.reticulum/config`, or whatever `HOKORA_CONFIG`'s `rns_config_dir` points at.
- **Local daemon-attached TUI**: reads the shared `rns_config_dir` — daemon and TUI see the same file.
- **Remote daemon-attached TUI** (TUI on one host, daemon on another): reads the TUI's own local config. Edits here affect only the local RNS instance, not the remote daemon's transport. If you intend to edit the remote daemon's config, SSH to that host and run `hokora seed` there.

The Apply button is topology-aware. Daemon-attached deployments get a supervisor-assisted restart path; standalone and remote-daemon TUIs get an honest "Restart the TUI to apply" message. The TUI never kills a process it does not own.

Every `add` / `remove` writes the RNS config atomically at 0o600 and leaves the prior content in `config.prev` (also 0o600). If a new seed entry bricks the daemon, restore with:

```bash
mv ~/.reticulum/config.prev ~/.reticulum/config
sudo systemctl restart hokorad
```

Authorization is implicit: the CLI mutates the filesystem, which is already protected by unix ownership of the RNS config directory. Any caller that can read `hokora.toml` and write `rns_config_dir` is by definition the node owner. The TUI inherits this — `hokora seed add` from the Network tab runs as the TUI's UID, which is the same UID as the daemon in every supported deployment.

Manual config edits are still supported and documented below for operators who prefer them; use whichever fits.

## TCP

### Client — connect to an existing seed

You can edit the config manually or use `hokora seed add`. The manual form:

```ini
[interfaces]
  [[Seed Node]]
    type         = TCPClientInterface
    enabled      = yes
    target_host  = 192.168.1.100
    target_port  = 4242
```

### Server — run a seed for others

```ini
[reticulum]
  enable_transport = Yes
  share_instance   = Yes

[interfaces]
  [[TCP Server]]
    type        = TCPServerInterface
    enabled     = yes
    listen_ip   = 0.0.0.0
    listen_port = 4242
```

Open the port on your firewall. For a public seed, front with a stable DNS name and mention it in the operator docs you distribute to clients.

### Multi-interface (seed plus AutoInterface)

```ini
[reticulum]
  enable_transport = Yes
  share_instance   = Yes

[interfaces]
  [[Auto]]
    type    = AutoInterface
    enabled = yes

  [[TCP Seed]]
    type        = TCPClientInterface
    enabled     = yes
    target_host = seed.example.invalid
    target_port = 4242
```

---

## I2P

Requires an I2P router (`i2pd` recommended) on the same host. The I2P SAM API should be reachable at `127.0.0.1:7656`.

```ini
[interfaces]
  [[I2P]]
    type             = I2PInterface
    enabled          = yes
    peers            = <remote-b32-address>.b32.i2p
    i2p_tunnel_port  = 7099
    bandwidth        = P
```

Gotchas:

- `bandwidth = P` is an I2P bandwidth class letter (K, L, M, N, O, P, X), **not** a kbit/s value.
- `i2p_tunnel_port` should be unique per tunnel.
- First tunnel establishment takes 5–30 s; subsequent reuse is fast.
- Link establishment timeout over I2P can hit the 30 s/hop floor; see [Known quirks](#known-quirks).

`i2pd` minimal config snippet (`/etc/i2pd/i2pd.conf`):

```ini
bandwidth = P
[sam]
enabled = true
address = 127.0.0.1
port = 7656
```

### Containers

The full image (`Dockerfile.full`) ships `i2pd` and the `i2plib` Python binding. Both are bundled regardless of deployment so the image is portable across transports; the i2pd process is opt-in at runtime.

Set `HOKORA_ENABLE_I2P=true` on the container to launch the SAM bridge alongside the daemon:

```yaml
services:
  hokorad:
    image: hokora:latest
    environment:
      HOKORA_ENABLE_I2P: "true"
```

Behaviour:

- The entrypoint probes `127.0.0.1:7656` first. If a SAM bridge is already listening — typical of `network_mode: host` deployments where the host runs `i2pd` as a system service — it reuses that bridge instead of spawning a duplicate that would lose the port race.
- Otherwise it launches `i2pd` with `--datadir=$HOKORA_DATA_DIR/i2pd`, which keeps router state on the same volume as the daemon's database. Tunnel reuse across container restarts is automatic.
- The signal trap reaps i2pd alongside the daemon on `SIGTERM`/`SIGINT`.

Pair it with the same `[[I2P]]` block in your mounted RNS config — for a connectable seed that omit `peers`:

```ini
[interfaces]
  [[I2P]]
    type            = I2PInterface
    enabled         = yes
    connectable     = yes
    i2p_tunnel_port = 7099
    bandwidth       = P
```

Verify the bridge is wired through with `ss -tn | grep :7656`. A live `[[I2P]]` interface holds two ESTAB SAM connections — one for the destination, one for the connectable listener.

If `HOKORA_ENABLE_I2P` is unset or `false`, no i2pd starts and no extra Python imports happen; the I2P bundle adds image size only.

---

## RNode / LoRa

Hokora has been tested on Heltec V3 boards flashed with RNode firmware. Use the UK 868 MHz or US 915 MHz band as appropriate for your region — **this is your regulatory responsibility.**

```ini
[interfaces]
  [[LoRa]]
    type            = RNodeInterface
    enabled         = yes
    port            = /dev/ttyUSB0
    frequency       = 868000000
    bandwidth       = 125000
    txpower         = 7
    spreadingfactor = 8
    codingrate      = 5
```

**Critical RNS config key gotchas** — these have no underscores:

- `spreadingfactor` (not `spreading_factor`)
- `codingrate` (not `coding_rate`)

Typos silently disable the interface.

### Region quick reference

| Region | Band | Typical frequency |
|---|---|---|
| UK / EU | 868 MHz | `868000000` |
| US / CA | 915 MHz | `915000000` |
| AU / NZ | 915 MHz | `915000000` |
| AS (region-dependent) | 433 / 868 / 915 | varies |

Always check national regulations for duty-cycle limits and permitted TX power.

### Recommended CDSP profile for LoRa

Clients on a LoRa transport should use the `MINIMAL` CDSP profile. Daemons handle this automatically when the client declares it; otherwise the TUI `/sync <channel_id> 3` command sets it manually (`3` = MINIMAL).

### RNode setup

1. Flash your board with [RNode firmware](https://unsigned.io/rnode/).
2. Connect via USB. The device appears as `/dev/ttyUSB0` or `/dev/ttyACM0`.
3. On Linux, add your user to the `dialout` group: `sudo usermod -aG dialout $USER`; log out and back in.
4. Test with `rnsd -v` before configuring Hokora.

---

## Multi-transport layering

A node can expose more than one transport. For example, a community node with both a public TCP seed and LoRa outreach:

```ini
[reticulum]
  enable_transport = Yes
  share_instance   = Yes

[interfaces]
  [[TCP Public]]
    type        = TCPServerInterface
    enabled     = yes
    listen_ip   = 0.0.0.0
    listen_port = 4242

  [[LoRa 868]]
    type            = RNodeInterface
    enabled         = yes
    port            = /dev/ttyUSB0
    frequency       = 868000000
    bandwidth       = 125000
    txpower         = 7
    spreadingfactor = 8
    codingrate      = 5
```

RNS treats each interface independently; announces reach peers on whichever interface they share with the node.

---

## Known quirks

- **Per-hop link establishment timeout: 30 seconds.** The TUI raises RNS's default to a 30 s-per-hop floor for I2P / LoRa tolerance. See `src/hokora_tui/sync/link_manager.py`.
- **Link keepalive: 120 s floor.** Both the daemon and the TUI enforce a 120 s minimum keepalive interval to prevent premature staleness on low-RTT links.
- **`TCPClientInterface` announce-rate attributes.** RNS 1.1.4's `TCPClientInterface` does not initialise `announce_rate_target` and siblings. Hokora monkey-patches these to `None` after `RNS.Reticulum()` init in both daemon and TUI. Remove the patch when RNS > 1.1.4 ships the fix.
- **Resource inbound size filter.** The daemon filters inbound `RNS.Resource` to 5 MB max. Larger transfers are rejected at the RNS layer before any Hokora code sees them.
- **Single Link per remote node.** All channels multiplex through one Link with a `channel_id` in the payload. RNS limits remote clients to one active Link per destination.

---

## Fleet operator notes

- Treat RNS config as configuration-managed state. Track it in your config-management system the same way you track `hokora.toml`.
- If you rotate a seed's DNS or IP, push an updated config to every client that points at it. RNS doesn't fall back to a new address automatically.
- For geographically distributed fleets, run one or more public TCP seeds with stable addresses and configure all community nodes to use them as `TCPClientInterface` targets. This bootstraps discovery quickly without relying on AutoInterface multicast.
- Health-check RNS interfaces with the `hokora_rns_interface_up` Prometheus metric family. See [09-monitoring-observability.md § Metrics catalogue](09-monitoring-observability.md#metrics-catalogue).

---

## See also

- [01-installation.md](01-installation.md) for system prerequisites.
- [05-federation.md](05-federation.md) for peer trust model once transport is established.
- [11-incident-response.md](11-incident-response.md) for transport diagnostics.

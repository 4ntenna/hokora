# 05 — Federation and Propagation

Hokora has two distinct inter-node mechanisms:

1. **Channel federation** — community node ↔ community node, per-peer per-channel mirror over an authenticated RNS Link. Uses Hokora's own protocol with Ed25519 challenge-response and forward-secret epochs.
2. **LXMF propagation peering** — relay node ↔ relay node, store-and-forward of arbitrary LXMF messages for offline destinations. Uses LXMF's native protocol with proof-of-work peering keys.

The two operate independently. A relay node typically only does propagation; a community node typically only does federation; an operator running both roles on the same host runs both subsystems.

This runbook covers each mechanism: peer discovery, handshake, trust, mirror setup, epoch semantics, propagation peering, and operational procedures.

## Glossary

| Term | Meaning |
|---|---|
| **Peer** | Another node this node has completed a federation handshake with. Stored in the `Peer` table. |
| **Trust** | A boolean on a peer row. Only trusted peers are allowed to push messages into local channels. |
| **Mirror** | A `(peer, channel)` row declaring that this node replicates that channel from that peer. |
| **Handshake** | The six-step Ed25519 challenge-response protocol that establishes a federation session. |
| **Epoch** | A forward-secret time slice. Each epoch has its own directional keys for XChaCha20-Poly1305. |
| **TOFU** | Trust On First Use. Default behaviour for peer Ed25519 keys: accept the first observed key, reject changes unless explicitly updated. |

## Peer discovery

Nodes announce themselves on RNS periodically (`announce_interval`, default 600 s). Announces reach every interface the node is reachable on.

To see what your node has discovered:

```bash
hokora node peers
```

The table shows each peer's identity hash, node name, last-seen timestamp, and federation trust state. Peers appear here only after the handshake has completed once — simply seeing a peer's announce is not enough.

## Adding a peer

Peering is bidirectional but initiated by one side. The initiator must know the remote destination hash (from the remote operator, or printed by `hokora node status` on the remote host).

Sequence:

1. **Register a mirror** — tells your node *which channel* to mirror from that peer.
2. **Trust the peer** — authorises their pushes into local channels.
3. **Restart the daemon** to pick up the new mirror config.

```bash
# On node A, learn the remote destination hash of node B
hokora node status         # on B, note the node identity hash

# On node A, register a mirror for channel "ops" from node B
hokora mirror add <B_identity_hash> <channel_id_of_ops>

# On A, trust B for federation writes
hokora mirror trust <B_identity_hash>

# Restart A so the MirrorLifecycleManager picks up the new row
sudo systemctl restart hokorad     # or: hokora daemon stop && hokora daemon start
```

Repeat symmetrically on B if you want two-way replication.

## Handshake

The six-step handshake runs automatically on first contact with a new peer. You should not have to interact with it, but understanding the steps helps during incident response.

| Step | Direction | Purpose |
|---|---|---|
| 1 | A → B | Ed25519 challenge (32 random bytes) + node metadata + timestamp |
| 2 | B → A | Signs A's challenge; sends a counter-challenge |
| 3 | A → B | Signs B's counter-challenge; sends its public key |
| 4 | B → A | ACK + FS-capability flag |
| 5 | A → B | If FS-capable, initiate epoch key exchange |
| 6 | B → A | Epoch rotate ACK |

Failure modes:

- **Step 2 fails**: the initiator's signature did not verify. Peer rejects — usually means mismatched identity keys on the sender side.
- **TOFU mismatch at step 3**: peer's public key differs from the stored one. Handshake is refused. See [Key changes](#key-changes) below.
- **Step 5 fails**: FS is enabled but the X25519 exchange failed. Falls back only if `require_signed_federation=false` — the default `true` refuses the fallback.

## Trust policy

Trust gates *writes*, not reads. An untrusted peer can still be seen in `hokora node peers` and its announces still propagate; it just can't push messages into your channels.

```bash
hokora mirror trust <peer_hash>    # allow writes
hokora mirror untrust <peer_hash>  # revoke
```

`federation_auto_trust=true` in `hokora.toml` will auto-trust every peer that completes a handshake. This is safe inside a closed trusted mesh; on a public mesh it is dangerous — do not enable it without understanding the consequences.

## Key changes (TOFU)

The default is `reject_key_change=True` in `PeerKeyStore`. If a peer's public key ever changes — key regeneration on the remote side, a compromised node, or a MITM attempt — the handshake fails with a `FederationError` and the stored key is left untouched.

To accept a legitimate new key, an operator must manually update it:

```bash
# There is no CLI flag for this; the procedure is:
# 1. Verify the new key with the remote operator out of band.
# 2. Delete the old peer row (hokora currently has no `peer delete` command;
#    a DB-level delete is required, documented here until added).
sqlcipher $DATA_DIR/hokora.db
PRAGMA key = "<your_db_key>";
DELETE FROM peers WHERE identity_hash = '<hex>';
.quit

# 3. Restart and re-handshake.
sudo systemctl restart hokorad
```

## Forward-secret epochs

Once the handshake establishes trust, every message on the federation link is encrypted under the current epoch's XChaCha20-Poly1305 key.

| Stage | Details |
|---|---|
| Ephemeral keypair | X25519, per epoch |
| Shared secret | ECDH over the peer's long-term key |
| Key derivation | HKDF-SHA256 with salt `b"hokora-epoch-v1"` |
| Directional keys | Initiator→Responder and Responder→Initiator, 32 bytes each |
| Nonce | 16-byte prefix + 8-byte counter → 24 byte XChaCha20 nonce |
| AAD | Epoch-scoped, prevents cross-epoch replay |
| At-rest wrapping | HKDF-derived KEK from node identity; `XChaCha20-Poly1305(key, AAD=b"epoch-key-wrap")` |
| Persistence | `FederationEpochState` table |
| Rotation cadence | `fs_epoch_duration`, default 3600 s |
| Acceptable range | `fs_min_epoch_duration` to `fs_max_epoch_duration` |
| Rotation retries | `fs_rotation_max_retries`, initial backoff `fs_rotation_initial_backoff` |
| Chain continuity | `HMAC-SHA256(epoch_key, b"epoch_chain")` — next epoch carries the previous chain hash, preventing epoch hijacking |
| Key erasure | Directional keys are held in bytearrays and zeroed on teardown |

Disabling forward secrecy (`fs_enabled=false`) disables all of the above and falls back to the RNS link encryption only. This is a supported configuration for legacy peers but not recommended for new deployments.

## Push cursors and retry

The `FederationPusher` maintains a per-peer cursor (`Peer.sync_cursor["_push"]`). Messages past the cursor are pushed in batches of 15 with at-least-once delivery (receivers dedupe by `msg_hash`).

| Field | Default | Purpose |
|---|---|---|
| `federation_push_retry_interval` | 60 s | Sweep failed pushes |
| `federation_push_max_backoff` | 600 s | Cap on exponential backoff per peer |

On peer reconnect, the pusher drains any queued messages immediately before resuming steady-state.

## Mirror ingest

Inbound pushes are validated at multiple layers:

1. Peer must be trusted.
2. `origin_node` must not equal the local node (loop prevention).
3. Ed25519 signature on the LXMF payload must verify.
4. Clock drift must fall within 5 min of the local node's clock.
5. Nonce must not have been seen in the last 10 min (replay protection).
6. Sealed-channel pushes with plaintext body are rejected; ciphertext-only is accepted verbatim.

Violations are logged to `hokorad.log` at WARNING level and emit a metric increment on `hokora_federation_peers`.

## Operational procedures

### Listing what is peered

```bash
hokora node peers
hokora mirror list
```

### Rotating a peer's trust state

```bash
hokora mirror untrust <peer_hash>
# Do whatever investigation you need
hokora mirror trust <peer_hash>
```

No restart required for trust toggles.

### Removing a mirror

```bash
hokora mirror remove <peer_hash> <channel_id>
sudo systemctl restart hokorad
```

### Watching federation health

Metrics to alert on:

- `hokora_federation_peers{trusted="true"}` — expected count matches your roster
- `hokora_peer_sync_cursor_seq{peer=...,channel=...}` — not falling behind the latest `hokora_channel_latest_seq_ingested`
- `hokora_deferred_sync_items{channel=...}` — spike implies push is queuing

See [09-monitoring-observability.md § Metrics catalogue](09-monitoring-observability.md#metrics-catalogue).

## Known issue

**Federation cold-start stall.** On first mirror-add after daemon boot, the RNS Link establishment to the peer can fail silently for up to 5 minutes before succeeding. Not cleanly reproducible. Workaround: restart the daemon once the peer is reachable on RNS (check `rnpath`).

---

# Part 2 — LXMF propagation peering

The remainder of this runbook covers LXMF propagation node peering. This is a distinct subsystem from channel federation above and is configured separately. Skip this section if you do not run a relay node.

## Layered model

| Layer | Mechanism | Operator action |
|---|---|---|
| Reticulum transport | Any node with `enable_transport = Yes` in its RNS config relays encrypted RNS packets between other nodes. | RNS config only; no Hokora configuration required. |
| LXMF propagation | Relay nodes with `propagation_enabled = true` store messages for offline destinations and deliver them when the destinations come back online. | Relay-mode `hokora.toml` and propagation peering. |
| Channel federation | Community nodes mirror channel state to one another via Hokora's own protocol. | `hokora mirror` CLI, see Part 1 above. |

## Setting up a propagation node

A propagation node is a relay node with LXMF propagation enabled.

### Configuration

```toml
# ~/.hokora/hokora.toml
node_name = "Relay-1"
data_dir = "/var/lib/hokora"
log_level = "INFO"
rns_config_dir = "/etc/reticulum"
announce_interval = 600

# Relay mode — no channels, no database.
relay_only = true

# LXMF propagation — store and forward messages.
propagation_enabled = true
propagation_storage_mb = 500
```

### Starting

```bash
HOKORA_CONFIG=/etc/hokora/hokora.toml hokorad --relay-only
```

Or via Docker:

```yaml
environment:
  HOKORA_RELAY_ONLY: "true"
```

Expected log lines on first start:

```
LXMF propagation enabled (storage limit: 500MB, autopeer=True, max_peers=20, static_peers=0)
Relay node started: Relay-1 (<identity_hash>)
```

The node now relays RNS packets, stores LXMF messages for offline destinations, and announces itself as a propagation node every `announce_interval` seconds.

## Propagation peering

Propagation peering connects relay nodes so they share their message stores. When a message arrives at relay A, it syncs to relay B. End-user clients can retrieve messages from whichever propagation node is reachable.

### Auto-peering

Auto-peering is enabled by default. Propagation nodes discover each other via RNS announces.

```toml
# Defaults — only set these to override.
propagation_autopeer = true
propagation_autopeer_maxdepth = 4
propagation_max_peers = 20
```

| Setting | Default | Purpose |
|---|---|---|
| `propagation_autopeer` | `true` | Enable automatic peer discovery |
| `propagation_autopeer_maxdepth` | `4` | Maximum network hops considered for auto-peering |
| `propagation_max_peers` | `20` | Concurrent peer cap (auto + static combined) |

The handshake fires within one announce cycle once two relays observe each other's announces on the `lxmf/propagation` aspect. Sync proceeds bidirectionally via offer / response. Low-performing peers are rotated out; unreachable peers are removed after 14 days.

### Static peering

Static peering pins a connection to specific nodes. Use it when you operate relays across geographic regions, when you require deterministic peering, or when peers exceed `autopeer_maxdepth` hops apart.

```toml
propagation_static_peers = [
    "a1b2c3d4e5f6789012345678abcdef01",
    "deadbeef12345678abcdef0123456789",
]
```

Each entry is the RNS destination hash of another propagation node's `lxmf/propagation` destination. Static peers are always maintained, retried indefinitely on failure, and resume from the last cursor on reconnect. Static peers count toward `propagation_max_peers`.

### Discovering a node's propagation destination hash

After starting a relay node, derive its propagation destination hash from the node identity:

```bash
PYTHONPATH=src python3 -c "
import RNS
RNS.Reticulum('/etc/reticulum')
identity = RNS.Identity.from_file('/var/lib/hokora/identities/node_identity')
dest_hash = RNS.Destination.hash_from_name_and_identity('lxmf.propagation', identity)
print(dest_hash.hex())
"
```

Share the resulting hash with peer operators for static peering.

### Combining auto and static

Auto and static peering coexist. Static peers are always maintained. Remaining `propagation_max_peers - len(static_peers)` slots are available for auto-discovered peers.

## Peering security

Propagation peering uses LXMF proof-of-work authentication. Each side derives a peering key by computing a hash collision against the combined identity hashes. This raises the cost of peering spam.

| Parameter | Default | Purpose |
|---|---|---|
| Peering cost | 18 | Proof-of-work difficulty for peering handshake |
| Max peering cost | 26 | Reject peers requesting higher difficulty |
| Propagation cost | 16 | Stamp cost for message propagation |

Defaults match LXMF's recommendations. Adjust only if you have a specific reason.

## LXMF sync protocol

Once two propagation nodes are peered, they sync as follows:

1. **Offer.** Node A sends a list of message IDs it holds for Node B.
2. **Response.** Node B replies with the subset it does not have.
3. **Transfer.** Node A sends the requested messages via `RNS.Resource` (reliable multi-packet transfer).
4. **Mark handled.** Both nodes update their sync state.

Both directions exchange messages independently. Sync runs each time a peer announces and after every successful transfer; there is no operator-tunable strategy.

## Federation versus propagation peering

| Property | Propagation peering | Channel federation |
|---|---|---|
| What syncs | Raw LXMF messages addressed to any destination | Channel-specific messages |
| Authentication | Proof-of-work peering keys | Ed25519 challenge-response |
| Forward secrecy | None | Optional (epoch-based) |
| Node types | Relay ↔ Relay | Community ↔ Community |
| Wire protocol | LXMF native (offer / response) | Hokora sync protocol |
| Use case | Message store-and-forward backbone | Cross-node channel mirroring |

## Example deployment: three-node mesh

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Community    │     │    Relay     │     │  Community    │
│  Node West    │◄───▶│   (Seed)     │◄───▶│  Node East    │
│  (channels)   │     │ (propagation)│     │  (channels)   │
└──────────────┘     └──────────────┘     └──────────────┘
       ▲                    ▲                     ▲
       │                    │                     │
   TUI clients         (no clients)          TUI clients
```

- **Relay (Seed):** `relay_only=true`, `propagation_enabled=true`. Auto-peers with both community nodes.
- **Community West / East:** Full channel management. Federated to each other via `hokora mirror add`.
- **TUI clients:** Connect to their nearest community node. Offline messages held by the relay until the recipient comes back.
- **LoRa clients:** Messages propagate through the relay even with intermittent connectivity.

## Monitoring propagation

Quick state checks:

```bash
# Peer count and sync state
ls $DATA_DIR/lxmf_node/lxmf/peers

# Message store size
du -sh $DATA_DIR/lxmf_node/lxmf/messagestore/

# Node stats blob
python3 -c "import msgpack; print(msgpack.unpackb(open('$DATA_DIR/lxmf_node/lxmf/node_stats','rb').read()))"
```

Under Docker, daemon logs surface peering events:

```bash
docker logs hokorad --tail 50 | grep -i 'propagation\|peer'
```

## Propagation troubleshooting

**Peers do not discover each other.**
Verify both nodes have `propagation_enabled = true`. Confirm RNS transport connectivity between them with `rnpath -t`. Increase `propagation_autopeer_maxdepth` if the nodes are more than four hops apart, or fall back to static peering.

**Messages do not sync.**
Confirm the peer state file exists at `lxmf/peers`. Check that `propagation_storage_mb` has not been exceeded. Search the logs for `peering key` validation failures, which indicate a proof-of-work cost mismatch.

**High storage usage.**
Reduce `propagation_storage_mb`. LXMF prunes the oldest messages automatically when the limit is reached.

## See also

- [06-sealed-channels.md](06-sealed-channels.md) for the sealed-channel invariant on federated channels.
- [10-database-operations.md](10-database-operations.md) for how federation state is persisted.
- [11-incident-response.md § Federation stalled](11-incident-response.md#federation-stalled) for runbook-level diagnosis.

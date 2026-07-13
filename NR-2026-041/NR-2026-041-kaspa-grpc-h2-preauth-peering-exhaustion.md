# NR-2026-041 — Kaspa (rusty-kaspa): pre-auth HTTP/2 stream flood on the tonic gRPC P2P endpoint → inbound-peering exhaustion (eviction + admission denial)

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

The `rusty-kaspa` tonic gRPC P2P service (`/protowire.P2P/MessageStream`) accepts inbound peer connections
with **no admission-time gate**: `connection_handler.rs:222` (`NewPeer`) applies **no TLS, no IP-allowlist, no
ban check, no per-IP connection cap, and no concurrency layer** before a peer is admitted. The only inbound
bound (`--maxinpeers`) is applied **lazily and randomly** by the connection manager
(`connectionmanager/lib.rs:247`), not synchronously at accept time. As a result **one unauthenticated,
crypto-free host** opening ~512 pre-auth HTTP/2 streams (a) **evicts 100% of honest inbound peers** at the
random 30-second connection-manager tick, and (b) **100%-denies honest inbound admission** via a serial-Hub
head-of-line stall. This is finding **KAS-H1**, **measured 2026-06-02**. It is an **inbound-peering
availability** DoS — MEDIUM; Kaspa is Proof-of-Work, so this is **not a consensus halt**. Availability-class
DoS on a public-by-default P2P surface is **out of paid scope**, handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `KASPA_P2P_GRPC_H2_PREAUTH_EXHAUSTION` (KAS-H1) | `kaspa_grpc_h2_preauth_stream_flood` | rusty-kaspa tonic gRPC P2P (`/protowire.P2P/MessageStream`) | `preauth-stream-flood` + `peering-DoS` | MEDIUM |

- **Reachability:** any remote host that can reach the node's gRPC P2P port; no auth, no crypto, no handshake
  completion, minimal bandwidth, single source suffices.
- **Severity:** MEDIUM — ~512 pre-auth HTTP/2 streams from **one** host both evict every honest inbound peer
  (random 30 s connection-manager tick) and deny all new honest inbound admission (serial-Hub HOL stall).
  Availability only, **out of paid scope**, publish-track.
- **Affected:** `rusty-kaspa` nodes exposing the tonic gRPC P2P endpoint with the default admission path
  (`connection_handler.rs:222` `NewPeer` with no pre-`NewPeer` gate).
- **Mitigation:** add an admission-time gate **before** `NewPeer` (per-IP connection + stream caps, ban list,
  TLS or handshake-proof); make `--maxinpeers` a real synchronous admission bound. See Mitigation.

## Mechanism (source-cited, `kaspanet/rusty-kaspa`)

- **No admission-time gate.** `connection_handler.rs:222` handles `NewPeer` on the tonic gRPC P2P service
  (`/protowire.P2P/MessageStream`) with **no TLS, no IP-allowlist, no ban-list check, no per-IP connection or
  stream cap, and no tower/concurrency layer** in front of it. A peer is admitted before any authentication or
  rate discipline is applied.
- **The only bound is lazy and random.** The inbound cap `--maxinpeers` is not enforced synchronously at
  accept time; the connection manager (`connectionmanager/lib.rs:247`) enforces it **lazily** and evicts peers
  **randomly** on a ~30-second tick. A flood of pre-auth connections is therefore admitted first and only
  reconciled later — and the eviction victim is chosen at random, so honest peers are swept out alongside (or
  instead of) the attacker's.
- **The attack.** One unauthenticated, crypto-free host opens ~512 pre-auth HTTP/2 streams to the gRPC P2P
  endpoint. Two effects compound:
  1. **Eviction:** at the random 30 s connection-manager tick the over-count is reconciled by random eviction,
     which removes **100% of honest inbound peers**.
  2. **Admission denial:** the accept path funnels through a **serial Hub**, so the flood creates a
     **head-of-line stall** that **100%-denies honest inbound admission** while the flood persists.

## Measurement (fidelity: explicit)

Finding **KAS-H1**, **measured 2026-06-02**. A single unauthenticated, crypto-free host opening **~512 pre-auth
HTTP/2 streams** against the rusty-kaspa tonic gRPC P2P endpoint produced, concurrently:

- **100% of honest inbound peers evicted** at the random 30-second connection-manager tick.
- **100% of honest inbound admission denied** via the serial-Hub head-of-line stall, for the duration of the
  flood.
- Attacker cost: **one host, no authentication, no crypto, sub-volumetric** stream setup — no handshake
  completion required.

This is a **measured** result, not a source trace alone. Because Kaspa is Proof-of-Work, block production
proceeds on a separate path and is **not halted**; the measured impact is confined to the inbound-peering layer
(eviction + admission denial). The published corpus reproducer (primitive `kaspa_grpc_h2_preauth_stream_flood`;
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **pre-auth HTTP/2
stream-flood wire signature across postures**.

## Scope

Availability only — inbound-peering eviction and inbound-admission denial. **No funds, no authentication
bypass, no data corruption, and no consensus-safety break**: Kaspa's Proof-of-Work block production is a
separate path and is **not** halted by this attack. A node fronted by a real admission-time gate (per-IP caps,
ban list, handshake-proof) is not affected. The reproducer targets a local self-owned mock, carries no public
IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Add an admission-time gate BEFORE `NewPeer`** (`connection_handler.rs:222`): enforce per-IP connection and
  per-IP stream caps, consult the ban list, and require TLS or a handshake-proof **before** a peer is admitted.
- **Make `--maxinpeers` a real synchronous admission bound**, not a lazy random-eviction tick
  (`connectionmanager/lib.rs:247`) — reject over-cap inbound at accept time instead of admitting and later
  evicting at random.
- **Reserve inbound slots for established / outbound-verified peers** so a pre-auth flood cannot displace known-
  good connections.
- **Parallelize the Hub accept path** so one peer cannot head-of-line-stall honest inbound admission.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable inbound-peering DoS on a public-by-default gRPC P2P surface →
**out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. This is our own
(`source_class: original`) **measured** finding (KAS-H1, measured 2026-06-02) of the rusty-kaspa
missing-admission-gate class, not an assigned Kaspa CVE. The corpus primitive
`kaspa_grpc_h2_preauth_stream_flood` is **on-spec** (registered in the known-class provenance map) and
**on-HF** (shipped in `NullRabbit/nr-bundles-public`, `HF_DATASET_PRIMITIVES`), so this advisory does not
outpace its shipped defensive artefact.

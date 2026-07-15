# NR-2026-052 — nearcore: pre-auth handshake decode + Ed25519 edge-verify before the admission gate (pending-slot starvation)

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

**nearcore**'s P2P peer transport reads a `u32`-little-endian length-prefixed protobuf `PeerMessage` from
every inbound TCP peer and **fully decodes the unauthenticated frame and runs the Ed25519 edge-signature
verify (`partial_edge_info`) BEFORE the identity / blacklist / capacity admission gate**
(`validate_new_connection`). Handshake messages are **exempt from the per-connection rate limiter**, and
there is **no per-IP rate limit and no per-IP connection cap** on the inbound accept path. The single
mitigation is a **global** semaphore `LIMIT_PENDING_PEERS = 60` whose permit is held across the connecting
state and released only at `handshake_timeout = 20s`. So an unauthenticated attacker from a **single source**
can open up to 60 connections, send a well-formed handshake (or none), and hold **all 60 global pending
permits** — denying honest inbound peering — with no per-IP limit to stop it. Availability only, on
NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Chain | Class | Severity |
|---|---|---|---|---|
| `NEAR_R1_HANDSHAKE_PREAUTH_PENDING_STARVATION` | `near_handshake_preauth_pending_starvation` | near | `connection-exhaustion` (pre-auth handshake pending-slot starvation) | MEDIUM |

- **Reachability:** any host that can open a TCP connection to the nearcore peer port — pre-auth, no node
  identity needed.
- **Severity:** MEDIUM — the impact is **pending-slot starvation** of the inbound handshake pool: with no
  per-IP gate, one source holds all 60 global `LIMIT_PENDING_PEERS` permits (each up to the 20s
  `handshake_timeout`), starving honest inbound peers. The per-node parallel-crypto CPU is **bounded** by the
  60-permit cap, so this is availability of the inbound pending pool, not an unbounded CPU burn. Secondary: a
  `≤512 MiB` exact-size pre-auth allocation is a memory-pressure angle. Availability only. **Out of paid
  scope**, publish-track.
- **Affected:** nearcore P2P peer transport (`chain/network`), the `u32_le`-framed protobuf `PeerMessage`
  handshake path with the global `LIMIT_PENDING_PEERS = 60` semaphore and no per-IP inbound gate.

## Mechanism (source-cited)

- `chain/network/src/peer_manager/tcp_transport.rs` — the accept loop admits inbound TCP peers and acquires
  a permit from the **global** `Semaphore::new(LIMIT_PENDING_PEERS)` (`LIMIT_PENDING_PEERS = 60`, `:14`,
  `:40`); the loop comment notes it lets the new peer "send handshake first" — there is **no per-IP rate
  limit and no per-IP connection cap** before the permit.
- `chain/network/src/peer/stream.rs` — the frame is a `u32`-little-endian length prefix
  (`read_u32_le` / `write_u32_le`) + the protobuf `PeerMessage` body (`≤512 MiB`).
- `chain/network/src/peer/peer_actor.rs` — the actor **fully decodes** the unauthenticated protobuf
  `PeerMessage` and runs the deferred **Ed25519 edge verify** (`partial_edge_info`) **before**
  `validate_new_connection` (the identity/blacklist/capacity admission gate); the per-connection rate
  limiter (`rate_limits/messages_limits.rs`) **exempts** handshake messages.
- `chain/network/src/network_protocol/network.proto` — the inbound handshake is
  `PeerMessage{ tier2_handshake = 4: Handshake{ protocol_version, oldest_supported_version, sender_peer_id,
  target_peer_id, sender_listen_port, sender_chain_info, partial_edge_info } }`.

An attacker opens fresh TCP connections and sends faithfully-encoded NEAR `tier2_handshake` frames (or simply
holds the connections in the pending state); the 60 global permits are consumed and honest inbound peers are
starved until `handshake_timeout`.

## Measurement (fidelity: explicit)

The **pre-auth handshake-flood traffic** is captured (fresh TCP connections each sending a byte-faithful
`u32_le`-framed protobuf `PeerMessage{tier2_handshake}` — verified against `network.proto`) against a
**loopback reproducer** that reads the `u32_le` frame, models the pre-auth protobuf decode + Ed25519 edge
verify, and holds a global `LIMIT_PENDING_PEERS = 60` pending permit per connection — **without** standing up
a full nearcore node. Bundles `near_handshake_preauth_pending_starvation` (saturating + distributed) ship in
`NullRabbit/nr-bundles-public`. **Honest split:** this is **source-confirmed** (the pre-auth decode + edge
verify precede `validate_new_connection`, handshakes are rate-limiter-exempt, and there is no per-IP gate
before the 60-permit semaphore) plus **class-representative captured traffic**; it is **not** an independent
measurement of a live nearcore node's inbound-peering starvation.

## Scope

Availability only — pre-auth handshake-slot starvation of the inbound pending pool (and a secondary
pre-auth allocation angle). No consensus-safety break, no funds, no memory corruption, no authentication
bypass. The reproducer targets a self-owned loopback mock, carries no public IPs or mainnet hostnames, and is
not a turnkey mainnet weapon.

## Mitigation

- **Add a per-source-IP inbound connection-rate limit and per-IP pending-handshake cap** so a single source
  cannot occupy all 60 global `LIMIT_PENDING_PEERS` permits.
- **Move (or duplicate) a cheap admission check — blacklist / capacity — BEFORE the full protobuf decode and
  the Ed25519 edge verify**, so unauthenticated peers cannot force pre-auth work + permit occupancy.
- **Tighten `handshake_timeout`** and reap incomplete pending handshakes aggressively; prefer a curated
  persistent-peer / boot-node set and firewall the peer port where the deployment allows.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth handshake pending-slot starvation → **out of paid
scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: NEAR (`near/nearcore`). This is
our own (`source_class: original`) source trace + class-representative captured traffic, not an assigned CVE.
The corpus primitive `near_handshake_preauth_pending_starvation` is **on-spec** and **on-HF** (shipped in
`NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.

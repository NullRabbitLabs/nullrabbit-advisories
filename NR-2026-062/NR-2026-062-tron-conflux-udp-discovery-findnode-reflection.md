# NR-2026-062 — TRON & Conflux: unauthenticated UDP node-discovery answers a spoofable FindNode with a full neighbour list → measured 9.15× / 13.54× reflection amplification (no endpoint proof)

**NullRabbit Operator Advisory** · Published 2026-09-10

## Summary

Two chains that wrote their own UDP node-discovery from scratch — **TRON** (`java-tron` /
`tronprotocol/libp2p`, UDP/18888) and **Conflux** (`conflux-rust`, UDP/32323) — answer an
**unauthenticated, connectionless `FindNode` with a full neighbour list sent to the datagram's claimed
source address, with no completed endpoint proof**. There is no bond, no ping/pong token and no
return-routability check ahead of the amplified reply; Conflux's only gate is a per-IP throttle keyed on
the same spoofable source address. An off-path attacker who forges the victim's IP as the source therefore
turns each node into a **DRDoS reflector**.

This is the textbook connectionless-UDP amplifier that Ethereum's `discv4` closes with its **bonding**
endpoint proof, and it is the same mechanism and the same fix-class in both cases — registered as
**`NRDAX-T0280` (Spoofed Endpoint-Proof Bypass Amplification)**, family `response_amp`.

Both are **MEDIUM**, **availability-only**, and **out of paid scope** (DoS/availability) for each chain's
own program → NullRabbit **publish-track**.

Unlike NR-2026-039 — three source-traced pre-auth crypto burns with no server-side measurement — the
amplification here is **measured on the wire against the real implementations**, and the byte counts below
are packet captures, not estimates.

## Findings at a glance

| Finding | Primitive | Endpoint | Measured BAF | PAF | Severity |
|---|---|---|---|---|---|
| `TRON_DISCOVERY_FINDNODE_REFLECTION` | `tron_discovery_findnode_reflection` | UDP/18888 Kademlia discovery | **9.15×** (161 B → 1473 B) | 1 | MEDIUM |
| `CFX_KRAKEN_TRANSPORT` (CFX-H2 angle) | `conflux_discovery_findnode_reflection` | UDP/32323 Kademlia discovery | **13.54×** well-connected (109 B → 1476 B); **6.9–10.6×** observed live | 2 / 1 | MEDIUM |

- **Reachability (both):** any host that can send a UDP datagram to the discovery port. No auth, no
  handshake, no prior contact, no session state. A single spoofed datagram elicits the amplified reply.
- **Severity:** MEDIUM each — measured bandwidth amplification against an internet-exposed, default-on
  discovery service. Ceiling is third-party DRDoS bandwidth and peering noise, **not** a consensus break.
- **Provenance:** both `source_class: original`. The Conflux reflection is the previously-unmeasured
  **CFX-H2** angle of `CFX_KRAKEN_TRANSPORT`; **NR-2026-039 published only that finding's ECIES
  handshake-burn (CFX-H1)** and left the amplification factor open. This advisory closes it.

## Mechanism (source-cited, per chain)

### TRON — `tron_discovery_findnode_reflection`

`tronprotocol/libp2p` implements a custom Kademlia discovery on raw UDP/18888. `KadService.handleEvent`
(`KadService.java:122-155`) builds a `NodeHandler` **straight from the kernel UDP source address** and
dispatches unconditionally; `NodeHandler.handleFindNode` → `getClosestNodes` → `sendNeighbours` then
returns up to `KademliaOptions.BUCKET_SIZE = 16` neighbours to that address. **There is no bond, ping,
expiry or liveness gate anywhere on that path** — the amplified reply is emitted for a peer the node has
never contacted. Messages are unsigned (type byte + protobuf).

A 161-byte `FindNode` elicits a **1473-byte** `Neighbours` carrying 16 nodes in a **single datagram** =
**9.15× BAF**. On first contact the node additionally sends a ~176 B bond-`Ping` back to the source — so a
spoofed victim also receives that (2 datagrams, 10.24× total); it is not part of the amplification.
Amplification scales approximately linearly with routing-table fill, from ~1.1× at one known node to
9.15× at a full bucket; a well-connected mainnet node sits at the top of that range.

### Conflux — `conflux_discovery_findnode_reflection`

`conflux-rust` implements a custom Kademlia discovery on raw UDP/32323. `discovery.rs:346 on_find_node`
answers with up to `discover_node_count = 16` neighbours sent to the datagram source. The only gate is
`find_nodes_throttling` — a **per-IP throttle keyed on the spoofable apparent source** — plus a timestamp
window; neither is return-routability, and both are trivially defeated by rotating the forged victim IP or
by distributing the request across nodes.

A 109-byte `FindNode` elicits **1476 bytes across two datagrams** (1134 + 342; chunked at 13 nodes per
datagram by `MAX_DATAGRAM_SIZE`) = **13.54× BAF / PAF 2** for a node whose table exceeds 16 entries.
Measured live against the shipping binary, a node holding exactly 16 entries returns 8–13 *unique* nodes —
`sample_nodes` draws `discover_node_count` times **with replacement** and then dedups — for **6.9–10.6×**
in a single datagram. The 13.54× figure is the mainnet case; the live range is the small-table case.

### Ethereum discv4 — the defended reference point

`discv4` is the same FINDNODE→NEIGHBORS shape and is **defended**: `verifyFindnode` → `checkBond` requires
a PONG received from that node within 24 h before the reply is emitted (`p2p/discover/v4_udp.go`), and the
guard's own code comment names this reflection attack as its rationale. The guard is present and
byte-equivalent across go-ethereum, Erigon, reth, Nethermind and Besu, and across the geth-lineage forks
we traced. Version-bounded caveat: `NethermindEth/nethermind#12211` shows the bond was **not tied to the
exact UDP IP:port** in Nethermind before that change — the mechanism is registered under `NRDAX-T0280`
from that fix, so "defended" means current releases, not every historical one.

## Measurement (fidelity: explicit)

**Both amplification factors are live-measured against the real implementations, over real sockets, with
packet captures retained in the corpus bundles.**

- **TRON** — the actual `tronprotocol/libp2p` discovery package compiled and run: the real `DiscoverServer`
  and `KadService` were booted, a 16-entry `NodeTable` seeded, and `FindNode` datagrams fired from a
  separate probe socket. The real `NodeHandler.handleFindNode → getClosestNodes → sendNeighbours` answered
  to the probe's source address. 161 B → 1473 B, six runs.
- **Conflux** — the **shipping `conflux-rust` v3.0.3 binary**, discovery enabled on UDP/32323, trusted-node
  table seeded, probed with a valid `FindNode`. The node answered `Neighbours` (`packet_id=4`) to the
  probe's source address. Every observed response size maps to an exact integer node count at the same
  per-node wire size, so the analytic 13.54× curve is validated against the binary, not merely asserted.

**What is source-traced, not wire-forged:** the *spoofability* itself. Both handlers reply to the datagram
source without any liveness proof (citations above), so a forged source is answered exactly as a genuine
one is — but **no packets with a forged source address were transmitted**. Amplification was measured with
a genuine probe source; the reflection claim rests on the handler trace.

**Not measured:** any third-party or internet node. No active scan or probe of any host we do not own was
performed, and the reflector population below is public data only.

## Calibration and reflector population (public data only — no active scan)

Against the classic UDP-reflector baseline (Rossow, NDSS 2014, Table III; Thomas et al., eCrime 2017), a
generic Kademlia peer-list exchange is a ~16.3× amplifier if unguarded. Both measurements sit in that band
— below DNS-open-resolver (28.7×) and SSDP (30.8×), far below NTP/CHARGEN — i.e. **useful to an attacker,
not an extreme vector**.

| Chain | Port | Measured BAF | Reachable nodes (public estimate) | Discovery on by default |
|---|---|---|---|---|
| TRON | UDP/18888 | 9.15× | ~8,000 (block-explorer node list) | yes (`node.discovery.enable=true`) |
| Conflux | UDP/32323 | 13.54× | hundreds (~259 PoW nodes/24 h, block explorer) | yes, as shipped |

Both populations are orders of magnitude below the classic open-resolver pools (millions). **Honest
bounded severity: a real but contained reflector class, not an internet-scale amplifier.** A precise census
of nodes actually answering unauthenticated discovery from arbitrary sources would require an active UDP
probe campaign, which was **not** performed.

## Scope

Availability only — third-party DRDoS bandwidth and discovery-service noise. **No consensus-safety break,
no funds at risk, no authentication bypass, no node compromise.** The amplified reply carries only public
peer records the discovery protocol exists to hand out; the defect is *who it is sent to*, not what it
contains. Neither reproducer forges a source address, targets a third party, or contacts any host outside
the local test rig: the TRON harness seeds its routing table from RFC 5737 documentation address space
only, and the Conflux probe addresses a local dev node on loopback. Neither is a turnkey mainnet weapon. A
node that completes an endpoint proof before answering `FindNode` — as `discv4` does — is not affected.

## Mitigation

- **Require a completed endpoint proof before emitting the amplified response.** This is `discv4`'s bond:
  answer `FindNode` only from a peer that has returned a PONG to a nonce the node itself chose, within a
  bounded window, **bound to the exact source IP and port**. This closes the vector completely and is the
  single fix for both chains.
- **Do not rely on a per-IP throttle keyed on the apparent source** (Conflux). The attacker controls that
  field; the throttle limits per-victim volume but does not prevent reflection, and rotating the forged
  victim IP evades it entirely.
- **Bound the response** as defence in depth: cap neighbours returned per request and prefer a reply no
  larger than the request until the peer is proven, so the unproven-peer path cannot amplify.
- **Operators:** if a node does not need to serve discovery, disable it or firewall the discovery port to
  known peers. TRON's discovery is on by default (`node.discovery.enable`), as is Conflux's in the shipped
  configuration.

## Disclosure & provenance

Availability-only, deployment-mitigable reflection amplification on public-by-default UDP discovery
listeners → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy, consistent
with the ruling recorded in NR-2026-039. Both findings are our own (`source_class: original`) source trace
plus original wire measurement; neither is an assigned CVE, and neither claims discovery of the underlying
protocol design, which is well documented as the reason `discv4` carries its bond guard.

The Conflux reflection is **not a new finding** — it is the CFX-H2 angle already recorded under
`CFX_KRAKEN_TRANSPORT` (whose CFX-H1 ECIES handshake-burn published as NR-2026-039), where it stood as
source-confirmed but unmeasured. What is new is the measurement.

Both corpus primitives are registered against `NRDAX-T0280`. This advisory publishes only once each
primitive is shipped in `NullRabbit/nr-bundles-public` and registered in `HF_DATASET_PRIMITIVES`, so it
does not outpace its shipped defensive artefact.

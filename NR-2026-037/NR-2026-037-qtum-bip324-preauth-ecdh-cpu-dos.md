# NR-2026-037 — Qtum (qtumd): BIP-324 v2 transport runs a pre-authentication ellswift-ECDH on every inbound key → single-source core saturation + honest-peer connection denial

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

`qtumd` inherits Bitcoin Core's **BIP-324 v2 transport with v2 enabled by default** (`DEFAULT_V2_TRANSPORT{true}`,
`src/net.h:95`); the inbound peer-protocol listener (mainnet port **3888**) is reachable by default. For any
inbound connection, the instant the peer sends its 64-byte ellswift key the node runs an **asymmetric-crypto
handshake step — a secp256k1 ellswift ECDH plus HKDF-SHA256 key derivation — BEFORE any authentication,
allowlist, per-IP rate limit, or proof-of-work gate** (`src/net.cpp:1140-1147` → `src/bip324.cpp:41-64`). The
only upstream cap is the inbound connection limit (default `maxconnections=125`), and it is **soft**: when the
node is full it *evicts* an existing peer to admit the new socket (`AttemptToEvictConnection`,
`src/net.cpp:1815`), so a churn of fresh inbound sockets always wins admission, and the v2 accept path is
**single-threaded**. A single source IP therefore saturates one core, and a small distributed fleet measurably
degrades or denies honest peers' ability to connect. Qtum's only divergence from the upstream Bitcoin Core
path is the salt string (`qtum_v2_shared_secret`), the network magic, and the port — the crypto is otherwise
binary-identical to a path we separately measured on Bitcoin Core (`BTC_V0_BIP324_PREHANDSHAKE_CPU`). This is
an **availability** DoS (fullnode-peering degradation, not a consensus halt); it is a rate-limit /
pre-auth-cost-gating hardening class, **out of paid scope**, handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `QTUM_KRAKEN_TRANSPORT` (H1) | `qtum_bip324_prehandshake_ecdh_cpu` | inbound peer P2P `:3888` (BIP-324 v2 responder) | `pre-auth-crypto-burn` + `bip324` | HIGH |

- **Reachability:** any remote host that can reach the peer port (`3888`, default-listened); no auth, no
  completed handshake, single source IP suffices.
- **Severity:** HIGH — a single IP pins one core; a 4-IP fleet inflates honest-peer handshake latency ~100× and
  causes ~11% outright connection denial (measured, DigitalOcean production-shape). **Out of paid scope**,
  publish-track. Ceiling is fullnode-peering availability, **not** a consensus halt (PoS block production is a
  separate path).
- **Affected:** `qtumd` inbound BIP-324 v2 transport (measured on v29.1.0).
- **Mitigation:** gate the pre-auth ellswift-ECDH behind a per-source-IP budget / cost gate; make the v2 accept
  path concurrent; harden the soft eviction cap so fresh-socket churn cannot displace established peers. See
  Mitigation.

## Mechanism (source-cited, `qtum/qtum`)

- **v2 default-on, internet-reachable.** `src/net.h:95` `DEFAULT_V2_TRANSPORT{true}`; the inbound transport is
  created as a v2 responder at `src/net.cpp:3784-3791`. Port 3888 is listened by default.
- **Asymmetric crypto BEFORE any gate.** On receiving the peer's 64 ellswift key bytes, `src/net.cpp:1140-1147`
  fires `Initialize`, which runs `src/bip324.cpp:41-64` — a secp256k1 **ellswift ECDH** plus **6× HKDF-SHA256
  Expand32**. No allowlist, per-IP rate-limit, or PoW precedes this. The attacker sends 64 bytes and disconnects
  (or holds), forcing repeated pre-auth ECDH.
- **Soft, evictable inbound cap.** `src/net.cpp:1815` `AttemptToEvictConnection()` admits fresh sockets by
  evicting established peers, so the connection limit does not bound attacker churn.
- **Single-threaded v2 accept.** Even one source IP saturates the accept path on a small node.

## Measurement (fidelity: explicit)

Verified `qtumd v29.1.0` (SHA256 `c04e3f49…`).

- **Loopback (isolated regtest, single attacker process):** qtumd held **96.3% avg / 100% median of one core**
  for a 60-second connection-churn run at **14,275 handshakes/s** (vs 0.3% baseline); **~39.6× egress
  amplification**; all 114 inbound slots filled with eviction-on-full live-confirmed (874,527 conns accepted);
  RSS flat ~56 MB; clean recovery on stop.
- **Production-shape (DigitalOcean, ~$0.05 total over 3 runs — nyc1 4-vCPU victim, 4 geo-distributed attacker
  hosts, one honest peer in tor1):** honest-peer v2 handshake latency **p50 32 ms baseline → 2057 ms @1 IP
  (65×) → 3371 ms @4 IP (107×)**; **p99 9656 ms (182×)**; **11% outright connection denial** at the 4-IP shape;
  immediate recovery once the attack stops.

The published corpus reproducer (primitive `qtum_bip324_prehandshake_ecdh_cpu`; family `compute_amp`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — a churn
of inbound TCP connections each sending a 64-byte ellswift key then closing (the v2-responder churn) across
postures. **This advisory stands on the source trace (pre-auth ECDH before any cost gate) and the loopback +
DigitalOcean production-shape measurements — not on the reproducer traffic alone.**

## Scope

Availability only (CPU saturation → honest-peer connection degradation/denial); no consensus-safety break, no
funds, no authentication bypass. PoS block production is a separate path and is not halted. A node whose
pre-auth handshake is cost-gated per source IP, with a concurrent accept path and a non-evictable honest-peer
reserve, is not affected. The reproducer targets a local self-owned mock, carries no public IPs or mainnet
hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Cost-gate the pre-auth crypto:** apply a per-source-IP budget (or a cheap PoW / connection-rate cap) BEFORE
  the ellswift-ECDH runs, so an unauthenticated peer cannot force unbounded asymmetric-crypto work.
- **Make the v2 accept path concurrent** so a single IP cannot serialize/saturate it.
- **Harden the inbound cap:** reserve slots for established/outbound-verified peers so fresh-socket churn cannot
  evict honest peers (`AttemptToEvictConnection`).

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth CPU-exhaustion on a public-by-default P2P listener →
**out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Qtum is a Kraken-listed,
non-Coinbase asset; DoS/availability is out of scope for the chain's own program, so this is publish-track (the
Kraken channel is a courtesy, not a bounty venue). This is our own (`source_class: original`) measurement of
the BIP-324 pre-auth-cost-gating gap — a near-drop-in port of the measured Bitcoin Core
`BTC_V0_BIP324_PREHANDSHAKE_CPU` — not a novel implementation flaw of ours or an assigned CVE. The corpus
primitive `qtum_bip324_prehandshake_ecdh_cpu` is **on-spec** (registered in the known-class provenance map) and
**on-HF** (shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive
artefact.

# NR-2026-045 — rippled (XRPL): the overlay-handshake secp256k1 ECDSA verify runs pre-cluster-check on every inbound peer Upgrade → single-IP core saturation, per-IP `Resource::Consumer` throttle ineffective

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

`rippled`'s peer port (mainnet **51235**) is publicly listened by default. An inbound peer opens TLS, then sends
an HTTP/1.1 `Upgrade` carrying crafted `Public-Key` + `Session-Signature` headers; the node responds by running
a **secp256k1 ECDSA signature verify on the handshake digest — post-TLS but BEFORE the peer is admitted to the
cluster / trusted set** (`xrpld/overlay/detail/Handshake.cpp:318` `verifyDigest(...)` →
`libxrpl/protocol/PublicKey.cpp:222-267` `secp256k1_ecdsa_verify`, pre-cluster-check). The documented defence
against handshake abuse is the per-IP `Resource::Consumer` budget (`OverlayImpl.cpp:235`), but at default config
it does **not** throttle a single source IP: a single attacker host drove **1000 handshakes in 0.90 s = 1117
handshakes/s**, at **~0.68 ms server CPU per handshake → 76% of one core** saturated from that one IP (measured).
Every handshake returned HTTP 400 (rejected) but was fully processed first. This is an **availability** issue
(overlay-peering degradation via CPU burn, not a consensus halt); it is a per-IP rate-limit / pre-auth
cost-gating hardening class, **out of paid scope**, handled on NullRabbit's publish-track.

**Honest framing of the cost source:** the measured 0.68 ms/handshake is a *mix* of the TLS handshake, the
HTTP/`Upgrade` parse, and the secp256k1 verify — the pure ECDSA-verify contribution was **not isolated**. The
load-bearing claim is therefore the **absent per-IP throttle** on the pre-cluster-check handshake path, not a
precise attribution of the cost to ECDSA alone.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `V0_RIP_OVERLAY_HANDSHAKE_ECDSA` | `rippled_overlay_handshake_ecdsa_burn` | inbound peer P2P `:51235` (overlay handshake responder) | `pre-auth-crypto-burn` + handshake-CPU | MEDIUM |

- **Reachability:** any remote host that can reach the peer port (`51235`, default-listened); no cluster
  membership, no trusted-peer status, no completed/accepted handshake — a single source IP suffices (each
  attempt is rejected with 400 but processed).
- **Severity:** MEDIUM (measured) — a single IP sustains 1117 hs/s and pins ~76% of one core; multi-attacker
  compounds. **Out of paid scope**, publish-track. Ceiling is overlay-peering availability, **not** a consensus
  halt or ledger-safety break.
- **Affected:** `rippled` inbound overlay handshake path; measured 2026-05-26 against rippled peer port 51235.
- **Mitigation:** cost-gate the pre-cluster-check handshake per source IP (tighten the `Resource::Consumer`
  budget so it actually rate-limits *handshake attempts*, not just steady-state traffic); add a cheap PoW /
  connection-rate cap before the verify; reserve overlay slots for established/validated peers. See Mitigation.

## Mechanism (source-cited, `XRPLF/rippled`)

- **Public peer port, default-listened.** Mainnet overlay peer port **51235** is reachable by default; any
  remote host can open TLS and present an `Upgrade`.
- **ECDSA verify runs pre-cluster-check.** On the inbound handshake, `xrpld/overlay/detail/Handshake.cpp:318`
  calls `verifyDigest(publicKey, sharedValue, makeSlice(sig), false)`, which dispatches to
  `libxrpl/protocol/PublicKey.cpp:222-267` `secp256k1_ecdsa_verify`. This executes **post-TLS but
  pre-cluster-check** — the node spends the asymmetric-crypto verify before deciding whether the peer is even a
  cluster/trusted member, so an unadmitted source can force the work repeatedly.
- **Per-IP throttle too loose for the handshake path.** The documented defence, the per-IP `Resource::Consumer`
  budget (`OverlayImpl.cpp:235`), governs steady-state peer traffic; at default config it **admitted 1000
  handshakes from a single source IP in 0.9 s without throttling**, so it does not bound handshake-attempt churn.

## Measurement (fidelity: explicit)

Measured **2026-05-26** against rippled peer port **51235**. A self-contained Python probe opens TLS to the peer
port and sends an HTTP/1.1 `Upgrade` with crafted `Public-Key` + `Session-Signature` headers, measuring server
CPU (jiffies) and RSS across a ramp of handshake counts. Full rig detail, probe, and raw results are in the
finding directory (`chains/xrp/findings/V0_RIP_OVERLAY_HANDSHAKE_ECDSA/README.md`; probe at
`.../probes/v0_rip.py`).

| N handshakes | Wall | Rate | CPU jiffies | Per-handshake server CPU |
|---|---|---|---|---|
| 10 | 0.02 s | 432 hs/s | 2 | ~2 ms |
| 50 | 0.08 s | 655 hs/s | 5 | ~1 ms |
| 200 | 0.19 s | 1042 hs/s | 14 | ~0.7 ms |
| **1000** | **0.90 s** | **1117 hs/s** | **68** | **0.68 ms → 76% of one core** |

- **Single source IP, sustained:** 1117 hs/s at ~0.68 ms/handshake ⇒ **~76% of one core** saturated from a single
  attacker. All handshakes returned **HTTP 400** (rejected) but were processed first. `Resource::Consumer` did
  **not** throttle the single source IP across the 1000 attempts.
- **Memory:** RSS delta **+1.5 MB over 1260 handshakes** — negligible; this is a **CPU-class** attack, not a
  RAM-pin class.

**Honesty caveats (as recorded in the finding):**

- **Cost-source not isolated.** The 0.68 ms/handshake includes the TLS handshake (likely ~0.3–0.5 ms) + HTTP
  parse + `Upgrade` processing + the secp256k1 verify (~0.05 ms raw verify). Isolating the verify share would
  require a comparison probe that omits the `Session-Signature` header. The **load-bearing** claim is the absent
  per-IP throttle, not that ECDSA verify alone dominates the cost.
- The probe used a **self-signed TLS cert**; production validators use larger/slower proper cert chains.
- **Multi-IP source range not tested** — single-source-IP saturation is the load-bearing measurement; a
  distributed fleet would compound but was not measured.
- Rated **MEDIUM** (not HIGH): 76% one-core is borderline (multi-attacker compounds but requires coordination),
  no memory pin (CPU class), and the pure secp256k1-verify share of the cost was not isolated.

The published corpus reproducer (primitive `rippled_overlay_handshake_ecdsa_burn`; `source_class: original`,
shipped in `NullRabbit/nr-bundles-public`) captures the **pre-auth overlay-handshake wire signature** — the churn
of TLS + HTTP/1.1 `Upgrade` handshake attempts each carrying crafted `Public-Key`/`Session-Signature` headers.
**This advisory stands on the source trace (ECDSA verify pre-cluster-check, per-IP throttle too loose) and the
2026-05-26 single-IP measurement — not on the reproducer traffic alone.**

## Scope

Availability only (single-IP CPU burn on the pre-cluster-check handshake path → overlay-peering degradation); no
consensus-safety break, no funds at risk, no authentication bypass. A node whose pre-cluster-check handshake is
cost-gated per source IP — with a cheap PoW / connection-rate cap before the verify and an established-peer
reserve — is not affected. The reproducer targets a local self-owned mock, carries no public IPs or mainnet
hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Cost-gate the pre-auth verify per source IP:** tighten the `Resource::Consumer` budget so it actually
  rate-limits **handshake attempts** from a single IP, not just steady-state peer traffic — an unadmitted peer
  should not be able to force unbounded pre-cluster-check ECDSA work.
- **Add a cheap gate before the verify:** a lightweight PoW or connection-rate cap ahead of the
  `secp256k1_ecdsa_verify` call, so a single IP cannot spend server CPU at handshake rate.
- **Reserve overlay slots for established/validated peers** so handshake-attempt churn from fresh sockets cannot
  crowd out honest peering.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth CPU-exhaustion on a public-by-default overlay peer
listener → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. This is our own
(`source_class: original`) 2026-05-26 measurement of the rippled overlay-handshake per-IP-throttle gap — not a
novel implementation flaw of ours or an assigned CVE. Vendor contact is **security@xrpl.org**; the finding is
already **route=publish / state=published**, so any note to that address is a **courtesy channel, not an open
coordinated embargo**. The corpus primitive `rippled_overlay_handshake_ecdsa_burn` is **on-HF** (shipped in
`NullRabbit/nr-bundles-public`, registered in `HF_DATASET_PRIMITIVES`), so this advisory does not outpace its
shipped defensive artefact.

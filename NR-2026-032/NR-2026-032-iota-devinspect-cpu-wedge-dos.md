# NR-2026-032 — IOTA (iota-node): `iota_devInspectTransactionBlock` synchronous Move-VM execution → CPU-wedge DoS

**NullRabbit Operator Advisory** · Published 2026-07-09

## Summary

The IOTA JSON-RPC method `iota_devInspectTransactionBlock` runs the Move virtual machine **synchronously on
the tokio async worker** that polls the request — there is no `spawn_blocking`, no `rayon` offload, and no
dedicated runtime — while the per-call compute budget is the full protocol cap
(`max_gas_computation_bucket = 5,000,000`). Because dev-inspect is an **unauthenticated, gas-free simulation**
endpoint, an attacker can publish a Move package whose function performs cap-consuming work (an O(N²) loop)
and then flood `iota_devInspectTransactionBlock` calls that each burn the full compute bucket **inline on a
node worker**. Measured cross-network against a 4-vCPU fullnode: 16 parallel callers for 60 s drove node CPU
to **avg 152 % / peak 394.7 %** (≈4 cores) and pushed healthy-probe RPC latency **p99 from ~18 ms to 1,426 ms
(85×)** for the duration. This is a **compute-exhaustion / RPC-degradation** DoS against an **exposed**
JSON-RPC surface. It is an **availability issue only** — no funds, no consensus break, no auth bypass — and
falls **out of paid scope**, so it is handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `IOTA_F14_DEV_INSPECT` | `iota_f14_devinspect_cpu_wedge` | `iota_devInspectTransactionBlock` (JSON-RPC) | `async-over-sync compute DoS` | HIGH (4-vCPU); CRITICAL-shape predicted (2-vCPU) |

- **Reachability:** any remote client that can reach a non-loopback-bound JSON-RPC (`:9000`) port; no auth, no
  gas. Requires the caller to have published a compute-heavy Move package (one-time, cheap).
- **Severity:** availability-only compute-wedge; **out of paid scope**, publish-track. HIGH on 4-vCPU
  fullnodes (RPC latency 85× for the attack duration, consensus holds with core headroom); a 2-vCPU
  validator is predicted to cross its CPU ceiling and starve the checkpoint executor.
- **Affected:** `iota-node` exposing the JSON-RPC `dev-inspect` method on a routable interface (measured on
  iota-node 1.23.2). This is the IOTA fork of the Sui F14 pattern.
- **Mitigation:** run dev-inspect on `spawn_blocking` / a bounded dedicated pool, and rate-limit / cap
  concurrent dev-inspect calls per source. See Mitigation.

## Mechanism (source-cited, IOTA `iota-node`)

`iota-core/src/authority.rs` (`:2214`, `:2417`) calls `executor.dev_inspect_transaction(...)`
**synchronously inside the `async fn`** that serves `iota_devInspectTransactionBlock` (exposed via
`iota-json-rpc-api/src/write.rs`). A grep of the dev-inspect path for `spawn_blocking` / `rayon` /
`tokio::task::spawn` / `tokio::runtime` returns **zero hits** — so the Move VM executes inline on the tokio
worker that is polling the dev-inspect future, and the per-call computation is bounded only by the protocol
cap `max_gas_computation_bucket: Some(5_000_000)` (`iota-protocol-config/src/lib.rs`). Dev-inspect charges no
gas and requires no signature, so each call is free to the attacker but consumes up to a full compute bucket
of node CPU. This is the verbatim fork of the Sui F14 bug (same cap, same async-over-sync shape).

An attacker publishes a Move package exposing e.g. `burn_cpu_vector(n)` (an O(N²) bubble sort over
`vector<u64>`); at N = 500 each `iota_devInspectTransactionBlock` call consumes ≈4.597 B NANOS of computation
(essentially the whole cap). Tight-looping the call from many workers starves the node's worker pool.

## Measurement (fidelity: explicit)

Fired 16 parallel callers from one operator IP against a 4-vCPU (t3.xlarge) fullnode for 60 s:
**node user CPU avg 152.4 % / peak 394.7 %** (≈1.5–4 cores), healthy-probe RPC **p50 18→55 ms, p90 →693 ms,
p99 →1,426 ms (85×)**, max 1,700 ms; checkpoint rate held at ~6.24 cp/s because val-A had spare cores. The
attacker rate was RTT-bound (~7.1 calls/s from a single cross-network IP); multiple in-VPC source IPs would
scale the pressure linearly. On a 2-vCPU validator the observed 394.7 % peak would exceed the 200 % ceiling
and starve the consensus/checkpoint loop (predicted CRITICAL-shape, not fired in this session).

The published corpus reproducer (primitive `iota_f14_devinspect_cpu_wedge`; family `compute_amp`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — the
flood of near-identical ~700-byte `iota_devInspectTransactionBlock` PTB `burn_cpu_vector(500)` requests at
high rate across postures (low-volume 7 calls/s, 16-worker saturating, distributed, and a mimicry variant
interleaving benign reads) — not the server-side CPU burn, which is the measured impact recorded in the
bundle provenance. **This advisory stands on the source trace (synchronous Move VM in the dev-inspect async
path) and the cross-network CPU/latency measurement — not on the reproducer's traffic alone.**

## Scope

Availability / RPC-worker CPU exhaustion only; no consensus-safety break, no funds, no authentication bypass,
no chain halt on adequately-provisioned fullnodes. The harm is degradation of an **exposed** dev-inspect RPC;
a loopback-bound RPC (the default) is not remotely reachable, and a fullnode that offloads dev-inspect to a
bounded blocking pool and rate-limits per source is not affected. The reproducer targets a local self-owned
mock, carries no public IPs or mainnet hostnames, and does not include a weaponized Move package.

## Mitigation

- **Execute dev-inspect off the async workers** — `tokio::task::spawn_blocking` or a bounded dedicated
  rayon/thread pool — so a cap-consuming simulation cannot wedge the RPC worker that polls it. (Sui addressed
  the analogous path; the IOTA fork still runs it inline.)
- **Rate-limit and cap concurrent `iota_devInspectTransactionBlock` calls per source**, and consider a
  tighter per-call compute budget for the gas-free simulation endpoint than for paid execution.
- **Do not expose the JSON-RPC unauthenticated on a routable interface**; keep it on loopback or behind an
  authenticating, rate-limiting gateway that only surfaces the methods an application needs.

## Disclosure & provenance

Availability-only, deployment/rate-limit-mitigable compute-wedge on the public JSON-RPC surface → **out of
paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **IOTA Foundation
(`iota-node`)**; this is our own (`source_class: original`) measurement of the fork's synchronous dev-inspect
execution, not a novel implementation flaw of ours or an assigned CVE. The corpus primitive
`iota_f14_devinspect_cpu_wedge` is **on-spec** (registered in the known-class provenance map) and **on-HF**
(shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.

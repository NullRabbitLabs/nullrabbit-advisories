# NR-2026-034 — IOTA (iota-node): chained `devInspect` CPU-wedge + gRPC batch egress-amp → compounded RPC-availability DoS

**NullRabbit Operator Advisory** · Published 2026-07-09

## Summary

Two independently-published IOTA availability defects **compound when fired together** against the same
fullnode: the `iota_devInspectTransactionBlock` synchronous Move-VM CPU wedge (NR-2026-032, primitive
`iota_f14_devinspect_cpu_wedge`) and the gRPC `GetObjects`/`GetTransactions` uncapped-batch response
amplification (NR-2026-031, primitive `iota_f10_grpc_batch_amp`). The CPU wedge is the dominant latency axis;
the gRPC egress amplification is an **orthogonal bandwidth axis**. Run concurrently they drove healthy-probe
RPC **p99 from 15.7 ms to 2,077 ms (132×)** — worse than the CPU wedge alone (1,848 ms / 117×) — while the
gRPC pull added ~322 MB of egress in 100 s. The operational point: **fixing the devInspect wedge alone (e.g.
`spawn_blocking`) does not close the gRPC-amplification vector** — the two require separate mitigations. This
is an **availability-only** compounded DoS on **exposed** RPC/gRPC surfaces, **out of paid scope**, handled on
NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Composes | Class | Severity |
|---|---|---|---|---|
| `IOTA_F14_F10_GRPC_CHAINED` | `iota_f14_f10_grpc_chained` | `iota_f14_devinspect_cpu_wedge` (NR-2026-032) + `iota_f10_grpc_batch_amp` (NR-2026-031) | `chained-composition` (async-over-sync CPU + byte-amplification) | HIGH |

- **Reachability:** any remote client that can reach the node's JSON-RPC (`:9000`) and gRPC (`:50051`) ports;
  no auth. Requires a published compute-heavy Move package for the devInspect axis (one-time, cheap).
- **Severity:** HIGH — compounded RPC unusability (p99 132×) for the attack duration on a 4-vCPU fullnode;
  a 2-vCPU validator is predicted to cross its CPU ceiling on the devInspect axis alone. **Out of paid
  scope**, publish-track.
- **Affected:** `iota-node` exposing both the JSON-RPC dev-inspect method and the gRPC `LedgerService`
  (measured on a DigitalOcean localnet, 2026-05-28).
- **Mitigation:** apply **both** underlying fixes (offload dev-inspect off the async workers **and** cap gRPC
  batch element count + dedup + rate-limit). See the two referenced advisories.

## Mechanism (source-cited)

The two axes are independent and additive:

- **CPU axis (F14, NR-2026-032):** `iota_devInspectTransactionBlock` runs the Move VM synchronously on the
  tokio worker (`iota-core/src/authority.rs:2214,2417`, no `spawn_blocking`), each call bounded only by the
  5,000,000 compute cap. A `burn_cpu_vector(500)` devInspect flood saturates the worker pool.
- **Bandwidth axis (F10, NR-2026-031):** gRPC `LedgerService/GetObjects`/`GetTransactions` accept an uncapped
  batch (bounded only by a generous response-byte ceiling) with no digest dedup, so a small request pulls a
  multi-hundred-MB response (up to 966 MB / 5,085× measured).

Because the CPU wedge starves the RPC worker pool while the gRPC pull simultaneously consumes egress and I/O,
the two crowd different bottlenecks — so the combined p99 (2,077 ms) exceeds the CPU wedge alone (1,848 ms).
A mitigation that only offloads dev-inspect leaves the gRPC-amplification egress vector fully open.

## Measurement (fidelity: explicit)

4-vCPU box: baseline p99 = 15.7 ms; F14 alone (8 workers × `burn_cpu_vector(500)` --dev-inspect)
p99 = 1,848 ms (117×, ~130 % CPU); **F14 + F10-gRPC chained p99 = 2,077 ms (132×)** with +322 MB egress in
100 s; recovery p99 = 15 ms. The published corpus reproducer (primitive `iota_f14_f10_grpc_chained`; family
`compute_amp`, `source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **combined
attack traffic** — a devInspect JSON-RPC request flood on one port and a gRPC `GetTransactions` batch pull on
another, running **concurrently** (both ports present in every capture) — across four postures. **This
advisory stands on the source trace of the two composed defects and the chained latency measurement, not on
the reproducer traffic alone.**

## Scope

Availability / RPC-worker-CPU + egress crowding only; no consensus-safety break, no funds, no authentication
bypass, no chain halt on an adequately-provisioned fullnode. Loopback-bound RPC/gRPC (the defaults) are not
remotely reachable; a node that offloads dev-inspect, caps + dedups gRPC batches, and rate-limits per source
is not affected. The reproducer targets local self-owned mocks, carries no public IPs or mainnet hostnames,
and includes no weaponized Move package.

## Mitigation

Apply **both** underlying mitigations — neither alone is sufficient:

1. **Dev-inspect (per NR-2026-032):** execute the Move VM off the async workers (`spawn_blocking` / bounded
   pool), rate-limit and cap concurrent dev-inspect calls per source, tighten the gas-free simulation compute
   budget.
2. **gRPC batch (per NR-2026-031):** cap the per-request element **count**, deduplicate repeated digests/IDs,
   and rate-limit the gRPC endpoint per source.
3. Keep both JSON-RPC and gRPC off routable interfaces unless fronted by an authenticating, rate-limiting
   gateway.

## Disclosure & provenance

Availability-only, deployment/rate-limit-mitigable compounded DoS on public RPC/gRPC surfaces → **out of paid
scope → publish-track**. Vendor: **IOTA Foundation (`iota-node`)**; our own (`source_class: original`)
measurement composing two already-published defects, no assigned CVE. The corpus primitive
`iota_f14_f10_grpc_chained` is **on-spec** and **on-HF** (`NullRabbit/nr-bundles-public`), so this advisory
does not outpace its shipped defensive artefact. See NR-2026-031 (F10 gRPC batch amp) and NR-2026-032 (F14
dev-inspect wedge) for the constituent defects.

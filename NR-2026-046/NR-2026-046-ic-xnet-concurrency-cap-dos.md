# NR-2026-046 — Internet Computer (replica XNet endpoint): 4-permit concurrency cap → any registered node stalls all cross-subnet message pulls

**NullRabbit Operator Advisory** · Published 2026-07-14

## Summary

The Internet Computer replica's **XNet endpoint** — the HTTP surface subnets use to pull each other's
certified message streams — admits every request against a **fixed pool of 4 concurrency permits** and
**rejects (does not queue) on overflow**:

```rust
// rs/http_endpoints/xnet/src/lib.rs:54
const XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS: usize = 4;
// :156-168  — non-blocking acquire, immediate 503 on overflow (no queue, no fairness)
match semaphore.clone().try_acquire_owned() {
    Ok(permit) => /* serve */,
    Err(_)     => return StatusCode::SERVICE_UNAVAILABLE /* body: "Queue full" */,
}
```

Because the TLS peer gate at `:261` is `SomeOrAllNodes::All`, **any node registered in the IC registry**
— not just members of the victim's own subnet — may open XNet requests. A single such node that holds the
4 permits (each request kept in-flight, e.g. by stalling inside the response encode) makes the endpoint
return `503 "Queue full"` to **100% of all other XNet pulls** for as long as it holds them. That is a full
cross-subnet XNet message-pull denial on the affected replica, from one host, with no per-source fairness
to shed it. This is an **availability / resource-bounding** class, **out of paid scope**, on NullRabbit's
publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `IC_N3_XNET_CONCURRENCY_CAP` | `ic_xnet_concurrency_cap` | replica XNet endpoint (peer HTTP) | `connection-exhaustion` + `global-concurrency-cap` | MEDIUM |

- **Reachability:** **any-registered-IC-node** — the `SomeOrAllNodes::All` gate (`:261`) admits any node
  with a valid registry `NodeId`, so the reach is *broader* than the subnet-internal CUP-pull body-bomb
  (NR-2026-035) but *narrower* than the public ingress-pool quota mis-key (NR-2026-036).
- **Severity:** MEDIUM — a global 4-permit cap with immediate-reject-no-queue lets one registered node
  starve all XNet pulls on a replica; availability only, self-recovers when the attacker releases, and the
  registered-node gate bounds the attacker set. **Out of paid scope**, publish-track.
- **Affected:** `dfinity/ic` replica (`rs/http_endpoints/xnet/src/lib.rs`, source-traced at HEAD).
- **Mitigation:** replace the global immediate-reject cap with a bounded **queue + per-source-node fairness**
  (round-robin / weighted-fair concurrency), so no single `NodeId` can hold the whole pool. See Mitigation.

## Mechanism (source-cited, `dfinity/ic`)

- **Global, tiny, non-queuing cap.** `XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS = 4` (`:54`) is a *process-wide*
  semaphore. The acquire is `try_acquire_owned()` (`:156-168`) — **non-blocking**: on contention it returns
  `503 "Queue full"` immediately rather than enqueuing. So the cap is a hard binary gate, not a scheduler.
- **No per-source fairness.** Permits are first-come; nothing partitions them per `NodeId` or per source IP.
  One peer that keeps 4 requests in flight owns 100% of the pool and every other peer sees `503`.
- **Broad admission.** The endpoint's TLS acceptor uses `SomeOrAllNodes::All` (`:261`), so the attacker need
  only be *some* registered IC node, not a member of the victim's subnet.
- **Compounding factor.** The per-request work is itself unbounded on the slice path —
  `certified_slice_pool.rs:405` takes `byte_limit.unwrap_or(usize::MAX)` — so a permit-holder can also make
  each held request expensive, not merely occupy the slot.

## Measurement (fidelity: explicit)

Reproduced as an **in-process integration test** against the real XNet endpoint handler and its real
4-permit semaphore: 4 attacker tasks acquire the permits and hold them behind an encode-barrier; a 5th
request issued while they are held returns **`status = 503`, body `"Queue full"`**. While the 4 permits are
held, **every** subsequent XNet request is rejected — i.e. 100% denial of cross-subnet message pulls on the
replica for the hold duration. This is a **source-confirmed + handler-level reproduced** finding: the cap,
the immediate-503 overflow behaviour, and the `All` admission gate are exercised directly; a full
inter-subnet live cluster run was not stood up (the denial follows deterministically from the cap being
global and non-queuing).

The published corpus reproducer (primitive `ic_xnet_concurrency_cap`; family `connection_exhaustion`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — a
small set of concurrent long-lived XNet requests from one source pinning the permit pool while a probe
stream collects the `503 "Queue full"` rejections. **This advisory stands on the source trace (global
non-queuing 4-permit cap under `SomeOrAllNodes::All`) and the handler-level reproduction — not on the
reproducer traffic alone.**

## Scope

Availability only — cross-subnet XNet message-pull denial on individual replicas. No consensus-safety
break, no funds, no authentication bypass, no state corruption. XNet starvation degrades the affected
replica's ability to advance on cross-subnet messages until the attacker releases (self-recovers on
release; no persistent state). Reach is any-registered-`NodeId`, not open-internet. The reproducer targets
a local self-owned mock, carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Queue with fairness instead of a global binary cap.** Replace the single 4-permit `try_acquire_owned()`
  gate with a bounded queue plus **per-source-`NodeId` fairness** (e.g. weighted-fair or round-robin
  admission), so no single registered node can hold the entire concurrency budget. A small global cap is
  fine *if* it is partitioned per peer.
- **Raise/segment the ceiling.** Four process-wide permits is very small for an any-registered-node surface;
  size the pool to the peer count and/or shard it per subnet.
- **Bound per-request cost.** Give the slice path a real `byte_limit` instead of
  `unwrap_or(usize::MAX)` (`certified_slice_pool.rs:405`) so a held permit cannot also be made arbitrarily
  expensive.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable concurrency-starvation on an any-registered-node replica
path → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **DFINITY
(`dfinity/ic`)**; this is our own (`source_class: original`) source trace + handler-level measurement of the
global XNet concurrency cap, not a novel implementation flaw of ours or an assigned CVE. The corpus
primitive `ic_xnet_concurrency_cap` is **on-spec** (registered in the known-class provenance map) and
**on-HF** (shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped
defensive artefact.

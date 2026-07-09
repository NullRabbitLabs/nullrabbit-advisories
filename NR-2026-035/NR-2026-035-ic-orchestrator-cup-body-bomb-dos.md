# NR-2026-035 — Internet Computer (replica orchestrator): unbounded `body.collect()` on the CUP-pull path → multi-GB heap pin per request

**NullRabbit Operator Advisory** · Published 2026-07-09

## Summary

The Internet Computer replica **orchestrator** pulls catch-up packages (CUPs) from its subnet peers. On the
response path (`rs/orchestrator/src/catch_up_package_provider.rs:343-372`) it collects the whole HTTP
response body with:

```rust
let body_req = timeout(self.backoff, res.into_body().collect());   // <-- BUG
```

`res.into_body().collect()` accumulates **every chunk** of the response into a single `Collected<Bytes>` heap
buffer. There is **no `http_body_util::Limited::new(body, max_bytes)`** wrapper anywhere in the call chain —
the only bound is `timeout(self.backoff, …)`, which caps **time, not bytes**. In production
`self.backoff` starts at `Duration::from_secs(30)` (`:136`) and **doubles on each failed round**
(`saturating_mul(2)` at `:366`). A malicious subnet replica that answers a CUP-pull `GET` with an unbounded
chunked-transfer body therefore pins the *requesting* replica's heap in proportion to
`link_speed × backoff_window`. The identical `.collect()` shape exists at the secondary site
`rs/canister_client/src/http_client.rs:302` (deadline-bound instead of timeout-bound). This is an
**availability / memory-exhaustion** DoS; it is a resource-bounding/hardening class, **out of paid scope**,
handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `IC_N2_CUP_BODY_BOMB` | `ic_orchestrator_cup_body_bomb` | orchestrator CUP-pull (peer HTTP) | `memory-pin` + `hyper-unbounded-body` | HIGH |

- **Reachability:** **subnet-internal** — the attacker must be a subnet member with a valid `NodeId` in the
  allow-list (the CUP-pull URL is constructed from registered subnet peer endpoints). This is a
  "one compromised/misbehaving replica endangers its subnet peers" threat model, **not** an open-internet DoS.
- **Severity:** HIGH — a single malicious responder pins **multi-GB heap per request** on the victim
  orchestrator, trending to OOM-kill under a sustained/backoff-doubling attack; **out of paid scope**,
  publish-track.
- **Affected:** `dfinity/ic` replica orchestrator (source-traced at HEAD, `catch_up_package_provider.rs`
  primary + `http_client.rs` secondary).
- **Mitigation:** wrap the body in `http_body_util::Limited::new(body, max_bytes)` before `.collect()` at both
  sites (CUP files are < 10 MB typical; a 64 MB cap gives ample headroom). See Mitigation.

## Mechanism (source-cited, `dfinity/ic`)

- **Time-bounded, not byte-bounded.** `catch_up_package_provider.rs:349` wraps the collect in
  `timeout(self.backoff, res.into_body().collect())`. `timeout` aborts on elapsed wall-time; it does **not**
  cap the bytes buffered before that. `http_body_util::Limited` — the documented hyper 1.x byte-cap extractor —
  is imported in the same crate but **not** applied on this path.
- **The window grows under attack.** `self.backoff` is `Duration::from_secs(30)` initially (`:136`); on a
  timeout it doubles (`saturating_mul(2)` at `:366`). So a responder that keeps timing the victim out drives
  successively **larger** windows: 30 s → 60 s → 120 s → …, each buffering proportionally more.
- **1:1 heap-to-bytes.** hyper's `Collected<Bytes>` retains all chunks with no compression/dedup/bound, so the
  victim commits ≈ 1 byte of RSS per body byte received.
- **Secondary site, same shape.** `http_client.rs:302` uses `timeout_at(deadline, response_body.collect())` —
  byte-identical exposure, deadline-bound.

## Measurement (fidelity: explicit)

A self-contained Rust probe using **the same hyper 1.x + http-body-util 0.1** versions the IC replica uses,
mirroring the exact `timeout(window, body.collect())` call, with an attacker `service_fn` streaming 1 MB
chunks under chunked transfer-encoding and an RSS sampler on the victim client:

| Window | Peak victim RSS | Δ heap in window | Server streamed | Timeout fired |
|---|---|---|---|---|
| 5 s (compressed) | 18.7 GB | **+18.8 GB** | 18.3 GB | t = 5.19 s |
| 30 s (prod `initial_backoff`) | 54.9 GB | **+40 GB** | 67.1 GB | t = 35.8 s |

Heap-to-bytes ratio ≈ **1:1**. Production-reachability translation (link-bound, 30 s window):
**3.75 GB/req at 1 Gbps**, **37.5 GB/req at 10 Gbps inter-subnet**. IC subnet-internal links are typically
1–10 Gbps; a single malicious responder pins 3.75–37.5 GB heap per CUP-pull round on the requesting replica,
and any single round exceeding available heap is OOM-fatal. Backoff doubling makes later rounds larger.

The published corpus reproducer (primitive `ic_orchestrator_cup_body_bomb`; family `memory_amp`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — one TCP
flow carrying a tiny outbound CUP-pull `GET` followed by a massive sustained inbound chunked response body,
across postures (single-flow low-volume/saturating, multi-flow distributed, paced slow-drip mimicry); the
transferred volume is capped for capture speed with the true +40 GB / 30 s ceiling preserved in bundle
provenance. **This advisory stands on the source trace (no `http_body_util::Limited` on the collect path) and
the hyper-parity heap measurement — not on the reproducer traffic alone.**

## Scope

Availability only (heap pin → OOM-kill of individual replicas). No consensus-safety break, no funds, no
authentication bypass, no state corruption. An OOM-killed replica drops from its subnet's consensus quorum
until restart; a coordinated set of compromised responders could drive multiple simultaneous OOMs, which
*indirectly* pressures subnet finality — this advisory does **not** claim a direct consensus halt. Reach is
subnet-internal (registered-`NodeId` gate), not public. The reproducer targets a local self-owned mock,
carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Byte-cap the collect.** Wrap the body in `http_body_util::Limited::new(body, max_bytes)` before
  `.collect()` at `catch_up_package_provider.rs:349` **and** `http_client.rs:302`. CUP artefacts are < 10 MB in
  practice; a 64 MB cap leaves headroom while bounding the pin. This is a 1–2 line change per site.
- **Keep the existing `timeout`** as a liveness bound in addition to the byte cap (they are complementary — one
  bounds time, one bounds memory).
- **Defence in depth:** treat inbound subnet-peer response bodies as untrusted regardless of `NodeId`
  allow-listing, since the allow-list does not attest response honesty.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable memory-exhaustion on a subnet-internal replica path →
**out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **DFINITY
(`dfinity/ic`)**; this is our own (`source_class: original`) measurement of the unbounded-`body.collect()`
exposure, not a novel implementation flaw of ours or an assigned CVE. The corpus primitive
`ic_orchestrator_cup_body_bomb` is **on-spec** (registered in the known-class provenance map) and **on-HF**
(shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.

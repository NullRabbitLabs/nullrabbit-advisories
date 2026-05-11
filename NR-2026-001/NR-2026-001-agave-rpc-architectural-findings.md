# NR-2026-001 — Three Agave RPC architectural findings

**NullRabbit Operator Advisory** · Published 2026-05-12

## Summary

Three architectural findings in the Agave JSON-RPC layer at
v3.1.9 allow an unauthenticated remote attacker to exhaust
validator egress bandwidth via response amplification
(`getMultipleAccounts`), and to saturate two independent
runtime worker pools — the Tokio async executor pool via
`simulateTransaction`, and the `spawn_blocking` pool via
`getProgramAccounts` — degrading latency across the entire RPC
tier rather than only the abused method. All three are
reachable on any validator exposing public JSON-RPC, gas-free,
and reproduce against an unmodified `solana-test-validator
2.2.16` on loopback.

These are architectural patterns, not request-rate spikes; an
operator-tier rate limiter that caps requests-per-second per IP
does not address them. The mitigation surface for each finding
is distinct and operator-applicable today, ahead of any
upstream change.

## Findings at a glance

| ID | RPC method | Family | Headline signature |
|---|---|---|---|
| SOL_F10 | `getMultipleAccounts` | Response amplification | 1,263× per-request byte amplification; 1,344 MB/s sustained server egress from 8 attacker workers |
| SOL_F14 | `simulateTransaction` | Tokio executor pool saturation | 1.13× aggregate scaling under 8× concurrency; 7.1× per-worker req/s drop; degrades the whole RPC tier |
| SOL_P07 | `getProgramAccounts` | `spawn_blocking` pool saturation | Aggregate throughput flat under 8× concurrency; 8× per-worker req/s drop; default behaviour for un-indexed programs |

SOL_F14 and SOL_P07 both produce ~7–8× per-worker degradation
at 8 workers, but saturate **different runtime pools**. Tuning
one pool's size has no effect on the other primitive; the two
findings have non-overlapping mitigations.

All citations below reference agave v3.1.9, commit
`765ee54adc4f574b1cd4f03a5500bf46c0af0817`. Measurements were
produced against `solana-test-validator 2.2.16` on
`127.0.0.1:8899`, single-process, default configuration. The
architectural patterns appear stable across recent v3.x; we
have not measured against v2.x or earlier explicitly.

---

## SOL_F10 — `getMultipleAccounts` byte amplification

**Family**: response amplification. **Auth**: none. **Gas**: none.

### Mechanism

`getMultipleAccounts` accepts up to `MAX_MULTIPLE_ACCOUNTS=100`
pubkeys per request. The handler:

1. Validates the pubkey count against the cap at the dispatch
   site (`rpc/src/rpc.rs:3230-3238`).
2. Iterates the pubkey list sequentially.
3. For each pubkey, awaits
   `runtime.spawn_blocking(get_encoded_account(...))`.
4. Serialises account data via the requested encoding
   (default `base64`).
5. Returns the assembled `Vec<Option<UiAccount>>`.

There is no per-account size cap, no per-response total-byte
cap, and no per-IP rate limit gating the read path. The
attacker's lever is pubkey selection: the BPF Loader v2
program-data stub (~178 KB) is carried by the Token,
BPFLoader2, and BPFLoaderUpgradeable program addresses.
Cycling 100 pubkeys across those three addresses produces a
~6.06 MB response from a ~4.8 KB request body.

### Measurement

`solana-test-validator 2.2.16`, single process, loopback
(`127.0.0.1:8899`), 8 attacker workers, 10 s sustained:

| Metric | Value |
|---|--:|
| Aggregate req/s | 220.9 |
| Per-request response | 6,062,041 bytes (6.06 MB) |
| Per-request request | 4,798 bytes |
| Amplification ratio | 1,263× |
| Sustained server egress | **1,344 MB/s** |
| p50 / p99 latency | 35.4 ms / 52.0 ms |
| HTTP 200 rate | 100 % (no throttling, no errors) |

Per-request amplification is a per-method property that
transfers to any network path; the egress magnitude scales with
the number of saturating attacker workers and is bounded by the
validator's upstream bandwidth, not the attacker's downstream.

### Operator mitigations

- **Per-response total-byte cap at the RPC tier or load
  balancer.** A 1–2 MB ceiling on `getMultipleAccounts`
  responses contains the amplification without breaking
  documented usage (most legitimate batched-read clients
  request small accounts).
- **Per-IP read-path rate limiting.** Bandwidth-aware limits
  (egress bytes per IP per unit time) are more effective than
  request-rate caps for this finding — a single request can
  produce megabytes.
- **Block `getMultipleAccounts` at the LB if not required by
  your clients.** Indexer and explorer workloads typically use
  it; trading and consensus-adjacent paths usually don't.
- **Monitor `getMultipleAccounts` egress and request-body
  composition.** Heavy-pubkey enumeration (Token, BPFLoader2,
  BPFLoaderUpgradeable repeated across the pubkey list) is the
  attacker signature.

---

## SOL_F14 — `simulateTransaction` runs synchronously on Tokio workers

**Family**: compute amplification, async-runtime saturation.
**Auth**: none. **Gas**: none.

This is the load-bearing finding for the "architectural
pattern, not rate-limit DoS" framing. The mechanism is not
about how many simulate requests per second an attacker can
send — it is that **each in-flight simulate request occupies a
Tokio executor thread for the full simulation duration**, and
the Tokio runtime is shared with every other async RPC method.
Saturating the executor pool with simulate work degrades
latency across the entire RPC tier, including methods the
attacker never touched.

### Mechanism

`simulateTransaction` is implemented as a synchronous handler
inside the async (Tokio) RPC runtime:

- Trait declaration (`rpc/src/rpc.rs:3502-3508`) returns
  `Result<RpcResponse<RpcSimulateTransactionResult>>` — a sync
  signature, not `BoxFuture<...>`.
- Implementation header (`rpc/src/rpc.rs:3943-3949`) is sync
  (no `async` keyword).
- The simulate call at `rpc/src/rpc.rs:4009` is
  `bank.simulate_transaction(&transaction, enable_cpi_recording)`
  — invoked directly from the Tokio handler, **no
  `spawn_blocking` interposed**.
- `bank.simulate_transaction` (`runtime/src/bank.rs:3066-3074`)
  is sync, calling `simulate_transaction_unchecked`
  (`runtime/src/bank.rs:3078-3093`), which calls
  `load_and_execute_transactions(...)` — the BPF VM runs on
  the calling Tokio worker.

The path is also unauthenticated and effectively gas-free:

- `sigVerify` defaults to `false`. Setting
  `replaceRecentBlockhash: true` requires `sigVerify: false` —
  the cheaper-and-more-attacker-friendly combination is the
  documented path.
- There is no RPC-tier compute-budget enforcement; the only CU
  cap is the on-chain `compute_unit_limit` instruction's
  value, set by the attacker in the submitted transaction
  (default ceiling 1,400,000 CU per tx).
- The path runs under a Tokio worker, not `spawn_blocking`.
  The attacker is bounded only by the Tokio runtime's worker
  count, not by any blocking-pool quota.

### Measurement

Transaction shape:
`ComputeBudget::SetComputeUnitLimit(1_400_000)` +
`ComputeBudget::SetComputeUnitPrice(1)` + 40 × SPL Memo v2
(small-payload), submitted via `simulateTransaction` with
`sigVerify=false` and `replaceRecentBlockhash=true`.

| Metric | 1-thread 30 s | 8-worker 10 s | Ratio |
|---|--:|--:|--:|
| Aggregate req/s | 918.7 | 1,036.5 | **1.13×** (vs ideal 8×) |
| Per-worker req/s | 918.7 | 129.6 | **7.1× drop** |
| p50 latency | 1.02 ms | 7.66 ms | **7.5×** |
| p99 latency | 2.01 ms | 12.12 ms | 6.0× |
| HTTP / sim status | 200 / `ok` (100 %) | 200 / `ok` (100 %) | constant |
| CU consumed / tx | 237,660 | 237,660 | constant |

The 1.13× scaling under 8× concurrency is the canonical
sync-handler-in-async-runtime saturation signature. Per-worker
throughput collapses by 7.1× and per-worker latency rises
proportionally; the wait time is queueing for a Tokio worker
that is busy running BPF VM bytecode for an attacker request.

Critically: the per-worker latency rise is observed on the
**simulate** path because that is what we measured, but it
applies to **every other async RPC method served by the same
Tokio runtime**. A trading client polling
`getLatestBlockhash` or an indexer reading
`getTransaction` sees the same queue-wait, because the same
worker pool serves all of them.

### Operator mitigations

- **Rate-limit `simulateTransaction` per IP at the LB.**
  Aggressive limits (single-digit req/s per IP, with bursting
  budget) are safe — most legitimate simulate workloads are
  bounded.
- **Require a non-default `compute_unit_limit` ceiling at the
  LB or proxy.** Reject simulate requests whose embedded
  `ComputeBudget::SetComputeUnitLimit` exceeds a target CU
  cap. The CU cap is in the transaction bytes; an
  envelope-aware proxy can enforce it without touching the
  validator.
- **Consider blocking `simulateTransaction` at the LB if not
  required by your clients.** Many RPC tiers (consensus-only,
  validator-internal monitoring) don't need to expose it.
- **Watch for sustained `simulateTransaction` workload from
  small IP ranges.** The signature is many simulate requests
  with high `unitsConsumed` and `sigVerify=false`.

The architecturally clean fix sits with upstream — dispatching
the simulate call into `spawn_blocking` (or a dedicated sim
pool), and enforcing an RPC-tier compute budget — but operators
do not need to wait for that to bound exposure.

---

## SOL_P07 — `getProgramAccounts` `spawn_blocking` pool saturation

**Family**: compute amplification, blocking-pool saturation.
**Auth**: none. **Gas**: none.

The substrate is the `spawn_blocking` pool, distinct from
SOL_F14's Tokio-executor-pool substrate. Both produce ~7–8×
per-worker req/s drop at 8 workers, but they saturate different
runtime pools and the mitigations are independent.

### Mechanism

`getProgramAccounts` runs a full account-set scan inside
`spawn_blocking`:

1. The handler (`rpc/src/rpc.rs:2199-2252`,
   `async fn get_filtered_program_accounts`) branches on
   `self.config.account_indexes.contains(&AccountIndex::ProgramId)`.
2. **Indexed branch** (`rpc/src/rpc.rs:2207-2227`): when the
   program is in `account_indexes`, the call routes to
   `get_filtered_indexed_accounts`, which uses a secondary
   index.
3. **Default un-indexed branch** (`rpc/src/rpc.rs:2235-2251`):
   wraps the scan in `runtime.spawn_blocking(...)` calling
   `bank.get_filtered_program_accounts(&program_id,
   &filter_closure, &ScanConfig::new(scan_order))`.
4. The filter closure is `filters.iter().all(filter_allows)` —
   checked **inline during scan iteration**, not via an index
   lookup.

A never-matching `memcmp` filter forces a full O(N) scan that
occupies a `spawn_blocking` thread for the entire scan duration
regardless of result-set size. The `spawn_blocking` pool is
shared across all RPC paths that use it (including
`getMultipleAccounts`'s per-key dispatch). Saturating the pool
blocks unrelated RPC paths.

### Default-vs-indexed scoping

The full-scan path is the **default** behaviour for un-indexed
programs. Operators can configure `account_indexes =
[ProgramId]` for specific programs (Token, etc.) to bypass the
full-scan path for those programs. The mitigation is partial:

- Indexes cover a fixed, operator-chosen set. The attacker can
  target any program **outside** the indexed set to force the
  full-scan path.
- Default `solana-test-validator` and most fullnode
  configurations don't run with the per-program secondary
  index for arbitrary programs.
- Even with indexes configured, the `spawn_blocking` pool
  saturation surface remains accessible via attacks against
  un-indexed programs.

This finding is framed as "default behaviour for un-indexed
program queries" — not "behaviour regardless of configuration."

### Sub-linear scan-cost calibration

The disclosure-grade signal is **concurrency**, not
single-request latency. A 1000× state increase produces only a
~1.9× single-thread latency rise:

- Sparse state (~5–10 BPFLoader2 program-data accounts):
  p50 8.6 ms, single-thread 109 req/s.
- Populated state (10,077 SPL token accounts via populator):
  p50 16.3 ms, single-thread 59.5 req/s.

Solana's AccountsDb in-memory scan is well-optimised
(~0.76 µs per account scanned). The operator-relevant signal
is `spawn_blocking` pool saturation under concurrency, not
per-request scan amplification.

### Measurement

State pre-condition: 10,077 SPL token accounts populated under
the SPL Token program. Single-process
`solana-test-validator 2.2.16`. Attacker submits never-matching
`memcmp` filter at offset 0 against
`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.

| Metric | 1-thread 30 s | 8-worker 10 s | Ratio |
|---|--:|--:|--:|
| Aggregate req/s | 59.5 | 60.0 | flat (saturated) |
| Per-worker req/s | 59.5 | 7.5 | **8× drop** |
| p50 latency | 16.3 ms | 130.3 ms | **8×** |
| p99 latency | 26.1 ms | 184.7 ms | 7.1× |
| Per-request response | 37 bytes (empty array) | 37 bytes | constant |

Aggregate throughput is **flat** under 8× more attacker workers
— the `spawn_blocking` pool is fully busy and total throughput
pegs at ~60 req/s. Per-worker req/s drops 8× and per-request
latency rises proportionally; the wait time is queueing for a
free pool worker.

### Operator mitigations

- **Configure `account_indexes` for programs you expect to be
  scanned.** Token, Token-2022, and any DeFi protocol your
  indexer queries. This bypasses the full-scan path for those
  programs. It does **not** close the pool-saturation surface
  against un-indexed programs.
- **Rate-limit `getProgramAccounts` per IP at the LB.**
  Single-digit req/s per IP for the un-indexed path is
  defensible — legitimate full-scan workloads are
  archival-class and rare.
- **Reject `getProgramAccounts` requests with filters that
  cannot narrow the scan.** An LB-layer filter check on
  `memcmp` offset/bytes (rejecting offsets at non-meaningful
  positions, or requiring a `dataSize` filter that bounds the
  result set) raises the attacker's per-request cost.
- **Block `getProgramAccounts` entirely if not required.**
  Consensus and trading paths typically don't need it. Indexer
  workloads do.
- **Monitor `spawn_blocking` pool queue depth.** If the
  validator exposes the metric, sustained high queue depth
  with low aggregate `getProgramAccounts` throughput is the
  saturation signature.

The architecturally clean fix is upstream — bounding scan
duration, separating the `getProgramAccounts` scan pool from
the shared `spawn_blocking` pool, and mandatory
filter-narrowing for un-indexed programs — but operators do not
need to wait for that.

---

## Scope

These findings were disclosed to the Anza security team via
GitHub Security Advisory at `anza-xyz/agave` on 2026-05-06 and
closed by Anza on 2026-05-10 as out of scope under the Agave
security policy's RPC carve-outs, with the closure-comment
characterising the findings as RPC denial-of-service.

We are publishing this advisory because we believe at least
SOL_F14 is not characterised by the rate-limit DoS framing the
RPC carve-out is built around. The finding is that a
synchronous handler runs inside the async runtime — every
in-flight simulate request occupies a Tokio executor thread for
the simulation duration, degrading the entire RPC tier rather
than only the simulate path. That is a runtime-architecture
property rather than a per-IP request volume property; an
operator-tier rate limit on `simulateTransaction` mitigates
exposure but does not address the underlying coupling. SOL_F10
and SOL_P07 are closer to the carve-out's framing, but the
mitigations operators need to apply differ from "cap requests
per second" — response-byte caps for F10, blocking-pool
isolation and filter-narrowing for P07.

The Anza GHSA is at
[github.com/anza-xyz/agave/security/advisories/GHSA-rvxh-p338-j9p3](https://github.com/anza-xyz/agave/security/advisories/GHSA-rvxh-p338-j9p3).

Operators applying the mitigations in this advisory are
acting ahead of any upstream change.

## Disclosure timeline

- **2026-05-06** — Disclosed to Anza via GHSA at
  `anza-xyz/agave`, with reproducers, source citations, and
  measurement bundles attached.
- **2026-05-10** — GHSA closed by Anza as out of scope under
  the Agave security-policy RPC carve-outs.
- **2026-05-12** — This public advisory published.

## Affected versions

Confirmed against agave v3.1.9, commit
`765ee54adc4f574b1cd4f03a5500bf46c0af0817`. The architectural
patterns (no per-response byte cap on `getMultipleAccounts`;
sync simulate handler on the Tokio runtime; un-indexed default
full-scan in `spawn_blocking`) appear stable across recent v3.x.
We have not measured against v2.x or earlier explicitly.

## Reproducers

Self-contained reproducers are available alongside this
advisory in [`reproducers/`](reproducers/), with a quick-start
in [`reproducers/README.md`](reproducers/README.md). Each
reproducer prints the run-local measurement followed by the
headline reference numbers from this advisory; the per-worker
1-vs-8 comparison is the canonical architectural signature for
SOL_F14 and SOL_P07.

All reproducers default to `127.0.0.1:8899` and are intended
for use against `solana-test-validator` instances the operator
owns. Do not point them at infrastructure you do not operate.

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

If you operate Solana validator or RPC infrastructure and have
applied the mitigations above, or have measurements at variance
with those in this advisory, we are interested in hearing about
it. Corrections to the advisory are welcomed.

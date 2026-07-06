# NR-2026-009 — IOTA node gRPC StreamCheckpoints subscriber-slot exhaustion

**NullRabbit Operator Advisory** · Published 2026-07-04

> **Why we publish publicly:** these are out-of-scope-for-bounty, no-embargo node-availability findings — analysis + reproducer only. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

An IOTA node's public gRPC `StreamCheckpoints` server-stream is gated by a single
**process-global semaphore** (`max_concurrent_stream_subscribers`, default 1024)
with **no per-IP or per-connection sub-quota and no idle eviction**. A single
unauthenticated source can open and hold 1024 long-lived `StreamCheckpoints`
subscriptions; once the semaphore is full, every subsequent *legitimate*
`StreamCheckpoints` request across the entire node is refused with
`grpc-status 14 UNAVAILABLE` ("maximum concurrent stream subscribers reached")
until the attacker disconnects. Because each held stream can sit idle at zero
protocol cost, one small box holds all 1024 slots trivially.

This is an **availability issue only** — no memory corruption, no crash, no funds
or consensus impact — but it is a full denial of the checkpoint-stream service to
every legitimate consumer (indexers, wallet/dApp backends, bridge and oracle
relayers, observability scrapers). Recovery happens only when the attacker's
streams close. **Severity: HIGH** for availability of the checkpoint-stream
consumers.

## Affected configuration

Any IOTA node exposing the public gRPC `LedgerService` with the default
subscriber cap and no per-peer sub-quota. Source pins:

- `crates/iota-grpc-server/src/ledger_service/get_checkpoint.rs` — the subscribe
  path does a `try_acquire_owned` against a shared
  `Arc<Semaphore::new(max_subscribers)>` and returns
  `Status::unavailable("maximum concurrent stream subscribers reached")` when the
  semaphore is exhausted. (The RAII guard correctly releases the slot on stream
  drop — the defect is the *global, unsegmented* cap, not a leak.)
- `crates/iota-config/src/node.rs` —
  `default_grpc_api_max_concurrent_stream_subscribers() = 1024`.
- `crates/iota-grpc-server/src/server.rs` — the cap is passed to the broadcaster
  unmodified; the semaphore is the only limiter on this path.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Hold-shape exhaustion of a global subscription semaphore → denial of a streaming RPC (`connection_exhaustion`) |
| Reachability | Remote, unauthenticated, single source IP |
| Trigger | Open and hold 1024 concurrent `StreamCheckpoints` subscriptions |
| Impact | All 1024 slots consumed; the 1025th and all later legitimate requests get `grpc-status 14`. Persists for the lifetime of the attack; recovery within ~1 s once the held streams close |
| Severity | HIGH — full DoS of the `StreamCheckpoints` consumers; no crash, no funds/consensus impact |
| Mitigation | Per-IP / per-connection subscription sub-quota (e.g. 10–20 streams per remote address); raise the global cap and add idle-eviction (reset subscribers that have not acknowledged flow-control within N seconds) |

## Mechanism

The subscription semaphore is the **only** limiter on `StreamCheckpoints`. There
is no per-IP cap (which would force an attacker onto 1024 distinct source IPs), no
per-connection cap (which would force 1024 distinct TCP connections from distinct
addresses), no idle-timeout eviction (a subscriber that never reads still holds its
slot), and no priority preemption for new subscribers. A single low-resource source
holds all 1024 slots at effectively zero cost, and the guard releases them only on
stream close — so the denial lasts exactly as long as the attacker chooses to hold
the connections open.

This is a **distinct** limiter and a distinct DoS class from the earlier IOTA gRPC
memory-amplification advisory (NR-2026-008 is Cosmos; the IOTA unary-call OOM is
NR-2026-003): that finding is unbounded-concurrency *memory* growth on the unary
ledger reads, which the 1024 subscriber cap does **not** bound; this finding is
*slot* exhaustion of the subscription cap itself on the `StreamCheckpoints`
server-stream.

## Impact & mitigation

- **Impact:** every legitimate `StreamCheckpoints` consumer — indexers falling
  behind real time, wallet/dApp backends losing confirmation streams, bridge and
  oracle relayers losing the finalized-checkpoint signal, observability scrapers
  losing their metric feed — is denied service for the duration of the attack.
- **Mitigation:** add a per-IP / per-connection subscription budget so no single
  source can consume more than a small share of the cap; independently, raise the
  global cap for a fullnode that serves many consumers and add idle-eviction so
  non-reading holders are reset rather than pinning slots indefinitely.

## Scope

This advisory targets node **availability** only. The reproducer is code-level
(open and hold subscriptions against a self-owned local node); it does not target
live infrastructure and is not a turnkey weapon. IOTA does not run a public paid
bug-bounty program, and node availability / DoS is not a paid-impact category, so
this finding is **out of scope** for any bounty; a class the vendor declines to
treat as a paid impact carries no disclosure embargo. It is published here as an
operator advisory so operators can add a per-peer subscription quota now.

## Reproduction

Measured against a self-owned local IOTA node: 1024 concurrently opened
`StreamCheckpoints` streams are all accepted; a 1025th request from a fresh
connection is refused with `grpc-status 14` and the literal message "maximum
concurrent stream subscribers reached"; two probes three seconds apart are both
refused; once the 1024 held streams close, the RAII guard releases the slots and a
recovery request succeeds within about a second. Representative multi-modal capture
bundles are published in the
[`nr-bundles-public`](https://huggingface.co/datasets/NullRabbit/nr-bundles-public)
dataset (`family_id=connection_exhaustion`).

## Provenance

NullRabbit original research (our own measurement on a self-owned lab node).
Cross-references: NullRabbit finding id `IOTA_GRPC_STREAM_CAP_DOS`; detection
primitive `iota_grpc_stream_cap_dos` (family `connection_exhaustion`).

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

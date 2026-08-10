# NR-2026-015 — Aptos `/v1/transactions/batch`: per-element work runs before the batch-size cap

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

The Aptos REST endpoint `POST /v1/transactions/batch` verifies and JSON→native-converts
**every** element of the submitted batch **before** it checks the batch-size cap
(default 10). So an unauthenticated attacker can POST a batch of thousands of signed
transactions; the node does the expensive per-element work on all of them and only
then rejects the batch for being over-cap. NullRabbit measured **1 attacker over 4
connections saturating an entire 4-core aptos-node (391% CPU)**, with legitimate
`/v1` request p99 latency degrading **70–100×** over baseline. It is an availability
issue only — no funds or consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | REST handler CPU exhaustion (`rpc_handler_cpu`) — unbounded `Vec<expensive-T>`, cap-after-work |
| Reachability | Remote, unauthenticated, public Aptos REST API (typically port 8080) |
| Trigger | `POST /v1/transactions/batch` with N ≫ cap signed transactions |
| Measured | 1 attacker × 4 conns → **391% CPU** on a 4-core node; legit `/v1` p99 **+70–100×** |
| Severity | High (external unauthenticated single-host CPU saturation of a fullnode) |
| Affected | Every Aptos fullnode exposing `/v1/transactions/batch` (default). `api.transaction_submission_enabled=false` disables it; changing `api.max_submit_transaction_batch_size` does NOT move the cap-check earlier |
| Mitigation | Check `params.len()` against the cap **before** any per-element verify/convert. See Mitigation |

## Mechanism (source-cited)

`api/src/transactions.rs:525` — `submit_transactions_batch` does its work in this order:

```rust
async fn submit_transactions_batch(data: SubmitTransactionsBatchPost) -> ... {
    data.verify()?;                                              // (1) per-element verify ALL elements
    ...
    let signed_transactions_batch = self.get_signed_transactions_batch(&ledger_info, data)?;
                                                                 // (2) JSON→native + state-view IO PER element
    if self.context.max_submit_transaction_batch_size()          // (3) size cap (default 10) — AFTER (1),(2)
        < signed_transactions_batch.len() {
        return Err(...);
    }
    ...
}
```

Steps (1) and (2) run per-element expensive work — signature verification, JSON→native
transaction conversion, and state-view IO — on **all** N submitted elements, and only
step (3) enforces the size cap. An attacker submits N far larger than the cap; the cap
rejects the request, but the CPU has already been spent. `data.verify()` and the
conversion dominate, scaling linearly with N.

## Reproduction (fidelity: explicit)

The CPU saturation is a server-side effect. The published corpus reproducer
(`chains/aptos/lab/drivers/known_class_aptos_batch_vec.py`, primitive
`aptos_batch_uncapped_vec_cpu` in `NullRabbit/nr-bundles-public`) captures the wire
signature — a large `POST /v1/transactions/batch` body of N ≫ cap signed-transaction
objects — with `provenance.wire_fidelity = "large_batch_body_representative"` and the
measured 391% CPU recorded in `attack_parameters`. **This advisory stands on the source
trace and the live measurement, not on the reproducer's synthetic batch.**

## Mitigation

- **Move the size-cap check first.** Reject on `params.len() > max_submit_transaction_batch_size`
  **before** `data.verify()` and any per-element conversion — the cap must gate the work, not follow it.
- Rate-limit `/transactions/batch` by request cost per source.
- Where the deployment permits, disable batch submission (`api.transaction_submission_enabled=false`)
  or front the API with a body/element-count-capping proxy.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). DoS/availability on the public
Aptos REST surface is publish-track under NullRabbit's disclosure-scope policy.
NullRabbit measurement; source-trace and live numbers in
`chains/aptos/findings/APT_REST_BATCH_UNCAPPED_VEC`. Corpus primitive
`aptos_batch_uncapped_vec_cpu` shipped in `NullRabbit/nr-bundles-public`.

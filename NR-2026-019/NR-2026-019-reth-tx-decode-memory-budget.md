# NR-2026-019 — reth: eth `Transactions`/`PooledTransactions` decoded into an unbounded `Vec` → decode-time memory amplification (fixed in #23718)

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

Before reth PR #23718 (merged 2026-04-27), the eth-wire `Transactions` and `PooledTransactions` message
bodies derive their RLP decode via `RlpDecodableWrapper` over a `Vec<_>` with **no in-memory bound**. The
list is fully decoded into that `Vec` **before** any per-transaction validation, so a **well-formed**
message that decodes without error does **not** trip reth's peer-misbehavior tracker (which only reacts to
decode *errors*) — yet its decoded representation can be an order of magnitude larger than its wire size.
Measured directly against reth's own decode path: a single clean-decoding message at or below
`MAX_MESSAGE_SIZE` (10 MB wire) allocates up to **436 MB** during decode (**41.6×**; **54.5 MB / 5.2×**
with realistic legacy transactions). N concurrent peers each sending such a message drive proportional
memory exhaustion. #23718 fixes this by bounding decode to `MAX_MESSAGE_SIZE * 2 = 20 MB`. It is an
availability issue only — no funds, no consensus-safety impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Decode-time memory amplification via unbounded RLP list decode (`memory_amp`) |
| Reachability | Remote devp2p peer that has completed the RLPx + eth `Status` handshake; a single unsolicited `Transactions` broadcast suffices |
| Trigger | A well-formed `Transactions`/`PooledTransactions` message (≤ `MAX_MESSAGE_SIZE`) carrying a large transaction list |
| Measured | Up to **436 MB decode allocation** for a ≤10 MB wire message (41.6×; 54.5 MB / 5.2× with realistic legacy txs); `elem_size` 416 B per decoded tx |
| Severity | Medium (pre-#23718; **fixed**) — remote, cheap, escapes the decode-error misbehavior path; per-node memory exhaustion at fleet scale, no chain halt |
| Affected | reth **< #23718** (merged 2026-04-27) |
| Mitigation | Upgrade past #23718 (decode memory budget). See Mitigation |

## Mechanism (source-cited, `paradigmxyz/reth`)

Pre-fix (`crates/net/eth-wire-types/src/broadcast.rs`, `.../transactions.rs`):

```rust
#[derive(... RlpDecodableWrapper ...)]
pub struct Transactions<T = TransactionSigned>(pub Vec<T>);
// PooledTransactions<T = PooledTransaction> is the same shape.
```

`RlpDecodableWrapper` expands to a `Decodable` impl that decodes the entire RLP list into `Vec<T>` with
no running memory bound. On the receive path the message is decoded in full **before** transactions are
validated, so the allocation happens for any structurally-valid list — including one whose per-element
signatures are junk (recovery is lazy, post-decode). Because the bytes decode without error, reth's
`reth_network_invalid_messages_received` misbehavior counter is **not** incremented during decode; the
peer is only disconnected later, at pool validation, **after** the memory spike.

Post-fix (#23718) adds `decode_with_memory_budget` (`.../transactions.rs`, `.../broadcast.rs`) and swaps
it into the receive path (`.../message.rs`) with `tx_memory_budget = MAX_MESSAGE_SIZE * 2 = 20 MB`,
aborting decode once the running allocation would exceed the budget.

## Measurement (fidelity: explicit)

Measured against reth's exact `reth_eth_wire_types::PooledTransactions` decode using a workspace harness
on reth-src at the pre-fix parent commit, with a counting global allocator recording peak allocation:

| Payload (well-formed, `DECODE OK` — no misbehavior bump) | txs in one ≤10 MB message | peak decode allocation | amplification |
|---|---|---|---|
| minimal legacy txs | 1,048,576 | **436 MB** | **41.6×** |
| realistic legacy tx (reth's own encode test vector) | 99,864 | **54.5 MB** | **5.2×** |

Both exceed the 20 MB budget #23718 introduces. The published corpus reproducer
(primitive `reth_pooledtx_decode_memory_amp`, family `memory_amp`, `source_class: original`, in
`NullRabbit/nr-bundles-public`) captures the **attack traffic** — a post-handshake `Transactions`
broadcast carrying a large well-formed tx list — against a protocol-compatible node; the decode-memory
magnitude is the harness measurement above. **This advisory stands on the source trace and the
measurement, not on the reproducer's transport shim.**

## Scope

Availability/resource-cost only; no consensus-safety or authentication break, no chain halt (a healthy
quorum keeps producing blocks; the harm is per-node memory pressure). The reproducer targets a local
self-owned node, carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Upgrade reth to a build including #23718** — the decode memory budget bounds `Transactions` /
  `PooledTransactions` decode to 20 MB, which closes this. The fix is already merged (2026-04-27); this
  advisory documents the pre-fix residual and its measured magnitude for operators still on older builds.

## Disclosure & provenance

Availability-only finding (no funds/consensus-safety impact), already fixed upstream. DoS/availability on
the public devp2p surface is publish-track under NullRabbit's disclosure-scope policy. Vendor: Paradigm /
`paradigmxyz/reth` (#23718). NullRabbit measurement; source-trace, harness, and numbers in
`chains/ethereum/findings/RETH_TX_MEMORY_BUDGET/` (`residual-measurement-2026-07-06/`). Corpus primitive
`reth_pooledtx_decode_memory_amp` shipped in `NullRabbit/nr-bundles-public`.

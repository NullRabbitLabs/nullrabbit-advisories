# NR-2026-059 — Ethereum (go-ethereum): eth_getBlockReceipts full-block receipt/log fanout amplification

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

`eth_getBlockReceipts` returns **every** receipt — with all logs — for a block, in one JSON-RPC response. A
log-dense block (an attacker can pack one cheaply with log-emitting transactions) yields a large reply for a
tiny (~80-byte) request — a **response-amplification** DoS payable by an unauthenticated caller. Availability
only, out of paid scope → publish-track.

## Findings at a glance

| Finding | Primitive | Method | Class | Severity |
|---|---|---|---|---|
| `ETH_GETBLOCKRECEIPTS_LOG_FANOUT_AMP` | `eth_getblockreceipts_full_block_receipt_log_fanout_amp` | `eth_getBlockReceipts` | `response_amp` | MEDIUM |

- **Reachability:** any remote client reaching a non-loopback JSON-RPC; no auth.
- **Affected:** go-ethereum exposing `eth_getBlockReceipts`.

## Affected versions

Observed on go-ethereum 1.17.4; documented method semantics.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`eth_getBlockReceipts` (`internal/ethapi/api.go`) loads the block's receipts and marshals each — including
its full `logs` array — into a single response. Response size scales with the number and size of logs in the
block, which the attacker steers by packing the block with cheap log-emitting transactions; no per-response
size cap applies.

## Measurement (fidelity: lab)

Self-owned go-ethereum 1.17.4 `--dev`: a block seeded with ~300 logs → **~80 B request → ~342 KB response
(≈4,273×)**; control (a no-log block) → ~1 KB. Corpus reproducer
`eth_getblockreceipts_full_block_receipt_log_fanout_amp` (`response_amp`, `source_class: original`) ships in
`NullRabbit/nr-bundles-public`.

## Scope

Availability / bandwidth-and-CPU only; no funds, consensus, or auth break.

## Mitigation

- Cap response size / paginate receipt reads at the RPC edge; rate-limit per source; keep the RPC transport
  on loopback or behind an authenticating gateway.

## Vendor channel and scope

Vendor **go-ethereum**. Availability-only, config-mitigable → **out of paid scope → publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai

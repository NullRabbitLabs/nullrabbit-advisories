# NR-2026-060 — Ethereum (go-ethereum): eth_createAccessList storage-key cardinality fanout amplification

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

`eth_createAccessList` returns the list of `(address, storageKeys)` a transaction touches. A contract that
reads N distinct storage slots produces an N-key access list, so a small request against such an enumerator
yields a large response — a **response-amplification** DoS payable by an unauthenticated caller. Availability
only, out of paid scope → publish-track.

## Findings at a glance

| Finding | Primitive | Method | Class | Severity |
|---|---|---|---|---|
| `ETH_CREATEACCESSLIST_STORAGEKEY_FANOUT_AMP` | `eth_createaccesslist_storagekey_cardinality_fanout_amp` | `eth_createAccessList` | `response_amp` | LOW |

- **Reachability:** any remote client reaching a non-loopback JSON-RPC; no auth. A call with a funded `from`
  is required (no `gasPrice`).
- **Affected:** go-ethereum exposing `eth_createAccessList`.

## Affected versions

Observed on go-ethereum 1.17.4; documented method semantics.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`eth_createAccessList` (`internal/ethapi/api.go` → `AccessList`) executes the transaction (iterating to a
stable list) and returns every `(address, storage-slot)` accessed. A contract that `SLOAD`s N distinct slots
yields N storage keys (~66 bytes each) in the response; the count is attacker-chosen via the enumerator
contract; no per-response size cap applies. (The call requires a funded `from` and no `gasPrice` — an empty
`gasPrice` is rejected post-London.)

## Measurement (fidelity: lab)

Self-owned go-ethereum 1.17.4 `--dev`: an SLOAD enumerator over 1000 slots → **~225 B request → ~70 KB
response (≈311×), 1001 storage keys**; control (an EOA target) → empty access list. Corpus reproducer
`eth_createaccesslist_storagekey_cardinality_fanout_amp` (`response_amp`, `source_class: original`) ships in
`NullRabbit/nr-bundles-public`.

## Scope

Availability / bandwidth-and-CPU only; no funds, consensus, or auth break.

## Mitigation

- Cap response size / access-list length at the RPC edge; rate-limit per source; keep the RPC transport on
  loopback or behind an authenticating gateway.

## Vendor channel and scope

Vendor **go-ethereum**. Availability-only, config-mitigable → **out of paid scope → publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai

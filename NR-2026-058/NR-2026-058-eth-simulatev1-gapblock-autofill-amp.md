# NR-2026-058 — Ethereum (go-ethereum): eth_simulateV1 gap-block autofill response amplification

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

`eth_simulateV1` accepts a list of `blockStateCalls`, each with a `blockOverrides.number`. When two entries
leave a gap in the block-number sequence, the node **synthesises every intervening block** and returns a full
header object for each — up to ~256 fabricated block objects for a tiny request. A small unauthenticated
request therefore expands into a large response. Availability only, out of paid scope → publish-track.

## Findings at a glance

| Finding | Primitive | Method | Class | Severity |
|---|---|---|---|---|
| `ETH_SIMULATEV1_GAPBLOCK_AUTOFILL_AMP` | `eth_simulateV1_gapblock_autofill_header_breadth_amp` | `eth_simulateV1` | `response_amp` | MEDIUM |

- **Reachability:** any remote client reaching a non-loopback JSON-RPC; no auth.
- **Affected:** go-ethereum exposing `eth_simulateV1` (its implementation of the `ethereum/execution-apis` `eth_simulate` method).

## Affected versions

Observed on go-ethereum 1.17.4; documented `eth_simulateV1` block-autofill semantics.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`eth_simulateV1` (`internal/ethapi/simulate.go`) processes `blockStateCalls` in order and, where a
`blockOverrides.number` skips ahead of the previous block, fills the gap with synthetic empty blocks (bounded
at ~256), each serialised as a full header object in the result. The count is attacker-chosen via the gap
between two tiny call entries; no per-response size cap applies.

## Measurement (fidelity: lab)

Self-owned go-ethereum 1.17.4 `--dev`: two `blockStateCalls` at block `0x1` and `0x100` → **~285 B request →
~434 KB response (≈1,523×), 256 synthesised block objects**; control (single block) → ~1.7 KB. Corpus
reproducer `eth_simulateV1_gapblock_autofill_header_breadth_amp` (`response_amp`, `source_class: original`)
ships in `NullRabbit/nr-bundles-public`.

## Scope

Availability / bandwidth-and-CPU only; no funds, consensus, or auth break.

## Mitigation

- Cap the block-number span / synthesised-block count for `eth_simulateV1` at the RPC edge; rate-limit per
  source; keep the RPC transport on loopback or behind an authenticating gateway.

## Vendor channel and scope

Vendor **go-ethereum**. Availability-only, config-mitigable → **out of paid scope → publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai

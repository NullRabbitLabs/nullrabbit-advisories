# NR-2026-056 — Ethereum (go-ethereum): eth_call compute exhaustion (gascap interpreter loop + BLAKE2F precompile)

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

`eth_call` executes attacker-influenced work synchronously on an RPC worker. Two vectors pin a worker's CPU
for a tiny request: (1) a `stateOverride`-injected tight `JUMP` loop that burns the full `rpc.gascap` (~50M
gas) before out-of-gas; (2) the BLAKE2F precompile (`0x09`), whose 4-byte **rounds** field is a direct
1-gas/round CPU knob, run for tens of millions of rounds. Both produce a tiny response (no byte
amplification) but sustained per-request CPU, and the RPC transport applies no per-source rate/concurrency
cap — so N concurrent calls each burn a core. Availability only, out of paid scope → publish-track.

## Findings at a glance

| Finding | Primitive | Vector | Class | Severity |
|---|---|---|---|---|
| `ETH_CALL_GASCAP_COMPUTE_BURN` | `eth_call_stateoverride_gascap_interpreter_compute_burn` | `eth_call` + stateOverride JUMP loop | `compute_amp` | LOW |
| `ETH_CALL_BLAKE2F_PRECOMPILE_CPU` | `eth_call_blake2f_precompile_rounds_cpu_amp` | `eth_call` → BLAKE2F precompile `0x09` | `compute_amp` | LOW |

- **Reachability:** any remote client reaching a non-loopback JSON-RPC; no auth.
- **Affected:** go-ethereum with `eth_call` exposed (default namespace).

## Affected versions

Observed on go-ethereum 1.17.4; documented method + precompile semantics, no version-specific regression.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`eth_call` (`internal/ethapi/api.go` → `doCall`) runs the message in the EVM up to `rpc.gascap` (default
50,000,000) and `rpc.evmtimeout`. (1) Override code `0x5b600056` (`JUMPDEST; PUSH1 0; JUMP`) loops until the
gascap is consumed, then out-of-gas — a tiny error response, real interpreter CPU. (2) The BLAKE2F precompile
(`core/vm/contracts.go`, EIP-152) runs `rounds` compressions; `rounds` is caller-set (gas = rounds), so a
~213-byte precompile input drives tens of millions of rounds. Neither is bounded by a per-source rate or
concurrency limit on the transport.

## Measurement (fidelity: lab)

Self-owned go-ethereum 1.17.4 `--dev`: (1) gascap loop → **~231 B request pins a worker ~73 ms** (vs ~7 ms
for a trivial call). (2) BLAKE2F at `rounds=0x02000000` (~33.5 M) → **~585 B request → ~405 ms CPU** (vs
~1 ms at `rounds=1`). Corpus reproducers `eth_call_stateoverride_gascap_interpreter_compute_burn` and
`eth_call_blake2f_precompile_rounds_cpu_amp` (`compute_amp`, `source_class: original`) ship in
`NullRabbit/nr-bundles-public`.

## Scope

Availability / CPU only; no funds, consensus, or auth break. Per-request cost is bounded by `rpc.gascap` /
`rpc.evmtimeout`; the aggregate is ceiling × attacker concurrency, which the transport does not cap.

## Mitigation

- Rate-limit `eth_call` per source and cap concurrency; tighten `rpc.gascap` / `rpc.evmtimeout` for public
  endpoints; restrict `stateOverride`.
- Keep `--http`/`--ws` on loopback or behind an authenticating gateway.

## Vendor channel and scope

Vendor **go-ethereum**. Availability-only, config-mitigable → **out of paid scope → publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai

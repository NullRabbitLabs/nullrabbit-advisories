# NR-2026-055 — Ethereum (go-ethereum): eth_call stateOverride large-return-buffer response amplification

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

`eth_call` accepts a `stateOverride` that replaces an address's `code` for the duration of the call. A few
bytes of injected bytecode — `RETURN(0, N)` — makes the node return `N` zero bytes, hex-encoded into the
JSON-RPC response (≈2N hex chars). A small request therefore expands into an attacker-sized response buffer,
bounded per call by `rpc.gascap` (memory expansion) and unbounded across repeated calls — a
**response-amplification** DoS payable by an **unauthenticated** caller when the JSON-RPC transport is
exposed. `eth_call` + `stateOverride` is default-enabled and unauthenticated. Availability only, out of paid
scope → publish-track.

## Findings at a glance

| Finding | Primitive | Method | Class | Severity |
|---|---|---|---|---|
| `ETH_CALL_LARGE_RETURN_BUFFER_AMP` | `eth_call_stateoverride_large_return_buffer_amp` | `eth_call` + `stateOverride` | `response_amp` | MEDIUM |

- **Reachability:** any remote client reaching a non-loopback JSON-RPC (`--http`/`--ws`); no auth.
- **Affected:** go-ethereum with `eth_call` exposed (default namespace).

## Affected versions

Observed on go-ethereum 1.17.4. The behaviour is the documented `eth_call` + `stateOverride` semantics, not a
version-specific regression; no specific affected range is established beyond "an exposed `eth_call`".

## Mechanism (source-cited, `ethereum/go-ethereum`)

`eth_call` (`internal/ethapi/api.go` → `doCall`) applies the caller-supplied `StateOverride` (per-address
`code`) then executes the message in the EVM. Injected `RETURN(0, N)` returns `N` bytes of zero-initialised
memory; the RPC hex-encodes them into a single response. `rpc.gascap` (default 50,000,000) bounds memory
expansion per call but not the response byte-size, and no per-call response-size cap applies.

## Measurement (fidelity: lab)

Self-owned go-ethereum 1.17.4 `--dev`: override code `RETURN(0, 0x080000)` → **~230 B request → ~1.05 MB
response (≈4,425×)**; control override `RETURN(0, 32)` → ~64-byte return (≈1×). Corpus reproducer
`eth_call_stateoverride_large_return_buffer_amp` (`response_amp`, `source_class: original`) ships in
`NullRabbit/nr-bundles-public` with the amplifier + 1× control.

## Scope

Availability / bandwidth-and-CPU only; no funds, consensus, or auth break. A loopback-bound RPC or one
behind a response-size-capping gateway is not affected.

## Mitigation

- Cap `eth_call` response size at the RPC edge; restrict or disable `stateOverride` on public endpoints.
- Rate-limit `eth_call` per source; keep `--http`/`--ws` on loopback or behind an authenticating gateway.

## Vendor channel and scope

Vendor **go-ethereum**. Availability-only, config-mitigable → **out of paid scope → publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai

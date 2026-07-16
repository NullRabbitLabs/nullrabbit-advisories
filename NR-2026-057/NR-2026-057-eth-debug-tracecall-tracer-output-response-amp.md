# NR-2026-057 — Ethereum (go-ethereum): debug_traceCall tracer-output response amplification

**NullRabbit Operator Advisory** · Published 2026-07-15

**Related:** NR-2026-025 covers `debug_traceCall` **compute** amplification; this advisory covers the
distinct **response-size** amplification produced by the tracer output.

## Summary

`debug_traceCall` returns the tracer's per-execution output. Two tracer configurations expand a small
request into a large response: (1) the default struct-logger with `enableMemory` re-serialises the whole
growing EVM memory array at **every** opcode step → O(steps × memory) output; (2) `callTracer` emits one
frame per CALL, so injected bytecode making N calls yields N frames. Gas stays trivial, so gas caps do not
bound the response. A caller drives a megabytes-class reply for a few hundred bytes of request on an exposed
`debug` namespace. Availability only, out of paid scope → publish-track.

## Findings at a glance

| Finding | Primitive | Tracer | Class | Severity |
|---|---|---|---|---|
| `ETH_DEBUG_TRACECALL_STRUCTLOG_MEMORY_AMP` | `eth_debug_tracecall_structlog_enablememory_quadratic_amp` | struct-logger `enableMemory` | `response_amp` | MEDIUM |
| `ETH_DEBUG_TRACECALL_CALLTRACER_BREADTH_AMP` | `eth_debug_tracecall_calltracer_callframe_breadth_amp` | `callTracer` | `response_amp` | LOW |

- **Reachability:** any remote client reaching a JSON-RPC port with the `debug` namespace enabled on a
  routable bind (`--http.api debug` / `--ws.api debug`); no auth. The `debug` namespace is off by default.
- **Affected:** go-ethereum with the `debug` namespace exposed.

## Affected versions

Observed on go-ethereum 1.17.4; documented tracer semantics, no version-specific regression.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`debug_traceCall` (`eth/tracers/api.go` → `API.TraceCall`) executes the call with a tracer hooked per step.
(1) The struct-logger with `EnableMemory` records the full memory array at each step, so a loop that grows
memory yields O(steps × memory) serialised output. (2) `callTracer` records one nested frame per CALL, so N
injected CALLs → N frames. Both scale response bytes with attacker-chosen work while gas stays low; no
per-response size cap applies.

## Measurement (fidelity: lab)

Self-owned go-ethereum 1.17.4 `--dev`: (1) struct-logger + `enableMemory` over a memory-growing loop →
**~348 B request → ~1.54 MB response (≈4,412×)**, 651 structLogs, ~24 k gas. (2) `callTracer` over 800 CALLs
→ **~346 B → ~140 KB (≈406×)**. Corpus reproducers (both `response_amp`, `source_class: original`) ship in
`NullRabbit/nr-bundles-public`; controls (memory-off trace / N=1) discriminate.

## Scope

Availability / bandwidth-and-CPU only; no funds, consensus, or auth break. A node with the `debug` namespace
off (default) or on loopback / behind auth is not affected.

## Mitigation

- Do not expose the `debug` namespace on a routable interface (go-ethereum's own guidance discourages it);
  if unavoidable, auth-gate it, rate-limit per source, and cap trace/response size.

## Vendor channel and scope

Vendor **go-ethereum**. Availability-only, exposure-mitigable → **out of paid scope → publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai

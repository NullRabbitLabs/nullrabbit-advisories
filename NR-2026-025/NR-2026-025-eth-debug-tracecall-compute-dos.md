# NR-2026-025 — Ethereum (go-ethereum): debug_traceCall compute amplification → compute-amp DoS

**NullRabbit Operator Advisory** · Published 2026-07-08

## Summary

`debug_traceCall` executes an `eth_call`-style message **with a full EVM tracer attached**, re-running the
call opcode-by-opcode against the target block's state and recording per-step instrumentation. A single small
request therefore converts into up to seconds of single-goroutine CPU on the target — a **compute
amplification** DoS. go-ethereum documents the `debug` namespace as **DoS-prone and not to be exposed**; the
finding is that where operators *do* expose it (block explorers, tracing/indexing backends, MEV tooling), an
**unauthenticated** caller drives heavy re-execution for the cost of one request. This is an **availability
issue only** — no funds, no consensus break, no auth bypass — and falls **out of paid scope** (an
exposure/configuration issue on a documented do-not-expose surface), so it is handled on NullRabbit's
publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `ETH_DEBUG_TRACECALL_COMPUTE` | `eth_debug_tracecall_compute` | `debug_traceCall` (JSON-RPC) | `compute_amp` | MEDIUM |

- **Reachability:** any remote client that can reach a JSON-RPC port with the `debug` namespace enabled
  (`--http.api debug` / `--ws.api debug`) on a non-loopback bind; no auth, no handshake. The `debug` namespace
  is **not** enabled by default and is documented do-not-expose.
- **Severity:** availability-only compute-amplification DoS; **out of paid scope**, publish-track.
- **Affected:** go-ethereum (`ethereum/go-ethereum`) run with the `debug` namespace exposed on a routable
  interface.
- **Mitigation:** do not expose the `debug` namespace; if unavoidable, auth-gate it and rate-limit + tighten
  `--rpc.evmtimeout` / `--rpc.gascap`. See Mitigation.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`debug_traceCall` is served by `API.TraceCall` (`eth/tracers/api.go`): it reconstructs the parent block's
state, builds the requested message, and executes it through the EVM **with a tracer hooked into every
step** — the default struct/opcode logger (or a JS/`callTracer`/`prestateTracer`) records instrumentation per
opcode, per memory/stack change. Tracing is materially more expensive than a plain `eth_call`, and the
attacker controls the cost by choosing a call whose execution path is long or memory-heavy.

The bounds that exist are per-request time/gas ceilings, not a rate or concurrency limit:

- `--rpc.gascap` (default 50,000,000) caps the gas a single traced call may consume, and `--rpc.evmtimeout`
  (default 5s) caps its wall-clock — so one call is bounded, but a crafted call runs *right up to* those
  ceilings.
- There is **no default per-source rate limit or per-connection concurrency cap** on the RPC transport, so N
  concurrent `debug_traceCall`s each burn up to the timeout of CPU in parallel, and N is attacker-chosen.

geth's own documentation (`debug` namespace reference) states the debug API is DoS-prone and should not be
exposed publicly — this advisory is the measured expression of that warning: exposure turns a documented
expensive method into an unauthenticated compute-amplification lever.

## Measurement (fidelity: explicit)

The per-request cost is **bounded by `--rpc.evmtimeout` / `--rpc.gascap`** and maximised by a call whose
traced execution is long or memory-heavy; the *aggregate* impact scales with the attacker's concurrency,
which the RPC server does not cap — so the realised CPU pressure is a function of those ceilings × connection
count, not a single fixed multiplier. The published corpus reproducer (primitive
`eth_debug_tracecall_compute`; family `compute_amp`, `source_class: original`, shipped in
`NullRabbit/nr-bundles-public`) captures the **attack traffic** — repeated `debug_traceCall` requests that
drive heavy traced re-execution, contrasted with a light benign `eth_call`/trace to the same surface. **This
advisory stands on the source trace and geth's own documentation of the `debug` namespace as DoS-prone /
do-not-expose — not on a single measured CPU figure from the lab reproducer.**

## Scope

Availability / CPU-cost only; no consensus-safety, no funds, no authentication break, no chain halt. The harm
is per-node CPU saturation of an **exposed** `debug` endpoint; the `debug` namespace is off by default and
documented do-not-expose, so a default node is not affected, and a node that keeps `debug` on loopback or
behind auth is not remotely reachable. The reproducer targets a local self-owned node, carries no public IPs
or mainnet RPC hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Do not expose the `debug` namespace on a routable interface** — this is geth's own guidance. Omit `debug`
  from `--http.api` / `--ws.api`, or keep it on loopback / behind an authenticating gateway.
- If tracing must be exposed, **auth-gate it, rate-limit per source, and cap concurrency**, and tighten
  `--rpc.evmtimeout` and `--rpc.gascap` below the defaults for the traced surface.
- Serve tracing from a dedicated, isolated, capacity-planned backend rather than a validating/RPC node that
  also serves consensus-critical traffic.

## Disclosure & provenance

Availability-only, exposure/configuration-mitigable compute amplification on a documented do-not-expose RPC
surface → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor:
**go-ethereum (`ethereum/go-ethereum`)**; this is our own (`source_class: original`) measurement of a
vendor-documented DoS-prone method, not a novel implementation flaw or an assigned CVE. The corpus primitive
`eth_debug_tracecall_compute` is **on-spec** (registered in the known-class provenance map) and **on-HF**
(shipped in the public dataset `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped
defensive artefact.

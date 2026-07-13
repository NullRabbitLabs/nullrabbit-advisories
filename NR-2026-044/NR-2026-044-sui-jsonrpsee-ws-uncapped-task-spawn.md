# NR-2026-044 — Sui (sui-json-rpc): jsonrpsee WebSocket transport spawns an uncapped task per RPC call + `u32::MAX` connection/response limits → per-connection memory amplification

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

Sui's JSON-RPC WebSocket transport (jsonrpsee) **spawns an unbounded tokio task per non-subscription RPC
call** (`jsonrpsee-server ws.rs:148`), and Sui configures the server with **`max_connections` and
`max_response_body_size` both set to `u32::MAX`** (`sui-json-rpc/lib.rs:175-179`). With no cap on
in-flight calls and no cap on response size, a **single slow-read WebSocket connection** that fires many
large-response calls back-to-back fills the per-connection `mpsc(1024)` send queue and **pins N large
response strings in memory** while their tasks block on the slow reader — a **per-connection memory
amplification** (this is finding **H4**). This is an **availability** issue against a public-by-default
RPC surface; it is a resource-bounding / hardening class, **out of paid scope**, handled on NullRabbit's
publish-track. **Sui-specific: IOTA is not in the blast radius.**

## Findings at a glance

| Finding | Primitive | Surface | Class | Severity |
|---|---|---|---|---|
| `JSONRPSEE_H4_SUI_WS_HANDLER_TASK_SPAWN` (H4) | `sui_jsonrpsee_h4_ws_task_spawn` | Sui JSON-RPC WebSocket transport (jsonrpsee-server) | `per-conn-rss-pin` + `handler-task-spawn` | MEDIUM |

- **Reachability:** any remote host that can reach the Sui JSON-RPC WebSocket port; the amplification is
  driven from a **single connection** (a slow reader), so it does not depend on connection fan-out.
- **Severity:** MEDIUM — per-connection memory amplification (pinned response strings + uncapped per-call
  task spawn), bounded to availability. **Out of paid scope**, publish-track.
- **Affected:** Sui full/RPC nodes serving jsonrpsee over WebSocket with the shipped `u32::MAX` connection
  and response-size limits. **IOTA is not affected** (not in the blast radius).
- **Mitigation:** bound `max_response_body_size` and `max_connections` (do not leave at `u32::MAX`), cap
  concurrent in-flight calls per connection (backpressure on the mpsc rather than unbounded task spawn),
  and add slow-read/idle timeouts. See Mitigation.

## Mechanism (source-cited)

- **Uncapped per-call task spawn.** In the jsonrpsee WebSocket server loop
  (`jsonrpsee-server ws.rs:148`), each incoming **non-subscription** RPC call is dispatched onto a freshly
  **spawned tokio task** with no ceiling on the number of concurrently outstanding tasks per connection.
  Nothing throttles how many calls a single connection may have in flight at once.
- **`u32::MAX` server limits.** Sui builds the jsonrpsee server with **`max_connections`** and
  **`max_response_body_size`** set to **`u32::MAX`** (`sui-json-rpc/lib.rs:175-179`), so neither the
  connection count nor the size of any single response is meaningfully bounded.
- **The amplification.** A client opens one WebSocket connection and **reads slowly** (or not at all) while
  issuing many RPC calls that each produce a **large response body**. Each response is serialized into a
  string and handed to the per-connection outbound **`mpsc(1024)`** queue. Because the client is not
  draining the socket, the queue fills and the spawned tasks **pin their (large) response strings in
  memory** waiting to send. With `max_response_body_size = u32::MAX`, each pinned string can be very large;
  with the uncapped task spawn and `max_connections = u32::MAX`, nothing sheds the accumulating in-flight
  work. The result is **per-connection memory amplification** — a small amount of attacker traffic pins a
  disproportionate amount of server memory.

## Measurement (fidelity: explicit)

This advisory is **source-traced + traffic-modelled**, not live-measured — no measured RSS/CPU figures are
claimed.

- **Source trace.** The uncapped per-call task spawn in the jsonrpsee WebSocket loop
  (`jsonrpsee-server ws.rs:148`) and the `u32::MAX` `max_connections` / `max_response_body_size`
  configuration (`sui-json-rpc/lib.rs:175-179`) are read directly from source; together they remove the two
  bounds (in-flight-call count and response size) that would otherwise cap the per-connection memory a slow
  reader can pin behind the `mpsc(1024)` queue.
- **Traffic model.** The published corpus reproducer (primitive `sui_jsonrpsee_h4_ws_task_spawn`; family
  `memory_amp`, `source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **wire
  signature** of the attack — a **slow-read / non-draining WebSocket** connection issuing **many
  large-response RPC calls** back-to-back so the per-connection queue backs up and response strings
  accumulate.
- **This advisory stands on the source trace** (uncapped per-call spawn + `u32::MAX` limits) **and the
  modelled traffic signature — it does not assert a live-measured memory or CPU number.**

## Scope

Availability only — **per-connection memory amplification** via pinned response strings plus uncapped
per-call task spawn. There is **no consensus-safety break, no funds impact, no authentication bypass, and
no data corruption**. A node that bounds `max_response_body_size`, bounds `max_connections`, and caps
concurrent in-flight calls per connection is not affected. The issue is **Sui-specific**; **IOTA is not in
the blast radius**. The reproducer targets a local self-owned mock, carries no public IPs or mainnet
hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Bound the response size:** set `max_response_body_size` to a realistic ceiling (not `u32::MAX`) so a
  single call cannot pin an unbounded string.
- **Bound connections:** set `max_connections` to a finite value (not `u32::MAX`).
- **Cap concurrent in-flight calls per connection:** apply **backpressure on the outbound mpsc** (limit how
  many calls a connection may have outstanding) rather than spawning an unbounded task per call, so a slow
  reader cannot make the server accumulate work faster than it can drain.
- **Add slow-read / idle timeouts:** disconnect connections that stop draining their socket, so pinned
  response state is reclaimed instead of held indefinitely.
- **Front the WebSocket RPC port with a gateway** that enforces response-size and per-connection
  concurrency limits where a bounded upstream cannot be relied upon.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable per-connection memory amplification on a
public-by-default RPC surface → **out of paid scope → publish-track** under NullRabbit's disclosure-scope
policy. This is our own (`source_class: original`) source-trace and traffic model of the Sui-specific
jsonrpsee WebSocket configuration — not an assigned Sui CVE. The corpus primitive
`sui_jsonrpsee_h4_ws_task_spawn` is **on-spec** (registered in the known-class provenance map) and
**on-HF** (shipped in `NullRabbit/nr-bundles-public`, `HF_DATASET_PRIMITIVES`), so this advisory does not
outpace its shipped defensive artefact.

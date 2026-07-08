# NR-2026-024 — Ethereum (go-ethereum): eth_getBlockByNumber full-transaction fetch flood → connection-exhaustion DoS

**NullRabbit Operator Advisory** · Published 2026-07-08

## Summary

`eth_getBlockByNumber(number, fullTx=true)` makes the node fetch a block and **serialise every transaction
in it** into the JSON-RPC response. Each call is individually cheap-ish, but geth's JSON-RPC server applies
**no per-source rate limit and no per-connection concurrency cap** by default, so an **unauthenticated**
caller who sustains full-block fetches at high rate — many connections, each streaming full-tx blocks — drives
the RPC handler pool and per-request marshalling CPU to saturation, congesting the endpoint for legitimate
users. This is a **request-flood / connection-exhaustion** DoS against an **exposed** JSON-RPC surface. It is
an **availability issue only** — no funds, no consensus break, no auth bypass — and falls **out of paid
scope** (a rate-limiting/deployment concern, not an implementation flaw), so it is handled on NullRabbit's
publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `ETH_GETBLOCK_FLOOD` | `eth_getblock_flood` | `eth_getBlockByNumber` (JSON-RPC) | `connection_exhaustion` | MEDIUM |

- **Reachability:** any remote client that can reach a non-loopback-bound JSON-RPC (`--http`/`--ws`) port; no
  auth, no handshake. The loopback default is not remotely reachable.
- **Severity:** availability-only request-flood / connection-exhaustion DoS; **out of paid scope**,
  publish-track.
- **Affected:** go-ethereum (`ethereum/go-ethereum`) with the `eth` namespace exposed on a routable interface
  and no external rate-limit.
- **Mitigation:** per-source rate-limit + connection cap at the RPC edge; do not expose the RPC unauthenticated
  on a routable bind. See Mitigation.

## Mechanism (source-cited, `ethereum/go-ethereum`)

`eth_getBlockByNumber` is served by `BlockChainAPI.GetBlockByNumber` (`internal/ethapi/api.go`): it loads the
block and calls `RPCMarshalBlock(...)` with `fullTx=true`, which marshals **every transaction object** in the
block (not just the hashes). For full, high-transaction blocks this is a non-trivial per-request cost paid on
the server's RPC worker goroutine.

The transport controls that exist bound **batches**, not **rate**: `--rpc.batch-request-limit` (default 1000)
and `--rpc.batch-response-max-size` (default 25 MB) cap a single JSON-RPC batch, and the WS server bounds
message size — but there is **no default per-IP/per-source request-rate limit and no per-connection
in-flight-request cap** in geth's HTTP/WS server (`rpc/`). An attacker therefore opens many connections and
streams a continuous flood of single (non-batched) `eth_getBlockByNumber(..., true)` calls, each of which
slips past the batch limits while collectively saturating the handler pool and marshalling CPU. The class is
generic request-flood congestion, with full-tx block marshalling as the per-request cost multiplier.

## Measurement (fidelity: explicit)

This is a **rate-driven congestion** class, so the impact is a function of attacker request rate, connection
count, and the target's core count and marshalling throughput rather than a single fixed amplification
constant. The published corpus reproducer (primitive `eth_getblock_flood`; family `connection_exhaustion`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — a
sustained high-rate `eth_getBlockByNumber(fullTx=true)` flood across multiple connections, contrasted with a
paced, low-rate benign block-fetch pattern to the same method. **This advisory stands on the source trace and
the absence of a default per-source RPC rate limit in geth's server — not on a single measured throughput
figure from the lab reproducer.**

## Scope

Availability / handler-and-CPU congestion only; no consensus-safety, no funds, no authentication break, no
chain halt. The harm is degradation of an **exposed** RPC endpoint under flood; a loopback-bound RPC (the
default) is not remotely reachable, and a node behind a gateway that rate-limits and caps concurrency per
source is not affected. The reproducer targets a local self-owned node, carries no public IPs or mainnet RPC
hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Rate-limit the RPC per source** and **cap concurrent connections / in-flight requests per client** at a
  reverse proxy or RPC gateway — geth's server does not do this itself.
- **Prefer `fullTx=false`** for callers that only need hashes, and cache hot block responses at the edge.
- **Do not expose the JSON-RPC unauthenticated on a routable interface.** Keep `--http`/`--ws` on loopback or
  behind an authenticating, rate-limiting gateway, exposing only the methods an application needs.

## Disclosure & provenance

Availability-only, deployment/rate-limit-mitigable request flood on the public JSON-RPC surface → **out of
paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **go-ethereum
(`ethereum/go-ethereum`)**; this is our own (`source_class: original`) measurement of the node's documented
absence of a built-in RPC rate limit, not a novel implementation flaw or an assigned CVE. The corpus
primitive `eth_getblock_flood` is **on-spec** (registered in the known-class provenance map) and **on-HF**
(shipped in the public dataset `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped
defensive artefact.

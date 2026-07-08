# NR-2026-023 — Ethereum (go-ethereum): eth_getLogs wide block-range response amplification → response-amp DoS

**NullRabbit Operator Advisory** · Published 2026-07-08

## Summary

`eth_getLogs` returns **every** log matching a `{fromBlock, toBlock, address, topics}` filter across the
requested block span, serialised into a single JSON-RPC response. A few hundred bytes of request therefore
expands into an arbitrarily large response bounded only by how many logs match — a **response-amplification**
DoS payable by an **unauthenticated** caller when the JSON-RPC transport is bound to a non-loopback address.
This is well-trodden ground: go-ethereum documents `eth_getLogs` as an expensive read and ships
`--rpc.rangelimit` to cap the block *span* — but where that flag is unset or set loose (and on the many
public/semi-public RPC endpoints that run without a tight limit), a single wide-range or broad-topic query
still forces the node to scan the range and emit an unbounded matched-log set, consuming bandwidth and
serialisation CPU. This is an **availability issue only** — no funds, no consensus-safety break, no auth
bypass — and it falls **out of paid scope** (a documented, config-mitigable expensive read), so it is handled
on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `ETH_GETLOGS_RESPONSE_AMP` | `eth_getlogs_response_amp` | `eth_getLogs` (JSON-RPC) | `response_amp` | MEDIUM |

- **Reachability:** any remote client that can reach a non-loopback-bound JSON-RPC (`--http`/`--ws`) port; no
  auth, no handshake. The loopback default is not remotely reachable.
- **Severity:** availability-only response-amplification DoS; **out of paid scope**, publish-track.
- **Affected:** go-ethereum (`ethereum/go-ethereum`) run with the log-filter RPC exposed and no (or a loose)
  `--rpc.rangelimit`.
- **Mitigation:** a tight block-range cap (`--rpc.rangelimit`) **plus** a result-size / result-count cap and
  a per-source rate-limit at the RPC edge. See Mitigation.

## Mechanism (source-cited, `ethereum/go-ethereum`)

The log-filter RPC is unauthenticated on the HTTP/WS transport — geth's JSON-RPC server applies no
per-method authorization; exposure is purely a function of the bind address and the enabled namespaces.

`eth_getLogs` is served by `FilterAPI.GetLogs` (`eth/filters/api.go`), which builds a `Filter` and calls
`filter.Logs(ctx)` (`eth/filters/filter.go`). `Logs` resolves the `[fromBlock, toBlock]` range and walks it
via the indexed (bloom-bit) and unindexed paths, and for every block whose bloom matches it decodes the
receipts and **appends every matching `*types.Log` into a single result slice**, which is returned whole and
JSON-serialised back to the caller. The controls that exist bound the *inputs*, not the *output*:

- `--rpc.rangelimit` caps the **block span** (`toBlock - fromBlock`); requests over the cap are rejected with
  a `-32000`/`-32602`-class error. It does **not** cap how many logs a permitted span returns.
- There is **no default cap on the number or byte-size of the returned logs** — a range/topic set matching a
  high-volume contract (e.g. a busy ERC-20 `Transfer` topic over a wide-but-permitted span) yields a
  megabytes-class response for a tiny request.

So the amplification is structural: response size scales with the matched-log count, which the attacker
steers via the range and topic filter, entirely within whatever range limit is configured.

## Measurement (fidelity: explicit)

The amplification is **structural, not a single measured constant**: response bytes scale linearly with the
number of matching logs, and the attacker controls that count through `fromBlock..toBlock` breadth and topic
selectivity — so the realised factor depends on the target's chain data and its `--rpc.rangelimit`, not on a
fixed multiplier. The published corpus reproducer (primitive `eth_getlogs_response_amp`; family
`response_amp`, `source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack
traffic** — a wide-range/broad-topic `eth_getLogs` request that returns a large log set, contrasted with a
narrow, selective benign query to the same method. **This advisory stands on the source trace and geth's own
documentation of `eth_getLogs` as an expensive, range-limited read — not on the reproducer's lab transport.**

## Scope

Availability / bandwidth-and-CPU cost only; no consensus-safety, no funds, no authentication break, no chain
halt. The harm is per-node egress + serialisation load on an **exposed** RPC endpoint; a loopback-bound RPC
(the default) is not remotely reachable, and a node behind a gateway that enforces a tight range and
result-size cap is not affected. The reproducer targets a local self-owned node, carries no public IPs or
mainnet RPC hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Cap the block range** with a tight `--rpc.rangelimit`, and additionally **cap the result size/count** at
  the RPC edge (a reverse proxy or RPC gateway) — the range limit alone does not bound a single wide-topic
  response.
- **Rate-limit `eth_getLogs` per source** and require pagination for historical scans.
- **Do not expose the log-filter RPC unauthenticated on a routable interface.** Keep `--http`/`--ws` on
  loopback or behind an authenticating gateway; expose only the methods an application needs.

## Disclosure & provenance

Availability-only, config-mitigable, documented-expensive read on the public JSON-RPC surface → **out of
paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **go-ethereum
(`ethereum/go-ethereum`)**; this is our own (`source_class: original`) measurement of a vendor-documented
expensive method, not a novel implementation flaw or an assigned CVE. The corpus primitive
`eth_getlogs_response_amp` is **on-spec** (registered in the known-class provenance map) and **on-HF**
(shipped in the public dataset `NullRabbit/nr-bundles-public`), so this advisory does not outpace its
shipped defensive artefact.

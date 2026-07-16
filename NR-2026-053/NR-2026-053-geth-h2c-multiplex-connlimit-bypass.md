# NR-2026-053 — Ethereum (go-ethereum): h2c stream-multiplexing bypasses an L4 connection cap on the JSON-RPC port

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

go-ethereum's JSON-RPC HTTP port terminates **cleartext HTTP/2 (h2c) by prior knowledge** — a client may
send the raw HTTP/2 connection preface with no TLS and no `Upgrade` dance and the node speaks h2. HTTP/2
multiplexes many requests as independent streams on **one** TCP connection. An operator who fronts the RPC
port with an **L4 / TCP-passthrough edge** (a cloud L4 load balancer, or nginx `stream`) and rate-limits
**connections** per source IP (`limit_conn`) therefore counts a single connection while being blind to the
requests multiplexed inside it. A single h2c connection carrying N `eth_getLogs` requests pulls N amplified
responses through the one permitted connection — an **amplification-multiplexing bypass** of the L4
connection cap. This is an **availability issue only** — no funds, no consensus-safety break, no
authentication bypass — and falls **out of paid scope** (a transport/configuration hardening gap), so it is
handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Surface | Class | Severity |
|---|---|---|---|---|
| `ETH_GETH_H2C_MULTIPLEX_CONNLIMIT_BYPASS` | `eth_geth_h2c_multiplex_connlimit_bypass` | JSON-RPC port (cleartext h2c) behind an L4 edge | `rate_limiter_bypass` | MEDIUM |

- **Reachability:** any remote client that can reach the JSON-RPC port through an L4/TCP-passthrough edge
  which forwards the connection opaquely; no auth, no TLS required (prior-knowledge h2c).
- **Boundary:** bypasses a **connection-count** control (L4 `limit_conn`), NOT an L7 per-request rate limit.
  A terminating L7 reverse proxy re-serialises each h2 stream to an origin request and rate-limits it.
- **Affected:** go-ethereum with the JSON-RPC HTTP transport exposed behind an L4/TCP-passthrough edge whose
  only control is a per-connection cap.

## Affected versions

Observed on go-ethereum 1.17.4. The behaviour is a property of the RPC server terminating cleartext h2c on
the HTTP transport plus HTTP/2 stream multiplexing, not a version-specific regression; no specific affected
range is established beyond "a go-ethereum JSON-RPC port fronted by a connection-counting L4 edge".

## Mechanism (source-cited, `ethereum/go-ethereum`)

geth's JSON-RPC HTTP server (`node/rpcstack.go`, `rpc/http.go`) is served by Go's `net/http`, whose
`h2c`-capable handler accepts a prior-knowledge HTTP/2 preface on the cleartext listener. HTTP/2 (RFC 9113)
multiplexes concurrent streams over one connection up to `SETTINGS_MAX_CONCURRENT_STREAMS`. An L4 edge
(nginx `stream` `limit_conn`, or a cloud L4 LB) operates below HTTP: it forwards the TCP byte stream — the
h2 preface and every multiplexed stream inside — opaquely to the origin, and its only lever is the count of
**connections**. So N requests + N responses ride one connection the edge counts as one; the per-connection
cap does not bound them. Each `eth_getLogs` inside is itself a response-amplifying read (see NR-2026-023),
so the multiplex delivers N amplified responses for one connection slot.

## Measurement (fidelity: lab)

Measured against a self-owned go-ethereum 1.17.4 `--dev` node behind an nginx `stream` L4 edge
(`limit_conn 1` per source IP):
- **ONE** prior-knowledge h2c connection multiplexing **20** `eth_getLogs` streams → **20/20 completed,
  ~43.9 MB** of response through the single connection (~2.2 MB/stream), identical whether direct to the
  origin or through the L4 edge.
- The same edge rejected **16 of 20 SEPARATE** connections from one IP (`limit_conn`), confirming the
  control is real and is bypassed only by the multiplexed tunnel.
- **Boundary:** through an L7 (h2-terminating) edge with a per-request rate limit, 17 of 20 streams were
  rejected (`503`) — the multiplex bypass does **not** defeat request-level rate limiting.

The published corpus reproducer (primitive `eth_geth_h2c_multiplex_connlimit_bypass`, family
`rate_limiter_bypass`, `source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the
attack traffic (the multiplexed streams + the rejected separate connections). This advisory stands on the
source behaviour (cleartext h2c on the RPC port) and the measured multiplex, on a self-owned lab node.

## Scope

Availability / bandwidth-and-CPU cost only; no consensus-safety, no funds, no authentication break. The harm
is per-node egress + serialisation load on an exposed RPC endpoint whose only edge control counts
connections. A node whose edge rate-limits **requests** (L7), or whose RPC port is not exposed on a routable
interface, is not affected. The reproducer targets a local self-owned node, carries no public IPs or mainnet
RPC hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Rate-limit at L7 (per request), not only L4 (per connection).** A terminating reverse proxy that counts
  requests sees each multiplexed stream; a connection cap does not.
- **Bound HTTP/2 multiplexing** at the edge/origin (a low `SETTINGS_MAX_CONCURRENT_STREAMS`) and cap the
  `eth_getLogs` result size / block range per the NR-2026-023 mitigation.
- **Do not expose the JSON-RPC port raw behind an L4/TCP passthrough**; keep it on loopback or behind an
  authenticating, request-aware gateway.

## Vendor channel and scope

Vendor: **go-ethereum (`ethereum/go-ethereum`)**. Availability-only, configuration-mitigable transport
hardening gap on the public JSON-RPC surface → **out of paid scope → publish-track** under NullRabbit's
disclosure-scope policy. Not a fund-loss / consensus-safety / auth-bypass class.

## Provenance

Our own (`source_class: original`) measurement, not an assigned CVE or a novel implementation flaw. The
corpus primitive `eth_geth_h2c_multiplex_connlimit_bypass` is on-spec (registered in the known-class
provenance map) and on-HF (shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its
shipped defensive artefact.

## Contact
research@nullrabbit.ai

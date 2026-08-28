# NR-2026-018 — Cosmos-SDK gRPC server: `grpc.NewServer` built without `MaxConcurrentStreams` → unbounded HTTP/2 stream pin

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

The Cosmos-SDK gRPC server is constructed with `grpc.NewServer` **without** setting
`grpc.MaxConcurrentStreams`. The underlying grpc-go library then defaults to an effectively unbounded
number of concurrent HTTP/2 streams **and** does not emit a `SETTINGS_MAX_CONCURRENT_STREAMS` cap to
the client. A remote client can open a very large number of concurrent streams over a **single** TCP
connection to the validator's gRPC port (default `9090`), each pinning a few KB of per-stream server
state (route lookup, request context, gas meter). With no cap, one source holds a very large stream
count without ever completing the requests, and the pinned memory grows accordingly. It is an
availability issue only — no funds, no consensus-safety impact. Sei's fork already sets
`grpc.MaxConcurrentStreams(100)` at the equivalent call site; upstream does not.

> **Correction, 2026-08-28.** This advisory previously stated a "per-source ceiling on the order of
> ~7-8 GB RSS" attributable to a grpc-go internal limit near 1M streams, and described scaling across
> attacker source IPs as measured and linear. Neither is supported by the underlying sweep, which grows
> monotonically with no plateau and which varied connection count rather than source addresses. Both
> claims are corrected below; the ~7 KB per-stream figure is unaffected and still holds.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Per-stream state pin via unbounded HTTP/2 concurrent streams (`connection_exhaustion`) |
| Reachability | Remote client on the Cosmos-SDK gRPC port (default `9090`); a stream open is all that is required |
| Trigger | Many concurrent HTTP/2 streams multiplexed on a single TCP connection, held open |
| Measured | ~7 KB pinned per held stream (gaiad, loopback); 962 MB RSS at 1 connection x 100k streams, rising to 7.6 GB at 10 x 100k — the top of the tested matrix, with no plateau observed |
| Severity | Medium (public reach, cheap per-stream cost, no default cap; per-validator availability, no chain halt) |
| Affected | Cosmos-SDK-based validators/nodes exposing the gRPC port without a `MaxConcurrentStreams` cap or an external per-source stream/connection limit |
| Mitigation | Set `grpc.MaxConcurrentStreams` at the server call site (Sei pattern); L7/iptables per-source connection limits; sentry architecture; cgroup `MemoryMax` + `Restart=on-failure`. See Mitigation |

## Mechanism (source-cited, `cosmos/cosmos-sdk`)

`server/grpc/server.go` builds the gRPC server via `grpc.NewServer(...)` with codec / message-size
options but **no** `grpc.MaxConcurrentStreams` option. Consequently:

1. **No server-side concurrent-stream cap** — grpc-go's default maximum concurrent streams is
   effectively unbounded, so the server accepts arbitrarily many simultaneously-open streams from one
   connection.
2. **No cap signalled to the client** — because the option is unset, the server does not advertise a
   `SETTINGS_MAX_CONCURRENT_STREAMS` value in its HTTP/2 `SETTINGS`, so a cooperative client sees no
   limit either.
3. **Per-stream state is pinned on open** — each accepted stream allocates per-stream server state
   (~7 KB observed on gaiad) that is retained while the stream is open. An attacker opens streams and
   holds them, converting stream count directly into pinned server memory.

The `MaxConcurrentStreams` cap that would bound this is present in Sei's fork of the same file and
absent upstream — a roughly two-line difference at the server construction site.

## Impact and scope boundaries (measured)

- **Per-validator availability, not chain halt.** On a multi-validator chain, one affected validator
  may OOM/restart under sustained pressure while quorum keeps producing blocks. The realistic harm is
  per-validator downtime cycles and, under sustained attack, slashing/jailing exposure from missed
  blocks — not a network-wide consensus halt.
- **Other submission paths are unaffected.** The CometBFT RPC (default `26657`) and LCD/REST (default
  `1317`) submission paths use separate server pools and were **not** measurably degraded during the
  attack; this is not a transaction-front-running or asymmetric-degradation finding.
- **Growth is monotonic across the tested range; no ceiling was established.** RSS rose with held-stream
  count at every point of the sweep, from 305 MB (1 connection x 1,000 streams) to 7.6 GB (10 x 100,000),
  with no plateau. 7.6 GB is where testing stopped, **not** a demonstrated per-source limit. Scaling
  across distinct attacker source IPs follows from the per-connection allocation but was **not**
  measured: the sweep varied connection count from a single client, not source addresses.

## Reproduction (fidelity: explicit)

The per-stream memory pin is a server-side effect measured separately; the published corpus reproducer
captures the **wire signature** — many HTTP/2 streams multiplexed on a single connection to a gRPC
endpoint — via the shared HTTP/2 multiplex capture template (primitive `cosmos_grpc_stream_flood` in
`NullRabbit/nr-bundles-public`, family `connection_exhaustion`, `source_class: original`). Sixteen
attack captures span a 512–2048 stream-count sweep at saturating posture. **This advisory stands on the
source trace and the measurement, not on the reproducer's transport shim.** It is the Cosmos-side
sibling of the IOTA `StreamCheckpoints` held-stream finding.

## Mitigation

- **Set a concurrent-stream cap at the server** — add `grpc.MaxConcurrentStreams(N)` to the gRPC server
  construction (the Sei fork uses `100`), so one connection cannot open unbounded streams.
- **Operator-side limits** (standard at institutional validators): per-source connection/stream limits
  at an L7 proxy or via `iptables` connlimit; do not expose the gRPC port on the consensus validator
  (sentry architecture); cap process memory with a cgroup `MemoryMax` and pair with
  `Restart=on-failure` for fast recovery.

## Disclosure & provenance

Availability-only finding (no funds/consensus-safety impact). DoS/availability on the public
Cosmos-SDK gRPC surface is publish-track under NullRabbit's disclosure-scope policy, consistent with the
already-published CometBFT/Cosmos availability family (NR-2026-007, NR-2026-008). Vendor: Interchain /
`cosmos/cosmos-sdk`. NullRabbit measurement; source-trace and numbers in
`chains/cosmos/findings/C11-disclosure-note.md`. Corpus primitive `cosmos_grpc_stream_flood` shipped in
`NullRabbit/nr-bundles-public`.

# NR-2026-003 — IOTA node gRPC OOM via unbounded HTTP/2 concurrent streams

**NullRabbit Operator Advisory** · Published 2026-07-02

## Summary

An IOTA node's public gRPC server accepts an **unbounded** number of concurrent
HTTP/2 streams on a single TCP connection. A single client that opens one TCP
connection and multiplexes ~200 concurrent `GetTransactions` calls (each
requesting a large batch) drives the server's resident memory from a few hundred
MB to **multiple GB in ~10 seconds**, until the kernel OOM-killer terminates the
node. No large bandwidth is required — the server buffers per-stream response
state regardless of how slowly the client reads — and there is no idle eviction.
One source IP, one burst, node down; **restart required**.

This is an availability issue only — no memory corruption, no funds or consensus
impact.

**A one-line server-side fix removes it:** bound the tonic gRPC server with
`.max_concurrent_streams(N)` (e.g. 64). Operators who cannot patch immediately can
reduce blast radius at the edge (see Mitigation), though the backend still needs
the cap.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Unbounded HTTP/2 concurrent streams on the public gRPC surface → memory amplification → OOM-kill (`memory_amp`) |
| Reachability | Remote, unauthenticated, single TCP connection, single source IP |
| Trigger | ~200 multiplexed `GetTransactions` streams (large batch each) on one connection |
| Impact | RSS climbs ~100 MB per concurrent stream; ~70–80 streams exhaust an 8 GB host, ~150 a 16 GB host, ~300 a 32 GB host → kernel OOM-kill of the node process. Recoverable on restart; the burst re-kills |
| Severity | Critical for node availability (single-connection remote OOM); not steady-state degradation, not RCE |
| Mitigation | Server: `tonic Server::max_concurrent_streams(64)`. Edge: an HTTP/2 stream cap forces the attacker onto 2–3 TCP connections but does not save an un-capped backend |

## Affected configuration

Any IOTA node exposing the public gRPC API whose tonic `Server` builder does not
set `.max_concurrent_streams(...)`. In that state the server's HTTP/2 SETTINGS
advertises `max_concurrent_streams = u32::MAX` (effectively unlimited). The
node's `default_grpc_api_max_concurrent_stream_subscribers` cap (1024) applies
**only** to the `StreamCheckpoints` subscription path — it does **not** bound
`GetTransactions` / `GetObjects` / `GetCheckpoint`, which are the unary calls
abused here.

## Mechanism (source-cited)

1. **No stream cap on the public gRPC server.** The tonic server is constructed
   without `.max_concurrent_streams(N)` (`iota-grpc-server/src/server.rs`), so the
   HTTP/2 layer advertises and honours an effectively unlimited concurrent-stream
   count on each connection.

2. **The existing subscriber cap does not cover unary calls.** The
   `..._max_concurrent_stream_subscribers = 1024` limit is scoped to the
   `StreamCheckpoints` server-stream only; `GetTransactions` and the other unary
   ledger reads have no per-connection concurrency bound.

3. **Per-stream response state is buffered server-side.** Each in-flight
   `GetTransactions(500 × digest)` accumulates response state in memory
   independent of the client's receive rate (no receive-rate backpressure that
   would bound retained memory). Concurrency, not bandwidth, is the multiplier —
   measured at roughly 100 MB RSS per concurrent stream.

The three compose: unlimited streams × un-capped unary calls × per-stream
buffering = linear-in-stream-count memory growth with no ceiling but the host's.

## Reproduction

A code-level reproducer accompanies this advisory (see `reproducers/`): it opens
one TCP connection to a **local** gRPC endpoint, multiplexes N concurrent
`GetTransactions` calls, and records the server RSS trajectory. Measured on an
8 GB lab node: RSS 472 MB → 7.6 GB in ~10 s, then kernel OOM-kill
(`oom-kill ... anon-rss:7798928kB`).

The reproducer is not a turnkey attack against live infrastructure: it drives a
locally-run node to demonstrate the memory slope, and does not target any public
or mainnet endpoint.

## Vendor channel and scope

IOTA's security contact is `security@iota.org`; IOTA does **not** run a public
paid bug-bounty program (the legacy program is defunct). Node availability / DoS
is not a paid-impact category, so this finding is **out of scope** for any bounty
— it is published here as an **operator advisory** so operators can apply the
`max_concurrent_streams` cap now. There is no embargo attached: the finding rests
on our own measurement against a self-owned lab node, and no vendor program terms
bind its disclosure.

## Scope

This advisory targets node **availability** only. The reproducer is code-level
(craft + drive the HTTP/2 multiplex against a self-owned local node); it does not
target live infrastructure and is not a turnkey weapon.

## Provenance

NullRabbit original research (our own measurement on a self-owned lab node).
Cross-references: NullRabbit finding id `IOTA_GRPC_H2_MULTIPLEX_OOM`; detection
primitive `iota_grpc_h2_multiplex_oom` (family `memory_amp`).

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

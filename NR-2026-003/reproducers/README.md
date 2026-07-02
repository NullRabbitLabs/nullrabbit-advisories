# NR-2026-003 reproducer — IOTA gRPC HTTP/2 concurrent-stream OOM

**Scope:** this reproducer drives a **self-owned, locally-run** IOTA node to
demonstrate the memory slope. It does **not** target live or mainnet
infrastructure and is **not a turnkey** attack tool — it is a measurement harness
for the mechanism described in the advisory.

## What it shows

On a single TCP connection to the node's public gRPC endpoint, HTTP/2 lets a
client open many concurrent streams. Because the server sets no
`max_concurrent_streams` bound and buffers per-stream response state regardless of
client receive rate, resident memory grows ~linearly with the number of
concurrent unary calls in flight — until the host OOM-kills the process.

## Method (code-level)

1. Stand up a local IOTA node with the public gRPC API enabled (lab box, e.g.
   8 GB RAM).
2. Open **one** TCP/HTTP-2 connection to the local gRPC endpoint.
3. Multiplex ~200 concurrent `GetTransactions` calls, each requesting a large
   batch of digests (e.g. 500 × a known digest), and do **not** drain responses
   quickly.
4. Sample the node process RSS (e.g. `ps`/`/proc/<pid>/status`) once per second.

Observed: RSS ~472 MB → ~7.6 GB in ~10 s, then kernel OOM-kill
(`dmesg`: `oom-kill ... anon-rss:7798928kB`). Slope ≈ 100 MB RSS per concurrent
stream (≈70–80 streams exhaust 8 GB).

## Confirming the fix

Rebuild the node with the tonic server bounded —
`Server::builder().max_concurrent_streams(64)...` — and repeat: the server caps
concurrent streams at the connection layer, so RSS plateaus instead of climbing
without bound.

## Endpoint

The harness connects only to a local endpoint (`127.0.0.1:<grpc-port>`). No
public or mainnet address is referenced or included.

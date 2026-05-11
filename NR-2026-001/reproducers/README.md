# NR-2026-001 reproducers — quick-start

Three self-contained reproducers for the findings described in
[`../NR-2026-001-agave-rpc-architectural-findings.md`](../NR-2026-001-agave-rpc-architectural-findings.md).

All three reproduce against an unmodified `solana-test-validator
2.2.16` on `127.0.0.1:8899`. They are calibrated against agave
v3.1.9, commit `765ee54adc4f574b1cd4f03a5500bf46c0af0817`.

## Prerequisites

- Python 3.10+
- A running `solana-test-validator 2.2.16` on `127.0.0.1:8899`:
  ```bash
  solana-test-validator --reset \
      --ledger ./ledger \
      --rpc-port 8899 \
      --bind-address 127.0.0.1
  ```
- For `SOL_F14_repro.py`: `pip install solders` (>= 0.18) and a
  funded payer keypair JSON (`solana airdrop` into the local
  test-validator faucet keypair is the simplest path; the bank
  must load the fee-payer even with `sigVerify=false`).
- For `SOL_P07_repro.py` at headline magnitude: the
  `populator/spl_token_populator.sh` helper requires the `solana`
  and `spl-token` CLIs on `PATH`. The populator is parameterised
  via the `WORK_DIR` and `RPC_URL` environment variables; defaults
  reflect NullRabbit's localnet layout and will need overriding
  for any other environment.

## Run order

### SOL_F10 — `getMultipleAccounts` byte amplification

Stdlib-only Python; no setup beyond a fresh test-validator.

```bash
# Single-thread baseline (amp ratio confirmation, no saturation)
python3 SOL_F10_repro.py --workers 1 --duration 30

# 8-worker headline (matches advisory measurement)
python3 SOL_F10_repro.py --workers 8 --duration 10
```

Expected at 8 workers: ~220 req/s aggregate, ~1,263× per-request
amplification, ~1,344 MB/s sustained server egress.

### SOL_F14 — `simulateTransaction` async-runtime saturation

Requires `solders` and a funded payer keypair. The 7.1×
per-worker drop is the load-bearing measurement and requires the
1-vs-8 worker comparison.

```bash
# Single-thread baseline
python3 SOL_F14_repro.py --payer /path/to/funded-keypair.json \
    --workers 1 --duration 30

# 8-worker headline
python3 SOL_F14_repro.py --payer /path/to/funded-keypair.json \
    --workers 8 --duration 10
```

Expected: baseline ~918 req/s aggregate, p50 ~1 ms. 8-worker
~1,036 req/s aggregate (1.13× scaling, not 8×), ~129 req/s per
worker (7.1× drop), p50 ~7.7 ms.

### SOL_P07 — `getProgramAccounts` `spawn_blocking` saturation

Stdlib-only Python. The 8× per-worker drop requires populated
state (~10K SPL token accounts) and the 1-vs-8 worker comparison.

```bash
# Optional but required for headline magnitude — seed state
bash populator/spl_token_populator.sh 10000 32

# Single-thread baseline (populated)
python3 SOL_P07_repro.py --workers 1 --duration 30

# 8-worker headline (populated)
python3 SOL_P07_repro.py --workers 8 --duration 10
```

Expected on populated state: baseline ~59.5 req/s, p50 ~16 ms.
8-worker aggregate ~60 req/s (flat — pool saturated), ~7.5 req/s
per worker (8× drop), p50 ~130 ms.

The reproducer runs without populator on sparse state — the
filter-miss path engages but the pool-saturation magnitude is
lower.

## Reading the output

Each reproducer prints the run-local measurement followed by the
headline reference numbers from the advisory. Per-worker req/s
and the 1-vs-8 comparison are the canonical signature; aggregate
req/s alone does not surface the architectural pattern.

Reproducer headers (the docstring at the top of each `.py`) carry
the full source-citation list against the v3.1.9 commit, plus a
brief mechanism description.

## Caveats

- Measurements are calibrated against `solana-test-validator
  2.2.16`. Magnitudes against other validator implementations
  (jito-solana, firedancer client RPC) or other versions may
  differ; the architectural pattern is the load-bearing claim.
- All reproducers run against `127.0.0.1` by default. Do not
  point them at infrastructure you do not operate.
